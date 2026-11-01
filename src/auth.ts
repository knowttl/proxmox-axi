import { createHash, randomUUID } from 'node:crypto'
import type { Credentials, SecretRef } from './credentials.js'
import { resolveSecret } from './credentials.js'
import { executeRequest } from './transport.js'
import { resultBinding } from './private-results.js'
import { Failure } from './errors.js'

interface Session {
  binding: string
  expires: number
  state: 'challenge' | 'ready'
  ticket: string
  csrf?: string
  kind?: 'openid'
}

// The map exists only inside an explicitly started caller-managed command process.
const sessions = new Map<string, Session>()
const denied = () => new Failure('AUTH_SESSION_INVALID', 'Session is absent, expired, cancelled or bound to another caller.', 'Acquire a new session with the explicitly selected profile.')

function binding(credentials: Credentials): string {
  return createHash('sha256').update(JSON.stringify({ origin: credentials.origin, identity: credentials.tokenId,
    actor: process.env.PROXMOX_AXI_ACTOR ?? `uid:${process.getuid?.() ?? 'native'}`, family: process.env.PROXMOX_AXI_SESSION_FAMILY,
    revision: process.env.PROXMOX_AXI_CREDENTIAL_REVISION, source: credentials.diagnostics, secret: credentials.token,
    ca: credentials.ca, pin: credentials.certificatePin })).digest('hex')
}

function selected(credentials: Credentials, id: string): Session {
  if (!sessions.has(id) && process.env.PROXMOX_AXI_AUTH_STATE) {
    // A host resolves its authenticated memory handle before injecting this state.
    // Explicit --session selection prevents it from silently replacing a profile.
    let value: Record<string, unknown>
    try { value = JSON.parse(process.env.PROXMOX_AXI_AUTH_STATE) as Record<string, unknown> } catch { throw denied() }
    if (value.session !== id || value.origin !== credentials.origin || value.identity !== credentials.tokenId ||
      value.actor !== process.env.PROXMOX_AXI_ACTOR || value.family !== process.env.PROXMOX_AXI_SESSION_FAMILY ||
      value.revision !== process.env.PROXMOX_AXI_CREDENTIAL_REVISION || !Number.isSafeInteger(value.expires) ||
      Number(value.expires) > Date.now() + 300_000 || !['ready', 'challenge'].includes(String(value.state)) ||
      typeof value.ticket !== 'string' || !value.ticket || /[^\x21-\x7e]/.test(value.ticket) ||
      value.state === 'ready' && (typeof value.csrfPreventionToken !== 'string' || !value.csrfPreventionToken || /[^\x21-\x7e]/.test(value.csrfPreventionToken))) throw denied()
    sessions.set(id, { binding: binding(credentials), expires: Number(value.expires), state: value.state as Session['state'], ticket: value.ticket,
      ...(value.kind === 'openid' ? { kind: 'openid' } : {}),
      ...(typeof value.csrfPreventionToken === 'string' ? { csrf: value.csrfPreventionToken } : {}) })
    delete process.env.PROXMOX_AXI_AUTH_STATE
  }
  const session = sessions.get(id)
  if (!session || session.expires <= Date.now()) { sessions.delete(id); throw denied() }
  if (session.binding !== binding(credentials)) throw denied()
  return session
}

export function useSession(credentials: Credentials, id: string): Credentials {
  const session = selected(credentials, id)
  if (session.state !== 'ready' || !session.csrf) throw denied()
  credentials.results.register(session.ticket)
  credentials.results.register(session.csrf)
  return { ...credentials, auth: 'ticket', token: session.ticket, csrf: session.csrf }
}

export async function authOperation(credentials: Credentials, action: string, input: Record<string, unknown>, id?: string) {
  for (const [key, session] of sessions) if (session.expires <= Date.now()) sessions.delete(key)
  if (action === 'cancel') {
    if (!id) throw denied()
    selected(credentials, id)
    sessions.delete(id)
    return { status: 'cancelled' }
  }
  credentials.results.sink()
  if (!['acquire', 'continue'].includes(action) || credentials.auth !== 'password') throw new Failure('AUTH_REQUIRED', 'Acquisition requires an explicitly selected password profile.', 'Select the intended password profile; API token failures never fall back.')
  if (action === 'acquire' && sessions.size >= 64) throw new Failure('AUTH_SESSION_LIMIT', 'The memory session limit is reached.', 'Cancel an existing session before acquiring another.')
  if (Object.keys(input).some(key => !['response', 'webauthnOrigin', 'openid'].includes(key))) throw denied()
  const values = new URLSearchParams({ username: credentials.tokenId, password: credentials.token })
  let path = '/access/ticket'
  if (credentials.otp) values.set('otp', credentials.otp)
  if (action === 'continue') {
    if (!id) throw denied()
    const session = selected(credentials, id)
    if (session.state !== 'challenge') throw denied()
    if (input.webauthnOrigin !== undefined && input.webauthnOrigin !== credentials.origin) throw new Failure('AUTH_ORIGIN_MISMATCH', 'WebAuthn requires the selected PVE relying-party origin.', 'Complete the ceremony at the PVE origin with a capable caller.')
    if (session.kind !== 'openid') {
      if (input.openid !== undefined) throw denied()
      const response = await resolveSecret(input.response as SecretRef)
      credentials.results.register(response)
      if (response.startsWith('webauthn:') && input.webauthnOrigin !== credentials.origin) throw new Failure('AUTH_ORIGIN_MISMATCH', 'A PVE WebAuthn origin assertion is required.', 'Use a caller capable of the PVE ceremony.')
      values.set('password', response)
      values.set('tfa-challenge', session.ticket)
    } else if (!input.openid || input.response !== undefined) throw denied()
    sessions.delete(id)
  }
  if (input.openid !== undefined) {
    // OpenID completion accepts only protected code/state and an exact origin redirect.
    const oidc = input.openid as Record<string, unknown>
    const fields = action === 'acquire' ? ['realm', 'redirect-url'] : ['code', 'state', 'redirect-url']
    if (!oidc || typeof oidc !== 'object' || Array.isArray(oidc) || Object.keys(oidc).some(key => !fields.includes(key)) || oidc['redirect-url'] !== credentials.origin) throw denied()
    values.delete('username'); values.delete('password')
    values.delete('otp')
    if (action === 'acquire') {
      if (typeof oidc.realm !== 'string' || !/^[A-Za-z][A-Za-z0-9._-]{0,31}$/.test(oidc.realm)) throw denied()
      values.set('realm', oidc.realm)
      path = '/access/openid/auth-url'
    } else {
      for (const name of ['code', 'state']) {
        const secret = await resolveSecret(oidc[name] as SecretRef)
        credentials.results.register(secret)
        values.set(name, secret)
      }
      path = '/access/openid/login'
    }
    values.set('redirect-url', credentials.origin)
  }
  if (action === 'acquire' && input.openid === undefined && !credentials.token) throw new Failure('AUTH_REQUIRED', 'Password acquisition requires a protected password source.', 'Supply the selected password SecretRef or use explicit OpenID acquisition.')
  const data = await executeRequest(credentials, `/api2/json${path}`, { method: 'POST', body: values.toString(), unauthenticated: true })
  const openid = path === '/access/openid/auth-url'
  if (openid) credentials.results.register(data)
  else credentials.results.registerMinted(data)
  if (openid) {
    if (typeof data !== 'string') throw denied()
    let url: URL
    try { url = new URL(data) } catch { throw denied() }
    if (url.protocol !== 'https:' || url.username || url.password || Buffer.byteLength(data) > 8192) throw denied()
  }
  const result = (openid ? { username: credentials.tokenId, ticket: data } : data) as { username?: unknown, ticket?: unknown, CSRFPreventionToken?: unknown }
  if (!result || result.username !== credentials.tokenId || typeof result.ticket !== 'string' || !result.ticket || /[^\x21-\x7e]/.test(result.ticket)) throw denied()
  const challenge = openid || result.ticket.startsWith('PVE:tfa!')
  if (!challenge && (typeof result.CSRFPreventionToken !== 'string' || !result.CSRFPreventionToken || /[^\x21-\x7e]/.test(result.CSRFPreventionToken))) throw denied()
  const sessionId = randomUUID()
  const session: Session = { binding: binding(credentials), expires: Date.now() + 300_000, state: challenge ? 'challenge' : 'ready', ticket: result.ticket,
    ...(openid ? { kind: 'openid' } : {}),
    ...(!challenge ? { csrf: result.CSRFPreventionToken as string } : {}) }
  sessions.set(sessionId, session)
  setTimeout(() => sessions.delete(sessionId), 300_000).unref()
  try { await credentials.results.deliver(resultBinding(credentials.origin, credentials.tokenId, `auth ${action}`, values.toString()),
    { session: sessionId, expires: session.expires, state: session.state, ticket: session.ticket,
      ...(session.kind ? { kind: session.kind } : {}), ...(session.csrf ? { csrfPreventionToken: session.csrf } : {}) }) }
  catch (error) { sessions.delete(sessionId); throw error }
  return { status: session.state, session: sessionId, expiresInSeconds: 300 }
}

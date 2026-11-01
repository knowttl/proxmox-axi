import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { Ajv } from 'ajv'
import schema from './profile-schema.json' with { type: 'json' }
import { Failure } from './errors.js'
import { readPrivateFile } from './private-file.js'
import { PrivateResults } from './private-results.js'

export type SecretRef = { env: string } | { file: string }
interface Profile { auth: 'api-token' | 'ticket' | 'password', origin: string, tokenId?: string, userId?: string, token?: SecretRef,
  ticket?: SecretRef, csrfPreventionToken?: SecretRef, password?: SecretRef, otp?: SecretRef, caBundle?: string, writes?: { operations: string[] },
  certificatePin?: { sha256: string, origin: string, replaceHostname?: boolean } }
export interface Credentials {
  auth: Profile['auth']
  origin: string
  tokenId: string
  token: string
  csrf?: string
  otp?: string
  results: PrivateResults
  writeOperations: string[]
  ca?: string
  certificatePin?: Profile['certificatePin']
  diagnostics: { profile: string, source: string, tokenSource: string }
}

const validateProfile = new Ajv({ strict: false }).compile<Profile>(schema)
const invalid = () => new Failure('CONFIG_INVALID', 'Invalid authentication profile or configuration.', 'Use one explicit authentication branch with SecretRefs; see proxmox-axi get --help.')

export async function resolveSecret(reference: SecretRef, verifyAcl = false): Promise<string> {
  if (!reference || typeof reference !== 'object' || Array.isArray(reference) || Object.keys(reference).length !== 1 ||
    !('env' in reference && typeof reference.env === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(reference.env) ||
      'file' in reference && typeof reference.file === 'string' && isAbsolute(reference.file))) throw invalid()
  const value = 'env' in reference ? process.env[reference.env] : (await readPrivateFile(reference.file, true, verifyAcl)).replace(/^\uFEFF/, '').trimEnd()
  if (!value) throw new Failure('AUTH_REQUIRED', 'The selected secret reference has no value.', 'Supply the selected protected secret source.')
  return value
}

export function configurationPath(config?: string): string {
  const env = process.env
  const home = process.platform === 'win32' ? env.APPDATA ?? join(homedir(), 'AppData', 'Roaming') :
    env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(homedir(), '.config')
  const path = config ?? env.PROXMOX_AXI_CONFIG ?? join(home, 'proxmox-axi', 'config.json')
  if (!isAbsolute(path)) throw invalid()
  return path
}

async function readConfiguration(path: string, verifyAcl = false): Promise<{ profiles: Record<string, unknown>, defaultProfile?: string }> {
  let document: unknown
  try { document = JSON.parse(await readPrivateFile(path, false, verifyAcl)) }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Failure('AUTH_REQUIRED', 'No API token profile is configured.', 'Configure PROXMOX_AXI_ORIGIN, PROXMOX_AXI_TOKEN_ID and PROXMOX_AXI_TOKEN.')
    if (error instanceof SyntaxError) throw invalid()
    throw error
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw invalid()
  const config = document as Record<string, unknown>
  if (config.version !== 1 || Object.keys(config).some(key => !['version', 'defaultProfile', 'profiles'].includes(key)) ||
    !config.profiles || typeof config.profiles !== 'object' || Array.isArray(config.profiles) ||
    (config.defaultProfile !== undefined && typeof config.defaultProfile !== 'string')) throw invalid()
  const profiles = config.profiles as Record<string, unknown>
  if (Object.keys(profiles).some(key => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(key))) throw invalid()
  return { profiles, ...(typeof config.defaultProfile === 'string' ? { defaultProfile: config.defaultProfile } : {}) }
}

export async function listProfiles(config?: string): Promise<{ name: string, default: boolean }[]> {
  const document = await readConfiguration(configurationPath(config))
  return Object.entries(document.profiles).map(([name, profile]) => {
    if (!validateProfile(profile)) throw invalid()
    return { name, default: name === document.defaultProfile }
  })
}

export async function resolveCredentials(selection: { config?: string, profile?: string, verifyAcl?: boolean }): Promise<Credentials> {
  const env = process.env
  if (env.PROXMOX_AXI_READ_ONLY !== undefined && !/^(1|0|true|false)$/i.test(env.PROXMOX_AXI_READ_ONLY)) throw invalid()
  const selected = selection.profile ?? env.PROXMOX_AXI_PROFILE
  if (selected !== undefined && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(selected)) throw invalid()
  let profile: unknown
  let name: string
  let source: string
  const environmentFields = ['ORIGIN', 'AUTH', 'TOKEN_ID', 'TOKEN', 'CA_BUNDLE', 'USER_ID', 'TICKET', 'CSRF_PREVENTION_TOKEN', 'PASSWORD', 'OTP']
  if (!selected && environmentFields.some(field => env[`PROXMOX_AXI_${field}`] !== undefined)) {
    const auth = env.PROXMOX_AXI_AUTH ?? 'api-token'
    const allowed = auth === 'api-token' ? ['TOKEN_ID', 'TOKEN'] : auth === 'ticket' ? ['USER_ID', 'TICKET', 'CSRF_PREVENTION_TOKEN'] : auth === 'password' ? ['USER_ID', 'PASSWORD', 'OTP'] : []
    const required = allowed.filter(field => field !== 'OTP' && field !== 'PASSWORD')
    if (!allowed.length || !env.PROXMOX_AXI_ORIGIN || required.some(field => !env[`PROXMOX_AXI_${field}`]) ||
      ['TOKEN_ID', 'TOKEN', 'USER_ID', 'TICKET', 'CSRF_PREVENTION_TOKEN', 'PASSWORD', 'OTP'].some(field => !allowed.includes(field) && env[`PROXMOX_AXI_${field}`] !== undefined)) throw invalid()
    profile = { auth, origin: env.PROXMOX_AXI_ORIGIN,
      ...(auth === 'api-token' ? { tokenId: env.PROXMOX_AXI_TOKEN_ID } : { userId: env.PROXMOX_AXI_USER_ID }),
      ...(auth === 'password' && env.PROXMOX_AXI_OTP ? { otp: { env: 'PROXMOX_AXI_OTP' } } : {}),
      ...(env.PROXMOX_AXI_CA_BUNDLE ? { caBundle: env.PROXMOX_AXI_CA_BUNDLE } : {}) }
    name = 'environment'
    source = 'environment'
  } else {
    const config = await readConfiguration(configurationPath(selection.config), selection.verifyAcl)
    const profiles = config.profiles
    const names = Object.keys(profiles)
    const chosen = selected ?? config.defaultProfile ?? (names.length === 1 ? names[0] : undefined)
    if (typeof chosen !== 'string') throw new Failure(names.length ? 'PROFILE_AMBIGUOUS' : 'PROFILE_REQUIRED',
      'Select one configured profile.', 'Use proxmox-axi get /version --profile <name>.')
    if (!Object.hasOwn(profiles, chosen)) throw new Failure('PROFILE_NOT_FOUND', 'Selected profile was not found.', 'Select a configured profile.')
    profile = profiles[chosen]
    name = chosen
    source = 'file'
  }
  if (!validateProfile(profile)) throw invalid()
  let origin: URL
  try { origin = new URL(profile.origin) } catch { throw invalid() }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash ||
    origin.pathname !== '/' || origin.origin !== profile.origin) throw invalid()
  if (profile.certificatePin && (profile.certificatePin.origin !== origin.origin || profile.caBundle)) throw invalid()
  const field = profile.auth === 'api-token' ? 'token' : profile.auth === 'ticket' ? 'ticket' : 'password'
  const reference = profile[field] ?? { env: `PROXMOX_AXI_${field.toUpperCase()}` }
  const tokenSource = 'env' in reference ? `env:${reference.env}` : `file:${reference.file}`
  const token = profile.auth === 'password' && !profile.password && !env.PROXMOX_AXI_PASSWORD ? '' : await resolveSecret(reference, selection.verifyAcl)
  if (profile.auth !== 'password' && /[^\x21-\x7e]/.test(token)) throw invalid()
  if (profile.auth === 'ticket' && !token.startsWith(`PVE:${profile.userId}:`)) throw invalid()
  const csrf = profile.auth === 'ticket' ? await resolveSecret(profile.csrfPreventionToken ?? { env: 'PROXMOX_AXI_CSRF_PREVENTION_TOKEN' }, selection.verifyAcl) : undefined
  if (csrf && /[^\x21-\x7e]/.test(csrf)) throw invalid()
  const otp = profile.otp ? await resolveSecret(profile.otp, selection.verifyAcl) : undefined
  const results = new PrivateResults()
  for (const secret of [token, csrf, otp]) results.register(secret)
  const ca = profile.caBundle ? await readPrivateFile(profile.caBundle, false, selection.verifyAcl) : undefined
  return { auth: profile.auth, origin: origin.origin, tokenId: (profile.auth === 'api-token' ? profile.tokenId : profile.userId)!, token,
    ...(csrf ? { csrf } : {}), ...(otp ? { otp } : {}), results,
    writeOperations: profile.writes?.operations ?? [], ...(ca ? { ca } : {}),
    ...(profile.certificatePin ? { certificatePin: profile.certificatePin } : {}),
    diagnostics: { profile: name, source, tokenSource } }
}

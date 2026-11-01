import { Agent, request } from 'node:https'
import { connect, checkServerIdentity } from 'node:tls'
import { createHash, X509Certificate } from 'node:crypto'
import { isIP } from 'node:net'
import type { Credentials } from './credentials.js'
import { Failure } from './errors.js'
import operations from './operations.json' with { type: 'json' }

// Complete TLS validation before a caller can transmit application bytes.
export async function trustedSocket(credentials: Credentials, deadlineMs = 5000) {
  const origin = new URL(credentials.origin)
  const hostname = origin.hostname.replace(/^\[|\]$/g, '')
  return await new Promise<ReturnType<typeof connect>>((resolve, reject) => {
    const socket = connect({ host: hostname, port: Number(origin.port || 443), servername: isIP(hostname) ? '' : hostname,
      ...(credentials.ca ? { ca: credentials.ca } : {}), rejectUnauthorized: !credentials.certificatePin })
    const timer = setTimeout(() => socket.destroy(new Failure('TIMEOUT', 'TLS connection timed out.', 'Check the approved origin.')), deadlineMs)
    socket.once('error', error => { clearTimeout(timer); reject(error instanceof Failure ? error : new Failure('CONNECTION_FAILED', 'Trusted TLS connection failed.', 'Review the configured origin and trust.')) })
    socket.once('secureConnect', () => {
      clearTimeout(timer)
      const pin = credentials.certificatePin
      if (pin) {
        const peer = socket.getPeerCertificate(true)
        const certificate = new X509Certificate(peer.raw)
        if (pin.origin !== credentials.origin || createHash('sha256').update(peer.raw).digest('hex') !== pin.sha256.toLowerCase() ||
          Date.now() < Date.parse(certificate.validFrom) || Date.now() > Date.parse(certificate.validTo) ||
          (!pin.replaceHostname && checkServerIdentity(hostname, peer))) {
          socket.destroy(new Error('Pinned trust mismatch'))
          return
        }
      }
      resolve(socket)
    })
  })
}

export function authorization(credentials: Credentials, method: string): Record<string, string> {
  if (credentials.auth === 'password') throw new Failure('AUTH_REQUIRED', 'A completed user session is required.', 'Acquire an explicit user session.')
  return credentials.auth === 'api-token' ? { Authorization: `PVEAPIToken=${credentials.tokenId}=${credentials.token}` } :
    { Cookie: `PVEAuthCookie=${encodeURIComponent(credentials.token)}`, ...(method !== 'GET' && credentials.csrf ? { CSRFPreventionToken: credentials.csrf } : {}) }
}

export async function executeRead(credentials: Credentials, wirePath: string, envelope = false, deadlineMs = 5000): Promise<unknown> {
  return executeRequest(credentials, wirePath, { method: 'GET', envelope, deadlineMs })
}

// Mutation callers must durably record intent and consume confirmation before calling.
export async function executeRequest(credentials: Credentials, wirePath: string, options: {
  method: string, envelope?: boolean, body?: string, deadlineMs?: number, unauthenticated?: boolean
}): Promise<unknown> {
  if (!options.unauthenticated && credentials.auth === 'password') throw new Failure('AUTH_REQUIRED', 'A completed user session is required.', 'Use explicit authentication acquisition before provider operations.')
  if (!wirePath.startsWith('/api2/json/') || wirePath.includes('#')) throw new Failure('INVALID_INPUT', 'Invalid API path.', 'Select a reviewed API operation.', 2)
  const started = performance.now()
  const socket = await trustedSocket(credentials, options.deadlineMs ?? 5000)
  if (performance.now() - started >= (options.deadlineMs ?? 5000)) {
    socket.destroy()
    throw new Failure('TIMEOUT', 'Request exceeded its elapsed deadline.', 'Check the approved origin.')
  }
  const body = await new Promise<string>((resolve, reject) => {
    const fail = (error: Error) => reject(error instanceof Failure ? error :
      new Failure('CONNECTION_FAILED', 'Trusted HTTPS request failed.', 'Check the origin and configured CA trust.'))
    const origin = new URL(credentials.origin)
    let req: ReturnType<typeof request> | undefined
    const deadline = setTimeout(() => {
      const error = new Failure('TIMEOUT', `Request exceeded ${options.deadlineMs ?? 5000} ms.`, 'Check the server and retry the read explicitly.')
      req?.destroy(error)
      socket.destroy(error)
    }, Math.max(1, (options.deadlineMs ?? 5000) - (performance.now() - started)))
    socket.once('close', () => clearTimeout(deadline))
    socket.on('error', fail)
      const agent = new Agent({ keepAlive: false })
      agent.createConnection = () => socket
      req = request(new URL(wirePath, origin), {
      method: options.method, agent,
      headers: { ...(!options.unauthenticated ? authorization(credentials, options.method) : {}), Accept: 'application/json',
        ...(options.body === undefined ? {} : { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(options.body) }) },
    }, response => {
      response.on('error', fail)
      const status = response.statusCode ?? 0
      if (status !== 200) {
        response.destroy()
        reject(new Failure(status === 401 ? 'AUTH_REQUIRED' : status === 403 ? 'PERMISSION_DENIED' : status === 404 ? 'NOT_FOUND_OR_HIDDEN' : 'HTTP_ERROR',
          `Request returned HTTP ${status}.`, 'Check the configured identity and its permission to read the selected operation.'))
        return
      }
      let bytes = 0
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length
        if (bytes > 65_536) req!.destroy(new Failure('OUTPUT_LIMIT', 'Response exceeds 65536 bytes.', 'Check the server response contract.'))
        else chunks.push(chunk)
      })
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    })
    req.on('error', fail)
    req.end(options.body)
  })
  let value: unknown
  try { value = JSON.parse(body) } catch { throw invalidResponse() }
  if (!value || typeof value !== 'object' || Array.isArray(value) || !('data' in value)) throw invalidResponse()
  if ('total' in value && (!Number.isSafeInteger(value.total) || Number(value.total) < 0 || (Array.isArray(value.data) && Number(value.total) < value.data.length))) throw invalidResponse()
  const data: unknown = value.data
  return options.envelope ? value : data
}

export async function readVersion(credentials: Credentials, wirePath: string): Promise<Record<string, string>> {
  const operation = operations[0]!
  const data = await executeRead(credentials, wirePath)
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalidResponse()
  const fields = data as Record<string, unknown>
  if (operation.requiredResponseFields.some(field => typeof fields[field] !== 'string' || !fields[field])) throw invalidResponse()
  return fields as Record<string, string>
}

function invalidResponse(): Failure {
  return new Failure('INVALID_RESPONSE', 'Version response is missing required string fields.', 'Check the /version response against the selected vendor contract.')
}

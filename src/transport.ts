import { request } from 'node:https'
import type { Credentials } from './credentials.js'
import { Failure } from './errors.js'
import operations from './operations.json' with { type: 'json' }

export async function readVersion(credentials: Credentials): Promise<Record<string, string>> {
  const operation = operations[0]!
  const body = await new Promise<string>((resolve, reject) => {
    const fail = (error: Error) => reject(error instanceof Failure ? error :
      new Failure('CONNECTION_FAILED', 'Trusted HTTPS version request failed.', 'Check the origin and configured CA trust.'))
    const req = request(new URL(operation.wirePath, credentials.origin), {
      method: operation.method, ca: credentials.ca, rejectUnauthorized: true,
      headers: { Authorization: `PVEAPIToken=${credentials.tokenId}=${credentials.token}`, Accept: 'application/json' },
    }, response => {
      response.on('error', fail)
      const status = response.statusCode ?? 0
      if (status !== 200) {
        response.resume()
        reject(new Failure(status === 401 ? 'AUTH_REQUIRED' : status === 403 ? 'PERMISSION_DENIED' : 'HTTP_ERROR',
          `Version request returned HTTP ${status}.`, 'Check the configured identity and its permission to read /version.'))
        return
      }
      let bytes = 0
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length
        if (bytes > 65_536) req.destroy(new Failure('OUTPUT_LIMIT', 'Version response exceeds 65536 bytes.', 'Check the server response contract.'))
        else chunks.push(chunk)
      })
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    })
    const deadline = setTimeout(() => req.destroy(new Failure('TIMEOUT', 'Version request exceeded 5000 ms.', 'Check the configured server and retry the read explicitly.')), 5000)
    req.on('close', () => clearTimeout(deadline))
    req.on('error', fail)
    req.end()
  })
  let value: unknown
  try { value = JSON.parse(body) } catch { throw invalidResponse() }
  if (!value || typeof value !== 'object' || Array.isArray(value) || !('data' in value)) throw invalidResponse()
  const data: unknown = value.data
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw invalidResponse()
  const fields = data as Record<string, unknown>
  if (operation.requiredResponseFields.some(field => typeof fields[field] !== 'string' || !fields[field])) throw invalidResponse()
  return Object.fromEntries(operation.requiredResponseFields.map(field => [field, fields[field] as string]))
}

function invalidResponse(): Failure {
  return new Failure('INVALID_RESPONSE', 'Version response is missing required string fields.', 'Check the /version response against the selected vendor contract.')
}

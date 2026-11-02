import type { IncomingMessage } from 'node:http'
import type { PrivateResults } from './private-results.js'

export class Failure extends Error {
  constructor(readonly code: string, message: string, readonly next: string, readonly exitCode = 1, readonly httpStatus?: number) {
    super(message)
  }
}

export function httpFailure(status: number, operation: 'Request' | 'Transfer'): Failure {
  return new Failure(status === 401 ? 'AUTH_REQUIRED' : status === 403 ? 'PERMISSION_DENIED' : status === 404 ? 'NOT_FOUND_OR_HIDDEN' : 'HTTP_ERROR',
    `${operation} returned HTTP ${status}.`, status === 400 ? 'Check the supplied API parameters against the selected operation schema.' :
      status === 501 && operation === 'Transfer' ? 'The server does not support this transfer formatter; check the selected operation and server release.' :
        'Check the configured identity and its permission for the selected operation.', 1, status)
}

export async function responseFailure(response: IncomingMessage, operation: 'Request' | 'Transfer', results: PrivateResults): Promise<Failure> {
  const failure = httpFailure(response.statusCode ?? 0, operation)
  const chunks: Buffer[] = []
  let bytes = 0
  try {
    for await (const chunk of response) {
      bytes += chunk.length
      if (bytes > 65536) { response.destroy(); return failure }
      chunks.push(Buffer.from(chunk))
    }
    const body: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (!body || typeof body !== 'object' || Array.isArray(body)) return failure
    results.registerMinted(body)
    const { message, errors } = body as { message?: unknown, errors?: unknown }
    const hints: string[] = []
    if (typeof message === 'string') {
      const permission = /^Permission check failed \(([^,\r\n]+), ((?:VM|Sys|Pool|Datastore|Permissions|SDN|User|Realm|Group|Mapping)\.[A-Za-z]{1,48})\)$/.exec(message)
      if (permission) hints.push(`Permission check failed (${permission[1] === '/' ? '/' : '[REDACTED]'}, ${permission[2]})`)
    }
    if (errors && typeof errors === 'object' && !Array.isArray(errors)) {
      for (const [field, detail] of Object.entries(errors).slice(0, 8)) {
        if (/^[a-z][a-z0-9_-]{0,63}$/i.test(field) && typeof detail === 'string') {
          const reason = /^(invalid format|value does not match the regex pattern|property is not defined in schema|parameter is required|missing required parameter|type check \([a-z]+\) failed)(?:\s*[-:.].*)?$/i.exec(detail)
          if (reason) hints.push(`${field}: ${reason[1]}`)
        }
      }
    }
    const hint = results.redact(hints.join('; ')).slice(0, 1024)
    if (hint) failure.message += ` ${hint}`
  } catch { return failure }
  return failure
}

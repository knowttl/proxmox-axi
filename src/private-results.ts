import { fstatSync, writeSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { Failure } from './errors.js'

export interface ResultBinding {
  origin: string
  identity: string
  operation: string
  request: string
  actor: string
  credentialRevision: string
}

// A frame is a four-byte unsigned big-endian length followed by UTF-8 JSON.
// The inherited descriptor belongs to the caller; it is never opened by pathname.
export class PrivateResults {
  private readonly secrets = new Set<string>()

  register(value: unknown): void {
    if (typeof value === 'string' && value) this.secrets.add(value)
    else if (Array.isArray(value)) for (const item of value) this.register(item)
    else if (value && typeof value === 'object') for (const item of Object.values(value)) this.register(item)
  }

  redact(text: string): string {
    for (const secret of [...this.secrets].sort((a, b) => b.length - a.length)) {
      for (const form of [secret, encodeURIComponent(secret), new URLSearchParams({ v: secret }).toString().slice(2),
        JSON.stringify(secret).slice(1, -1), Buffer.from(secret).toString('base64'), Buffer.from(secret).toString('base64url')]) text = text.replaceAll(form, '[REDACTED]')
    }
    return text
  }

  sanitize(value: unknown): unknown {
    if (typeof value === 'string') return this.redact(value)
    if (Array.isArray(value)) return value.map(item => this.sanitize(item))
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [this.redact(key), this.sanitize(item)]))
    return value
  }

  sink(): number {
    const value = process.env.PROXMOX_AXI_RESULT_FD
    if (!value || !/^[0-9]+$/.test(value) || Number(value) < 3 || !Number.isSafeInteger(Number(value))) throw sinkFailure()
    const fd = Number(value)
    try {
      const info = fstatSync(fd)
      if (!info.isFIFO() && !info.isSocket()) throw sinkFailure()
      writeSync(fd, Buffer.alloc(0))
    } catch { throw sinkFailure() }
    return fd
  }

  deliver(binding: ResultBinding, payload: unknown): void {
    const bytes = Buffer.from(JSON.stringify({ version: 1, binding, payload }))
    if (bytes.length > 65536) throw deliveryFailure()
    const header = Buffer.alloc(4)
    header.writeUInt32BE(bytes.length)
    const frame = Buffer.concat([header, bytes])
    try {
      const fd = this.sink()
      let offset = 0
      while (offset < frame.length) offset += writeSync(fd, frame, offset, frame.length - offset)
    } catch { throw deliveryFailure() }
  }
}

export function resultBinding(origin: string, identity: string, operation: string, request: string): ResultBinding {
  return { origin, identity, operation, request: process.env.PROXMOX_AXI_REQUEST_ID ?? createHash('sha256').update(request).digest('hex'),
    actor: process.env.PROXMOX_AXI_ACTOR ?? `uid:${process.getuid?.() ?? 'native'}`,
    credentialRevision: process.env.PROXMOX_AXI_CREDENTIAL_REVISION ?? 'standalone' }
}

function sinkFailure(): Failure {
  return new Failure('PRIVATE_SINK_REQUIRED', 'A private inherited pipe is required before requesting sensitive results.', 'Supply a caller-owned pipe using PROXMOX_AXI_RESULT_FD; terminals and files are refused.')
}

function deliveryFailure(): Failure {
  return new Failure('DELIVERY_UNCERTAIN', 'Private delivery is uncertain; the operation was not retried.', 'Inspect the retained intent and caller channel before taking further action.')
}

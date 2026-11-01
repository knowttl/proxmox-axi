import { fstatSync, writeSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { Socket } from 'node:net'
import { Failure } from './errors.js'

const pipes = new Map<number, Socket>()
const protectedField = /^(?:password|passwd|secret|token|ticket|otp|challenge|recovery|value|csrf[-_]?prevention[-_]?token|private[-_]?key|api[-_]?key|access[-_]?token|refresh[-_]?token|authorization|cookie)$/i

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

  registerMinted(value: unknown): void {
    if (Array.isArray(value)) for (const item of value) this.registerMinted(item)
    else if (value && typeof value === 'object') for (const [name, item] of Object.entries(value)) {
      if (protectedField.test(name)) this.register(item)
      else this.registerMinted(item)
    }
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
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.sanitize(item)]))
    return value
  }

  sink(): number {
    const value = process.env.PROXMOX_AXI_RESULT_FD
    if (!value || !/^[0-9]+$/.test(value) || Number(value) < 3 || !Number.isSafeInteger(Number(value))) throw sinkFailure()
    const fd = Number(value)
    try {
      const info = fstatSync(fd)
      if (!info.isFIFO() && !info.isSocket()) throw sinkFailure()
      for (const publicFd of [1, 2]) {
        const publicInfo = fstatSync(publicFd)
        if (info.dev === publicInfo.dev && info.ino === publicInfo.ino) throw sinkFailure()
      }
      writeSync(fd, Buffer.alloc(0))
    } catch { throw sinkFailure() }
    return fd
  }

  async deliver(binding: ResultBinding, payload: unknown): Promise<void> {
    const bytes = Buffer.from(JSON.stringify({ version: 1, binding, payload }))
    if (bytes.length > 65536) throw deliveryFailure()
    const header = Buffer.alloc(4)
    header.writeUInt32BE(bytes.length)
    const frame = Buffer.concat([header, bytes])
    try {
      const fd = this.sink()
      let pipe = pipes.get(fd)
      if (!pipe) {
        pipe = new Socket({ fd, readable: false, writable: true })
        pipe.unref()
        pipe.on('error', () => pipes.delete(fd))
        pipe.once('close', () => pipes.delete(fd))
        pipes.set(fd, pipe)
      }
      const channel = pipe
      await new Promise<void>((resolve, reject) => {
        const deadline = setTimeout(() => { channel.destroy(); reject(deliveryFailure()) }, 5000)
        channel.write(frame, error => {
          clearTimeout(deadline)
          if (error) reject(deliveryFailure())
          else resolve()
        })
      })
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

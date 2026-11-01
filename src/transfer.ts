import { Agent, request } from 'node:https'
import { createHash, randomBytes } from 'node:crypto'
import { constants, fstatSync } from 'node:fs'
import { open, type FileHandle } from 'node:fs/promises'
import { Socket } from 'node:net'
import { once } from 'node:events'
import { Readable, Transform, type Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { createGunzip } from 'node:zlib'
import type { Credentials } from './credentials.js'
import { buildPath, type Contract } from './contract.js'
import { authorization, trustedSocket } from './transport.js'
import { Failure } from './errors.js'

export interface TransferOptions {
  formatter: string
  input?: string
  raw: boolean
  expectedBytes?: number
  expectedSha256?: string
}

export function transferLimits() {
  const bytes = Number(process.env.PROXMOX_AXI_TRANSFER_BYTES ?? 8 * 1024 ** 3)
  const lifetimeMs = Number(process.env.PROXMOX_AXI_TRANSFER_MS ?? 1800000)
  if (!Number.isSafeInteger(bytes) || bytes < 1 || !Number.isSafeInteger(lifetimeMs) || lifetimeMs < 1 || lifetimeMs > 1800000) throw invalid('Invalid administrator transfer limits.')
  return { bytes, lifetimeMs, bufferBytes: 65536, guestEnvelopeBytes: 128 * 1024 ** 2, peakRssBytes: 384 * 1024 ** 2 }
}

export function byteDescriptor(): number {
  const descriptor = process.env.PROXMOX_AXI_STREAM_FD
  if (!descriptor || !/^\d+$/.test(descriptor) || !Number.isSafeInteger(Number(descriptor)) || Number(descriptor) < 3) throw invalid('A private inherited byte channel is required.')
  const fd = Number(descriptor)
  const info = fstatSync(fd)
  if (!info.isFIFO() && !info.isSocket()) throw invalid('The byte channel must be a pipe or socket.')
  for (const publicFd of [1, 2]) {
    const output = fstatSync(publicFd)
    if (info.dev === output.dev && info.ino === output.ino) throw invalid('Public output cannot carry transport bytes.')
  }
  if (descriptor === process.env.PROXMOX_AXI_RESULT_FD) throw invalid('Setup and byte channels must be distinct.')
  if (process.env.PROXMOX_AXI_RESULT_FD) {
    const result = fstatSync(Number(process.env.PROXMOX_AXI_RESULT_FD))
    if (info.dev === result.dev && info.ino === result.ino) throw invalid('Setup and byte channels must be distinct.')
  }
  return fd
}

export function byteChannel(): Socket {
  const channel = new Socket({ fd: byteDescriptor(), readable: true, writable: true, allowHalfOpen: true })
  channel.on('error', () => {})
  return channel
}

export function formatters(contract: Contract): string[] {
  if (/\/rrd$/.test(contract.path)) return ['png']
  if (/\/(spiceproxy|spiceshell)$/.test(contract.path)) return ['spiceconfig']
  if (/\/storage\/\{storage\}\/upload$/.test(contract.path)) return ['multipart']
  if (/\/agent\/file-read$/.test(contract.path)) return ['guest-file']
  if (/\/file-restore\/download$/.test(contract.path)) return ['download']
  if (contract.path === '/nodes/{node}/journal' || contract.path === '/nodes/{node}/tasks/{upid}/log') return ['text']
  return []
}

// Hold the opened source through confirmation and transmission, so pathname replacement
// cannot switch the source after its digest has been bound to the shared journal.
export async function prepareTransfer(contract: Contract, values: Record<string, unknown>, options: TransferOptions) {
  const limits = transferLimits()
  if (!formatters(contract).includes(options.formatter)) throw invalid('Formatter is not allowed for this operation.')
  if (options.raw && options.formatter !== 'guest-file') throw invalid('Raw export applies to guest files only.')
  if (options.expectedBytes !== undefined && (!Number.isSafeInteger(options.expectedBytes) || options.expectedBytes < 0 || options.expectedBytes > limits.bytes)) throw invalid('Invalid expected byte count.')
  if (options.expectedSha256 !== undefined && !/^[a-f0-9]{64}$/.test(options.expectedSha256)) throw invalid('Expected SHA-256 must be lowercase hexadecimal.')
  if (options.formatter === 'text' && contract.path.endsWith('/log') &&
    (values.download !== true || values.start !== undefined || values.limit !== undefined)) throw invalid('Task-log transfer requires download=true without paging parameters.')
  if (options.formatter === 'spiceconfig' && values.proxy !== undefined) throw invalid('SPICE uses only the selected node proxy.')
  let file: FileHandle | undefined
  let source: { bytes: number, sha256: string } | undefined
  try {
    if (options.formatter === 'multipart') {
      if (!options.input || !options.input.startsWith('/') || typeof values.filename !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(values.filename) || values.tmpfilename !== undefined) throw invalid('Upload requires an absolute input file and a safe filename; tmpfilename is forbidden.')
      file = await open(options.input, constants.O_RDONLY | constants.O_NOFOLLOW)
      const info = await file.stat()
      if (!info.isFile() || info.size > limits.bytes) throw invalid('Source is not a regular file within the selected quota.')
      const hash = createHash('sha256')
      for await (const chunk of file.createReadStream({ autoClose: false, start: 0, highWaterMark: limits.bufferBytes })) hash.update(chunk)
      source = { bytes: info.size, sha256: hash.digest('hex') }
      if (options.expectedBytes !== undefined && source.bytes !== options.expectedBytes || options.expectedSha256 !== undefined && source.sha256 !== options.expectedSha256) throw invalid('Upload source does not match the expected bytes or digest.')
    } else if (options.input) throw invalid('Only uploads accept an input file.')
    return {
      binding: { formatter: options.formatter, raw: options.raw, source, expectedBytes: options.expectedBytes, expectedSha256: options.expectedSha256, limits },
      close: async () => file?.close(),
      execute: async (credentials: Credentials, selected: Contract, resolved: Record<string, unknown>) => {
        if (!formatters(selected).includes(options.formatter)) throw invalid('Selected release does not admit this formatter.')
        const channel = byteChannel()
        try { return await runTransfer(credentials, selected, resolved, options, channel, limits, file, source) }
        finally { channel.end(); channel.unref() }
      },
    }
  } catch (error) { await file?.close(); throw error }
}

async function runTransfer(credentials: Credentials, contract: Contract, values: Record<string, unknown>, options: TransferOptions,
  output: Writable, limits: ReturnType<typeof transferLimits>, file?: FileHandle, source?: { bytes: number, sha256: string }) {
  const headers = authorization(credentials, contract.method)
  const wire = buildPath(contract, values)
  const formatter = options.formatter === 'multipart' || options.formatter === 'guest-file' || options.formatter === 'download' ? 'json' : options.formatter
  const [path, query] = wire.replace('/api2/json/', `/api2/${formatter}/`).split('?')
  const boundary = `proxmox-${randomBytes(24).toString('hex')}`
  let prefix = Buffer.alloc(0), suffix = Buffer.alloc(0)
  if (source) {
    prefix = Buffer.from([...new URLSearchParams(query)].filter(([name]) => !['filename', 'node', 'storage'].includes(name)).map(([name, value]) =>
      `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`).join('') +
      `--${boundary}\r\nContent-Disposition: form-data; name="filename"; filename="${values.filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`)
    suffix = Buffer.from(`\r\n--${boundary}--\r\n`)
    headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`
    headers['Content-Length'] = String(prefix.length + source.bytes + suffix.length)
  } else if (contract.method !== 'GET') {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    headers['Content-Length'] = String(Buffer.byteLength(query ?? ''))
  }
  const socket = await trustedSocket(credentials)
  const agent = new Agent({ keepAlive: false })
  agent.createConnection = () => socket
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), limits.lifetimeMs)
  try {
    const req = request(new URL(contract.method === 'GET' ? `${path}${query ? `?${query}` : ''}` : path!, credentials.origin),
      { method: contract.method, agent, headers, signal: controller.signal })
    const responsePromise = once(req, 'response')
    void responsePromise.catch(() => {})
    if (source && file) {
      const sourceHash = createHash('sha256')
      let sourceBytes = 0
      const body = Readable.from((async function* () {
        yield prefix
        for await (const chunk of file.createReadStream({ autoClose: false, start: 0, highWaterMark: limits.bufferBytes })) {
          const bytes = Buffer.from(chunk)
          sourceBytes += bytes.length
          if (sourceBytes > source.bytes) throw invalid('Upload source changed.')
          sourceHash.update(bytes)
          yield bytes
        }
        if (sourceBytes !== source.bytes || sourceHash.digest('hex') !== source.sha256) throw invalid('Upload source changed.')
        yield suffix
      })())
      await pipeline(body, req, { signal: controller.signal })
    } else req.end(contract.method === 'GET' ? undefined : query)
    const [response] = await responsePromise as [import('node:http').IncomingMessage]
    if (response.statusCode !== 200) { response.destroy(); throw new Failure('HTTP_ERROR', `Transfer returned HTTP ${response.statusCode ?? 0}.`, 'Inspect the selected operation and identity.') }
    const decoded = response.headers['content-encoding'] === 'gzip' ? response.pipe(createGunzip()) : response
    if (decoded !== response) response.once('error', error => decoded.destroy(error))
    if (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'gzip' && response.headers['content-encoding'] !== 'identity') throw invalid('Unsupported response encoding.')
    if (source) {
      const chunks: Buffer[] = []
      let bytes = 0
      for await (const chunk of decoded) {
        bytes += chunk.length
        if (bytes > 65536) throw invalid('Upload result exceeded its metadata budget.')
        chunks.push(Buffer.from(chunk))
      }
      const envelope: unknown = JSON.parse(Buffer.concat(chunks).toString())
      if (!envelope || typeof envelope !== 'object' || !('data' in envelope) || typeof envelope.data !== 'string') throw invalid('Invalid upload task result.')
      return { data: envelope.data, transfer: { status: 'complete', ...source, limits, peakRssBytes: process.resourceUsage().maxRSS * 1024 } }
    }
    const hash = createHash('sha256')
    let bytes = 0, signature = Buffer.alloc(0)
    const meter = new Transform({ transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length
      if (bytes > limits.bytes) { callback(new Failure('TRANSFER_LIMIT', 'Transfer exceeded the selected byte quota.', 'Increase the administrator quota or select a smaller transfer.')); return }
      hash.update(chunk)
      if (signature.length < 8) signature = Buffer.concat([signature, chunk.subarray(0, 8 - signature.length)])
      callback(null, chunk)
    } })
    // Guest JSON is bounded by the vendor's 16 MiB read limit, independently of
    // the administrator's image-transfer quota. It never enters public output.
    let guest: { encoding: string, truncated: boolean | 'unknown', providerBytes?: number } | undefined
    if (options.formatter === 'guest-file') {
      const chunks: Buffer[] = []
      let total = 0
      for await (const chunk of decoded) {
        total += chunk.length
        if (total > limits.guestEnvelopeBytes) throw invalid('Guest-file envelope exceeded its fixed budget.')
        chunks.push(Buffer.from(chunk))
      }
      const envelope: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      if (!envelope || typeof envelope !== 'object' || !('data' in envelope) || !envelope.data || typeof envelope.data !== 'object') throw invalid('Invalid guest-file envelope.')
      const data = envelope.data as Record<string, unknown>
      if (typeof data.content !== 'string' || data.truncated !== undefined && ![true, false, 0, 1].includes(data.truncated as boolean)) throw invalid('Invalid guest-file content.')
      const encoding = contract.release === 'legacy-8.2.7' ? 'legacy-unknown' : values.decode === false ? 'base64-chunks' : 'utf8'
      if (options.raw && encoding === 'legacy-unknown') throw invalid('Legacy encoding is unknown; raw export is unavailable.')
      let content: Buffer
      if (options.raw && encoding === 'base64-chunks') {
        if (/[^A-Za-z0-9+/=]/.test(data.content)) throw invalid('Invalid chunked base64 content.')
        const decodedChunks: Buffer[] = []
        let offset = 0
        while (offset < data.content.length) {
          const padding = data.content.indexOf('=', offset)
          const end = padding < 0 ? data.content.length : padding + (data.content[padding + 1] === '=' ? 2 : 1)
          const encoded = data.content.slice(offset, end)
          const decoded = Buffer.from(encoded, 'base64')
          if (decoded.toString('base64') !== encoded) throw invalid('Invalid chunked base64 content.')
          decodedChunks.push(decoded)
          offset = end
        }
        content = Buffer.concat(decodedChunks)
      } else content = Buffer.from(data.content, 'utf8')
      if (content.length > 32 * 1024 ** 2) throw invalid('Guest content exceeds the vendor read budget.')
      if (data['bytes-read'] !== undefined && (!Number.isSafeInteger(data['bytes-read']) || Number(data['bytes-read']) > Number(values.count ?? 16777216) || Number(data['bytes-read']) < 0)) throw invalid('Invalid guest byte count.')
      if (data['bytes-read'] !== undefined && (options.raw || encoding === 'utf8') && content.length !== Number(data['bytes-read'])) throw invalid('Guest-file content does not match the provider byte count.')
      guest = { encoding: options.raw ? 'raw' : encoding, truncated: data.truncated === undefined ? 'unknown' : !!data.truncated,
        ...(data['bytes-read'] === undefined ? {} : { providerBytes: Number(data['bytes-read']) }) }
      await pipeline(Readable.from([content]), meter, output, { end: false, signal: controller.signal })
    } else await pipeline(decoded, meter, output, { end: false, signal: controller.signal })
    const sha256 = hash.digest('hex')
    if (options.formatter === 'png' && !signature.equals(Buffer.from('89504e470d0a1a0a', 'hex'))) throw invalid('Invalid PNG signature.')
    if (options.expectedBytes !== undefined && bytes !== options.expectedBytes || options.expectedSha256 !== undefined && sha256 !== options.expectedSha256) throw invalid('Transfer byte count or digest did not match.')
    return { data: null, transfer: { status: 'complete', bytes, sha256, limits, peakRssBytes: process.resourceUsage().maxRSS * 1024, ...guest } }
  } catch (error) {
    if (error instanceof Failure) throw error
    throw new Failure('TRANSFER_FAILED', 'Transfer did not complete; partial bytes must be discarded.', 'Inspect the retained intent before retrying a write.')
  } finally { clearTimeout(timer); controller.abort(); socket.destroy(); agent.destroy() }
}

function invalid(message: string) { return new Failure('INVALID_INPUT', message, 'Use the reviewed transfer schema and private byte channel.', 2) }

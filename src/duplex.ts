import { Agent, request } from 'node:https'
import { createHash, randomBytes } from 'node:crypto'
import type { Socket } from 'node:net'
import type { Credentials } from './credentials.js'
import { buildPath, selectContract, validateResponse, type Contract } from './contract.js'
import { authorization, executeRequest, trustedSocket } from './transport.js'
import { byteChannel, byteDescriptor } from './transfer.js'
import { Failure } from './errors.js'
import { resultBinding } from './private-results.js'

export function duplexLimits() {
  const limits = { frameBytes: 1048576, bytes: Number(process.env.PROXMOX_AXI_DUPLEX_BYTES ?? 64 * 1024 ** 2),
    idleMs: Number(process.env.PROXMOX_AXI_DUPLEX_IDLE_MS ?? 30000), lifetimeMs: Number(process.env.PROXMOX_AXI_DUPLEX_MS ?? 300000) }
  if (Object.values(limits).some(value => !Number.isSafeInteger(value) || value < 1) || limits.lifetimeMs > 1800000) throw failed('Invalid administrator session limits.')
  return limits
}

export function duplexSetup(contract: Contract): boolean {
  return contract.method === 'POST' && /\/(vncproxy|termproxy|vncshell|mtunnel)$/.test(contract.path)
}

export function prepareDuplex(contract: Contract, preview: boolean) {
  if (!duplexSetup(contract)) throw failed('Select a reviewed console, shell or migration setup.')
  const limits = duplexLimits()
  if (!preview) byteDescriptor()
  return { binding: { duplex: 'length-prefixed-binary-v1', limits },
    execute: async (credentials: Credentials, selected: Contract, values: Record<string, unknown>) => {
      const channel = byteChannel()
      let socket: Socket | undefined
      try {
        credentials.results.sink()
        const wire = buildPath(selected, values)
        const [path, body] = wire.split('?')
        const data = await executeRequest(credentials, path!, { method: 'POST', ...(body ? { body } : {}) })
        credentials.results.registerMinted(data)
        validateResponse(data, selected.returns)
        if (!data || typeof data !== 'object') throw failed('Invalid protected session setup.')
        const setup = data as Record<string, unknown>
        if (typeof setup.ticket !== 'string' || !setup.ticket || setup.ticket.length > 4096) throw failed('Invalid private session ticket.')
        const migration = selected.path.endsWith('/mtunnel')
        // The opaque socket is accepted only from this exact authenticated setup,
        // then sent back to its matching node/guest route with the bound ticket.
        if (migration ? typeof setup.socket !== 'string' || !setup.socket || setup.socket.length > 4096 || /[\x00-\x1f\x7f]/.test(setup.socket) :
          !Number.isSafeInteger(setup.port) || Number(setup.port) < 5900 || Number(setup.port) > 5999) throw failed('Invalid provider session target.')
        await credentials.results.deliver(resultBinding(credentials.origin, credentials.tokenId, selected.id, wire), data)
        const target = selected.path.replace(/\/(vncproxy|termproxy|vncshell|mtunnel)$/, migration ? '/mtunnelwebsocket' : '/vncwebsocket')
        const route = selectContract('GET', target, selected.release)
        const params = Object.fromEntries(Object.entries(values).filter(([name]) => route.path.includes(`{${name}}`)))
        const connectPath = buildPath(route, { ...params, ...(migration ? { socket: setup.socket, ticket: setup.ticket } : { port: setup.port, vncticket: setup.ticket }) })
        socket = await upgrade(credentials, connectPath)
        const transfer = await exchange(socket, channel, limits)
        return { data: null, transfer }
      } finally { socket?.destroy(); channel.end(); channel.unref() }
    } }
}

async function upgrade(credentials: Credentials, path: string): Promise<Socket> {
  const started = performance.now()
  const socket = await trustedSocket(credentials)
  const remaining = 5000 - (performance.now() - started)
  if (remaining <= 0) { socket.destroy(); throw failed('WebSocket connection deadline exceeded.') }
  const agent = new Agent({ keepAlive: false })
  agent.createConnection = () => socket
  const key = randomBytes(16).toString('base64')
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(failed('WebSocket connection deadline exceeded.')) }, remaining)
    const req = request(new URL(path, credentials.origin), { agent, headers: { ...authorization(credentials, 'GET'),
      Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Protocol': 'binary' } })
    req.once('error', () => { clearTimeout(timer); socket.destroy(); reject(failed('WebSocket upgrade failed.')) })
    req.once('response', response => { clearTimeout(timer); response.destroy(); socket.destroy(); reject(failed('WebSocket upgrade refused.')) })
    req.once('upgrade', (response, peer, head) => {
      clearTimeout(timer)
      if (response.statusCode !== 101 || response.headers.upgrade?.toLowerCase() !== 'websocket' ||
        response.headers['sec-websocket-accept'] !== createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64') ||
        response.headers['sec-websocket-extensions'] || response.headers['sec-websocket-protocol'] && response.headers['sec-websocket-protocol'] !== 'binary') {
        peer.destroy(); reject(failed('Invalid WebSocket upgrade.')); return
      }
      if (head.length) peer.unshift(head)
      resolve(peer)
    })
    req.end()
  })
}

async function write(socket: Socket, bytes: Buffer) {
  await new Promise<void>((resolve, reject) => socket.write(bytes, error => error ? reject(error) : resolve()))
}

function frame(opcode: number, bytes: Buffer) {
  const header = Buffer.alloc(bytes.length < 126 ? 6 : bytes.length < 65536 ? 8 : 14)
  header[0] = 0x80 | opcode
  if (bytes.length < 126) header[1] = 0x80 | bytes.length
  else if (bytes.length < 65536) { header[1] = 0xfe; header.writeUInt16BE(bytes.length, 2) }
  else { header[1] = 0xff; header.writeBigUInt64BE(BigInt(bytes.length), 2) }
  const mask = randomBytes(4)
  mask.copy(header, header.length - 4)
  const payload = Buffer.allocUnsafe(bytes.length)
  for (let index = 0; index < bytes.length; index++) payload[index] = bytes[index]! ^ mask[index % 4]!
  return Buffer.concat([header, payload])
}

async function exchange(peer: Socket, channel: Socket, limits: ReturnType<typeof duplexLimits>) {
  let sent = 0, received = 0, framesSent = 0, framesReceived = 0, closed = false, inputClosed = false
  const outgoing = createHash('sha256'), incoming = createHash('sha256')
  const fail = () => { const error = failed('Session exceeded its idle or lifetime bound.'); peer.destroy(error); channel.destroy(error) }
  const lifetime = setTimeout(fail, limits.lifetimeMs)
  const idle = setTimeout(fail, limits.idleMs)
  const activity = () => idle.refresh()
  const upload = (async () => {
    let pending = Buffer.alloc(0)
    for await (const chunk of channel.iterator({ destroyOnReturn: false })) {
      pending = Buffer.concat([pending, Buffer.from(chunk)])
      if (pending.length > limits.frameBytes + 65540) throw failed('Input frame exceeds its quota.')
      while (pending.length >= 4) {
        const size = pending.readUInt32BE(0)
        if (size > limits.frameBytes) throw failed('Input frame exceeds its quota.')
        if (pending.length < size + 4) break
        const payload = pending.subarray(4, size + 4)
        sent += size
        if (sent > limits.bytes) throw failed('Session byte quota exceeded.')
        outgoing.update(payload); framesSent++
        await write(peer, frame(2, payload)); activity()
        pending = pending.subarray(size + 4)
      }
    }
    if (pending.length) throw failed('Incomplete input frame.')
    inputClosed = true
    if (!closed) await write(peer, frame(8, Buffer.from([3, 232])))
  })()
  upload.catch(error => peer.destroy(error instanceof Error ? error : failed('Input failed.')))
  try {
    let pending = Buffer.alloc(0), fragments: Buffer[] = [], fragmentBytes = 0, fragmented = false
    for await (const chunk of peer) {
      pending = Buffer.concat([pending, Buffer.from(chunk)])
      if (pending.length > limits.frameBytes + 65550) throw failed('Peer frame exceeds its quota.')
      while (pending.length >= 2) {
        const first = pending[0]!, second = pending[1]!, opcode = first & 15, final = !!(first & 128)
        if (first & 112 || second & 128) throw failed('Invalid peer frame flags.')
        let length = second & 127, header = 2
        if (length === 126) { if (pending.length < 4) break; length = pending.readUInt16BE(2); header = 4 }
        else if (length === 127) {
          if (pending.length < 10) break
          const large = pending.readBigUInt64BE(2)
          if (large > BigInt(limits.frameBytes)) throw failed('Peer frame exceeds its quota.')
          length = Number(large); header = 10
        }
        if (length > limits.frameBytes || opcode >= 8 && (!final || length > 125)) throw failed('Peer frame exceeds its quota.')
        if (pending.length < header + length) break
        const payload = pending.subarray(header, header + length)
        pending = pending.subarray(header + length)
        activity()
        if (opcode === 8) {
          if (payload.length === 1 || payload.length >= 2 && payload.readUInt16BE(0) !== 1000 || fragmented) throw failed('Peer closed without successful completion.')
          closed = true
          if (!inputClosed) await write(peer, frame(8, payload))
          peer.end()
          break
        }
        if (opcode === 9) { await write(peer, frame(10, payload)); continue }
        if (opcode === 10) continue
        if (opcode !== 2 && opcode !== 0 || opcode === 0 && !fragmented || opcode === 2 && fragmented) throw failed('Invalid binary fragmentation.')
        fragmentBytes += payload.length
        received += payload.length
        if (fragmentBytes > limits.frameBytes || received > limits.bytes) throw failed('Session byte quota exceeded.')
        fragments.push(payload)
        fragmented = !final
        if (final) {
          const message = Buffer.concat(fragments)
          incoming.update(message); framesReceived++
          const prefix = Buffer.alloc(4); prefix.writeUInt32BE(message.length)
          await write(channel, Buffer.concat([prefix, message]))
          fragments = []; fragmentBytes = 0
        }
      }
      if (closed) break
    }
    if (!closed || pending.length || fragmented) throw failed('Duplex session ended without a clean protocol close.')
    if (!inputClosed) { channel.push(null); channel.resume() }
    await upload
    return { status: 'complete', sent, received, framesSent, framesReceived, sentSha256: outgoing.digest('hex'), receivedSha256: incoming.digest('hex'), limits }
  } catch (error) {
    peer.destroy(); channel.destroy()
    if (error instanceof Failure) throw error
    throw failed('Duplex transport did not complete.')
  } finally { clearTimeout(lifetime); clearTimeout(idle); peer.destroy() }
}

function failed(message: string) { return new Failure('DUPLEX_FAILED', message, 'Inspect the session outcome; setup and confirmation cannot be replayed.') }

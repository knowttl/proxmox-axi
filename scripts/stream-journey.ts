import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:https'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { Socket } from 'node:net'
import type { Duplex } from 'node:stream'
import { gzipSync } from 'node:zlib'
import { decode } from '@toon-format/toon'

interface Journey {
  task: string, scratch: string, out: string, executable: string, caFile: string, env: Record<string, string>
  cases: Record<string, unknown>[], ledger: Record<string, unknown>[], transcripts: string[]
  hosted?: {
    otherActorEnv: Record<string, string>
    configure: (origin: string, operations: string[]) => Promise<void>
    limits: (bytes: number, idleMs: number) => Promise<void>
  }
}
const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex')
const version = { version: '9.2.0', release: '9.2', repoid: 'synthetic' }
const uploadPath = '/nodes/{node}/storage/{storage}/upload'
const consolePath = '/nodes/{node}/qemu/{vmid}/vncproxy'
const setupPaths = ['qemu', 'lxc'].flatMap(family => ['vncproxy', 'termproxy', 'mtunnel'].map(action => `/nodes/{node}/${family}/{vmid}/${action}`))
  .concat('/nodes/{node}/termproxy', '/nodes/{node}/vncshell')
const operation = (path: string) => `OP-POST-${createHash('sha256').update(`POST ${path}`).digest('hex').slice(0, 10)}`
const privateTicket = 'CANARY-S5-private-session-ticket'
const spiceSecret = 'CANARY-S5-spice-password'
const upid = 'UPID:pve-test:00000001:00000002:12345678:imgcopy:100:synthetic@pve:'

export async function exerciseStreamJourney(options: Journey) {
  const directory = join(options.scratch, options.hosted ? `hosted-${options.task}` : options.task)
  await mkdir(directory, { mode: 0o700 })
  const image = Buffer.alloc(5 * 1024 ** 2 + 37)
  for (let index = 0; index < image.length; index++) image[index] = index % 251
  const guestChunks = [Buffer.alloc(1048576, 0x61), Buffer.alloc(1048576, 0x62), Buffer.from('last chunk')]
  const guestRaw = Buffer.concat(guestChunks)
  const guestEncoded = guestChunks.map(chunk => chunk.toString('base64')).join('')
  const textFile = Buffer.from('independent provider log\nsecond line\n')
  const spiceFile = Buffer.from(`[virt-viewer]\ntype=spice\npassword=${spiceSecret}\n`)
  const spicePaths = ['/nodes/{node}/qemu/{vmid}/spiceproxy', '/nodes/{node}/lxc/{vmid}/spiceproxy', '/nodes/{node}/spiceshell']
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.from('independent fake PNG transport fixture')])
  const file = join(directory, 'image.iso')
  await writeFile(file, image, { mode: 0o600 })
  let mode = 'success', active = '', uploadDigest = '', uploads = 0
  let cancelCurrent = () => {}
  let peerClosed = Promise.resolve()
  const peers = new Set<Duplex>()
  const sockets = new Set<Duplex>()
  const certificate = await readFile(options.caFile)
  const server = createServer({ key: await readFile(join(options.scratch, 'server.key')), cert: certificate }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid')
    options.ledger.push({ case: active, method: request.method, path: url.pathname })
    if (url.pathname.endsWith('/version')) { response.end(JSON.stringify({ data: mode === 'legacy' ? { ...version, version: '8.2.7' } : version })); return }
    if (url.pathname.endsWith('/upload')) {
      uploads++
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = Buffer.concat(chunks)
      const start = body.indexOf(Buffer.from('Content-Type: application/octet-stream\r\n\r\n')) + Buffer.byteLength('Content-Type: application/octet-stream\r\n\r\n')
      const boundary = /boundary=(.+)$/.exec(String(request.headers['content-type']))![1]!
      const end = body.lastIndexOf(Buffer.from(`\r\n--${boundary}--\r\n`))
      uploadDigest = hash(body.subarray(start, end))
      response.end(JSON.stringify({ data: upid })); return
    }
    if (/\/(vncproxy|termproxy|vncshell|mtunnel)$/.test(url.pathname)) {
      for await (const _chunk of request) { /* Consume the independently validated setup body. */ }
      response.end(JSON.stringify({ data: url.pathname.endsWith('/mtunnel') ? { ticket: privateTicket, socket: '/run/pve/migrate-test.sock', upid } :
        { ticket: privateTicket, port: mode === 'wrong-target' ? 22 : 5900, cert: 'synthetic', user: 'synthetic@pve', upid } })); return
    }
    if (url.pathname.endsWith('/file-read')) {
      const decoded = url.searchParams.get('decode') !== '0'
      if (mode === 'legacy') { response.end(JSON.stringify({ data: { content: 'legacy representation' } })); return }
      const source = mode === 'maximum-guest' ? Buffer.alloc(16777216, 0x61) : mode === 'binary-guest' ? image : guestRaw
      const offset = Number(url.searchParams.get('offset') ?? 0), count = Number(url.searchParams.get('count') ?? 16777216)
      const selected = source.subarray(offset, offset + count)
      const chunks: string[] = []
      for (let index = 0; index < selected.length; index += 1048576) chunks.push(selected.subarray(index, index + 1048576).toString('base64'))
      const data = { content: decoded ? selected.toString('utf8') : chunks.join(''), 'bytes-read': selected.length, truncated: offset + selected.length < source.length ? 1 : 0 }
      response.end(JSON.stringify({ data })); return
    }
    if (url.pathname.startsWith('/api2/spiceconfig/')) {
      for await (const _chunk of request) { /* Consume the setup form. */ }
      response.end(spiceFile); return
    }
    if (url.pathname.endsWith('/file-restore/download')) { response.end(image); return }
    if (url.pathname.startsWith('/api2/text/')) {
      response.writeHead(200, mode === 'gzip' ? { 'content-encoding': 'gzip' } : {})
      response.end(mode === 'gzip' ? gzipSync(textFile) : textFile); return
    }
    if (url.pathname.startsWith('/api2/png/')) {
      if (mode === 'truncated') { response.writeHead(200, { 'content-length': png.length + 10 }); response.end(png); return }
      response.end(mode === 'corrupt' ? Buffer.alloc(png.length) : png); return
    }
    response.writeHead(404); response.end()
  })
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)) })
  server.on('upgrade', (request, socket, head) => {
    peers.add(socket)
    peerClosed = new Promise<void>(resolve => socket.once('close', () => { peers.delete(socket); resolve() }))
    const url = new URL(request.url!, 'https://fake.invalid')
    options.ledger.push({ case: active, method: 'GET', path: url.pathname, upgrade: 'websocket' })
    assert.ok(url.searchParams.get(url.pathname.endsWith('/mtunnelwebsocket') ? 'ticket' : 'vncticket') === privateTicket, 'Fake vendor requires the ticket from protected setup')
    assert.equal(url.searchParams.get(url.pathname.endsWith('/mtunnelwebsocket') ? 'socket' : 'port'), url.pathname.endsWith('/mtunnelwebsocket') ? '/run/pve/migrate-test.sock' : '5900')
    const accept = createHash('sha1').update(String(request.headers['sec-websocket-key']) + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: binary\r\n\r\n`)
    let pending = head
    socket.on('data', chunk => {
      if (mode === 'cancel') { cancelCurrent(); return }
      if (mode === 'idle') return
      pending = Buffer.concat([pending, chunk])
      while (pending.length >= 6) {
        const opcode = pending[0]! & 15
        let length = pending[1]! & 127, offset = 2
        if (length === 126) { if (pending.length < 8) return; length = pending.readUInt16BE(2); offset = 4 }
        if (pending.length < offset + 4 + length) return
        const mask = pending.subarray(offset, offset + 4)
        const payload = Buffer.from(pending.subarray(offset + 4, offset + 4 + length))
        for (let index = 0; index < payload.length; index++) payload[index] = payload[index]! ^ mask[index % 4]!
        pending = pending.subarray(offset + 4 + length)
        if (opcode === 8) { socket.end(Buffer.from([0x88, 2, 3, 232])); return }
        assert.equal(opcode, 2)
        // Independent peer fragments one message across a binary and continuation frame.
        socket.write(Buffer.concat([Buffer.from([0x02, 2]), payload.subarray(0, 2), Buffer.from([0x80, payload.length - 2]), payload.subarray(2)]))
      }
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const origin = `https://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}`
  const config = join(directory, 'profile.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'stream', profiles: { stream: {
    auth: 'api-token', origin, tokenId: 'synthetic@pve!stream', token: { env: 'STREAM_TOKEN' }, caBundle: options.caFile,
    writes: { operations: [operation(uploadPath), operation('/nodes/{node}/execute'), ...setupPaths.map(operation), ...spicePaths.map(operation)] },
  } } }), { mode: 0o600 })
  const env = { ...options.env, PROXMOX_AXI_CONFIG: config, PROXMOX_AXI_PROFILE: 'stream', STREAM_TOKEN: 'CANARY-S5-auth', PROXMOX_AXI_STREAM_FD: '3', PROXMOX_AXI_RESULT_FD: '4',
    XDG_STATE_HOME: join(directory, 'state') }
  if (options.hosted) await options.hosted.configure(origin, [operation(uploadPath), operation('/nodes/{node}/execute'), ...setupPaths.map(operation), ...spicePaths.map(operation)])
  const run = async (id: string, args: string[], expected: number | null, input?: Buffer, extra: Record<string, string> = {}) => {
    active = `${options.task}/${id}`
    if (options.hosted) await options.hosted.limits(Number(extra.PROXMOX_AXI_TRANSFER_BYTES ?? 8 * 1024 ** 3), Number(extra.PROXMOX_AXI_DUPLEX_IDLE_MS ?? 30000))
    const streaming = ['transfer', 'duplex'].includes(args[0]!)
    const invocation = [options.executable, ...(options.hosted ? streaming ? ['proxmox-axi', 'stream', '--'] : ['proxmox-axi'] : []), ...args, '--format', 'json']
    const child = spawn(process.execPath, invocation, {
      env: { ...(options.hosted ? options.env : env), PROXMOX_AXI_STREAM_FD: '3', PROXMOX_AXI_RESULT_FD: '4', ...extra }, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'], timeout: 15000,
    })
    const stream = child.stdio[3] as Socket
    cancelCurrent = () => { child.kill('SIGTERM') }
    const bytes: Buffer[] = [], stdout: Buffer[] = [], stderr: Buffer[] = []
    const privateFrames: Buffer[] = []
    child.stdio[4]!.on('data', (chunk: Buffer) => privateFrames.push(chunk))
    stream.on('data', chunk => bytes.push(Buffer.from(chunk)))
    stream.on('error', () => {})
    child.stdout!.on('data', chunk => stdout.push(chunk)); child.stderr!.on('data', chunk => stderr.push(chunk))
    if (input) stream.end(input)
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    const text = Buffer.concat(stdout).toString(), errors = Buffer.concat(stderr).toString()
    for (const secret of [privateTicket, spiceSecret]) assert.ok(!text.includes(secret) && !errors.includes(secret), 'Setup secrets stay private')
    assert.equal(code, expected, text + errors)
    if (options.hosted && !streaming && expected !== 0 && errors) assert.match(errors, /^artium-axi: request_id [0-9a-f-]{36}\n$/)
    else assert.equal(errors, '')
    if (expected === null) { assert.equal(child.signalCode, 'SIGTERM'); assert.equal(text, '', 'Cancellation cannot report completion') }
    const output = text ? (text.trimStart().startsWith('{') ? JSON.parse(text) : decode(text)) as Record<string, unknown> : {}
    const received = Buffer.concat(bytes)
    if (args[0] === 'duplex' && expected === 0 && !args.includes('--preview')) {
      const frame = Buffer.concat(privateFrames)
      assert.equal(frame.readUInt32BE(0), frame.length - 4)
      assert.ok(JSON.parse(frame.subarray(4).toString()).payload.ticket === privateTicket, 'Inner-protocol setup is available only through the private result pipe')
    }
    options.transcripts.push(`case: ${active}\nexit: ${code}\nstdout:\n${text}`)
    options.cases.push({ id: active, hosted: !!options.hosted, status: 'pass', expected: { exitCode: expected,
      hostBoundary: (output.error as { source?: string } | undefined)?.source === 'artium-axi' },
      invocation: { executable: process.execPath, args: invocation }, actual: { exitCode: code, bytes: received.length, sha256: hash(received), output } })
    return { output, bytes: received }
  }
  try {
    const upload = ['transfer', 'create', uploadPath, '--api-node', 'pve-test', '--api-storage', 'local', '--api-content', 'iso', '--api-filename', 'image.iso', '--input-file', file, '--response-format', 'multipart']
    const preview = await run('upload-preview', [...upload, '--preview'], 0)
    assert.equal(uploads, 0)
    if (options.hosted) await run('upload-cross-actor-denied', [...upload, '--confirm', String(preview.output.confirmation)], 1, undefined, options.hosted.otherActorEnv)
    await run('upload-confirm', [...upload, '--confirm', String(preview.output.confirmation)], 0)
    assert.equal(uploadDigest, hash(image), 'Multipart body preserves bytes beyond the legacy host upload cap')
    await run('upload-replay-denied', [...upload, '--confirm', String(preview.output.confirmation)], 1)
    assert.equal(uploads, 1)
    await run('batch-cannot-open-byte-channel', ['create', '/nodes/{node}/execute', '--api-node', 'pve-test', '--api-commands', JSON.stringify([
      { method: 'POST', path: 'storage/local/upload', args: { content: 'iso', filename: 'image.iso' } },
    ]), '--preview'], 2)
    const download = ['transfer', 'get', '/nodes/{node}/rrd', '--api-node', 'pve-test', '--api-ds', 'cpu', '--api-timeframe', 'hour', '--response-format', 'png']
    for (const quota of [png.length - 1, png.length, png.length + 1]) {
      const result = await run(`download-quota-${quota}`, download, quota < png.length ? 1 : 0, undefined, { PROXMOX_AXI_TRANSFER_BYTES: String(quota) })
      if (quota >= png.length) assert.deepEqual(result.bytes, png)
    }
    mode = 'corrupt'; await run('png-signature-denied', download, 2)
    mode = 'truncated'; await run('short-download-denied', download, 1)
    mode = 'success'
    for (const [path, parameters] of [
      ['/nodes/{node}/qemu/{vmid}/rrd', ['--api-vmid', '100']],
      ['/nodes/{node}/lxc/{vmid}/rrd', ['--api-vmid', '100']],
      ['/nodes/{node}/storage/{storage}/rrd', ['--api-storage', 'local']],
    ] as const) {
      const result = await run(`png-${path}`, [...download.slice(0, 2), path, ...download.slice(3), ...parameters], 0)
      assert.equal(hash(result.bytes), hash(png))
    }
    for (const path of spicePaths) {
      const args = ['transfer', 'create', path, '--api-node', 'pve-test', ...(path.includes('{vmid}') ? ['--api-vmid', '100'] : []), '--response-format', 'spiceconfig']
      const approved = await run(`spice-preview-${path}`, [...args, '--preview'], 0)
      const delivered = await run(`spice-private-${path}`, [...args, '--confirm', String(approved.output.confirmation)], 0)
      assert.equal(hash(delivered.bytes), hash(spiceFile), 'SPICE configuration retains exact private bytes')
    }
    const restored = await run('restore-download', ['transfer', 'get', '/nodes/{node}/storage/{storage}/file-restore/download', '--api-node', 'pve-test', '--api-storage', 'local',
      '--api-volume', 'backup/vm/100/fixture', '--api-filepath', Buffer.from('/fixture').toString('base64'), '--response-format', 'download', '--expected-sha256', hash(image)], 0)
    assert.equal(hash(restored.bytes), hash(image))
    for (const compressed of [false, true]) {
      mode = compressed ? 'gzip' : 'success'
      for (const path of ['/nodes/{node}/journal', '/nodes/{node}/tasks/{upid}/log']) {
        const args = ['transfer', 'get', path, '--api-node', 'pve-test', ...(path.endsWith('/log') ? ['--api-upid', upid, '--api-download', 'true'] : []), '--response-format', 'text']
        const result = await run(`${compressed ? 'gzip' : 'text'}-${path}`, args, 0)
        assert.deepEqual(result.bytes, textFile)
      }
    }
    mode = 'success'
    const guest = ['transfer', 'get', '/nodes/{node}/qemu/{vmid}/agent/file-read', '--catalogue', 'published-current', '--api-node', 'pve-test', '--api-vmid', '100', '--api-file', '/fixture', '--api-count', '16777216', '--response-format', 'guest-file']
    for (const decoded of [false, true]) {
      const encoded = await run(`guest-${decoded ? 'decoded' : 'encoded'}`, [...guest, '--api-decode', String(decoded)], 0)
      assert.equal(hash(encoded.bytes), hash(decoded ? guestRaw : Buffer.from(guestEncoded)))
      if (!decoded) {
        const raw = await run('guest-padding-between-chunks', [...guest, '--api-decode', 'false', '--raw'], 0)
        assert.equal(raw.bytes.length, guestRaw.length)
        assert.equal(hash(raw.bytes), hash(guestRaw))
      }
    }
    const sliced = await run('guest-offset-and-count', [...guest.filter((_value, index) => index < guest.indexOf('--api-count') || index > guest.indexOf('--api-count') + 1), '--api-count', '1', '--api-offset', '1048576'], 0)
    assert.deepEqual(sliced.bytes, Buffer.from('b'))
    assert.equal((sliced.output.transfer as { truncated: boolean }).truncated, true)
    mode = 'maximum-guest'
    const maximum = await run('guest-16777216-bytes', [...guest, '--api-decode', 'true'], 0)
    assert.equal(maximum.bytes.length, 16777216)
    assert.equal(hash(maximum.bytes), hash(Buffer.alloc(16777216, 0x61)))
    const memory = maximum.output.transfer as { peakRssBytes: number, limits: { peakRssBytes: number } }
    assert.ok(memory.peakRssBytes <= memory.limits.peakRssBytes, 'Guest transfer remains within its declared constant memory budget')
    mode = 'binary-guest'
    const binary = await run('guest-arbitrary-bytes', [...guest, '--api-decode', 'false', '--raw'], 0)
    assert.equal(hash(binary.bytes), hash(image))
    mode = 'legacy'
    const legacy = ['transfer', 'get', '/nodes/{node}/qemu/{vmid}/agent/file-read', '--api-node', 'pve-test', '--api-vmid', '100', '--api-file', '/fixture', '--response-format', 'guest-file']
    assert.deepEqual((await run('guest-legacy-representation', legacy, 0)).bytes, Buffer.from('legacy representation'))
    await run('guest-legacy-raw-denied', [...legacy, '--raw'], 2)
    mode = 'success'
    if (options.task === 'S5.2') for (const setup of setupPaths) {
      const family = setup.replace('/nodes/{node}/', '')
      const args = ['duplex', 'create', setup, '--api-node', 'pve-test', ...(setup.includes('{vmid}') ? ['--api-vmid', '100'] : [])]
      const approved = await run(`${family}-preview`, [...args, '--preview'], 0)
      if (options.hosted) await run(`${family}-wrong-owner`, [...args, '--confirm', String(approved.output.confirmation)], 1, undefined, options.hosted.otherActorEnv)
      const payload = Buffer.from([0, 1, 255, 13, 10, 128])
      const prefix = Buffer.alloc(4); prefix.writeUInt32BE(payload.length)
      const result = await run(`${family}-frames`, [...args, '--confirm', String(approved.output.confirmation)], 0, Buffer.concat([prefix, payload]))
      await peerClosed
      assert.equal(peers.size, 0, 'Clean protocol completion releases the vendor peer')
      assert.deepEqual(result.bytes, Buffer.concat([prefix, payload]), 'Duplex peer fragmentation preserves the exact message')
      await run(`${family}-reconnect-denied`, [...args, '--confirm', String(approved.output.confirmation)], 1)
      if (setup !== consolePath && setup !== consolePath.replace('/vncproxy', '/mtunnel')) continue
      const expiring = await run(`${family}-idle-preview`, [...args, '--preview'], 0, undefined, { PROXMOX_AXI_DUPLEX_IDLE_MS: '50' })
      mode = 'idle'
      const expired = await run(`${family}-idle-expired`, [...args, '--confirm', String(expiring.output.confirmation)], 1, undefined, { PROXMOX_AXI_DUPLEX_IDLE_MS: '50' })
      assert.equal((expired.output.error as { code: string }).code, 'WRITE_UNCERTAIN', 'Idle expiry occurs after the confirmed session opens')
      await peerClosed
      assert.equal(peers.size, 0, 'Idle expiry releases the vendor peer')
      mode = 'success'
      const cancelling = await run(`${family}-cancel-preview`, [...args, '--preview'], 0)
      mode = 'cancel'
      await run(`${family}-cancelled`, [...args, '--confirm', String(cancelling.output.confirmation)], null, Buffer.concat([prefix, payload]))
      await peerClosed
      assert.equal(peers.size, 0, 'Caller cancellation closes the provider connection')
      mode = 'success'
      if (setup === consolePath) {
        const wrong = await run('console-target-preview', [...args, '--preview'], 0)
        mode = 'wrong-target'
        const before = options.ledger.filter(row => row.upgrade === 'websocket').length
        await run('console-wrong-target-denied', [...args, '--confirm', String(wrong.output.confirmation)], 1)
        assert.equal(options.ledger.filter(row => row.upgrade === 'websocket').length, before, 'An unapproved port never opens a WebSocket')
        mode = 'success'
      }
    }
  } finally {
    for (const socket of sockets) socket.destroy()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
}

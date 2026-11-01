import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:https'
import { mkdir, open, readFile, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Readable } from 'node:stream'
import { decode } from '@toon-format/toon'

interface Journey {
  task: string
  scratch: string
  out: string
  executable: string
  caFile: string
  env: Record<string, string>
  cases: Record<string, unknown>[]
  ledger: Record<string, unknown>[]
  transcripts: string[]
  hosted?: {
    otherActorEnv: Record<string, string>
    configure: (origin: string, auth: string, operations: string[]) => Promise<void>
    clock: (offset: number) => Promise<void>
    stateDirectory: string
  }
}
interface Frame { version: number, binding: Record<string, string>, payload: Record<string, unknown> }
const operation = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const mint = ['create', '/access/users/{userid}/token/{tokenid}', '--api-userid', 'synthetic@pve', '--api-tokenid', 'minted']
const minted = 'CANARY-minted+secret/value?S4="private"'
const password = 'CANARY-operation+password/value-S4'
const ticket = 'PVE:synthetic@pve:12345678::CANARY-session-ticket-S4'
const csrf = 'CANARY-session-csrf-S4'
const challenge = 'PVE:tfa!CANARY-signed-challenge-S4'
const recovery = 'CANARY-one-time-recovery-S4'
const taskUpid = 'UPID:pve-test:00000001:00000002:12345678:qmstart:100:synthetic@pve:'
const version = { version: '8.2.7', release: '8.2', repoid: '3e0176e6bb2ade3b' }
const object = (value: unknown): Record<string, unknown> => { assert.ok(value && typeof value === 'object' && !Array.isArray(value)); return value as Record<string, unknown> }

function queue<T>() {
  const values: T[] = []
  const readers: ((value: T) => void)[] = []
  return {
    push(value: T) { const reader = readers.shift(); if (reader) reader(value); else values.push(value) },
    next(): Promise<T> {
      if (values.length) return Promise.resolve(values.shift()!)
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Packaged response deadline exceeded')), 10000)
        readers.push(value => { clearTimeout(timer); resolve(value) })
      })
    },
  }
}

export async function exerciseSecretJourney(options: Journey): Promise<void> {
  const { scratch, executable, caFile } = options
  const directory = join(scratch, options.hosted ? 'hosted-secrets' : 'secrets')
  await mkdir(directory, { mode: 0o700 })
  let activeCase = '', mode = 'success', mutations = 0, selectedPassword = password
  let breakSink = () => {}
  const acquired = [ticket, csrf, challenge, minted, recovery, 'CANARY-openid-state-S4']
  const protectedValues = [...acquired, password, 'totp:123456', 'webauthn:synthetic-response', (await readFile(join(scratch, 'server.key'), 'utf8')).trimEnd()]
  const safePublic = (text: string): string => {
    for (const secret of protectedValues) for (const form of [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1),
      Buffer.from(secret).toString('base64'), Buffer.from(secret).toString('base64url')]) text = text.replaceAll(form, '[REDACTED]')
    return text
  }
  const server = createServer({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) }, async (request, reply) => {
    const url = new URL(request.url!, 'https://fake.invalid')
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const params = Object.fromEntries(request.method === 'GET' || request.method === 'DELETE' ? url.searchParams : new URLSearchParams(Buffer.concat(chunks).toString()))
    options.ledger.push({ case: activeCase, method: request.method, path: url.pathname, parameterNames: Object.keys(params),
      authentication: request.headers.cookie ? 'ticket' : request.headers.authorization ? 'api-token' : 'acquire' })
    let data: unknown
    if (url.pathname === '/api2/json/access/ticket' || url.pathname === '/api2/json/access/openid/login') {
      assert.ok(request.headers.authorization === undefined, 'acquisition must not send token authorization')
      assert.ok(request.headers.cookie === undefined, 'acquisition must not send a prior cookie')
      if (url.pathname.endsWith('/ticket')) {
        assert.equal(params.username, 'synthetic@pve')
        if (params['tfa-challenge']) { assert.ok(params['tfa-challenge'] === challenge, 'signed challenge reaches the vendor'); assert.ok(/^(totp:123456|webauthn:synthetic-response)$/.test(params.password ?? ''), 'challenge response reaches the vendor') }
        else assert.ok(params.password === selectedPassword, 'selected password reaches the vendor')
      } else { assert.ok(params.code === password, 'OpenID code reaches the vendor'); assert.ok(params.state === 'CANARY-openid-state-S4', 'OpenID state reaches the vendor') }
      data = { username: mode === 'wrong-identity' ? 'other@pve' : 'synthetic@pve', ticket: mode === 'challenge' && !params['tfa-challenge'] ? challenge : ticket,
        ...(mode !== 'challenge' || params['tfa-challenge'] ? { CSRFPreventionToken: csrf } : {}) }
    } else if (url.pathname.endsWith('/openid/auth-url')) {
      assert.equal(params['redirect-url'], origin)
      data = 'https://identity.test/authorize?state=CANARY-openid-state-S4'
    } else {
      const authorized = request.headers.authorization === `PVEAPIToken=synthetic@pve!acceptance=${options.env.PROXMOX_AXI_TOKEN}` ||
        request.headers.cookie === `PVEAuthCookie=${encodeURIComponent(ticket)}`
      if (!authorized) { reply.writeHead(401).end(); return }
      if (request.headers.cookie && request.method !== 'GET') assert.ok(request.headers.csrfpreventiontoken === csrf, 'correct CSRF reaches only the selected origin')
      if (url.pathname.endsWith('/version')) data = version
      else if (url.pathname.endsWith('/access/permissions')) data = {}
      else if (url.pathname.endsWith('/nodes')) data = []
      else if (request.method === 'GET' && url.pathname.endsWith('/status')) data = {
        upid: taskUpid, node: 'pve-test', status: 'stopped', exitstatus: 'OK', starttime: 1, type: 'qmstart', pstart: 2, id: '100', user: 'synthetic@pve', pid: 1,
      }
      else if (request.method === 'GET' && url.pathname.endsWith('/log')) data = [{ n: 1, t: `TASK OK ${selectedPassword}` }]
      else if (request.method === 'GET' && url.pathname.endsWith('/config')) data = { cipassword: password }
      else if (request.method === 'GET' && url.pathname.endsWith('/status/current')) data = { status: 'running' }
      else {
        mutations++
        if (mode === 'broken') breakSink()
        if (url.pathname.includes('/token/')) data = { 'full-tokenid': 'synthetic@pve!minted', info: {}, value: minted }
        else if (url.pathname.endsWith('/scan/cifs') || url.pathname.endsWith('/scan/pbs')) {
          assert.ok(params.password === password, 'protected scan password reaches the vendor')
          data = url.pathname.endsWith('/cifs') ? [{ share: 'synthetic', description: `raw ${password} encoded ${encodeURIComponent(password)} base64 ${Buffer.from(password).toString('base64')}` }] : [{ comment: password, store: 'synthetic' }]
        } else if (url.pathname.endsWith('/certificates/custom')) { assert.ok(params.key === (await readFile(join(scratch, 'server.key'), 'utf8')).trimEnd(), 'protected key reaches the vendor'); data = {} }
        else if (url.pathname.endsWith('/execute')) {
          const batch = JSON.parse(params.commands!) as { method: string, path: string, args: Record<string, string> }[]
          const apply = (items: typeof batch): unknown[] => items.map(child => ({ status: 200, data: child.path === 'execute' ? apply(JSON.parse(child.args.commands!) as typeof batch) :
            /\/(vncproxy|termproxy)$/.test(child.path) ? { port: 5900, cert: 'synthetic-cert', ticket: minted, password: recovery, user: 'synthetic@pve', upid: 'synthetic-upid' } :
            child.path.endsWith('/start') ? taskUpid :
              (assert.ok(child.args.cipassword === password, 'nested protected password reaches the vendor'), null) }))
          data = apply(batch)
        } else if (url.pathname.includes('/access/tfa/') && request.method === 'POST') data = { id: 'synthetic-tfa', recovery: [recovery] }
        else data = null
      }
    }
    const bytes = JSON.stringify({ data })
    reply.writeHead(200, { 'Content-Type': 'application/json' })
    reply.write(bytes.slice(0, Math.floor(bytes.length / 2)))
    reply.end(bytes.slice(Math.floor(bytes.length / 2)))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address(); assert.ok(address && typeof address === 'object')
  const origin = `https://127.0.0.1:${address.port}`
  const config = join(directory, 'config.json'), bodyFile = join(directory, 'input.json'), log = join(directory, 'writes.log')
  const passwordFile = join(directory, 'password')
  await writeFile(passwordFile, password, { mode: 0o600 })
  const clock = join(directory, 'clock')
  const now = Date.now()
  await writeFile(clock, String(now), { mode: 0o600 })
  const ids = [operation('POST', mint[1]!), operation('GET', '/nodes/{node}/scan/cifs'), operation('GET', '/nodes/{node}/scan/pbs'),
    operation('POST', '/nodes/{node}/certificates/custom'), operation('POST', '/nodes/{node}/execute'), operation('PUT', '/nodes/{node}/qemu/{vmid}/config'),
    operation('POST', '/nodes/{node}/qemu/{vmid}/vncproxy'), operation('PUT', '/access/password'), operation('POST', '/access/tfa/{userid}'),
    operation('POST', '/nodes/{node}/qemu/{vmid}/status/start'), operation('PUT', '/nodes/{node}/lxc/{vmid}/config'),
    operation('DELETE', '/nodes/{node}/tasks/{upid}'),
    operation('POST', '/nodes/{node}/qemu/{vmid}/termproxy'), operation('POST', '/nodes/{node}/lxc/{vmid}/vncproxy'), operation('POST', '/nodes/{node}/lxc/{vmid}/termproxy'),
    operation('PUT', '/access/tfa/{userid}/{id}'), operation('DELETE', '/access/tfa/{userid}/{id}')]
  let auth = 'api-token'
  const env = { ...options.env, PROXMOX_AXI_PROFILE: 'secrets', PROXMOX_AXI_CONFIG: config, PROXMOX_AXI_WRITE_LOG: log,
    PVE_INPUT_PASSWORD: password, PVE_INPUT_TICKET: ticket, PVE_INPUT_CSRF: csrf, PVE_INPUT_OTP: 'totp:123456',
    PVE_INPUT_WEBAUTHN: 'webauthn:synthetic-response', PVE_INPUT_OPENID_STATE: 'CANARY-openid-state-S4',
    PVE_INPUT_KEY: (await readFile(join(scratch, 'server.key'), 'utf8')).trimEnd(), PROXMOX_AXI_TEST_CLOCK_FILE: clock, PVE_NUMERIC_SECRET: '12345678' }
  const configure = async (kind: string) => {
    auth = kind
    if (options.hosted) return options.hosted.configure(origin, kind, ids)
    await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'secrets', profiles: { secrets: { auth: kind, origin, caBundle: caFile,
      ...(kind === 'api-token' ? { tokenId: 'synthetic@pve!acceptance', token: { env: 'PROXMOX_AXI_TOKEN' } } : { userId: 'synthetic@pve',
        ...(kind === 'password' ? { password: { file: passwordFile } } : { ticket: { env: 'PVE_INPUT_TICKET' }, csrfPreventionToken: { env: 'PVE_INPUT_CSRF' } }) }), writes: { operations: ids } } } }), { mode: 0o600 })
  }
  const start = (args: string[], environment: Record<string, string>, sink: string | number = 'pipe', session = false) => {
    const child = spawn(process.execPath, [...(!options.hosted && session ? ['--import', fileURLToPath(new URL(import.meta.url.endsWith('.ts') ? './auth-clock.ts' : './auth-clock.js', import.meta.url))] : []), executable,
      ...(options.hosted ? ['proxmox-axi'] : []), ...args], { env: { ...environment, PROXMOX_AXI_RESULT_FD: sink === 'missing' ? '' : '3' },
      stdio: ['pipe', 'pipe', 'pipe', ...(sink === 'missing' ? [] : [typeof sink === 'number' ? sink : 'pipe' as const])] })
    const frames = queue<Frame>(), lines = queue<Record<string, unknown>>()
    let privateBytes = Buffer.alloc(0), stdout = '', stderr = '', pending = ''
    const timer = setTimeout(() => child.kill('SIGKILL'), 60000)
    child.stdout!.on('data', (chunk: Buffer) => {
      stdout += chunk.toString(); pending += chunk.toString()
      if (session) { let end: number; while ((end = pending.indexOf('\n')) >= 0) { lines.push(object(JSON.parse(pending.slice(0, end)))); pending = pending.slice(end + 1) } }
    })
    child.stderr!.on('data', (chunk: Buffer) => { stderr += chunk.toString() })
    if (typeof sink !== 'number' && sink !== 'missing') (child.stdio[3] as Readable).on('data', (chunk: Buffer) => {
      privateBytes = Buffer.concat([privateBytes, chunk])
      if (privateBytes.length > 65540) throw new Error('Oversized private frame')
      while (privateBytes.length >= 4 && privateBytes.length >= 4 + privateBytes.readUInt32BE(0)) {
        const length = privateBytes.readUInt32BE(0)
        let frame: Frame
        try { frame = JSON.parse(privateBytes.subarray(4, 4 + length).toString()) as Frame }
        catch { throw new Error('Malformed private frame') }
        frames.push(frame)
        privateBytes = privateBytes.subarray(4 + length)
      }
    })
    const closed = new Promise<{ code: number, stdout: string, stderr: string }>((resolve, reject) => {
      child.once('error', reject)
      child.once('close', (code, signal) => {
        clearTimeout(timer)
        if (signal) reject(new Error(`Command terminated by ${signal}`))
        else resolve({ code: code!, stdout, stderr })
      })
    })
    return { child, frames, lines, closed }
  }
  let processSession: ReturnType<typeof start> | undefined
  const invoke = async (id: string, args: string[], expected: { error?: string, status?: string, mutations?: number, private?: boolean, sink?: string, otherActor?: boolean } = {}, api?: Record<string, unknown>) => {
    activeCase = id
    const before = mutations
    const commandArgs = [...args, ...(args[0] === 'result' ? [] : ['--format', 'json'])]
    let value: Record<string, unknown>, frame: Frame | undefined
    if (api && !options.hosted) { await writeFile(bodyFile, JSON.stringify(api), { mode: 0o600 }); commandArgs.push('--body-file', bodyFile) }
    if (processSession) {
      processSession.child.stdin!.write(JSON.stringify(commandArgs) + '\n')
      value = await processSession.lines.next()
      if (expected.private) frame = await processSession.frames.next()
    } else {
      const fileSink = expected.sink === 'file' ? await open(join(directory, 'invalid-result-file'), 'w', 0o600) : undefined
      const running = start([...commandArgs, ...(api && options.hosted ? ['--protected-input'] : [])], expected.otherActor ? options.hosted!.otherActorEnv : options.hosted ? options.env : env, fileSink?.fd ?? expected.sink)
      breakSink = () => running.child.stdio[3]?.destroy()
      running.child.stdin!.end(api && options.hosted ? JSON.stringify({ api, secrets: { PVE_INPUT_PASSWORD: password, PVE_INPUT_OTP: env.PVE_INPUT_OTP,
        PVE_INPUT_WEBAUTHN: env.PVE_INPUT_WEBAUTHN, PVE_INPUT_OPENID_STATE: env.PVE_INPUT_OPENID_STATE, PVE_INPUT_KEY: env.PVE_INPUT_KEY } }) : '')
      const result = await running.closed
      await fileSink?.close()
      value = object(result.stdout.startsWith('{') ? JSON.parse(result.stdout) : decode(result.stdout))
      assert.equal(result.code === 0, !expected.error, `${id}: ${safePublic(result.stdout + result.stderr)}`)
      if (expected.private && !options.hosted) frame = await running.frames.next()
      options.transcripts.push(`case: ${id}\nstdout:\n${safePublic(result.stdout)}\nstderr:\n${safePublic(result.stderr)}`)
      if (expected.private && options.hosted && id !== 'CRED-14/private-minted-value') {
        const handle = object(value.result)
        const delivered = start(['result', 'take', String(handle.operation), String(handle.id)], options.env)
        delivered.child.stdin!.end()
        const delivery = await delivered.closed
        assert.equal(delivery.code, 0, safePublic(delivery.stdout + delivery.stderr))
        frame = await delivered.frames.next()
      }
    }
    if (expected.error) assert.equal(object(value.error).code, expected.error, `${id}: ${safePublic(JSON.stringify(value))}`)
    if (expected.status) assert.ok(value.status === expected.status, `${id}: ${safePublic(JSON.stringify(value))}`)
    assert.equal(mutations - before, expected.mutations ?? 0, `${id}: no mutation retry`)
    assert.ok(safePublic(JSON.stringify(value)) === JSON.stringify(value), `${id}: protected value in public output`)
    if (frame) { assert.equal(frame.version, 1); assert.equal(frame.binding.origin, origin); assert.equal(frame.binding.identity, auth === 'api-token' ? 'synthetic@pve!acceptance' : 'synthetic@pve') }
    options.cases.push({ id: `${options.hosted ? 'artium' : 'standalone'}/${id}`, status: 'pass', hosted: !!options.hosted,
      expected: { hostBoundary: !!expected.otherActor || args[0] === 'result', ...(args[0] === 'result' ? {} : { auditExit: expected.error === 'NOT_FOUND' ? null : expected.error ? 1 : 0 }) },
      actual: { mutationTransmissions: mutations - before, privateFrame: !!frame, privateFrameBytes: frame ? Buffer.byteLength(JSON.stringify(frame)) + 4 : 0 } })
    return { value, frame }
  }
  try {
    await configure('api-token')
    if (!options.hosted) {
      await invoke('CRED-13/qemu-numeric-path', ['set', '/nodes/{node}/qemu/{vmid}/config', '--preview'], { error: 'INVALID_INPUT' },
        { node: 'pve-test', vmid: 12345678, cipassword: { env: 'PVE_NUMERIC_SECRET' } })
      for (const guest of ['qemu', 'lxc']) await invoke(`CRED-13/nested-${guest}-sibling-path`, ['create', '/nodes/{node}/execute', '--preview'], { error: 'INVALID_INPUT' }, {
        node: 'pve-test', commands: JSON.stringify([
          { method: 'PUT', path: `${guest}/12345678/config`, args: { description: 'updated' } },
          { method: 'POST', path: 'execute', args: { commands: JSON.stringify([
            { method: 'PUT', path: 'qemu/100/config', args: { cipassword: { env: 'PVE_NUMERIC_SECRET' } } },
          ]) } },
        ]),
      })
    }
    const preview = await invoke('CRED-14/mint-preview', [...mint, '--preview'], { status: 'preview' })
    if (!options.hosted) {
      await invoke('CRED-15/missing-sink', [...mint, '--confirm', String(preview.value.confirmation)], { error: 'PRIVATE_SINK_REQUIRED', sink: 'missing' })
      await invoke('CRED-15/regular-file-sink', [...mint, '--confirm', String(preview.value.confirmation)], { error: 'PRIVATE_SINK_REQUIRED', sink: 'file' })
    }
    const created = await invoke('CRED-14/private-minted-value', [...mint, '--confirm', String(preview.value.confirmation)], { status: 'success', mutations: 1, private: true })
    if (created.frame) assert.ok(created.frame.payload.value === minted, 'minted value reaches the authorized private sink')
    if (options.hosted) {
      const handle = object(created.value.result)
      await invoke('CRED-18/result-other-actor', ['result', 'take', String(handle.operation), String(handle.id)], { error: 'NOT_FOUND', otherActor: true })
      const delivered = start(['result', 'take', String(handle.operation), String(handle.id)], options.env)
      delivered.child.stdin!.end()
      assert.equal((await delivered.closed).code, 0)
      assert.ok((await delivered.frames.next()).payload.value === minted, 'host private retrieval preserves the minted value')
      options.cases.push({ id: 'artium/CRED-14/result-owner', status: 'pass', hosted: true, expected: { hostBoundary: true }, actual: { privateFrame: true } })
    } else {
      const next = await invoke('CRED-15/broken-preview', [...mint, '--preview'])
      mode = 'broken'
      await invoke('CRED-15/broken-after-mint', [...mint, '--confirm', String(next.value.confirmation)], { error: 'DELIVERY_UNCERTAIN', mutations: 1 })
      mode = 'success'
    }
    for (const family of ['cifs', 'pbs']) {
      const args = ['get', `/nodes/{node}/scan/${family}`]
      const api = { node: 'pve-test', server: 'synthetic.test', username: 'synthetic', password: { env: 'PVE_INPUT_PASSWORD' } }
      const check = await invoke(`AC-SPECIAL-SECRET-INPUTS/${family}-preview`, [...args, '--preview'], {}, api)
      const result = await invoke(`AC-SPECIAL-SECRET-INPUTS/${family}-redacted-provider-text`, [...args, '--confirm', String(check.value.confirmation)], { mutations: 1, status: 'success' }, api)
      assert.ok(JSON.stringify(result.value.data).includes('[REDACTED]'))
    }
    const certificate = { node: 'pve-test', key: { env: 'PVE_INPUT_KEY' }, certificates: await readFile(caFile, 'utf8') }
    const certArgs = ['create', '/nodes/{node}/certificates/custom']
    const certPreview = await invoke('AC-SPECIAL-SECRET-INPUTS/private-key-preview', [...certArgs, '--preview'], {}, certificate)
    await invoke('AC-SPECIAL-SECRET-INPUTS/private-key-wire', [...certArgs, '--confirm', String(certPreview.value.confirmation)], { status: 'success', mutations: 1 }, certificate)
    const batch = { node: 'pve-test', commands: JSON.stringify([{ method: 'POST', path: 'execute', args: { commands: JSON.stringify([
      { method: 'PUT', path: 'qemu/100/config', args: { cipassword: { env: 'PVE_INPUT_PASSWORD' } } }, { method: 'POST', path: 'qemu/100/vncproxy' },
      { method: 'POST', path: 'qemu/100/status/start' },
      { method: 'POST', path: 'qemu/100/termproxy' }, { method: 'POST', path: 'lxc/100/vncproxy' }, { method: 'POST', path: 'lxc/100/termproxy' },
    ]) } }]) }
    const batchArgs = ['create', '/nodes/{node}/execute']
    const batchPreview = await invoke('AC-SPECIAL-BATCH-POLICY/nested-private-preview', [...batchArgs, '--preview'], {}, batch)
    const batchResult = await invoke('AC-SPECIAL-BATCH-RESULTS/nested-private-results', [...batchArgs, '--confirm', String(batchPreview.value.confirmation)], { status: 'accepted', mutations: 1, private: true }, batch)
    assert.equal(object((object((batchResult.value.children as unknown[])[0]).children as unknown[])[2]).upid, taskUpid)
    if (batchResult.frame) assert.ok(JSON.stringify(batchResult.frame.payload).includes(recovery))

    if (options.task === 'S4.2') {
    await configure('ticket')
    if (!options.hosted) {
      env.PVE_INPUT_TICKET = 'PVE:other@pve:12345678::CANARY-other-ticket'
      await invoke('CRED-11/supplied-identity-mismatch', ['get', '/version'], { error: 'CONFIG_INVALID' })
      env.PVE_INPUT_TICKET = ticket
    }
    await invoke('CRED-16/supplied-ticket', ['get', '/version'])
    await configure('password')
    if (!options.hosted) processSession = start(['auth', 'session'], env, 'pipe', true)
    await invoke('CRED-16/no-implicit-acquisition', ['get', '/version'], { error: 'AUTH_REQUIRED' })
    const authenticated = await invoke('CRED-16/password-acquire', ['auth', 'acquire'], { status: 'ready', private: true })
    const session = String(authenticated.value.session)
    await invoke('CRED-16/session-read', ['get', '/version', '--session', session])
    for (const command of ['home', 'doctor', 'ls']) await invoke(`CRED-16/session-${command}`, [command, '--session', session])
    for (const command of ['status', 'log', 'wait']) await invoke(`CRED-16/session-task-${command}`,
      ['task', command, '--api-node', 'pve-test', '--api-upid', taskUpid, '--session', session])
    const sessionBatch = await invoke('CRED-16/session-batch-preview', [...batchArgs, '--preview', '--session', session], {}, batch)
    await invoke('CRED-16/session-batch-confirm', [...batchArgs, '--confirm', String(sessionBatch.value.confirmation), '--session', session],
      { status: 'accepted', mutations: 1, private: true }, batch)
    for (const command of ['show', 'reconcile']) await invoke(`CRED-16/session-journal-${command}`,
      ['journal', command, String(sessionBatch.value.id), '--session', session])
    const cancelArgs = ['task', 'cancel', '--api-node', 'pve-test', '--api-upid', taskUpid, '--session', session]
    const cancelPreview = await invoke('CRED-16/session-task-cancel-preview', [...cancelArgs, '--preview'])
    await invoke('CRED-16/session-task-cancel-confirm', [...cancelArgs, '--confirm', String(cancelPreview.value.confirmation)], { status: 'success', mutations: 1 })
    for (const [command, path, api] of [
      ['set', '/access/password', { userid: 'synthetic@pve', password: { env: 'PVE_INPUT_PASSWORD' } }],
      ['create', '/access/tfa/{userid}', { userid: 'synthetic@pve', type: 'recovery', password: { env: 'PVE_INPUT_PASSWORD' } }],
      ['set', '/access/tfa/{userid}/{id}', { userid: 'synthetic@pve', id: 'synthetic-tfa', enable: false }],
      ['delete', '/access/tfa/{userid}/{id}', { userid: 'synthetic@pve', id: 'synthetic-tfa', password: { env: 'PVE_INPUT_PASSWORD' } }],
    ] as const) {
      const args = [command, path, '--session', session]
      const preview = await invoke(`AC-AUTH/${command}-${path}-preview`, [...args, '--preview'], {}, { ...api })
      await invoke(`AC-AUTH/${command}-${path}-session`, [...args, '--confirm', String(preview.value.confirmation)], { status: 'success', mutations: 1, private: command === 'create' }, { ...api })
    }
    if (options.hosted) await invoke('CRED-18/session-other-actor', ['get', '/version', '--session', session], { error: 'NOT_FOUND', otherActor: true })
    await invoke('CRED-17/cancel', ['auth', 'cancel', '--session', session], { status: 'cancelled' })
    await invoke('CRED-17/cancelled-reuse', ['get', '/version', '--session', session], { error: options.hosted ? 'NOT_FOUND' : 'AUTH_SESSION_INVALID' })
    mode = 'challenge'
    const pending = await invoke('CRED-16/otp-challenge', ['auth', 'acquire'], { status: 'challenge', private: true })
    await invoke('AC-AUTH/webauthn-origin-mismatch', ['auth', 'continue', '--session', String(pending.value.session)], { error: 'AUTH_ORIGIN_MISMATCH' },
      { response: { env: 'PVE_INPUT_OTP' }, webauthnOrigin: 'https://artium.test' })
    if (options.hosted) {
      // A failed continuation consumes its host handle, so obtain a fresh challenge.
      const fresh = await invoke('CRED-16/fresh-otp-challenge', ['auth', 'acquire'], { status: 'challenge', private: true })
      pending.value.session = fresh.value.session
    }
    const otp = await invoke('CRED-16/otp-continue', ['auth', 'continue', '--session', String(pending.value.session)], { status: 'ready', private: true }, { response: { env: 'PVE_INPUT_OTP' } })
    await invoke('CRED-17/otp-session-cancel', ['auth', 'cancel', '--session', String(otp.value.session)], { status: 'cancelled' })
    const webauthn = await invoke('AC-AUTH/webauthn-acquire', ['auth', 'acquire'], { status: 'challenge', private: true })
    const verified = await invoke('AC-AUTH/webauthn-continue', ['auth', 'continue', '--session', String(webauthn.value.session)], { status: 'ready', private: true },
      { response: { env: 'PVE_INPUT_WEBAUTHN' }, webauthnOrigin: origin })
    await invoke('CRED-17/webauthn-session-cancel', ['auth', 'cancel', '--session', String(verified.value.session)], { status: 'cancelled' })
    mode = 'success'
    if (!options.hosted) {
      const profile = object(JSON.parse(await readFile(config, 'utf8')))
      delete object(object(profile.profiles).secrets).password
      await writeFile(config, JSON.stringify(profile), { mode: 0o600 })
    }
    const oidc = await invoke('AC-AUTH/openid-acquire', ['auth', 'acquire'], { status: 'challenge', private: true }, { openid: { realm: 'synthetic', 'redirect-url': origin } })
    const completed = await invoke('AC-AUTH/openid-continue', ['auth', 'continue', '--session', String(oidc.value.session)], { status: 'ready', private: true },
      { openid: { code: { env: 'PVE_INPUT_PASSWORD' }, state: { env: 'PVE_INPUT_OPENID_STATE' }, 'redirect-url': origin } })
    await invoke('CRED-17/openid-session-cancel', ['auth', 'cancel', '--session', String(completed.value.session)], { status: 'cancelled' })
    if (!options.hosted) await configure('password')
    const expiring = await invoke('CRED-17/expiry-acquire', ['auth', 'acquire'], { status: 'ready', private: true })
    if (options.hosted) await options.hosted.clock(300001)
    else await writeFile(clock, String(now + 300001))
    await invoke('CRED-17/expired-reuse', ['get', '/version', '--session', String(expiring.value.session)], { error: options.hosted ? 'NOT_FOUND' : 'AUTH_SESSION_INVALID' })
    if (options.hosted) await options.hosted.clock(0)
    else await writeFile(clock, String(now))
    const bound = await invoke('CRED-17/revision-acquire', ['auth', 'acquire'], { status: 'ready', private: true })
    if (options.hosted) await configure('password')
    else await writeFile(passwordFile, `${password}-revised`)
    await invoke('CRED-17/changed-revision', ['get', '/version', '--session', String(bound.value.session)], { error: options.hosted ? 'NOT_FOUND' : 'AUTH_SESSION_INVALID' })
    if (!options.hosted) await writeFile(passwordFile, password)
    mode = 'wrong-identity'
    await invoke('CRED-11/acquired-identity-mismatch', ['auth', 'acquire'], { error: 'AUTH_SESSION_INVALID' })
    mode = 'success'
    if (processSession) { processSession.child.stdin!.end(); await processSession.closed; processSession = undefined }
    if (!options.hosted) {
      for (const secret of ['compatibility', 'success']) {
        selectedPassword = secret
        await writeFile(passwordFile, secret)
        processSession = start(['auth', 'session'], env, 'pipe', true)
        const acquired = await invoke(`CRED-16/${secret}-acquire`, ['auth', 'acquire'], { status: 'ready', private: true })
        const id = String(acquired.value.session)
        const read = await invoke(`CRED-16/${secret}-json-keys`, ['get', '/version', '--session', id])
        assert.equal(object(read.value.compatibility).status, 'unverified')
        await invoke(`CRED-16/${secret}-json-status`, ['task', 'status', '--api-node', 'pve-test', '--api-upid', taskUpid, '--session', id], { status: 'success' })
        const state = JSON.stringify({ ...acquired.frame!.payload, origin, identity: 'synthetic@pve', actor: options.env.PROXMOX_AXI_ACTOR,
          family: options.env.PROXMOX_AXI_SESSION_FAMILY, revision: options.env.PROXMOX_AXI_CREDENTIAL_REVISION })
        for (const args of [['get', '/version'], ['task', 'status', '--api-node', 'pve-test', '--api-upid', taskUpid],
          ['task', 'log', '--api-node', 'pve-test', '--api-upid', taskUpid]]) {
          const command = start([...args, '--session', id, '--format', 'toon'], { ...env, PROXMOX_AXI_AUTH_STATE: state })
          command.child.stdin!.end()
          const result = await command.closed
          assert.equal(result.code, 0, result.stderr)
          const value = object(decode(result.stdout))
          if (args[0] === 'get') assert.equal(object(value.compatibility).status, 'unverified')
          else if (args[1] === 'status') assert.equal(value.status, 'success')
          else assert.equal(object((value.data as unknown[])[0]).t, 'TASK OK [REDACTED]')
        }
        processSession.child.stdin!.end()
        await processSession.closed
        processSession = undefined
      }
      selectedPassword = password
      await writeFile(passwordFile, password)
      processSession = start(['auth', 'session'], env, 'pipe', true)
      mode = 'challenge'
      const oidc = await invoke('CRED-17/capacity-openid-acquire', ['auth', 'acquire'], { status: 'challenge', private: true },
        { openid: { realm: 'synthetic', 'redirect-url': origin } })
      const challenges: string[] = []
      for (let index = 0; index < 63; index++) {
        const acquired = await invoke(`CRED-17/capacity-acquire-${index}`, ['auth', 'acquire'], { status: 'challenge', private: true })
        challenges.push(String(acquired.value.session))
      }
      await invoke('CRED-17/capacity-reject-acquire', ['auth', 'acquire'], { error: 'AUTH_SESSION_LIMIT' })
      await invoke('CRED-17/capacity-otp-continue', ['auth', 'continue', '--session', challenges[0]!], { status: 'ready', private: true }, { response: { env: 'PVE_INPUT_OTP' } })
      await invoke('CRED-17/capacity-webauthn-continue', ['auth', 'continue', '--session', challenges[1]!], { status: 'ready', private: true },
        { response: { env: 'PVE_INPUT_WEBAUTHN' }, webauthnOrigin: origin })
      mode = 'success'
      await invoke('CRED-17/capacity-openid-continue', ['auth', 'continue', '--session', String(oidc.value.session)], { status: 'ready', private: true },
        { openid: { code: { env: 'PVE_INPUT_PASSWORD' }, state: { env: 'PVE_INPUT_OPENID_STATE' }, 'redirect-url': origin } })
      processSession.child.stdin!.end()
      await processSession.closed
      processSession = undefined
    }
    }

    const scan = async (path: string, journal = false): Promise<void> => {
      for (const entry of await readdir(path, { withFileTypes: true })) {
        // The fixture links its immutable package installation into the host directory.
        if (entry.isSymbolicLink()) continue
        const file = join(path, entry.name)
        if (entry.isDirectory()) await scan(file, journal || entry.name.endsWith('.log.d'))
        else {
          const text = (await readFile(file)).toString('utf8')
          if (journal) assert.ok(safePublic(text) === text, 'protected value persisted in a durable journal')
          for (const secret of acquired) for (const form of [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1), Buffer.from(secret).toString('base64')]) {
            assert.ok(!text.includes(form), `acquired secret persisted in ${entry.name}`)
          }
        }
      }
    }
    await scan(directory)
    if (options.hosted) await scan(options.hosted.stateDirectory)
    options.cases.push({ id: `${options.hosted ? 'artium' : 'standalone'}/CRED-13/protected-metadata-and-journal`, status: 'pass', hosted: !!options.hosted,
      expected: { hostBoundary: true }, actual: { protectedValuesPersisted: 0 } })
    await writeFile(join(options.out, `${options.hosted ? 'hosted-' : ''}secret-custody.json`), JSON.stringify({ status: 'pass', protectedValuesPersisted: 0, mutationTransmissions: mutations,
      origin, cases: options.cases.filter(row => String(row.id).startsWith(options.hosted ? 'artium/' : 'standalone/')).map(row => row.id) }, null, 2))
  } finally {
    if (processSession) {
      processSession.child.kill('SIGKILL')
      await processSession.closed.catch(() => {})
    }
    await new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections() })
  }
}

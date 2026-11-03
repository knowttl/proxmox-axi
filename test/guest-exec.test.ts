import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Readable } from 'node:stream'
import test from 'node:test'
import { Ajv } from 'ajv'

const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PROXMOX_AXI_')))
const base = '/nodes/{node}/qemu/{vmid}/agent', launch = `${base}/exec`, status = `${base}/exec-status`, batch = '/nodes/{node}/execute'
const operationId = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const commandCanary = 'CANARY-private-guest-command', outputCanary = 'CANARY-unregistered-guest-output'
const argv = ['/usr/bin/printf', '%s', commandCanary]

test('confirmed guest execution and consuming status keep commands and results private', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-guest-exec-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', sequence = 700, mode = 'success', argvText = JSON.stringify(argv)
  const launched: string[][] = [], consumed: number[] = [], processes = new Set<number>(), requests: string[] = []
  const start = (values: string[]) => {
    assert.deepEqual(values, argv)
    launched.push(values)
    const pid = ++sequence
    processes.add(pid)
    return { pid }
  }
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), path = url.pathname
    requests.push(`${request.method} ${request.url}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (path.endsWith('/exec-status')) {
      assert.equal(request.method, 'GET')
      const pid = Number(url.searchParams.get('pid'))
      assert.equal(processes.has(pid), true)
      consumed.push(pid)
      if (mode === 'running') { response.end(JSON.stringify({ data: { exited: 0 } })); return }
      processes.delete(pid)
      response.end(JSON.stringify({ data: mode === 'malformed' ? { exited: outputCanary } : {
        exited: 1, exitcode: mode === 'nonzero' ? 7 : 0, 'out-data': outputCanary, 'err-data': `${outputCanary}-stderr`, 'out-truncated': 0, 'err-truncated': 1,
      } })); return
    }
    assert.equal(request.method, 'POST')
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const values = new URLSearchParams(Buffer.concat(chunks).toString())
    if (path.endsWith('/execute')) {
      const commands = JSON.parse(values.get('commands')!) as { method: string, path: string, args: { command: string[] } }[]
      assert.equal(commands.length, 1)
      assert.equal(commands[0]!.method, 'POST')
      assert.equal(commands[0]!.path, 'qemu/100/agent/exec')
      response.end(JSON.stringify({ data: [{ status: 200, data: start(commands[0]!.args.command) }] })); return
    }
    assert.equal(path, '/api2/json/nodes/node-a/qemu/100/agent/exec')
    assert.equal(values.has('input-data'), false)
    const data = start(values.getAll('command'))
    if (mode === 'server-error') { response.writeHead(500).end(JSON.stringify({ message: `Execution failed: ${commandCanary} ${outputCanary}` })); return }
    response.end(JSON.stringify({ data }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin, caBundle: caFile, tokenId: 'synthetic@pve!test', token: { env: 'EXEC_TOKEN' },
    writes: { operations: [operationId('POST', launch), operationId('GET', status), operationId('POST', batch)] },
  } } }), { mode: 0o600 })
  const command = async (verb: string, path: string, api: Record<string, unknown>, flags: string[] = [], privateResult = false, extraEnv: Record<string, string> = {}) => {
    const body = join(scratch, 'request.json')
    await writeFile(body, JSON.stringify(api), { mode: 0o600 })
    const child = spawn(process.execPath, [executable, verb, path, '--body-file', body, ...flags, '--config', config, '--format', 'json'], {
      env: { ...environment, EXEC_TOKEN: 'synthetic-token', VM_ARGV_JSON: argvText, PROXMOX_AXI_WRITE_LOG: log,
        PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '', ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', bytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { bytes = Buffer.concat([bytes, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    for (const canary of [commandCanary, outputCanary]) assert.equal((stdout + stderr).includes(canary), false)
    if (bytes.length) assert.equal(bytes.readUInt32BE(0), bytes.length - 4)
    return { code, value: JSON.parse(stdout), frame: bytes.length ? JSON.parse(bytes.subarray(4).toString()) : undefined }
  }
  const target = { node: 'node-a', vmid: 100 }, input = { ...target, command: { env: 'VM_ARGV_JSON' } }
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    await t.test(`${release.name} status requires confirmation even though its method is GET`, async () => {
      const reads = consumed.length
      const result = await command('get', status, { ...target, pid: 700 }, [], true)
      assert.equal(result.value.error.code, 'CONFIRMATION_REQUIRED')
      assert.equal(consumed.length, reads)
    })
    await t.test(`${release.name} confirms launch and separate consuming status with private PID and output`, async () => {
      const count = launched.length, reads = consumed.length
      const preview = await command('create', launch, input, ['--preview'])
      assert.equal(preview.code, 0)
      assert.equal(launched.length, count)
      const confirmation = preview.value.confirmation
      argvText = JSON.stringify(['/usr/bin/id', commandCanary])
      const changed = await command('create', launch, input, ['--confirm', confirmation], true)
      assert.equal(changed.value.error.code, 'CONFIRMATION_MISMATCH')
      argvText = JSON.stringify(argv)
      const otherGuest = await command('create', launch, { ...input, vmid: 101 }, ['--confirm', confirmation], true)
      assert.equal(otherGuest.value.error.code, 'CONFIRMATION_MISMATCH')
      requests.length = 0
      const missing = await command('create', launch, input, ['--confirm', confirmation])
      assert.equal(missing.value.error.code, 'PRIVATE_SINK_REQUIRED')
      assert.equal(requests.length, 0)
      const result = await command('create', launch, input, ['--confirm', confirmation], true)
      assert.equal(result.code, 0)
      assert.equal(result.value.status, 'success')
      assert.equal(result.value.pid, undefined)
      assert.deepEqual(result.frame.payload, { pid: sequence })
      assert.equal(result.frame.binding.request, createHash('sha256').update(confirmation.split('.')[1]).digest('hex'))
      assert.equal(result.frame.binding.operation, operationId('POST', launch))
      assert.equal(launched.length, count + 1)
      const statusInput = { ...target, pid: sequence }
      mode = 'running'
      const pending = await command('get', status, statusInput, ['--preview'])
      assert.equal(consumed.length, reads)
      const changedPid = await command('get', status, { ...statusInput, pid: sequence + 1 }, ['--confirm', pending.value.confirmation], true)
      assert.equal(changedPid.value.error.code, 'CONFIRMATION_MISMATCH')
      const running = await command('get', status, statusInput, ['--confirm', pending.value.confirmation], true)
      assert.deepEqual(running.frame.payload, { exited: 0 })
      assert.equal(processes.has(statusInput.pid), true)
      mode = 'success'
      const donePreview = await command('get', status, statusInput, ['--preview'])
      const done = await command('get', status, statusInput, ['--confirm', donePreview.value.confirmation], true)
      assert.equal(done.code, 0)
      assert.equal(done.frame.binding.request, createHash('sha256').update(donePreview.value.confirmation.split('.')[1]).digest('hex'))
      assert.deepEqual(done.frame.payload, { exited: 1, exitcode: 0, 'out-data': outputCanary, 'err-data': `${outputCanary}-stderr`, 'out-truncated': 0, 'err-truncated': 1 })
      assert.equal(processes.has(statusInput.pid), false)
      const replay = await command('get', status, statusInput, ['--confirm', donePreview.value.confirmation], true)
      assert.equal(replay.value.error.code, 'CONFIRMATION_USED')
      assert.equal(consumed.length, reads + 2)
    })
    await t.test(`${release.name} retains a nonzero guest exit privately rather than claiming process success`, async () => {
      const preview = await command('create', launch, input, ['--preview'])
      const result = await command('create', launch, input, ['--confirm', preview.value.confirmation], true)
      const statusInput = { ...target, pid: result.frame.payload.pid }
      const check = await command('get', status, statusInput, ['--preview'])
      mode = 'nonzero'
      const done = await command('get', status, statusInput, ['--confirm', check.value.confirmation], true)
      assert.equal(done.frame.payload.exitcode, 7)
      assert.equal(done.frame.payload.exited, 1)
      assert.equal(done.frame.payload['err-data'], `${outputCanary}-stderr`)
      mode = 'success'
    })
    await t.test(`${release.name} records uncertain launch on provider failure without retry`, async () => {
      const preview = await command('create', launch, input, ['--preview']), before = launched.length
      mode = 'server-error'
      const result = await command('create', launch, input, ['--confirm', preview.value.confirmation], true)
      assert.equal(launched.length, before + 1)
      assert.equal(result.value.error.code, 'WRITE_UNCERTAIN')
      const saved = JSON.parse(await readFile(join(`${log}.d`, `${preview.value.id}.json`), 'utf8'))
      assert.equal(saved.status, 'uncertain')
      mode = 'success'
    })
    await t.test(`${release.name} malformed consumed output remains uncertain without retry`, async () => {
      const preview = await command('create', launch, input, ['--preview'])
      const result = await command('create', launch, input, ['--confirm', preview.value.confirmation], true)
      const statusInput = { ...target, pid: result.frame.payload.pid }
      const check = await command('get', status, statusInput, ['--preview']), reads = consumed.length
      mode = 'malformed'
      const failed = await command('get', status, statusInput, ['--confirm', check.value.confirmation], true)
      assert.equal(failed.value.error.code, 'WRITE_UNCERTAIN')
      assert.equal(failed.frame, undefined)
      assert.equal(consumed.length, reads + 1)
      assert.equal(processes.has(statusInput.pid), false)
      const saved = JSON.parse(await readFile(join(`${log}.d`, `${check.value.id}.json`), 'utf8'))
      assert.equal(saved.status, 'uncertain')
      mode = 'success'
    })
    await t.test(`${release.name} confirmed batch keeps resolved argv and returned PID private`, async () => {
      const api = { node: target.node, commands: JSON.stringify([{ method: 'POST', path: 'qemu/100/agent/exec', args: { command: input.command } }]) }
      const preview = await command('create', batch, api, ['--preview'])
      const result = await command('create', batch, api, ['--confirm', preview.value.confirmation], true)
      assert.equal(result.code, 0)
      assert.deepEqual(result.frame.payload, [{ status: 200, data: { pid: sequence } }])
      assert.equal(result.value.children[0].status, 'success')
    })
    for (const invalid of [
      { name: 'malformed JSON', value: 'not JSON' }, { name: 'empty array', value: '[]' }, { name: 'empty program', value: '[""]' },
      { name: 'empty argument', value: JSON.stringify(['/usr/bin/id', '']) },
      { name: 'non-string argument', value: JSON.stringify(['/usr/bin/id', 7]) }, { name: 'control character', value: JSON.stringify(['/usr/bin/id', 'line\nbreak']) },
    ]) {
      await t.test(`${release.name} refuses referenced argv with ${invalid.name}`, async () => {
        argvText = invalid.value; requests.length = 0
        const result = await command('create', launch, input, ['--preview'])
        assert.equal(result.value.error.code, 'INVALID_INPUT')
        assert.equal(requests.length, 0)
        argvText = JSON.stringify(argv)
      })
    }
  }
  await t.test('exec resolves JSON argv from a protected file SecretRef', async () => {
    const source = join(scratch, 'argv.json')
    await writeFile(source, `${JSON.stringify(argv)}\n`, { mode: 0o600 })
    const api = { ...target, command: { file: source } }
    const preview = await command('create', launch, api, ['--preview'])
    const result = await command('create', launch, api, ['--confirm', preview.value.confirmation], true)
    assert.equal(result.code, 0)
    assert.deepEqual(result.frame.payload, { pid: sequence })
  })
  await t.test('exec bounds referenced JSON before provider access', async () => {
    argvText = `${' '.repeat(65536)}${JSON.stringify(argv)}`; requests.length = 0
    const result = await command('create', launch, input, ['--preview'])
    assert.equal(result.value.error.code, 'INVALID_INPUT')
    assert.equal(requests.length, 0)
    argvText = JSON.stringify(argv)
  })
  for (const invalid of [
    { name: 'literal argv', api: { ...input, command: argv }, code: 'INVALID_INPUT' },
    { name: 'unreviewed stdin', api: { ...input, 'input-data': 'refused stdin' }, code: 'CONTRACT_UNRESOLVED' },
  ]) await t.test(`exec refuses ${invalid.name} before provider access`, async () => {
    requests.length = 0
    const result = await command('create', launch, invalid.api, ['--preview'])
    assert.equal(result.value.error.code, invalid.code)
    assert.equal(requests.length, 0)
  })
  for (const extraEnv of [{ PROXMOX_AXI_READ_ONLY: '1' }, { PROXMOX_AXI_ACTOR: 'fixture', PROXMOX_AXI_HOST_OPERATIONS: '[]' }]) {
    for (const [verb, path, api] of [['create', launch, input], ['get', status, { ...target, pid: 700 }]] as const) {
      requests.length = 0
      const result = await command(verb, path, api, ['--preview'], false, extraEnv)
      assert.equal(result.value.error.code, 'WRITE_DISABLED')
      assert.equal(requests.length, 0)
    }
  }
  for (const release of ['legacy-8.2.7', 'published-current']) {
    const schemaChild = spawn(process.execPath, [executable, 'schema', 'create', launch, '--catalogue', release, '--format', 'json'], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
    let schemaText = ''
    schemaChild.stdout.on('data', chunk => { schemaText += chunk.toString() })
    await new Promise<void>(resolve => schemaChild.once('close', () => resolve()))
    const validate = new Ajv({ strict: false }).compile(JSON.parse(schemaText).invocation.schema)
    assert.equal(validate({ api: input }), true)
    assert.equal(validate({ api: { ...input, command: argv } }), false)
  }
  for (const name of (await readdir(`${log}.d`)).filter(name => name.endsWith('.json'))) {
    const retained = await readFile(join(`${log}.d`, name), 'utf8')
    for (const canary of [commandCanary, outputCanary, '/usr/bin/printf']) assert.equal(retained.includes(canary), false)
  }
})

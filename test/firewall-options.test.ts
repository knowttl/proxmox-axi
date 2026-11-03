import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { Ajv } from 'ajv'

const execute = promisify(execFile)
const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const id = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const scopes = [
  { name: 'cluster', path: '/cluster/firewall/options', target: {}, defaults: { policy_in: 'DROP', policy_out: 'DROP', policy_forward: 'DROP' } },
  { name: 'node', path: '/nodes/{node}/firewall/options', target: { node: 'node-a' }, defaults: {} },
  ...['qemu', 'lxc'].map(name => ({ name, path: `/nodes/{node}/${name}/{vmid}/firewall/options`, target: { node: 'node-a', vmid: 100 }, defaults: { policy_in: 'DROP', policy_out: 'DROP' } })),
]
const batch = '/nodes/{node}/execute', digest = '0123456789012345678901234567890123456789', canary = 'CANARY-unreviewed-firewall-data'

test('firewall options retain scoped confirmation and expose protection warnings', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-firewall-options-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', mode = 'success', revision = 1
  const states = new Map<string, Record<string, unknown>>()
  const requests: string[] = [], writes: { path: string, inputs: Record<string, unknown> }[] = []
  const wire = (path: string) => `/api2/json${path.replace('{node}', 'node-a').replace('{vmid}', '100')}`
  const apply = (path: string, inputs: Record<string, unknown>) => {
    const state = states.get(path)!
    writes.push({ path, inputs })
    if (inputs.digest !== undefined && inputs.digest !== state.digest) return false
    Object.assign(state, inputs, { ...(inputs.enable !== undefined ? { enable: Number(inputs.enable) } : {}), digest: (++revision).toString(16).padStart(40, '0') })
    return true
  }
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const path = new URL(request.url!, 'https://fake.invalid').pathname
    requests.push(`${request.method} ${path}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (request.method === 'GET') {
      assert.equal(states.has(path), true)
      response.end(JSON.stringify({ data: mode === 'malformed' ? { enable: 'invalid' } : { ...states.get(path), unreviewed: canary } })); return
    }
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const inputs = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))
    if (path.endsWith('/execute')) {
      assert.equal(request.method, 'POST')
      const [child] = JSON.parse(inputs.commands!) as { method: string, path: string, args: Record<string, unknown> }[]
      assert.equal(child!.method, 'PUT')
      assert.equal(child!.path, 'qemu/100/firewall/options')
      assert.equal(apply(wire(scopes[2]!.path), child!.args), true)
      response.end(JSON.stringify({ data: [{ status: 200, data: null }] })); return
    }
    assert.equal(request.method, 'PUT')
    assert.equal(states.has(path), true)
    if (!apply(path, inputs)) { response.writeHead(400).end(JSON.stringify({ message: 'configuration digest mismatch' })); return }
    if (mode === 'uncertain') { response.writeHead(500).end(JSON.stringify({ message: 'delivery uncertain' })); return }
    response.end(JSON.stringify({ data: null }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!firewall', token: { env: 'FIREWALL_TOKEN' },
    writes: { operations: [...scopes.map(scope => id('PUT', scope.path)), id('POST', batch)] },
  } } }), { mode: 0o600 })
  const command = async (verb: string, path: string, api: Record<string, unknown>, flags: string[] = [], extraEnv: Record<string, string> = {}) => {
    const body = join(scratch, 'request.json')
    await writeFile(body, JSON.stringify(api), { mode: 0o600 })
    const result = await execute(process.execPath, [executable, verb, path, '--body-file', body, ...flags, '--config', config, '--format', 'json'], {
      env: { ...environment, FIREWALL_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: log, ...extraEnv }, timeout: 15000,
    }).catch((error: { code: number, stdout: string, stderr: string }) => error)
    assert.equal(result.stderr, '')
    assert.equal((result.stdout + result.stderr).includes(canary), false)
    return { code: 'code' in result ? result.code : 0, value: JSON.parse(result.stdout) }
  }
  const retained = async (intent: string) => JSON.parse(await readFile(join(`${log}.d`, `${intent}.json`), 'utf8'))
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    for (const scope of scopes) {
      const path = wire(scope.path), settings = Object.fromEntries(Object.keys(scope.defaults).map(key => [key, 'ACCEPT']))
      states.set(path, { enable: 1, ...scope.defaults, digest })
      await t.test(`${release.name} ${scope.name} option reads project only reviewed fields`, async () => {
        const result = await command('get', scope.path, scope.target, ['--full'])
        assert.equal(result.code, 0)
        assert.deepEqual(result.value.data, { enable: 1, ...scope.defaults, digest })
        mode = 'malformed'
        const invalid = await command('get', scope.path, scope.target)
        assert.equal(invalid.value.error.code, 'INVALID_RESPONSE')
        mode = 'success'
      })
      await t.test(`${release.name} ${scope.name} warns and confirms disabling protection and ACCEPT defaults`, async () => {
        const api = { ...scope.target, enable: scope.name === 'cluster' ? 0 : false, ...settings, digest }, before = writes.length
        const missing = await command('set', scope.path, api)
        assert.equal(missing.value.error.code, 'CONFIRMATION_REQUIRED')
        const preview = await command('set', scope.path, api, ['--preview'])
        assert.equal(preview.code, 0)
        assert.equal(writes.length, before)
        assert.equal(preview.value.warnings[0].target, path)
        assert.match(preview.value.warnings[0].messages.join(' '), /cut off management access/)
        assert.match(preview.value.warnings[0].messages.join(' '), /FIREWALL PROTECTION DISABLED/)
        for (const input of Object.keys(settings)) assert.ok(preview.value.warnings[0].messages.some((message: string) => message.includes(`DEFAULT ACCEPT: ${input}`)))
        for (const changed of [{ ...api, enable: scope.name === 'cluster' ? 1 : true }, { ...api, digest: 'changed' },
          ...Object.keys(settings).map(key => ({ ...api, [key]: 'DROP' })), ...('vmid' in scope.target ? [{ ...api, vmid: 101 }] : [])]) {
          const refused = await command('set', scope.path, changed, ['--confirm', preview.value.confirmation])
          assert.equal(refused.value.error.code, 'CONFIRMATION_MISMATCH')
        }
        const other = scope.name === 'cluster' ? scopes[1]! : scopes[0]!
        const wrongScope = await command('set', other.path, { ...other.target, enable: other.name === 'cluster' ? 0 : false, digest }, ['--confirm', preview.value.confirmation])
        assert.equal(wrongScope.value.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(writes.length, before)
        const result = await command('set', scope.path, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.code, 0)
        assert.equal(result.value.status, 'success')
        assert.equal(result.value.upid, undefined)
        assert.deepEqual(writes.slice(before), [{ path, inputs: { enable: '0', ...settings, digest } }])
        const observed = await command('get', scope.path, scope.target)
        assert.equal(observed.value.data.enable, 0)
        for (const key of Object.keys(settings)) assert.equal(observed.value.data[key], 'ACCEPT')
        assert.notEqual(observed.value.data.digest, digest)
        assert.equal((await retained(preview.value.id)).status, 'success')
        const replay = await command('set', scope.path, api, ['--confirm', preview.value.confirmation])
        assert.equal(replay.value.error.code, 'CONFIRMATION_USED')
        assert.equal(writes.length, before + 1)
      })
      await t.test(`${release.name} ${scope.name} provider digest conflict retains failure`, async () => {
        const current = await command('get', scope.path, scope.target)
        const api = { ...scope.target, enable: scope.name === 'cluster' ? 1 : true, digest: current.value.data.digest }, before = writes.length
        const preview = await command('set', scope.path, api, ['--preview'])
        assert.equal(preview.value.warnings[0].messages.length, 1)
        states.get(path)!.digest = 'concurrent-change'
        const result = await command('set', scope.path, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.code, 1)
        assert.equal((await retained(preview.value.id)).status, 'failed')
        const observed = await command('get', scope.path, scope.target)
        assert.equal(observed.value.data.enable, 0)
        assert.equal(writes.length, before + 1)
      })
    }
    await t.test(`${release.name} uncertain firewall delivery is not repeated`, async () => {
      const scope = scopes[2]!, api = { ...scope.target, enable: false }, before = writes.length
      const preview = await command('set', scope.path, api, ['--preview'])
      assert.match(preview.value.warnings[0].messages.join(' '), /FIREWALL PROTECTION DISABLED/)
      mode = 'uncertain'
      const result = await command('set', scope.path, api, ['--confirm', preview.value.confirmation])
      mode = 'success'
      assert.equal(result.value.error.code, 'WRITE_UNCERTAIN')
      assert.equal((await retained(preview.value.id)).status, 'uncertain')
      const replay = await command('set', scope.path, api, ['--confirm', preview.value.confirmation])
      assert.equal(replay.value.error.code, 'CONFIRMATION_USED')
      assert.equal(writes.length, before + 1)
    })
    await t.test(`${release.name} batch preview exposes child protection warnings before confirmation`, async () => {
      const api = { node: 'node-a', commands: JSON.stringify([{ method: 'PUT', path: 'qemu/100/firewall/options', args: { enable: false, policy_in: 'ACCEPT' } }]) }
      const before = writes.length, preview = await command('create', batch, api, ['--preview'])
      assert.equal(preview.value.warnings[0].target, wire(scopes[2]!.path))
      assert.match(preview.value.warnings[0].messages.join(' '), /FIREWALL PROTECTION DISABLED.*DEFAULT ACCEPT: policy_in/)
      assert.equal(writes.length, before)
      const result = await command('create', batch, api, ['--confirm', preview.value.confirmation])
      assert.equal(result.code, 0)
      assert.equal(result.value.children[0].status, 'success')
      const observed = await command('get', scopes[2]!.path, scopes[2]!.target)
      assert.equal(observed.value.data.enable, 0)
      assert.equal(observed.value.data.policy_in, 'ACCEPT')
      assert.equal(writes.length, before + 1)
    })
    for (const [scope, fields, code] of [
      [scopes[0]!, { enable: 2 }, 'INVALID_INPUT'], [scopes[0]!, { ebtables: 0 }, 'CONTRACT_UNRESOLVED'],
      [scopes[1]!, { nftables: 1 }, 'CONTRACT_UNRESOLVED'], [scopes[1]!, { policy_in: 'DROP' }, 'CONTRACT_UNRESOLVED'],
      [scopes[2]!, { ipfilter: 0 }, 'CONTRACT_UNRESOLVED'], [scopes[3]!, { delete: 'enable' }, 'CONTRACT_UNRESOLVED'],
    ] as const) await t.test(`${release.name} refuses ${scope.name} ${Object.keys(fields)[0]} outside the reviewed branch`, async () => {
      const before = requests.length
      const refused = await command('set', scope.path, { ...scope.target, ...fields }, ['--preview'])
      assert.equal(refused.value.error.code, code)
      assert.equal(requests.length, before)
    })
    for (const extraEnv of [{ PROXMOX_AXI_READ_ONLY: '1' }, { PROXMOX_AXI_ACTOR: 'fixture', PROXMOX_AXI_HOST_OPERATIONS: '[]' }]) {
      const before = requests.length
      const refused = await command('set', scopes[2]!.path, { ...scopes[2]!.target, enable: true }, ['--preview'], extraEnv)
      assert.equal(refused.value.error.code, 'WRITE_DISABLED')
      assert.equal(requests.length, before)
    }
    for (const verb of ['get', 'set']) {
      const before = requests.length
      const refused = await command(verb, '/cluster/sdn/vnets/{vnet}/firewall/options', { vnet: 'net-a' }, verb === 'set' ? ['--preview'] : [])
      assert.equal(refused.value.error.code, 'CONTRACT_UNRESOLVED')
      assert.equal(requests.length, before)
    }
    await t.test(`${release.name} executable schema narrows cluster enable to zero or one`, async () => {
      const schema = await execute(process.execPath, [executable, 'schema', 'set', scopes[0]!.path, '--catalogue', release.name, '--format', 'json'], { env: environment })
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      assert.equal(validate({ api: { enable: 0 } }), true)
      assert.equal(validate({ api: { enable: 1 } }), true)
      assert.equal(validate({ api: { enable: 2 } }), false)
      assert.equal(validate({ api: { enable: 1, ebtables: 0 } }), false)
    })
  }
  for (const name of (await readdir(`${log}.d`)).filter(name => name.endsWith('.json'))) assert.equal((await readFile(join(`${log}.d`, name), 'utf8')).includes(canary), false)
})

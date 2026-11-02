import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Readable } from 'node:stream'
import { promisify } from 'node:util'
import test from 'node:test'

const execute = promisify(execFile)
const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const hash = (value: string) => createHash('sha256').update(value).digest('hex')
const configPath = (family: string) => `/nodes/{node}/${family}/{vmid}/config`
const canary = 'CANARY-private-guest-credential'
const digest = '0123456789012345678901234567890123456789'
const releases = [{ release: 'legacy-8.2.7', version: '8.2.7' }, { release: 'published-current', version: '9.2.1' }]
const guests = [
  { family: 'qemu', initial: { digest, memory: '512', cipassword: canary }, settings: {
    cores: 4, sockets: 2, vcpus: 6, memory: 'current=2048', balloon: 1024, cpu: 'cputype=x86-64-v2-AES',
    cpulimit: 2.5, cpuunits: 100, onboot: 1, startup: 'order=2,up=10,down=15', name: 'guest-01', description: 'managed guest',
  } },
  { family: 'lxc', initial: { digest, memory: 512, password: canary }, settings: {
    cores: 2, memory: 2048, swap: 512, cpulimit: 1.5, cpuunits: 200, onboot: 1,
    startup: 'up=10,down=15', hostname: 'container-01', description: 'managed container',
  } },
]

test('guest settings use private reads and confirmed compute writes', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-guest-settings-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(scratch, 'server.key'), '-out', caFile])
  await chmod(caFile, 0o600)
  let version = '8.2.7', malformed = false
  const requests: { method: string, path: string }[] = []
  const state: Record<string, Record<string, unknown>> = Object.fromEntries(guests.map(guest => [guest.family, { ...guest.initial }]))
  const server = createServer({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) }, async (request, response) => {
    requests.push({ method: request.method!, path: request.url! })
    const family = request.url!.includes('/lxc/') ? 'lxc' : 'qemu'
    if (request.method === 'PUT') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      for (const [name, value] of new URLSearchParams(Buffer.concat(chunks).toString())) state[family]![name] =
        ['cores', 'sockets', 'vcpus', 'balloon', 'swap', 'cpulimit', 'cpuunits', 'onboot'].includes(name) || (name === 'memory' && family === 'lxc') ? Number(value) : value
      response.end(JSON.stringify({ data: null }))
      return
    }
    const data = request.url!.endsWith('/version') ? { version, release: 'synthetic', repoid: 'synthetic' } :
      request.url!.endsWith('/config') ? malformed ? { digest: 123, password: canary } : state[family] :
      request.url!.endsWith('/pending') ? [{ key: malformed ? 123 : 'cipassword', value: canary, pending: `${canary}-pending` }] :
      { ha: {}, status: 'running', vmid: malformed ? '100' : 100, cpus: 2, maxmem: 536870912 }
    response.end(JSON.stringify({ data }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`
  const config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin, tokenId: 'synthetic@pve!test', token: { env: 'GUEST_SETTINGS_TOKEN' }, caBundle: caFile,
    writes: { operations: ['qemu', 'lxc'].map(family => `OP-PUT-${hash(`PUT ${configPath(family)}`).slice(0, 10)}`) },
  } } }), { mode: 0o600 })
  const command = async (args: string[], privateResult = false) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, GUEST_SETTINGS_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: log, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' },
      stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', bytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { bytes = Buffer.concat([bytes, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    let frame: { binding: Record<string, string>, payload: unknown } | undefined
    if (bytes.length) {
      assert.equal(bytes.readUInt32BE(0), bytes.length - 4)
      frame = JSON.parse(bytes.subarray(4).toString()) as typeof frame
    }
    return { code, stdout, stderr, frame }
  }
  const target = ['--api-node', 'node-a', '--api-vmid', '100']
  for (const contract of releases) for (const family of ['qemu', 'lxc']) {
    const { release } = contract
    version = contract.version
    for (const { suffix, expected } of [
      { suffix: 'config', expected: state[family] },
      { suffix: 'pending', expected: [{ key: 'cipassword', value: canary, pending: `${canary}-pending` }] },
    ]) {
      const path = `/nodes/{node}/${family}/{vmid}/${suffix}`
      await t.test(`${release} ${family} ${suffix} requires a private pipe before network access`, async () => {
        requests.length = 0
        const result = await command(['get', path, ...target])
        assert.equal(result.code, 1, result.stderr)
        assert.equal(JSON.parse(result.stdout).error.code, 'PRIVATE_SINK_REQUIRED')
        assert.deepEqual(requests, [])
      })
      await t.test(`${release} ${family} ${suffix} delivers protected values only privately`, async () => {
        const result = await command(['get', path, ...target, '--catalogue', release, '--full'], true)
        assert.equal(result.code, 0, result.stderr)
        assert.deepEqual(JSON.parse(result.stdout).data, { privateResult: true })
        assert.doesNotMatch(result.stdout + result.stderr, /CANARY-private-guest-credential/)
        assert.deepEqual(result.frame?.payload, expected)
        assert.equal(result.frame?.binding.origin, origin)
        assert.equal(result.frame?.binding.identity, 'synthetic@pve!test')
        assert.equal(result.frame?.binding.operation, `OP-GET-${hash(`GET ${path}`).slice(0, 10)}`)
        assert.equal(result.frame?.binding.request, hash(`${release} /api2/json/nodes/node-a/${family}/100/${suffix}`))
      })
      await t.test(`${release} ${family} ${suffix} rejects malformed protected responses without delivery`, async () => {
        malformed = true
        const result = await command(['get', path, ...target, '--catalogue', release], true)
        malformed = false
        assert.equal(result.code, 1, result.stderr)
        assert.equal(JSON.parse(result.stdout).error.code, 'INVALID_RESPONSE')
        assert.equal(result.frame, undefined)
        assert.doesNotMatch(result.stdout + result.stderr, /CANARY-private-guest-credential/)
      })
    }
    await t.test(`${release} ${family} status is an ordinary bounded read`, async () => {
      const result = await command(['get', `/nodes/{node}/${family}/{vmid}/status/current`, ...target])
      assert.equal(result.code, 0, result.stderr)
      assert.deepEqual(JSON.parse(result.stdout).data, { ha: {}, status: 'running', vmid: 100, cpus: 2, maxmem: 536870912 })
      assert.equal(JSON.parse(result.stdout).compatibility.catalogue, release)
    })
  }
  await assert.rejects(readdir(`${log}.d`), { code: 'ENOENT' })
  for (const contract of releases) for (const { family, initial, settings } of guests) {
    const { release } = contract
    version = contract.version
    await t.test(`${release} ${family} compute settings change only after exact confirmation`, async () => {
      state[family] = { ...initial }
      const before = { ...initial }
      const args = ['set', configPath(family), ...target, '--api-digest', digest,
        ...Object.entries(settings).flatMap(([name, value]) => [`--api-${name}`, String(value)])]
      requests.length = 0
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0, preview.stdout + preview.stderr)
      assert.equal(JSON.parse(preview.stdout).status, 'preview')
      assert.deepEqual(state[family], before)
      assert.ok(requests.every(request => request.method === 'GET'))
      const result = await command([...args, '--confirm', JSON.parse(preview.stdout).confirmation])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).status, 'success')
      const observed = await command(['get', configPath(family), ...target], true)
      assert.equal(observed.code, 0, observed.stderr)
      assert.deepEqual(observed.frame?.payload, { ...before, ...settings })
      assert.doesNotMatch(observed.stdout + observed.stderr, /CANARY-private-guest-credential/)
    })
  }
  const refusals: [string, string, string, string, number][] = [
    ['qemu', 'cpu', 'host', 'INVALID_INPUT', 2], ['qemu', 'cpu', 'qemu64,flags=+aes', 'INVALID_INPUT', 2],
    ['qemu', 'memory', '15', 'INVALID_INPUT', 2], ['lxc', 'memory', '15', 'INVALID_INPUT', 2],
    ['qemu', 'startup', 'order=1,up=2,up=3', 'INVALID_INPUT', 2], ['lxc', 'startup', 'order=1,hookscript=x', 'INVALID_INPUT', 2],
    ['qemu', 'name', 'bad/name', 'INVALID_INPUT', 2], ['qemu', 'hookscript', 'local:snippets/script', 'CONTRACT_UNRESOLVED', 1],
    ['qemu', 'hostpci0', '0000:00:00.0', 'INVALID_INPUT', 2],
  ]
  for (const [family, field, value, error, exit] of refusals) {
    await t.test(`${family} rejects unreviewed ${field} value ${value} before network access`, async () => {
      requests.length = 0
      const result = await command(['set', configPath(family), ...target, `--api-${field}`, value, '--preview'])
      assert.equal(result.code, exit, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).error.code, error)
      assert.deepEqual(requests, [])
    })
  }
  await t.test('changing a reviewed compute value invalidates its confirmation', async () => {
    const before = { ...state.qemu }
    const args = ['set', configPath('qemu'), ...target, '--api-vcpus', '2']
    const preview = await command([...args, '--preview'])
    assert.equal(preview.code, 0, preview.stdout + preview.stderr)
    requests.length = 0
    const result = await command(['set', configPath('qemu'), ...target, '--api-vcpus', '3', '--confirm', JSON.parse(preview.stdout).confirmation])
    assert.equal(result.code, 1, result.stderr)
    assert.equal(JSON.parse(result.stdout).error.code, 'CONFIRMATION_MISMATCH')
    assert.deepEqual(state.qemu, before)
    assert.ok(requests.every(request => request.method === 'GET'))
  })
})

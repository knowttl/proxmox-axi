import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

const execute = promisify(execFile)
const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const nodeStatus = {
  'boot-info': { mode: 'efi' }, cpu: 0.1, cpuinfo: { cores: 4, cpus: 8, model: 'synthetic', sockets: 1 },
  'current-kernel': { machine: 'x86_64', release: 'synthetic', sysname: 'Linux', version: 'synthetic' },
  loadavg: ['0.1', '0.2', '0.3'], memory: { available: 1024, free: 1024, total: 4096, used: 3072 },
  pveversion: 'synthetic', rootfs: { avail: 1024, free: 1024, total: 4096, used: 3072 },
}
const storageStatus = { active: 1, enabled: 1, type: 'dir', content: 'iso,vztmpl', avail: 1024, total: 4096, used: 3072 }
const upid = 'UPID:node-a:00000001:00000002:00000003:vzdump:100:synthetic@pve:'
const logPath = '/nodes/{node}/tasks/{upid}/log'
const logWire = `/api2/json/nodes/node-a/tasks/${encodeURIComponent(upid)}/log`
const logLines = [{ n: 1, t: 'first line' }, { n: 2, t: 'second line' }]

test('infrastructure discovery through named profiles', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-infrastructure-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  const tls = { key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }
  const requests: { profile: string, authorization: string | undefined, path: string }[] = []
  let permissions: Record<string, unknown> = { '/': { 'Sys.Audit': 1, 'Datastore.Audit': 1 } }
  let override: { path: string, status: number, data: unknown, total?: number } | undefined
  const profiles: Record<string, unknown> = {}
  for (const [name, version] of [['lab', '8.2.7'], ['secondary', '9.2.1']]) {
    const server = createServer(tls, (request, response) => {
      const path = request.url!
      requests.push({ profile: name!, authorization: request.headers.authorization, path })
      const data: Record<string, unknown> = {
        '/api2/json/version': { version, release: 'synthetic', repoid: 'synthetic' },
        '/api2/json/nodes/node-a/version': { version, release: 'synthetic', repoid: 'synthetic' },
        '/api2/json/access/permissions': permissions,
        '/api2/json/cluster/status': [{ id: 'cluster', name, type: 'cluster', quorate: 1, nodes: 1 },
          { id: 'node/node-a', name: 'node-a', type: 'node', online: 1 }],
        '/api2/json/cluster/nextid': 123,
        '/api2/json/cluster/nextid?vmid=123': 123,
        '/api2/json/nodes/node-a/status': nodeStatus,
        '/api2/json/storage': [{ storage: `${name}-store`, password: 'backend-secret-canary', server: 'private-backend' }],
        '/api2/json/nodes/node-a/storage/local/status': storageStatus,
        [logWire]: logLines,
        [`${logWire}?download=0`]: logLines,
      }
      if (path === `${logWire}?download=1`) response.end('first line\nsecond line\n')
      else if (override?.path === path) response.writeHead(override.status).end(JSON.stringify({ data: override.data,
        ...(override.total === undefined ? {} : { total: override.total }) }))
      else if (Object.hasOwn(data, path)) response.end(JSON.stringify({ data: data[path] }))
      else response.writeHead(404).end(JSON.stringify({ data: null }))
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
    profiles[name!] = { auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`,
      tokenId: `synthetic@pve!${name}`, token: { env: `INFRA_${name!.toUpperCase()}_TOKEN` }, caBundle: caFile }
  }
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles }), { mode: 0o600 })
  const env = { ...environment, INFRA_LAB_TOKEN: 'lab-secret', INFRA_SECONDARY_TOKEN: 'secondary-secret',
    PROXMOX_AXI_ORIGIN: 'https://competing.invalid', PROXMOX_AXI_TOKEN_ID: 'ignored@pve!ignored', PROXMOX_AXI_TOKEN: 'ignored-secret' }
  const command = async (args: string[]) => {
    try { return { code: 0, ...await execute(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], { env }) } }
    catch (error) {
      const result = error as { code: number, stdout: string, stderr: string }
      return { code: result.code, stdout: result.stdout, stderr: result.stderr }
    }
  }
  await t.test('profile listing does not resolve token references or contact either host', async () => {
    requests.length = 0
    const result = await execute(process.execPath, [executable, 'profile', 'list', '--config', config, '--format', 'json'],
      { env: { ...environment, INFRA_LAB_TOKEN: '', INFRA_SECONDARY_TOKEN: '' } })
    assert.deepEqual(JSON.parse(result.stdout), { count: 2, profiles: [{ name: 'lab', default: true }, { name: 'secondary', default: false }] })
    assert.deepEqual(requests, [])
  })
  await t.test('an unknown selected profile cannot fall back to another host', async () => {
    requests.length = 0
    const result = await command(['get', '/cluster/status', '--profile', 'missing'])
    assert.equal(result.code, 1, result.stdout + result.stderr)
    assert.equal(JSON.parse(result.stdout).error.code, 'PROFILE_NOT_FOUND')
    assert.deepEqual(requests, [])
  })
  for (const verb of ['get', 'ls']) for (const catalogue of [
    { name: 'detected', args: [] },
    { name: 'legacy-8.2.7', args: ['--catalogue', 'legacy-8.2.7'] },
    { name: 'published-current', args: ['--catalogue', 'published-current'] },
  ]) {
    await t.test(`#6 ${verb} refuses task-log download before HTTP in ${catalogue.name}`, async () => {
      requests.length = 0
      const result = await command([verb, logPath, '--api-node', 'node-a', '--api-upid', upid,
        '--api-download', 'true', ...catalogue.args, '--profile', 'lab'])
      assert.equal(result.code, 2, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).error.code, 'INVALID_INPUT')
      assert.deepEqual(requests, [])
    })
    await t.test(`#6 ${verb} preserves numbered logs with download=false in ${catalogue.name}`, async () => {
      const result = await command([verb, logPath, '--api-node', 'node-a', '--api-upid', upid,
        '--api-download', 'false', ...catalogue.args, '--profile', 'lab'])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      assert.deepEqual(JSON.parse(result.stdout).data, logLines)
    })
  }
  for (const row of [
    { profile: 'lab', args: [], release: 'legacy-8.2.7' },
    { profile: 'secondary', args: [], release: 'published-current' },
    { profile: 'lab', args: ['--catalogue', 'published-current'], release: 'published-current' },
  ]) await t.test(`#7 ${row.profile} schema suggestion executes without credentials for ${row.release}`, async () => {
    const result = await command(['get', '/storage', '--profile', row.profile, ...row.args])
    assert.equal(result.code, 0, result.stdout + result.stderr)
    const args = (JSON.parse(result.stdout).help[0] as string).split(' ').slice(1)
    requests.length = 0
    const schema = await execute(process.execPath, [executable, ...args, '--format', 'json'], { env: environment })
    assert.equal(JSON.parse(schema.stdout).release, row.release)
    assert.deepEqual(requests, [])
  })
  for (const row of [
    { granted: true, total: 20, empty: 'empty-page', visibleTotal: 20, pagination: 'partial' },
    { granted: false, total: 20, empty: 'empty-page', visibleTotal: null, pagination: 'partial' },
    { granted: true, total: 0, empty: 'verified-empty', visibleTotal: 0, pagination: 'complete' },
    { granted: false, total: 0, empty: 'visibility-unverified', visibleTotal: null, pagination: 'complete' },
  ]) await t.test(`#8 empty task page with total=${row.total} and root audit=${row.granted}`, async () => {
    permissions = row.granted ? { '/': { 'Sys.Audit': 1, 'Datastore.Audit': 1 } } : {}
    override = { path: '/api2/json/nodes/node-a/tasks?start=20', status: 200, data: [], total: row.total }
    const result = await command(['get', '/nodes/{node}/tasks', '--api-node', 'node-a', '--api-start', '20', '--profile', 'lab'])
    assert.equal(result.code, 0, result.stdout + result.stderr)
    const value = JSON.parse(result.stdout)
    assert.equal(value.empty, row.empty)
    assert.equal(value.providerTotal, row.total)
    assert.equal(value.total, row.visibleTotal)
    assert.equal(value.providerPagination, row.pagination)
    assert.deepEqual(value.data, [])
    override = undefined
  })
  const routes = [
    { path: '/cluster/status', api: [], wire: '/api2/json/cluster/status', invalid: {},
      expected: (name: string) => [{ id: 'cluster', name, type: 'cluster', quorate: 1 }, { id: 'node/node-a', name: 'node-a', type: 'node', online: 1 }] },
    { path: '/cluster/nextid', api: ['--api-vmid', '123'], wire: '/api2/json/cluster/nextid?vmid=123', invalid: '123', expected: () => 123 },
    { path: '/nodes/{node}/status', api: ['--api-node', 'node-a'], wire: '/api2/json/nodes/node-a/status', invalid: { ...nodeStatus, memory: null }, expected: () => nodeStatus },
    { path: '/storage', api: [], wire: '/api2/json/storage', invalid: [{}], expected: (name: string) => [{ storage: `${name}-store` }] },
    { path: '/nodes/{node}/storage/{storage}/status', api: ['--api-node', 'node-a', '--api-storage', 'local'],
      wire: '/api2/json/nodes/node-a/storage/local/status', invalid: [], expected: () => storageStatus },
  ]
  for (const profile of ['lab', 'secondary']) for (const row of routes) {
    await t.test(`${profile} reads ${row.path} with its own credentials and contract`, async () => {
      requests.length = 0
      const result = await command(['get', row.path, ...row.api, '--profile', profile])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      const value = JSON.parse(result.stdout)
      assert.deepEqual(value.data, row.expected(profile))
      assert.equal(value.compatibility.catalogue, profile === 'lab' ? 'legacy-8.2.7' : 'published-current')
      assert.ok(requests.every(request => request.profile === profile && request.authorization === `PVEAPIToken=synthetic@pve!${profile}=${profile}-secret`))
    })
    await t.test(`${profile} rejects malformed ${row.path} responses`, async () => {
      override = { path: row.wire, status: 200, data: row.invalid }
      const result = await command(['get', row.path, ...row.api, '--profile', profile])
      assert.equal(result.code, 1, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).error.code, 'INVALID_RESPONSE')
      override = undefined
    })
  }
  for (const path of ['/storage', '/cluster/status']) for (const granted of [false, true]) {
    await t.test(`${path} distinguishes empty inventory with root audit=${granted}`, async () => {
      permissions = granted ? { '/': { 'Sys.Audit': 1, 'Datastore.Audit': 1 } } : {}
      override = { path: `/api2/json${path}`, status: 200, data: [] }
      const result = await command(['get', path, '--profile', 'lab'])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      const value = JSON.parse(result.stdout)
      assert.deepEqual(value.data, [])
      assert.equal(value.visibility, granted ? 'complete' : 'permission-filtered')
      assert.equal(value.empty, granted ? 'verified-empty' : 'visibility-unverified')
      override = undefined
    })
  }
  await t.test('storage full output excludes backend configuration during explicit replay', async () => {
    const result = await command(['get', '/storage', '--profile', 'secondary', '--catalogue', 'published-current', '--full'])
    assert.equal(result.code, 0, result.stdout + result.stderr)
    assert.deepEqual(JSON.parse(result.stdout).data, [{ storage: 'secondary-store' }])
    assert.equal(JSON.parse(result.stdout).visibility, 'unknown')
    assert.doesNotMatch(result.stdout + result.stderr, /backend-secret-canary|private-backend/)
  })
  for (const [status, error] of [[403, 'PERMISSION_DENIED'], [404, 'NOT_FOUND_OR_HIDDEN']] as const) {
    await t.test(`storage HTTP ${status} is a failure rather than empty inventory`, async () => {
      override = { path: '/api2/json/storage', status, data: null }
      const result = await command(['get', '/storage', '--profile', 'lab'])
      assert.equal(result.code, 1, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).error.code, error)
      override = undefined
    })
  }
  await t.test('task wait retains its observation when the final request times out before the clock advances', async t => {
    const root = new URL('../../', import.meta.url)
    const { taskOperation } = await import(new URL('dist/tasks.js', root).href) as typeof import('../src/tasks.js')
    const { PrivateResults } = await import(new URL('dist/private-results.js', root).href) as typeof import('../src/private-results.js')
    const upid = 'UPID:node-a:00000001:00000002:00000003:qmstart:100:synthetic@pve:'
    const status = { id: '100', node: 'node-a', pid: 1, pstart: 2, starttime: 3, status: 'running', type: 'qmstart', upid, user: 'synthetic@pve' }
    let clock = 0
    let observed = false
    const server = createServer(tls, (_request, response) => {
      if (!observed) {
        observed = true
        clock = 990
        response.end(JSON.stringify({ data: status }))
      }
      // The next read exhausts its remaining transport budget while the clock stays just before the deadline.
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const time = t.mock.method(performance, 'now', () => clock)
    try {
      const result = await taskOperation({ auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`,
        tokenId: 'synthetic@pve!test', token: 'synthetic-token', ca: tls.cert.toString(), results: new PrivateResults(), writeOperations: [],
        diagnostics: { profile: 'test', source: 'test', tokenSource: 'test' } }, 'wait', { node: 'node-a', upid }, 1000)
      const { status: processState, ...details } = status
      assert.ok('status' in result)
      assert.equal(result.status, 'running')
      assert.equal(result.wait, 'deadline-reached')
      assert.deepEqual(result.data, { processState, ...details })
    } finally {
      time.mock.restore()
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
  })
})

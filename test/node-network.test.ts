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

type Row = Record<string, unknown>
const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const path = '/nodes/{node}/network', item = `${path}/{iface}`, node = 'node-a'
const id = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const canary = 'CANARY-private-network-configuration'
const initial = (): Row[] => [
  { iface: 'eth0', type: 'eth', method: 'manual', active: 1, exists: 1 },
  { iface: 'bond0', type: 'bond', slaves: 'eth0', method: 'manual' },
  { iface: 'vmbr0', type: 'bridge', bridge_ports: 'bond0', method: 'static', cidr: '192.0.2.10/24', comments: canary },
  { iface: 'vmbr0.20', type: 'vlan', 'vlan-raw-device': 'vmbr0', 'vlan-id': '20', method: 'manual', method6: 'static', cidr6: '2001:db8::10/64' },
]
const mutations: { method: string, route: string, api: Row }[] = [
  ...['bridge', 'vlan', 'bond'].flatMap((type, index) => [
    { method: 'POST', route: path, api: { node, iface: ['vmbr7', 'vlan7', 'bond7'][index], type } },
    { method: 'PUT', route: item, api: { node, iface: ['vmbr0', 'vmbr0.20', 'bond0'][index], mtu: 1500 } },
    { method: 'DELETE', route: item, api: { node, iface: ['vmbr0', 'vmbr0.20', 'bond0'][index] } },
  ]),
  { method: 'PUT', route: path, api: { node } },
  { method: 'DELETE', route: path, api: { node } },
]
const grants = [...new Set([...mutations.map(({ method, route }) => id(method, route)), id('POST', '/nodes/{node}/execute')])]

test('private preferred network reads and local mutation refusals', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-node-network-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), journal = join(scratch, 'journal')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', pending = initial(), changes: unknown = null, total: number | undefined, unreadable = false
  const requests: string[] = []
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, (request, response) => {
    const route = new URL(request.url!, 'https://fake.invalid').pathname
    requests.push(`${request.method} ${route}`)
    if (route.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (request.method !== 'GET') { response.writeHead(500).end(JSON.stringify({ message: canary })); return }
    if (unreadable) { response.writeHead(403).end(JSON.stringify({ message: canary })); return }
    const iface = route.split('/')[6]
    response.end(JSON.stringify({ data: iface ? pending.find(row => row.iface === iface) : pending,
      ...(!iface && changes !== null ? { changes } : {}), ...(!iface && total !== undefined ? { total } : {}) }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!network', token: { env: 'NETWORK_TOKEN' }, writes: { operations: grants },
  } } }), { mode: 0o600 })
  const command = async (verb: string, route: string, api: Row, flags: string[] = [], privateResult = true) => {
    const body = join(scratch, 'request.json')
    await writeFile(body, JSON.stringify(api), { mode: 0o600 })
    const child = spawn(process.execPath, [executable, verb, route, '--body-file', body, ...flags, '--config', config, '--format', 'json'], {
      env: { ...environment, NETWORK_TOKEN: 'synthetic-token', PROXMOX_AXI_HOST_OPERATIONS: JSON.stringify(grants),
        PROXMOX_AXI_WRITE_LOG: journal, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' },
      stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', bytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { bytes = Buffer.concat([bytes, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal(stderr, '')
    assert.equal((stdout + stderr).includes(canary), false)
    if (bytes.length) assert.equal(bytes.readUInt32BE(0), bytes.length - 4)
    return { code, value: JSON.parse(stdout), payload: bytes.length ? JSON.parse(bytes.subarray(4).toString()).payload : undefined }
  }
  for (const [release, catalogue] of [['8.2.7', 'legacy-8.2.7'], ['9.2.1', 'published-current']] as const) {
    version = release
    const reset = () => { pending = initial(); changes = null; total = undefined; unreadable = false }
    await t.test(`${release} private reads retain preferred values, native pending diff and uncertainty`, async () => {
      reset()
      changes = `+# ${canary}`
      const read = await command('get', path, { node })
      assert.equal(read.code, 0, JSON.stringify(read.value))
      assert.deepEqual(read.value.data, { privateResult: true })
      assert.equal(read.payload.pendingDiff, changes)
      assert.equal(read.payload.activeConfiguration, 'unverified')
      assert.equal(read.payload.visibility, 'unknown')
      assert.deepEqual(read.payload.interfaces.map((row: Row) => row.iface), ['bond0', 'eth0', 'vmbr0', 'vmbr0.20'])
      const detail = await command('get', item, { node, iface: 'vmbr0' })
      assert.equal(detail.code, 0, JSON.stringify(detail.value))
      assert.equal(detail.payload.cidr, '192.0.2.10/24')
      assert.equal(detail.payload.comments, canary)
      assert.equal((await command('ls', path, { node })).payload.pendingDiff, changes)
      changes = null
      assert.equal((await command('get', path, { node })).payload.pendingDiff, null)
    })
    await t.test(`${release} native scalar strings normalize in collection and detail reads`, async () => {
      reset()
      const native = { mtu: '1500', netmask6: '64', 'vlan-id': '20', 'vxlan-id': '100', 'bridge-access': '20', ovs_tag: '30',
        'bridge-learning': 'on', 'bridge-arp-nd-suppress': 'off', 'bridge-unicast-flood': '1', 'bridge-multicast-flood': '0' }
      const expected = { mtu: 1500, netmask6: 64, 'vlan-id': 20, 'vxlan-id': 100, 'bridge-access': 20, ovs_tag: 30,
        'bridge-learning': 1, 'bridge-arp-nd-suppress': 0, 'bridge-unicast-flood': 1, 'bridge-multicast-flood': 0 }
      Object.assign(pending[0]!, native)
      const collection = await command('get', path, { node })
      assert.equal(collection.code, 0, JSON.stringify(collection.value))
      const detail = await command('get', item, { node, iface: 'eth0' })
      assert.equal(detail.code, 0, JSON.stringify(detail.value))
      for (const [name, value] of Object.entries(expected)) {
        assert.equal(collection.payload.interfaces.find((row: Row) => row.iface === 'eth0')[name], value)
        assert.equal(detail.payload[name], value)
      }
    })
    for (const [name, value] of [['mtu', '1500oops'], ['netmask6', '64.0'], ['vlan-id', ' 20'], ['vxlan-id', '1e2'],
      ['bridge-access', '9007199254740992'], ['ovs_tag', ''], ['bridge-learning', 'true'], ['bridge-arp-nd-suppress', '2'],
      ['bridge-unicast-flood', 'enabled'], ['bridge-multicast-flood', 'false']]) {
      await t.test(`${release} malformed native ${name} is refused in collection and detail reads`, async () => {
        reset()
        pending[0]![name!] = value
        for (const [route, api] of [[path, { node }], [item, { node, iface: 'eth0' }]] as const)
          assert.equal((await command('get', route, api)).value.error.code, 'INVALID_RESPONSE')
      })
    }
    for (const { method, route, api } of mutations) await t.test(`${release} refuses ${method} ${route} ${api.iface ?? 'apply/revert'} with grants`, async () => {
      reset()
      const count = requests.length
      const verb = { POST: 'create', PUT: 'set', DELETE: 'delete' }[method]!
      for (const action of [verb, method.toLowerCase()]) for (const flags of [['--preview'], ['--confirm', 'synthetic.confirmation']])
        assert.equal((await command(action, route, api, ['--catalogue', catalogue, ...flags])).value.error.code, 'CONTRACT_UNRESOLVED')
      const childPath = route === path ? 'network' : `network/${api.iface}`
      const { node: ignoredNode, iface: ignoredIface, ...args } = api
      assert.equal((await command('create', '/nodes/{node}/execute', { node,
        commands: JSON.stringify([{ method, path: childPath, args }]) }, ['--catalogue', catalogue, '--preview'])).value.error.code, 'WRITE_DISABLED')
      assert.equal(requests.length, count)
    })
    await t.test(`${release} private collection, detail and list reads require a sink before provider access`, async () => {
      reset()
      const count = requests.length
      for (const [verb, route, api] of [['get', path, { node }], ['get', item, { node, iface: 'vmbr0' }], ['ls', path, { node }]] as const)
        assert.equal((await command(verb, route, api, [], false)).value.error.code, 'PRIVATE_SINK_REQUIRED')
      assert.equal(requests.length, count)
    })
    for (const problem of ['diff', 'total', 'duplicate']) await t.test(`${release} malformed collection ${problem} is refused`, async () => {
      reset()
      if (problem === 'diff') changes = { unexpected: canary }
      if (problem === 'total') total = 99
      if (problem === 'duplicate') pending.push({ ...pending[0] })
      assert.equal((await command('get', path, { node })).value.error.code, 'INVALID_RESPONSE')
    })
    await t.test(`${release} unreadable configuration does not become an empty successful read`, async () => {
      reset()
      unreadable = true
      for (const [route, api] of [[path, { node }], [item, { node, iface: 'vmbr0' }]] as const) {
        const read = await command('get', route, api)
        assert.equal(read.value.error.code, 'PERMISSION_DENIED')
        assert.equal(read.payload, undefined)
      }
    })
    await t.test(`${release} filtered collection get and ls are refused before provider access`, async () => {
      reset()
      const count = requests.length
      for (const verb of ['get', 'ls'])
        assert.equal((await command(verb, path, { node, type: 'bridge' })).value.error.code, 'CONTRACT_UNRESOLVED')
      assert.equal(requests.length, count)
    })
  }
  assert.equal(requests.some(route => !route.startsWith('GET ')), false)
  assert.equal((await readdir(scratch)).includes('journal.d'), false)
})

test('network executable discovery exposes only admitted read selectors', async () => {
  const { commands } = JSON.parse(await readFile(new URL('../../artium-invocations.json', import.meta.url), 'utf8')) as {
    commands: { command: string, flags: Record<string, string>, privateResult?: boolean }[]
  }
  const network = commands.filter(entry => /^(get|ls|create|set|delete) \/nodes\/\{node\}\/network(?:\/\{iface\})?$/.test(entry.command))
  assert.deepEqual(network.map(entry => entry.command).sort(), [`get ${path}`, `get ${item}`, `ls ${path}`])
  for (const entry of network) {
    assert.deepEqual(Object.keys(entry.flags).filter(name => name.startsWith('api-')).sort(),
      entry.command.endsWith('{iface}') ? ['api-iface', 'api-node'] : ['api-node'])
    assert.equal(entry.privateResult, true)
  }
})

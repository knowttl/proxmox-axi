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
const path = '/nodes/{node}/network', item = `${path}/{iface}`, target = { node: 'node-a', iface: 'vmbr7' }
const id = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const canary = 'CANARY-private-network-configuration'
const initial = (): Row[] => [
  ...['eth0', 'eth1', 'eth2'].map(iface => ({ iface, type: 'eth', method: 'manual', autostart: 1, active: 1, exists: 1 })),
  { iface: 'bond0', type: 'bond', slaves: 'eth0 eth1', bond_mode: 'active-backup', method: 'manual', active: 1 },
  { iface: 'vmbr0', type: 'bridge', bridge_ports: 'bond0', method: 'static', cidr: '192.0.2.10/24', address: '192.0.2.10', netmask: '24', comments: canary },
  { iface: 'vmbr0.20', type: 'vlan', 'vlan-raw-device': 'vmbr0', 'vlan-id': 20, method: 'manual', method6: 'static', cidr6: '2001:db8::10/64' },
]

test('pending Linux bridges retain private diffs, management warnings and exact confirmation', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-node-network-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), journal = join(scratch, 'journal')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', pending = initial(), changes: unknown = null, mode = 'success', revision = 0, dispatched = false
  const active = initial(), writes: Row[] = [], requests: string[] = []
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), route = url.pathname
    requests.push(`${request.method} ${route}`)
    if (route.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    assert.match(route, /^\/api2\/json\/nodes\/node-a\/network(?:\/[^/]+)?$/)
    const iface = route.split('/')[6]
    if (request.method === 'GET') {
      if (mode === 'unreadable' && dispatched) { response.writeHead(403).end(JSON.stringify({ message: canary })); return }
      response.end(JSON.stringify({ data: iface ? pending.find(row => row.iface === iface) : pending, ...(!iface && changes !== null ? { changes } : {}) })); return
    }
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const fields = Object.fromEntries(request.method === 'DELETE' ? url.searchParams : new URLSearchParams(Buffer.concat(chunks).toString()))
    writes.push({ method: request.method, route, fields })
    if (mode === 'reject') { response.writeHead(400).end(JSON.stringify({ message: canary })); return }
    assert.ok(iface || request.method === 'POST', 'CRUD must not apply or revert the collection')
    const name = iface ?? fields.iface!, selected = pending.find(row => row.iface === name)
    if (request.method === 'DELETE') pending = pending.filter(row => row.iface !== name)
    else {
      // Native Network.pm maps CIDRs and replaces methods/families; Interfaces.pm reparses bridge defaults and sorted ports.
      const row: Row = { ...selected, ...fields, iface: name, type: 'bridge', method: fields.cidr ? 'static' : 'manual', method6: fields.cidr6 ? 'static' : 'manual',
        autostart: fields.autostart === undefined ? selected?.autostart ?? 0 : Number(fields.autostart),
        bridge_ports: [...new Set(String(fields.bridge_ports ?? selected?.bridge_ports ?? '').split(' ').filter(Boolean))].sort().join(' '),
        bridge_stp: selected?.bridge_stp ?? 'off', bridge_fd: selected?.bridge_fd ?? '0' }
      if (fields.mtu) row.mtu = Number(fields.mtu)
      for (const suffix of ['', '6']) if (fields[`cidr${suffix}`]) {
        const [address, mask] = fields[`cidr${suffix}`]!.split('/')
        row[`address${suffix}`] = address
        row[`netmask${suffix}`] = suffix ? Number(mask) : mask
      }
      pending = [...pending.filter(row => row.iface !== name), row]
    }
    // Writing the whole native file supplies defaults for pre-existing Linux bonds too.
    for (const row of pending.filter(row => row.type === 'bond')) {
      row.bond_mode ??= 'balance-rr'
      row.bond_miimon = String(row.bond_miimon ?? 100)
    }
    dispatched = true
    changes = `--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n@@ -1 +1 @@\n-# revision ${revision++}\n+# ${canary}\n`
    if (mode === 'race') pending[0]!.autostart = 0
    response.end(JSON.stringify({ data: null }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!network', token: { env: 'NETWORK_TOKEN' }, writes: { operations: [['POST', path], ['PUT', item], ['DELETE', item]].map(([method, path]) => id(method!, path!)) },
  } } }), { mode: 0o600 })
  const command = async (verb: string, route: string, api: Row, flags: string[] = [], privateResult = true) => {
    const body = join(scratch, 'request.json')
    await writeFile(body, JSON.stringify(api), { mode: 0o600 })
    const child = spawn(process.execPath, [executable, verb, route, '--body-file', body, ...flags, '--config', config, '--format', 'json'], {
      env: { ...environment, NETWORK_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: journal, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' },
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
  const confirm = async (verb: string, route: string, api: Row) => {
    const preview = await command(verb, route, api, ['--preview'])
    assert.equal(preview.code, 0, JSON.stringify(preview.value))
    assert.match(JSON.stringify(preview.value.warnings), /MANAGEMENT ACCESS AT RISK.*UNKNOWN/)
    return command(verb, route, api, ['--confirm', preview.value.confirmation])
  }
  for (const release of ['8.2.7', '9.2.1']) {
    version = release
    const reset = () => { pending = initial(); changes = null; mode = 'success'; dispatched = false }
    await t.test(`${release} bridge CRUD changes pending configuration without applying it`, async () => {
      reset()
      assert.equal((await confirm('create', path, { ...target, bridge_ports: 'eth2 eth2', autostart: true, cidr: '198.51.100.10/24', cidr6: '2001:db8::10/64' })).value.status, 'success')
      const read = await command('get', path, { node: target.node })
      assert.match(read.payload.pendingDiff, /CANARY-private-network/)
      assert.equal(read.payload.activeConfiguration, 'unverified')
      assert.equal((await confirm('set', item, { ...target, mtu: 1500, bridge_ports: '' })).value.status, 'success')
      const detail = await command('get', item, target)
      assert.equal(detail.code, 0, JSON.stringify(detail.value))
      assert.equal(detail.payload.cidr, '198.51.100.10/24')
      assert.equal(detail.payload.method, 'static')
      assert.equal(detail.payload.cidr6, '2001:db8::10/64')
      assert.equal(detail.payload.method6, 'static')
      assert.equal(detail.payload.bridge_ports, '')
      assert.equal(detail.payload.mtu, 1500)
      assert.equal((await confirm('delete', item, target)).value.status, 'success')
      assert.equal((await command('get', path, { node: target.node })).payload.interfaces.some((row: Row) => row.iface === target.iface), false)
      assert.deepEqual(active, initial())
    })
    await t.test(`${release} indirect addressed bond/VLAN dependencies remain explicitly uncertain`, async () => {
      reset()
      const api = { node: target.node, iface: 'vmbr0', mtu: 1500 }, preview = await command('set', item, api, ['--preview'])
      assert.equal(preview.code, 0, JSON.stringify(preview.value))
      assert.deepEqual(preview.payload.management, { classification: 'unknown', affected: ['bond0', 'eth0', 'eth1', 'vmbr0', 'vmbr0.20'], addressed: ['vmbr0', 'vmbr0.20'] })
      assert.equal(preview.payload.after.find((row: Row) => row.iface === 'vmbr0').cidr, '192.0.2.10/24')
      assert.match(JSON.stringify(preview.value.warnings), /MANAGEMENT ACCESS AT RISK.*UNKNOWN/)
      const count = writes.length
      assert.equal((await command('set', item, api)).value.error.code, 'CONFIRMATION_REQUIRED')
      assert.equal(writes.length, count)
      assert.equal((await command('set', item, api, ['--confirm', preview.value.confirmation])).value.status, 'success')
    })
    for (const change of ['diff', 'interface']) await t.test(`${release} changed pending ${change} invalidates confirmation before mutation`, async () => {
      reset()
      const api = { ...target, bridge_ports: 'eth2' }, preview = await command('create', path, api, ['--preview'])
      if (change === 'diff') changes = `+# ${canary}`
      else pending[0]!.autostart = 0
      const count = writes.length
      assert.equal((await command('create', path, api, ['--confirm', preview.value.confirmation])).value.error.code, 'CONFIRMATION_MISMATCH')
      assert.equal(writes.length, count)
    })
    for (const failure of ['reject', 'race', 'unreadable']) await t.test(`${release} ${failure} retains its actual pending outcome without replay`, async () => {
      reset()
      mode = failure
      const count = writes.length, api = { ...target, bridge_ports: 'eth2' }, result = await confirm('create', path, api)
      assert.equal(result.value.error.code, failure === 'reject' ? 'HTTP_ERROR' : 'WRITE_UNCERTAIN')
      assert.equal(writes.length, count + 1)
      assert.equal(pending.some(row => row.iface === target.iface), failure !== 'reject')
      assert.deepEqual(active, initial())
    })
    await t.test(`${release} private reads and previews require a sink before provider access`, async () => {
      reset()
      const count = requests.length
      for (const [verb, route, api, flags] of [['get', path, { node: target.node }, []], ['create', path, target, ['--preview']]] as const)
        assert.equal((await command(verb, route, api, [...flags], false)).value.error.code, 'PRIVATE_SINK_REQUIRED')
      assert.equal(requests.length, count)
    })
    for (const api of [{ ...target, type: 'bond' }, { ...target, bridge_ports: 'eth2;eth1' }, { ...target, cidr: '192.0.2.5/33' },
      { ...target, cidr: '192.0.2.5/0' }, { ...target, cidr6: '2001:db8::10/0' }, { ...target, ovs_ports: 'eth2' }, { ...target, delete: 'cidr' }, { ...target, iface: 'eth2' }])
      await t.test(`${release} refuses unreviewed bridge inputs ${JSON.stringify(api)}`, async () => {
        reset()
        const count = requests.length
        assert.notEqual((await command('create', path, api, ['--preview'])).code, 0)
        assert.equal(requests.length, count)
      })
    await t.test(`${release} malformed pending metadata is not treated as an empty diff`, async () => {
      reset()
      changes = { unexpected: canary }
      assert.equal((await command('get', path, { node: target.node })).value.error.code, 'INVALID_RESPONSE')
      assert.equal((await command('create', path, target, ['--preview'])).value.error.code, 'INVALID_RESPONSE')
    })
    await t.test(`${release} filtered network reads are refused before provider access`, async () => {
      reset()
      const count = requests.length
      assert.equal((await command('get', path, { node: target.node, type: 'bridge' })).value.error.code, 'CONTRACT_UNRESOLVED')
      assert.equal(requests.length, count)
    })
  }
  assert.equal(requests.some(route => /^(PUT|DELETE) \/api2\/json\/nodes\/node-a\/network$/.test(route)), false)
  for (const file of await readdir(`${journal}.d`)) assert.equal((await readFile(join(`${journal}.d`, file), 'utf8')).includes(canary), false)
})

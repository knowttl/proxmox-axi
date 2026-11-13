import type { AddressInfo } from 'node:net'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import { join } from 'node:path'
import test from 'node:test'

test('reported read failures through the native CLI', async t => {
  const scratch = await mkdtemp(join(process.cwd(), '.retest-cli-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const transcript: Record<string, unknown>[] = []
  t.after(async () => {
    if (process.env.RETEST_EVIDENCE) await writeFile(process.env.RETEST_EVIDENCE, JSON.stringify(transcript, null, 2))
  })
  const cert = new URL('./fixtures/localhost-cert.pem', import.meta.url)
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(cert), { mode: 0o600 })
  let data: unknown
  const requests: string[] = []
  const server = createServer({ cert: await readFile(cert), key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)) }, (request, response) => {
    requests.push(request.url!)
    response.end(JSON.stringify({ data: request.url!.endsWith('/version') ? { version: '8.2.7', release: 'synthetic', repoid: 'synthetic' } : data }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => server.close(resolve)))
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!test', token: { env: 'RETEST_TOKEN' },
  } } }), { mode: 0o600 })
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
  const command = async (path: string, input: string[] = [], flags: string[] = [], privateResult = false) => {
    const args = ['get', path, ...input, ...flags, '--config', config, '--format', 'json']
    const child = spawn(process.execPath, ['bin/proxmox-axi.mjs', ...args], {
      env: { ...environment, RETEST_TOKEN: 'synthetic', PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '', XDG_CONFIG_HOME: scratch, XDG_STATE_HOME: scratch, XDG_CACHE_HOME: scratch },
      stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
    })
    let stdout = '', stderr = '', bytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk })
    child.stderr!.on('data', chunk => { stderr += chunk })
    child.stdio[3]!.on('data', (chunk: Buffer) => { bytes = Buffer.concat([bytes, chunk]) })
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    let payload: unknown
    if (bytes.length) {
      assert.equal(bytes.readUInt32BE(0), bytes.length - 4)
      payload = JSON.parse(bytes.subarray(4).toString()).payload
    }
    const output: { data: unknown, error: { code: string }, help: string[] } = JSON.parse(stdout)
    transcript.push({ command: ['node bin/proxmox-axi.mjs', 'get', path, ...input, ...flags].join(' '), code, output, stderr, privatePayload: payload, responseBytes: Buffer.byteLength(JSON.stringify({ data })) })
    assert.equal(stderr, '')
    return { code, output, payload }
  }
  const node = ['--api-node', 'node-a'], guest = [...node, '--api-vmid', '100']

  for (const family of ['qemu', 'lxc']) {
    await t.test(`${family} config converts numeric strings in the private result`, async () => {
      data = { digest: 'synthetic', cpulimit: '1.5', cores: '2' }
      const result = await command(`/nodes/{node}/${family}/{vmid}/config`, guest, [], true)
      assert.equal(result.code, 0)
      assert.deepEqual(result.output.data, { privateResult: true })
      assert.deepEqual(result.payload, { digest: 'synthetic', cpulimit: 1.5, cores: 2 })
    })
    await t.test(`${family} pending preserves mixed scalar values and refuses objects`, async () => {
      data = [{ key: 'cores', value: 2, pending: 3 }, { key: 'onboot', value: false, pending: null }, { key: 'name', value: 'old', pending: 'new' }]
      const result = await command(`/nodes/{node}/${family}/{vmid}/pending`, guest, [], true)
      assert.equal(result.code, 0)
      assert.deepEqual(result.payload, data)
      data = [{ key: 'cores', value: {} }]
      const invalid = await command(`/nodes/{node}/${family}/{vmid}/pending`, guest, [], true)
      assert.equal(invalid.output.error.code, 'INVALID_RESPONSE')
      assert.equal(invalid.payload, undefined)
    })
  }
  await t.test('next ID normalizes strings and rejects malformed and unsafe integers', async () => {
    data = '100'
    const result = await command('/cluster/nextid')
    assert.equal(result.code, 0)
    assert.equal(result.output.data, 100)
    for (const value of ['100x', '1e3', ' 1', '1.2', '9007199254740992', null]) {
      data = value
      const invalid = await command('/cluster/nextid')
      assert.equal(invalid.code, 1)
      assert.equal(invalid.output.error.code, 'INVALID_RESPONSE')
    }
  })
  await t.test('firewall rule positions normalize on list and object reads', async () => {
    const rule = { pos: '0', type: 'in', action: 'ACCEPT' }
    data = [rule]
    const list = await command('/nodes/{node}/qemu/{vmid}/firewall/rules', guest, [], true)
    assert.equal(list.code, 0)
    assert.deepEqual(list.payload, [{ ...rule, pos: 0 }])
    data = rule
    const detail = await command('/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}', [...guest, '--api-pos', '0'], [], true)
    assert.equal(detail.code, 0)
    assert.equal((detail.payload as { pos: number }).pos, 0)
  })
  await t.test('network collection and detail accept optional nulls but require an interface', async () => {
    const row = { iface: 'vlan1', type: 'vlan', method: 'manual', exists: null }
    data = [row]
    const list = await command('/nodes/{node}/network', node, [], true)
    assert.equal(list.code, 0)
    assert.deepEqual((list.payload as { interfaces: unknown }).interfaces, [row])
    data = row
    const detail = await command('/nodes/{node}/network/{iface}', [...node, '--api-iface', 'vlan1'], [], true)
    assert.equal(detail.code, 0)
    assert.deepEqual(detail.payload, row)
    data = [{ ...row, iface: null }]
    assert.equal((await command('/nodes/{node}/network', node, [], true)).output.error.code, 'INVALID_RESPONSE')
  })
  const storage = [...node, '--api-storage', 'local']
  await t.test('storage content accepts optional null parent and rejects null volume ID', async () => {
    const row = { volid: 'local:vm-100-disk-0', format: 'raw', size: 1024, parent: null }
    data = [row]
    const result = await command('/nodes/{node}/storage/{storage}/content', storage, ['--fields', 'volid,format,size'])
    assert.equal(result.code, 0)
    assert.deepEqual(result.output.data, [{ volid: row.volid, format: 'raw', size: 1024 }])
    data = [{ ...row, volid: null }]
    assert.equal((await command('/nodes/{node}/storage/{storage}/content', storage)).output.error.code, 'INVALID_RESPONSE')
  })
  await t.test('appliance catalogue permits 95KB and rejects above 256KiB while other reads retain 64KiB', async () => {
    data = [{ template: 'base.tar.zst', description: 'x'.repeat(95_000) }]
    const result = await command('/nodes/{node}/aplinfo', node)
    assert.equal(result.code, 0)
    assert.deepEqual(result.output.data, [{ template: 'base.tar.zst' }])
    data = [{ template: 'base.tar.zst', description: 'x'.repeat(263_000) }]
    assert.equal((await command('/nodes/{node}/aplinfo', node)).output.error.code, 'OUTPUT_LIMIT')
    data = [{ volid: 'local:test.iso', format: 'iso', size: 1, notes: 'x'.repeat(95_000) }]
    assert.equal((await command('/nodes/{node}/storage/{storage}/content', storage)).output.error.code, 'OUTPUT_LIMIT')
  })
  await t.test('object field selection excludes other properties and rejects unknown fields before the target read', async () => {
    data = { format: 'iso', size: 4096, used: 2048, path: 'synthetic-private-path' }
    const path = '/nodes/{node}/storage/{storage}/content/{volume}'
    const input = [...storage, '--api-volume', 'local:iso/test.iso']
    const result = await command(path, input, ['--fields', 'size'])
    assert.equal(result.code, 0)
    assert.deepEqual(result.output.data, { size: 4096 })
    const before = requests.length
    const invalid = await command(path, input, ['--fields', 'path'])
    assert.equal(invalid.code, 2)
    assert.equal(invalid.output.error.code, 'INVALID_INPUT')
    assert.ok(requests.slice(before).every(path => path.endsWith('/version')))
    data = '100'
    const scalar = await command('/cluster/nextid', [], ['--fields', 'size'])
    assert.equal(scalar.code, 2)
    assert.match(scalar.output.help.join(' '), /no selectable fields/)
  })
})

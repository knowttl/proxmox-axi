import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import { selectContract, validateResponse } from '../dist/contract.js'
import { readOperation } from '../dist/reads.js'

test('synthetic captured read shapes validate and normalize', () => {
  for (const [path, data, expected] of [
    ['/nodes/{node}/qemu/{vmid}/config', { digest: 'synthetic', cpulimit: '1.5' }, { digest: 'synthetic', cpulimit: 1.5 }],
    ['/nodes/{node}/lxc/{vmid}/config', { digest: 'synthetic', cpulimit: '1' }, { digest: 'synthetic', cpulimit: 1 }],
    ['/nodes/{node}/network', [{ iface: 'vlan1', type: 'vlan', exists: null }], [{ iface: 'vlan1', type: 'vlan', exists: null }]],
    ['/nodes/{node}/storage/{storage}/content', [{ volid: 'local:vm-100-disk-0', format: 'raw', size: 1024, parent: null }], [{ volid: 'local:vm-100-disk-0', format: 'raw', size: 1024, parent: null }]],
    ['/cluster/nextid', '100', 100],
    ['/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}', { pos: '0', type: 'in', action: 'ACCEPT' }, { pos: 0, type: 'in', action: 'ACCEPT' }],
  ]) {
    assert.deepEqual(validateResponse(data, selectContract('GET', path, 'legacy-8.2.7').returns), expected, path)
  }
})

test('pending reads accept scalar values and reject objects', async t => {
  let data = [{ key: 'cores', value: 2, pending: 3 }, { key: 'onboot', value: 0, pending: null }]
  let delivered
  const cert = await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url))
  const server = createServer({ cert, key: await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url)) }, (_request, response) => response.end(JSON.stringify({ data })))
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => server.close(resolve)))
  const credentials = { origin: `https://127.0.0.1:${server.address().port}`, ca: cert, auth: 'api-token', tokenId: 'synthetic', token: 'synthetic',
    results: { sink() {}, async deliver(_binding, value) { delivered = value } } }
  for (const guest of ['qemu', 'lxc']) {
    const contract = selectContract('GET', `/nodes/{node}/${guest}/{vmid}/pending`, 'legacy-8.2.7')
    await readOperation(credentials, contract, { node: 'node-a', vmid: 100 }, 'legacy-8.2.7')
    assert.deepEqual(delivered, data)
    data = [{ key: 'cores', value: {} }]
    await assert.rejects(readOperation(credentials, contract, { node: 'node-a', vmid: 100 }, 'legacy-8.2.7'), { code: 'INVALID_RESPONSE' })
    data = [{ key: 'cores', value: 2, pending: 3 }, { key: 'onboot', value: 0, pending: null }]
  }
})

test('invalid numeric strings and required nulls remain invalid', () => {
  for (const value of ['1e3', ' 1', '1.2', '9007199254740992', null]) {
    assert.throws(() => validateResponse(value, { type: 'integer' }), { code: 'INVALID_RESPONSE' })
  }
})

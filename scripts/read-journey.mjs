import assert from 'node:assert/strict'
import { retainedReads } from './read-cases.mjs'

export async function exerciseReadJourney({ runCase, pack, retained, contracts, env, entry, hosted, task }) {
  const cases = await retainedReads(pack, retained, contracts)
  const prefix = hosted ? ['proxmox-axi'] : []
  const run = (id, args, expected, response) => runCase(`${hosted ? 'artium' : 'standalone'}/${id}`,
    [...prefix, ...args], env, { ...expected, ...(hosted ? { identity: 'hosted-canary' } : {}) }, response, entry)
  for (const row of cases) {
    const value = await run(`retained/${row.id}`, [...row.args, '--catalogue', 'legacy-8.2.7', '--full', '--format', 'json'],
      { exitCode: 0, requests: 1, path: row.path, ...(row.contract.path === '/version' ? { version: true } : { data: row.expected }) }, row.response)
    if (Array.isArray(row.expected) && !row.verified) assert.equal(value.visibility, 'unknown', 'Pre-permission samples are never proof of empty inventory')
  }
  const verified = cases.filter(row => row.verified)
  const version = verified.find(row => row.contract.path === '/version').response
  const permissions = verified.find(row => row.contract.path === '/access/permissions').response
  const routes = new Map(verified.map(row => [row.path, row.response]))
  routes.set('/api2/json/access/permissions', permissions)
  routes.set('/api2/json/nodes/node-a/version', version)
  const vendor = path => routes.get(path) ?? { httpStatus: 404, body: { data: null } }
  for (const [route, count] of [['/nodes', 1], ['/nodes/{node}/qemu', 9], ['/nodes/{node}/lxc', 1], ['/nodes/{node}/storage', 4], ['/nodes/{node}/tasks', 1], ['/nodes/{node}/tasks/{upid}/log', 2]]) {
    const row = verified.find(row => row.contract.path === route)
    const paths = ['/api2/json/version', ...(row.values.node ? ['/api2/json/nodes/node-a/version'] : []),
      ...(route.endsWith('/log') ? [] : ['/api2/json/access/permissions']), row.path]
    for (const format of ['toon', 'json']) {
      const value = await run(`AC-READ/${route}/${format}`, [...row.args, '--format', format], { exitCode: 0, requests: paths.length, paths }, vendor)
      assert.equal(value.count, count, route)
      if (!route.endsWith('/log')) assert.equal(value.visibility, 'complete')
      if (route.endsWith('/log')) assert.deepEqual(value.data.map(row => row.n), [1, 2])
    }
  }
  const status = verified.find(row => row.contract.path.endsWith('/status'))
  const statusPaths = ['/api2/json/version', '/api2/json/nodes/node-a/version', status.path]
  const stopped = await run('AC-READ/stopped-task', [...status.args, '--format', 'json'], { exitCode: 0, requests: 3, paths: statusPaths }, vendor)
  assert.equal(stopped.data.status, 'stopped')
  assert.equal(stopped.data.exitstatus, 'OK')
  const nodes = verified.find(row => row.contract.path === '/nodes')
  const nodePaths = ['/api2/json/version', '/api2/json/access/permissions', nodes.path]
  await run('AC-PERMISSIONS/forbidden', ['ls', '--format', 'json'],
    { exitCode: 1, requests: 2, paths: nodePaths.slice(0, 2), error: 'PERMISSION_DENIED' },
    path => path.includes('/permissions') ? { httpStatus: 403, body: '' } : vendor(path))
  for (const granted of [false, true]) {
    const value = await run(`AC-PERMISSIONS/empty/${granted}`, ['ls', '--format', 'json'], { exitCode: 0, requests: 3, paths: nodePaths },
      path => path === nodes.path ? { httpStatus: 200, body: { data: [] } } : path.includes('/permissions') ?
        { httpStatus: 200, body: { data: granted ? permissions.body.data : {} } } : vendor(path))
    assert.equal(value.empty, granted ? 'verified-empty' : 'visibility-unverified')
    assert.equal(value.visibility, granted ? 'complete' : 'permission-filtered')
    assert.equal(value.total, null)
  }
  const vms = verified.find(row => row.contract.path.endsWith('/qemu'))
  const vmPaths = ['/api2/json/version', '/api2/json/nodes/node-a/version', '/api2/json/access/permissions', vms.path]
  const bounded = await run('display-limit', [...vms.args, '--limit', '2', '--format', 'json'], { exitCode: 0, requests: 4, paths: vmPaths }, vendor)
  assert.equal(bounded.count, 2)
  assert.equal(bounded.received, 9)
  assert.equal(bounded.displayTruncated, true)
  const page = await run('provider-page', [...vms.args, '--catalogue', 'legacy-8.2.7', '--full', '--format', 'json'],
    { exitCode: 0, requests: 1, path: vms.path }, { httpStatus: 200, body: { data: vms.expected.slice(0, 2), total: 20 } })
  assert.equal(page.providerTotal, 20)
  assert.equal(page.providerPagination, 'partial')
  assert.equal(page.displayTruncated, false)
  assert.equal(page.total, null, 'Unknown visibility does not make a provider total authoritative')
  await run('invalid-required-vmid', [...vms.args, '--catalogue', 'legacy-8.2.7', '--format', 'json'],
    { exitCode: 1, requests: 1, path: vms.path, error: 'INVALID_RESPONSE' }, { httpStatus: 200, body: { data: [{ status: 'running' }] } })
  await run('invalid-provider-total', [...vms.args, '--catalogue', 'legacy-8.2.7', '--format', 'json'],
    { exitCode: 1, requests: 1, path: vms.path, error: 'INVALID_RESPONSE' }, { httpStatus: 200, body: { data: vms.expected, total: 1 } })
  await run('rendered-output-cap', ['get', '/version', '--format', 'json'], { exitCode: 1, requests: 1, error: 'OUTPUT_LIMIT' },
    { httpStatus: 200, body: { data: { ...version.body.data, repoid: 'x'.repeat(65400) } } })
  const added = { ...version, body: { data: { ...version.body.data, compatibleAddedField: 'retained' } } }
  const extra = await run('compatible-added-fields', ['get', '/version', '--format', 'json'], { exitCode: 0, requests: 1 }, added)
  assert.equal(extra.version.compatibleAddedField, 'retained')
  for (const [httpStatus, error] of [[403, 'PERMISSION_DENIED'], [404, 'NOT_FOUND_OR_HIDDEN'], [429, 'HTTP_ERROR']]) {
    await run(`http/${httpStatus}`, ['get', '/version', '--format', 'json'], { exitCode: 1, requests: 1, error }, { httpStatus, body: '' })
  }
  for (const command of [['home'], ['auth', 'status'], ['profile', 'list'], ['config', 'path'], ['help']]) {
    await run(`discovery/${command.join('-')}`, [...command, '--format', 'json'], { exitCode: 0, requests: command[0] === 'home' ? 1 : 0 }, vendor)
  }
  if (task === 'S2.3') {
    const doctorPaths = ['/api2/json/version', '/api2/json/access/permissions', '/api2/json/nodes', '/api2/json/nodes/node-a/version',
      '/api2/json/nodes/node-a/qemu', '/api2/json/nodes/node-a/lxc', '/api2/json/nodes/node-a/storage', '/api2/json/nodes/node-a/tasks?limit=1', status.path]
    const checked = await run('VP-05/doctor', ['doctor', '--format', 'json'], { exitCode: 0, requests: 9, paths: doctorPaths }, vendor)
    assert.equal(checked.checks.length, 9)
    assert.equal(checked.compatibility.evidence, 'legacy regression fixtures')
    for (const target of ['8.2.7', '9.2.1', '10.0.1']) {
      const value = await run(`VP-01/mixed-node/${target}`, [...vms.args, '--format', 'json'], { exitCode: 0, requests: 4, paths: vmPaths },
        path => path.endsWith('/node-a/version') ? { httpStatus: 200, body: { data: { ...version.body.data, version: target } } } : vendor(path))
      assert.equal(value.compatibility.catalogue, target.startsWith('8') ? 'legacy-8.2.7' : 'published-current')
      assert.equal(value.compatibility.status, target.startsWith('9.2') ? 'supported' : 'unverified')
      assert.equal(value.compatibility.writes, 'disabled')
    }
    await run('VP-06/removed-route', ['get', '/nodes/{node}/scan/glusterfs', '--api-node', 'node-a', '--format', 'json'],
      { exitCode: hosted ? 2 : 1, requests: 0, error: hosted ? 'INVALID_INPUT' : 'CAPABILITY_UNSUPPORTED', hostBoundary: hosted }, vendor)
    await run('VP-06/unknown-write', ['post', '/nodes/{node}/qemu/{vmid}/status/start', '--format', 'json'],
      { exitCode: hosted ? 2 : 1, requests: 0, error: hosted ? 'INVALID_INPUT' : 'CONTRACT_UNRESOLVED', hostBoundary: hosted }, vendor)
  }
}

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

const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PROXMOX_AXI_')))
const canary = 'CANARY-private-first-boot-details', base = '/nodes/{node}/qemu/{vmid}/agent'
const routes = [
  { command: 'ping', method: 'POST', result: {} },
  { command: 'info', method: 'GET', result: { version: '9.2.0', supported_commands: [{ name: 'guest-ping', enabled: true, 'success-response': true }] } },
  { command: 'get-host-name', method: 'GET', result: { 'host-name': canary } },
  { command: 'get-osinfo', method: 'GET', result: { id: 'linux', name: canary, 'version-id': '1' } },
  { command: 'network-get-interfaces', method: 'GET', result: [{ name: 'eth0', 'hardware-address': '02:00:00:00:00:01', 'ip-addresses': [{ 'ip-address-type': 'ipv4', 'ip-address': '192.0.2.10', prefix: 24 }] }] },
]

test('guest readiness and first-boot files remain private without mutation grants', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-readiness-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', mode = 'success'
  const requests: { method: string, path: string }[] = []
  const marker = `${canary}\n`
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), command = url.pathname.split('/').at(-1)!
    requests.push({ method: request.method!, path: request.url! })
    if (command === 'version') { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (mode === 'unavailable') { response.writeHead(500).end(JSON.stringify({ message: `Guest agent unavailable: ${canary}` })); return }
    if (command === 'file-read') {
      assert.equal(request.method, 'GET')
      assert.equal(url.searchParams.get('file'), '/var/lib/cloud/instance/boot-finished')
      if (version.startsWith('8.')) {
        assert.equal(url.searchParams.has('count'), false)
        response.end(JSON.stringify({ data: { content: Buffer.from(marker).toString('base64'), truncated: 0 } })); return
      }
      assert.equal(url.searchParams.get('count'), '8')
      assert.equal(url.searchParams.get('offset'), '0')
      assert.equal(url.searchParams.get('decode'), '1')
      response.end(JSON.stringify({ data: { content: marker.slice(0, 8), truncated: 1, 'bytes-read': 8 } })); return
    }
    const route = routes.find(row => row.command === command)!
    assert.equal(request.method, route.method)
    assert.equal(url.search, '')
    response.end(JSON.stringify({ data: mode === 'malformed' ? [] : mode === 'oversized' ? { result: canary.repeat(3000) } : { result: route.result, extension: canary } }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin, caBundle: caFile, tokenId: 'synthetic@pve!test', token: { env: 'READINESS_TOKEN' },
  } } }), { mode: 0o600 })
  const command = async (args: string[], channel?: 'result' | 'bytes') => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, READINESS_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: log, PROXMOX_AXI_READ_ONLY: '1',
        PROXMOX_AXI_RESULT_FD: channel === 'result' ? '3' : '', PROXMOX_AXI_STREAM_FD: channel === 'bytes' ? '3' : '' },
      stdio: ['ignore', 'pipe', 'pipe', ...(channel ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', privateBytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (channel) (child.stdio[3] as Readable).on('data', chunk => { privateBytes = Buffer.concat([privateBytes, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal((stdout + stderr).includes(canary), false)
    if (channel === 'result' && privateBytes.length) assert.equal(privateBytes.readUInt32BE(0), privateBytes.length - 4)
    return { code, value: JSON.parse(stdout), bytes: privateBytes,
      frame: channel === 'result' && privateBytes.length ? JSON.parse(privateBytes.subarray(4).toString()) : undefined }
  }
  const target = ['--api-node', 'node-a', '--api-vmid', '100']
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    for (const route of routes) await t.test(`${release.name} privately checks ${route.command} with its vendor method`, async () => {
      const path = `${base}/${route.command}`, verb = route.method.toLowerCase()
      const schema = await command(['schema', verb, path, '--catalogue', release.name])
      assert.equal(schema.value.callable, true)
      assert.equal(schema.value.policy.effect, 'read')
      assert.equal(schema.value.policy.secrets, 'private-result')
      requests.length = 0
      const missing = await command([verb, path, ...target])
      assert.equal(missing.value.error.code, 'PRIVATE_SINK_REQUIRED')
      assert.equal(requests.length, 0)
      const checked = await command([verb, path, ...target, '--full'], 'result')
      assert.equal(checked.code, 0, JSON.stringify(checked.value))
      assert.deepEqual(checked.value.data, { privateResult: true })
      assert.equal(checked.value.compatibility.catalogue, release.name)
      assert.deepEqual(checked.frame.payload, { result: route.result, extension: canary })
      assert.equal(checked.frame.version, 1)
      assert.equal(checked.frame.binding.origin, origin)
      assert.equal(checked.frame.binding.operation, schema.value.id)
      assert.equal(checked.frame.binding.request, createHash('sha256').update(`${release.name} /api2/json/nodes/node-a/qemu/100/agent/${route.command}`).digest('hex'))
      assert.deepEqual(requests.filter(row => !row.path.endsWith('/version')), [{ method: route.method, path: `/api2/json/nodes/node-a/qemu/100/agent/${route.command}` }])
    })
    await t.test(`${release.name} unavailable agent gives safe prerequisite guidance`, async () => {
      mode = 'unavailable'
      const result = await command(['post', `${base}/ping`, ...target], 'result')
      assert.equal(result.code, 1)
      assert.equal(result.value.error.code, 'HTTP_ERROR')
      assert.match(result.value.help.join(' '), /guest-agent service/)
      assert.match(result.value.help.join(' '), /does not prove the VM is unhealthy/)
      assert.equal(result.bytes.length, 0)
      mode = 'success'
    })
    for (const invalid of [{ mode: 'malformed', code: 'INVALID_RESPONSE' }, { mode: 'oversized', code: 'OUTPUT_LIMIT' }]) {
      await t.test(`${release.name} refuses ${invalid.mode} readiness output before private delivery`, async () => {
        mode = invalid.mode
        const result = await command(['get', `${base}/info`, ...target], 'result')
        assert.equal(result.value.error.code, invalid.code)
        assert.equal(result.bytes.length, 0)
        mode = 'success'
      })
    }
    await t.test(`${release.name} first-boot file uses only the private byte channel`, async () => {
      const current = release.name === 'published-current'
      const args = ['transfer', 'get', `${base}/file-read`, ...target, '--api-file', '/var/lib/cloud/instance/boot-finished',
        '--response-format', 'guest-file', ...(current ? ['--api-count', '8', '--api-offset', '0', '--api-decode', '1'] : [])]
      requests.length = 0
      const missing = await command(args)
      assert.equal(missing.value.error.code, 'INVALID_INPUT')
      assert.equal(requests.length, 0)
      const result = await command(args, 'bytes')
      assert.equal(result.code, 0, JSON.stringify(result.value))
      assert.equal(result.value.transfer.status, 'complete')
      assert.equal(result.value.transfer.encoding, current ? 'utf8' : 'legacy-unknown')
      assert.equal(result.value.transfer.truncated, current)
      assert.equal(result.bytes.toString(), current ? marker.slice(0, 8) : Buffer.from(marker).toString('base64'))
      assert.equal(result.value.transfer.bytes, result.bytes.length)
    })
  }
  for (const path of [base, `${base}/set-user-password`, `${base}/file-write`, `${base}/fsfreeze-freeze`]) {
    await t.test(`keeps unreviewed ${path} dispatch refused`, async () => {
      requests.length = 0
      const result = await command(['post', path, ...target])
      assert.equal(result.value.error.code, 'CONTRACT_UNRESOLVED')
      assert.equal(requests.length, 0)
    })
  }
  assert.equal((await readdir(scratch)).some(name => name.startsWith('writes.log')), false)
})

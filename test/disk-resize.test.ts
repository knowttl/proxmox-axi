import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { Ajv } from 'ajv'

const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const resize = (family: string) => `/nodes/{node}/${family}/{vmid}/resize`
const upid = 'UPID:node-a:00000001:00000001:00000001:qmresize:100:root@pam:'
const digest = '0123456789012345678901234567890123456789'

test('disk growth uses confirmed relative increments and retained task outcomes', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-resize-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', sizeGiB = 32, loseResponse = false
  const requests: string[] = [], bodies: Record<string, string>[] = []
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    requests.push(`${request.method} ${request.url}`)
    if (request.method === 'PUT') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      bodies.push(Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString())))
      sizeGiB += 8
      if (loseResponse) { request.socket.destroy(); return }
      response.end(JSON.stringify({ data: upid }))
      return
    }
    response.end(JSON.stringify({ data: request.url!.endsWith('/version') ? { version, release: 'synthetic', repoid: 'synthetic' } : {
      node: 'node-a', upid, id: '100', pid: 1, pstart: 1, starttime: 1, type: 'qmresize', user: 'root@pam', status: 'stopped', exitstatus: 'OK',
    } }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, tokenId: 'synthetic@pve!test',
    token: { env: 'RESIZE_TOKEN' }, caBundle: caFile, writes: { operations: ['qemu', 'lxc'].map(family =>
      `OP-PUT-${createHash('sha256').update(`PUT ${resize(family)}`).digest('hex').slice(0, 10)}`) },
  } } }), { mode: 0o600 })
  const command = async (args: string[]) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, RESIZE_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: join(scratch, 'writes.log') }, stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk.toString() })
    child.stderr.on('data', chunk => { stderr += chunk.toString() })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    return { code, data: JSON.parse(stdout), stderr }
  }
  const target = ['--api-node', 'node-a', '--api-vmid', '100']
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    for (const [family, disk] of [['qemu', 'scsi0'], ['lxc', 'rootfs']]) {
      await t.test(`${release.name} ${family} discovery admits growth and refuses absolute sizes and lock bypass`, async () => {
        const schema = await command(['schema', 'set', resize(family!), '--catalogue', release.name])
        assert.equal(schema.code, 0, schema.stderr)
        const validate = new Ajv({ strict: false }).compile(schema.data.invocation.schema)
        assert.equal(validate({ api: { node: 'node-a', vmid: 100, disk, size: '+8G' } }), true)
        assert.equal(validate({ api: { node: 'node-a', vmid: 100, disk, size: '24G' } }), false)
        assert.equal(validate({ api: { node: 'node-a', vmid: 100, disk, size: '+8G', skiplock: true } }), false)
        if (family === 'qemu') assert.equal(schema.data.parameters.properties.skiplock.type, 'boolean')
      })
      await t.test(`${release.name} ${family} grows only after exact confirmation and tracks completion`, async () => {
        version = release.version
        sizeGiB = 32
        bodies.length = 0
        const args = ['set', resize(family!), ...target, '--api-disk', disk!, '--api-size', '+8G', '--api-digest', digest]
        const preview = await command([...args, '--preview'])
        assert.equal(preview.code, 0, preview.stderr)
        assert.equal(sizeGiB, 32)
        assert.deepEqual(bodies, [])
        const changed = await command(['set', resize(family!), ...target, '--api-disk', disk!, '--api-size', '+16G', '--api-digest', digest, '--confirm', preview.data.confirmation])
        assert.equal(changed.data.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(sizeGiB, 32)
        const result = await command([...args, '--confirm', preview.data.confirmation])
        assert.equal(result.code, 0, JSON.stringify(result.data))
        assert.equal(result.data.status, 'accepted')
        assert.equal(result.data.upid, upid)
        assert.equal(sizeGiB, 40)
        assert.deepEqual(bodies, [{ disk, size: '+8G', digest }])
        const completion = await command(['task', 'wait', '--api-node', 'node-a', '--api-upid', upid, '--journal', result.data.id])
        assert.equal(completion.code, 0, JSON.stringify(completion.data))
        assert.equal(completion.data.status, 'success')
        const journal = await command(['journal', 'show', result.data.id])
        assert.equal(journal.data.journal.status, 'success')
      })
    }
  }
  for (const [field, value] of [['size', '24G'], ['size', '-8G'], ['size', '+0G'], ['size', '+0.00G'], ['size', '+8'], ['disk', 'efidisk0'], ['disk', '/dev/sda'], ['skiplock', '1']]) {
    await t.test(`refuses ${field}=${value} before provider access`, async () => {
      requests.length = 0
      const inputs = { disk: 'scsi0', size: '+8G', [field!]: value! }
      const result = await command(['set', resize('qemu'), ...target, ...Object.entries(inputs).flatMap(([name, input]) => [`--api-${name}`, input]), '--preview'])
      assert.notEqual(result.code, 0)
      assert.deepEqual(requests, [])
    })
  }
  await t.test('lost growth response retains uncertainty and prevents replay of its confirmation', async () => {
    sizeGiB = 32
    const args = ['set', resize('qemu'), ...target, '--api-disk', 'scsi0', '--api-size', '+8G']
    const preview = await command([...args, '--preview'])
    assert.equal(preview.code, 0)
    loseResponse = true
    const result = await command([...args, '--confirm', preview.data.confirmation])
    loseResponse = false
    assert.equal(result.data.error.code, 'WRITE_UNCERTAIN')
    assert.equal(sizeGiB, 40)
    const journal = await command(['journal', 'show', preview.data.id])
    assert.equal(journal.data.journal.status, 'uncertain')
    const repeated = await command([...args, '--confirm', preview.data.confirmation])
    assert.equal(repeated.data.error.code, 'CONFIRMATION_USED')
    assert.equal(sizeGiB, 40)
  })
})

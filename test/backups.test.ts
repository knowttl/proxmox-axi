import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { Ajv } from 'ajv'

const execute = promisify(execFile)
const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PROXMOX_AXI_')))
const backupPath = '/nodes/{node}/vzdump', contentPath = '/nodes/{node}/storage/{storage}/content', deletePath = `${contentPath}/{volume}`
const archives = ['archive:backup/vzdump-qemu-100-2026_11_03-06_00_00.vma.zst', 'archive:backup/vzdump-lxc-101-2026_11_03-06_00_00.tar.zst']
const pbs = ['pbs:backup/vm/100/2026-11-03T06:00:00Z', 'pbs:backup/ct/101/2026-11-03T06:00:00Z']
const initial = ['archive:iso/installer.iso', 'archive:vm-100-disk-0']

test('explicit backups and backup-only deletion retain confirmation and task controls', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-backups-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', sequence = 0, failNext = false
  const volumes = new Map<string, boolean>(initial.map(name => [name, false]))
  const tasks = new Map<string, { failed: boolean, apply: () => void }>()
  const requests: string[] = []
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), path = url.pathname
    requests.push(`${request.method} ${path}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (request.method === 'POST' || request.method === 'DELETE') {
      let apply: () => void
      if (request.method === 'POST') {
        const chunks: Buffer[] = []
        for await (const chunk of request) chunks.push(Buffer.from(chunk))
        const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))
        assert.equal(path, '/api2/json/nodes/node-a/vzdump')
        assert.deepEqual(body, { remove: '0', vmid: '100,101', storage: body.storage, mode: 'snapshot', compress: 'zstd', bwlimit: '1024', protected: '0' })
        apply = () => { for (const name of body.storage === 'pbs' ? pbs : archives) volumes.set(name, false) }
      } else {
        const name = decodeURIComponent(/\/content\/(.+)$/.exec(path)![1]!)
        if (volumes.get(name)) { response.writeHead(400).end(JSON.stringify({ message: 'Backup is protected' })); return }
        assert.equal(url.search, '')
        apply = () => { volumes.delete(name) }
      }
      const upid = `UPID:node-a:${(++sequence).toString(16).padStart(8, '0')}:00000001:00000001:${request.method === 'POST' ? 'vzdump' : 'imgdel'}:100:synthetic@pve:`
      tasks.set(upid, { failed: failNext, apply })
      failNext = false
      response.end(JSON.stringify({ data: upid })); return
    }
    const task = /\/tasks\/([^/]+)\/status$/.exec(path)
    if (task) {
      const upid = decodeURIComponent(task[1]!), pending = tasks.get(upid)!
      if (!pending.failed) pending.apply()
      response.end(JSON.stringify({ data: { node: 'node-a', upid, id: '100', pid: sequence, pstart: 1, starttime: 1,
        type: upid.includes(':vzdump:') ? 'vzdump' : 'imgdel', user: 'synthetic@pve', status: 'stopped', exitstatus: pending.failed ? 'ERROR: backup storage unavailable' : 'OK' } })); return
    }
    const storage = /\/storage\/([^/]+)\/content$/.exec(path)?.[1]
    if (!storage) { response.writeHead(404).end(); return }
    response.end(JSON.stringify({ data: [...volumes].filter(([name]) => name.startsWith(`${storage}:`) &&
      (url.searchParams.get('content') !== 'backup' || name.includes(':backup/'))).map(([volid, protectedValue]) => ({ volid, format: 'raw', size: 4096, protected: protectedValue })) }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!test', token: { env: 'BACKUP_TOKEN' }, writes: { operations: [['POST', backupPath], ['DELETE', deletePath]].map(([method, path]) =>
      `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`) },
  } } }), { mode: 0o600 })
  const command = async (args: string[]) => {
    try {
      const result = await execute(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
        env: { ...environment, BACKUP_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: join(scratch, 'writes.log') },
      })
      return { code: 0, data: JSON.parse(result.stdout) }
    } catch (error) {
      const result = error as { code: number, stdout: string }
      return { code: result.code, data: JSON.parse(result.stdout) }
    }
  }
  const node = ['--api-node', 'node-a']
  const backup = ['create', backupPath, ...node, '--api-vmid', '100,101', '--api-storage', 'archive', '--api-mode', 'snapshot', '--api-compress', 'zstd', '--api-bwlimit', '1024', '--api-protected', '0']
  const wait = (result: { id: string, node: string, upid: string }) => command(['task', 'wait', '--api-node', result.node, '--api-upid', result.upid, '--journal', result.id])
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    await t.test(`${release.name} schema requires explicit selection and fixes no-pruning`, async () => {
      const schema = await command(['schema', 'create', backupPath, '--catalogue', release.name])
      assert.equal(schema.code, 0)
      const validate = new Ajv({ strict: false }).compile(schema.data.invocation.schema)
      assert.equal(validate({ api: { node: 'node-a', vmid: '100,101', storage: 'archive' } }), true)
      assert.equal(validate({ api: { node: 'node-a', vmid: '999999999', storage: 'archive' } }), true)
      assert.equal(validate({ api: { node: 'node-a', vmid: '1000000000', storage: 'archive' } }), false)
      assert.equal(validate({ api: { node: 'node-a', storage: 'archive' } }), false)
      assert.equal(validate({ api: { node: 'node-a', vmid: '100' } }), false)
      assert.equal(validate({ api: { vmid: '100', storage: 'archive' } }), false)
      assert.equal(validate({ api: { node: 'node-a', vmid: '100', storage: 'archive', remove: true } }), false)
    })
    for (const { storage, names } of [{ storage: 'archive', names: archives }, { storage: 'pbs', names: pbs }]) await t.test(`${release.name} creates, lists and deletes ${storage} guest backups after task success`, async () => {
      const args = backup.map(value => value === 'archive' ? storage : value)
      requests.length = 0
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0, JSON.stringify(preview.data))
      assert.equal(requests.some(row => row.startsWith('POST')), false)
      const changed = await command([...args.map(value => value === '100,101' ? '100,102' : value), '--confirm', preview.data.confirmation])
      assert.equal(changed.data.error.code, 'CONFIRMATION_MISMATCH')
      const result = await command([...args, '--confirm', preview.data.confirmation])
      assert.equal(result.code, 0, JSON.stringify(result.data))
      assert.equal(result.data.status, 'accepted')
      assert.equal((await wait(result.data)).data.status, 'success')
      const listed = await command(['get', contentPath, ...node, '--api-storage', storage, '--api-content', 'backup', '--fields', 'volid'])
      assert.deepEqual(listed.data.data, names.map(volid => ({ volid })))
      for (const name of names) {
        const remove = ['delete', deletePath, ...node, '--api-storage', storage, '--api-volume', name]
        requests.length = 0
        const preview = await command([...remove, '--preview'])
        assert.equal(preview.code, 0, JSON.stringify(preview.data))
        const changed = await command([...remove.map(value => value === name ? names.find(other => other !== name)! : value), '--confirm', preview.data.confirmation])
        assert.equal(changed.data.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(requests.some(row => row.startsWith('DELETE')), false)
        const deleted = await command([...remove, '--confirm', preview.data.confirmation])
        assert.equal(deleted.code, 0, JSON.stringify(deleted.data))
        assert.equal(deleted.data.status, 'accepted')
        assert.equal((await wait(deleted.data)).data.status, 'success')
      }
      const remaining = await command(['get', contentPath, ...node, '--api-storage', 'archive', '--fields', 'volid'])
      assert.deepEqual(remaining.data.data, initial.map(volid => ({ volid })))
    })
    await t.test(`${release.name} backup task failure remains failed without retry`, async () => {
      const preview = await command([...backup, '--preview'])
      failNext = true
      requests.length = 0
      const result = await command([...backup, '--confirm', preview.data.confirmation])
      assert.equal(result.data.status, 'accepted')
      const failed = await wait(result.data)
      assert.equal(failed.code, 1)
      assert.equal(failed.data.status, 'failed')
      assert.equal(requests.filter(row => row.startsWith('POST')).length, 1)
      assert.equal((await command(['journal', 'show', result.data.id])).data.journal.status, 'failed')
    })
    await t.test(`${release.name} protected backup rejection preserves the volume`, async () => {
      volumes.set(archives[0]!, true)
      const args = ['delete', deletePath, ...node, '--api-storage', 'archive', '--api-volume', archives[0]!]
      const preview = await command([...args, '--preview'])
      requests.length = 0
      const result = await command([...args, '--confirm', preview.data.confirmation])
      assert.equal(result.code, 1)
      assert.equal((await command(['journal', 'show', preview.data.id])).data.journal.status, 'failed')
      assert.equal(requests.filter(row => row.startsWith('DELETE')).length, 1)
      const listed = await command(['get', contentPath, ...node, '--api-storage', 'archive', '--api-content', 'backup', '--fields', 'volid,protected'])
      assert.deepEqual(listed.data.data, [{ volid: archives[0], protected: true }])
      volumes.delete(archives[0]!)
    })
  }
  const valid = { node: 'node-a', vmid: '100,101', storage: 'archive' }
  for (const values of [
    { node: 'node-a', storage: 'archive' }, { node: 'node-a', vmid: '100' }, { vmid: '100', storage: 'archive' },
    { ...valid, all: true }, { ...valid, script: '/hook' }, { ...valid, dumpdir: '/destination' },
    { ...valid, 'prune-backups': 'keep-last=1' }, { ...valid, remove: true }, { ...valid, vmid: '99' },
  ]) await t.test(`refuses unreviewed backup inputs ${JSON.stringify(values)}`, async () => {
    const body = join(scratch, 'refused.json')
    await writeFile(body, JSON.stringify(values), { mode: 0o600 })
    requests.length = 0
    const refused = await command(['create', backupPath, '--body-file', body, '--preview'])
    assert.notEqual(refused.code, 0)
    assert.deepEqual(requests, [])
  })
  for (const volume of [initial[0]!, initial[1]!, `${archives[0]}.notes`, 'pbs:backup/host/server/2026-11-03T06:00:00Z']) await t.test(`refuses non-guest-backup volume ${volume}`, async () => {
    requests.length = 0
    const refused = await command(['delete', deletePath, ...node, '--api-storage', 'archive', '--api-volume', volume, '--preview'])
    assert.notEqual(refused.code, 0)
    assert.deepEqual(requests, [])
  })
  for (const args of [
    ['delete', deletePath, ...node, '--api-volume', archives[0]!],
    ['delete', deletePath, ...node, '--api-storage', 'archive', '--api-volume', archives[0]!, '--api-delay', '1'],
  ]) await t.test(`refuses unreviewed delete input ${args[args.length - 2]}`, async () => {
    requests.length = 0
    const refused = await command([...args, '--preview'])
    assert.notEqual(refused.code, 0)
    assert.deepEqual(requests, [])
  })
})

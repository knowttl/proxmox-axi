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
import { Ajv } from 'ajv'

const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PROXMOX_AXI_')))
const canary = 'CANARY-private-backup-credential', extractPath = '/nodes/{node}/vzdump/extractconfig'

for (const family of ['qemu', 'lxc']) test(`${family} restores use reviewed sources, private inspection and retained task outcomes`, async t => {
  const qemu = family === 'qemu', createPath = `/nodes/{node}/${family}`, configPath = `${createPath}/{vmid}/config`
  const archive = `backups:backup/vzdump-${family}-100-2026_11_03-06_00_00.${qemu ? 'vma' : 'tar'}.zst`
  const pbs = `pbs:backup/${qemu ? 'vm' : 'ct'}/100/2026-11-03T06:00:00Z`
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-restore-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  const saved: Record<string, unknown> = { digest: '0123456789012345678901234567890123456789', memory: qemu ? '1024' : 1024,
    [qemu ? 'cipassword' : 'password']: canary, ...(qemu ? {} : { unprivileged: 1 }) }
  const text = `memory: 1024\n${qemu ? 'cipassword' : 'password'}: ${canary}\n${qemu ? '' : 'unprivileged: 1\n'}`
  const guests = new Map<number, Record<string, unknown>>([[100, { ...saved }]])
  const tasks = new Map<string, { id: number, failed: boolean, config: Record<string, unknown> }>()
  const requests: string[] = []
  let version = '8.2.7', sequence = 0, failNext = false, malformed = false
  let batchMode = 'success'
  const batchUpid = 'UPID:node-a:00000001:00000001:00000001:qmstart:100:synthetic@pve:'
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), path = url.pathname
    requests.push(`${request.method} ${path}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (path.endsWith('/vzdump/extractconfig')) {
      assert.ok([archive, pbs].includes(url.searchParams.get('volume')!))
      response.end(JSON.stringify({ data: malformed ? { password: canary } : text })); return
    }
    if (request.method === 'POST') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString())), id = Number(body.vmid)
      if (path.endsWith('/execute')) {
        type Command = { method: string, path: string, args?: { commands?: string, volume?: string } }
        const apply = (commands: Command[]): unknown[] => commands.map(child => {
          if (child.path === 'execute') return { status: 200, data: apply(JSON.parse(child.args!.commands!)) }
          if (child.method === 'GET') {
            assert.equal(child.path, 'vzdump/extractconfig')
            assert.equal(child.args?.volume, archive)
            return batchMode === 'refused-read' ? { status: 403 } : { status: 200, data: batchMode === 'invalid-read' ? { password: canary } : text }
          }
          assert.equal(child.method, 'POST')
          assert.equal(child.path, 'qemu/100/status/start')
          return { status: 200, data: batchMode === 'invalid-upid' ? 'invalid-task' : batchUpid }
        })
        response.end(JSON.stringify({ data: apply(JSON.parse(body.commands!)) })); return
      }
      if (guests.has(id)) { response.writeHead(400).end(JSON.stringify({ message: 'VMID already exists' })); return }
      assert.ok([archive, pbs].includes(body[qemu ? 'archive' : 'ostemplate']!))
      assert.equal(body.storage, 'local-lvm')
      assert.equal(body.unique, '1')
      assert.equal(body.start, '0')
      assert.equal(body.bwlimit, '1024')
      assert.equal(body.force, undefined)
      if (!qemu) { assert.equal(body.restore, '1'); assert.equal(body.unprivileged, '1') }
      const upid = `UPID:node-a:${(++sequence).toString(16).padStart(8, '0')}:00000001:00000001:${qemu ? 'qm' : 'vz'}restore:${id}:synthetic@pve:`
      tasks.set(upid, { id, failed: failNext, config: { ...saved, memory: qemu ? body.memory : Number(body.memory),
        [qemu ? 'scsi0' : 'rootfs']: `local-lvm:${qemu ? 'vm' : 'subvol'}-${id}-disk-0,size=8G` } })
      failNext = false
      response.end(JSON.stringify({ data: upid })); return
    }
    const task = /\/tasks\/([^/]+)\/status$/.exec(path)
    if (task) {
      const upid = decodeURIComponent(task[1]!), pending = tasks.get(upid)!
      if (!pending.failed) guests.set(pending.id, pending.config)
      response.end(JSON.stringify({ data: { node: 'node-a', upid, id: String(pending.id), pid: sequence, pstart: 1, starttime: 1,
        type: `${qemu ? 'qm' : 'vz'}restore`, user: 'synthetic@pve', status: 'stopped', exitstatus: pending.failed ? 'ERROR: restore storage unavailable' : 'OK' } })); return
    }
    const guest = /\/(?:qemu|lxc)\/(\d+)\/config$/.exec(path)
    if (!guest) { response.writeHead(404).end(); return }
    response.end(JSON.stringify({ data: guests.get(Number(guest[1])) }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!test', token: { env: 'RESTORE_TOKEN' }, writes: { operations: [
      ...[['POST', createPath], ['POST', '/nodes/{node}/execute'], ['GET', extractPath], ['POST', '/nodes/{node}/qemu/{vmid}/status/start']].map(([method, path]) =>
        `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`),
    ] },
  } } }), { mode: 0o600 })
  const command = async (args: string[], privateResult = false) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, RESTORE_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: log, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' },
      stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', frame = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { frame = Buffer.concat([frame, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal((stdout + stderr).includes(canary), false)
    if (frame.length) assert.equal(frame.readUInt32BE(0), frame.length - 4)
    return { code, data: JSON.parse(stdout), payload: frame.length ? JSON.parse(frame.subarray(4).toString()).payload : undefined }
  }
  const node = ['--api-node', 'node-a'], sourceName = qemu ? 'archive' : 'ostemplate'
  const values = { node: 'node-a', vmid: 200, storage: 'local-lvm', [sourceName]: archive, ...(!qemu ? { restore: true } : {}), memory: qemu ? '2048' : 2048, unique: true, start: false, bwlimit: 1024 }
  const args = ['create', createPath, ...node, '--api-vmid', '200', '--api-storage', 'local-lvm', `--api-${sourceName}`, archive,
    ...(!qemu ? ['--api-restore', '1'] : []), '--api-memory', '2048', '--api-unique', '1', '--api-start', '0', '--api-bwlimit', '1024']
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    if (qemu) await t.test(`${release.name} refuses restore drives while preserving ordinary creation`, async () => {
      const schema = await command(['schema', 'create', createPath, '--catalogue', release.name])
      const validate = new Ajv({ strict: false }).compile(schema.data.invocation.schema)
      for (const [prefix, count] of [['ide', 4], ['sata', 6], ['scsi', 31], ['virtio', 16]] as const) {
        for (let index = 0; index < count; index++) {
          const slot = `${prefix}${index}`
          assert.equal(validate({ api: { ...values, [slot]: 'local-lvm:8' } }), false, slot)
          assert.equal(validate({ api: { node: 'node-a', vmid: 200, [slot]: 'local-lvm:8' } }), true, slot)
        }
      }
      for (const [slot, value] of [
        ['ide0', 'local-lvm:8'], ['ide3', 'local-lvm:8'], ['sata0', 'local-lvm:8'], ['sata5', 'local-lvm:8'],
        ['scsi0', 'local-lvm:8'], ['scsi30', 'local-lvm:8'], ['virtio0', 'local-lvm:8'], ['virtio15', 'local-lvm:8'],
        ['ide2', 'local:iso/installer.iso,media=cdrom'], ['ide2', 'local-lvm:cloudinit'],
      ]) {
        assert.equal(validate({ api: { ...values, [slot!]: value } }), false)
        requests.length = 0
        const refused = await command([...args, `--api-${slot}`, value!, '--preview'])
        assert.equal(refused.data.error.code, 'INVALID_INPUT')
        assert.equal(requests.length, 0)
        const created = await command(['create', createPath, ...node, '--api-vmid', '200', `--api-${slot}`, value!, '--preview'])
        assert.equal(created.code, 0, JSON.stringify(created.data))
        assert.equal(created.data.status, 'preview')
        assert.equal(requests.some(row => row.startsWith('POST')), false)
      }
    })
    if (qemu) for (const nested of [false, true]) for (const mode of ['success', 'invalid-read', 'refused-read', 'accepted', 'invalid-upid']) {
      await t.test(`${release.name} ${nested ? 'nested' : 'flat'} private backup batch ${mode}`, async () => {
        batchMode = mode
        const children = [{ method: 'GET', path: 'vzdump/extractconfig', args: { volume: archive } },
          ...(['accepted', 'invalid-upid'].includes(mode) ? [{ method: 'POST', path: 'qemu/100/status/start' }] : [])]
        const commands = JSON.stringify(nested ? [{ method: 'POST', path: 'execute', args: { commands: JSON.stringify(children) } }] : children)
        const call = ['create', '/nodes/{node}/execute', ...node, '--api-commands', commands]
        const preview = await command([...call, '--preview'])
        assert.equal(preview.code, 0, JSON.stringify(preview.data))
        requests.length = 0
        const missing = await command([...call, '--confirm', preview.data.confirmation])
        assert.equal(missing.data.error.code, 'PRIVATE_SINK_REQUIRED')
        assert.equal(requests.length, 0)
        const result = await command([...call, '--confirm', preview.data.confirmation], true)
        const expected = mode === 'invalid-read' || mode === 'invalid-upid' ? 'uncertain' : mode === 'refused-read' ? 'failed' : mode
        assert.equal(result.code, ['success', 'accepted'].includes(expected) ? 0 : 1, JSON.stringify(result.data))
        assert.equal(result.data.status, expected)
        const leaf = nested ? result.data.children[0].children : result.data.children
        assert.equal(leaf[0].status, mode === 'invalid-read' ? 'uncertain' : mode === 'refused-read' ? 'failed' : 'success')
        if (mode === 'accepted') assert.equal(leaf[1].upid, batchUpid)
        if (mode === 'invalid-upid') assert.equal(leaf[1].status, 'uncertain')
        const payload = nested ? result.payload[0].data : result.payload
        if (mode !== 'refused-read' && mode !== 'invalid-read') assert.equal(payload[0].data, text)
        const retained = await command(['journal', 'show', result.data.id])
        assert.equal(retained.data.journal.status, expected)
        assert.deepEqual(retained.data.journal.children, result.data.children)
        assert.equal(requests.filter(row => row.startsWith('POST')).length, 1)
      })
    }
    for (const source of [archive, pbs]) await t.test(`${release.name} restores ${source.split(':')[0]} to a new guest after private inspection and task completion`, async () => {
      guests.delete(200)
      const inspected = await command(['get', extractPath, ...node, '--api-volume', source], true)
      assert.equal(inspected.code, 0, JSON.stringify(inspected.data))
      assert.equal(inspected.payload, text)
      const schema = await command(['schema', 'create', createPath, '--catalogue', release.name])
      const validate = new Ajv({ strict: false }).compile(schema.data.invocation.schema)
      assert.equal(validate({ api: { ...values, [sourceName]: source } }), true)
      const { storage: _storage, ...withoutStorage } = values
      assert.equal(validate({ api: withoutStorage }), false)
      const call = args.map(value => value === archive ? source : value)
      requests.length = 0
      const preview = await command([...call, '--preview'])
      assert.equal(preview.code, 0, JSON.stringify(preview.data))
      assert.equal(requests.some(row => row.startsWith('POST')), false)
      const changedSource = await command([...call.map(value => value === source ? source === archive ? pbs : archive : value), '--confirm', preview.data.confirmation])
      assert.equal(changedSource.data.error.code, 'CONFIRMATION_MISMATCH')
      const changedStorage = await command([...call.map(value => value === 'local-lvm' ? 'other-storage' : value), '--confirm', preview.data.confirmation])
      assert.equal(changedStorage.data.error.code, 'CONFIRMATION_MISMATCH')
      assert.equal(requests.some(row => row.startsWith('POST')), false)
      const result = await command([...call, '--confirm', preview.data.confirmation])
      assert.equal(result.code, 0, JSON.stringify(result.data))
      assert.equal(result.data.status, 'accepted')
      const completed = await command(['task', 'wait', '--api-node', result.data.node, '--api-upid', result.data.upid, '--journal', result.data.id])
      assert.equal(completed.code, 0, JSON.stringify(completed.data))
      assert.equal(completed.data.status, 'success')
      const observed = await command(['get', configPath, ...node, '--api-vmid', '200'], true)
      assert.equal(observed.code, 0, JSON.stringify(observed.data))
      assert.equal(observed.payload.memory, qemu ? '2048' : 2048)
      assert.equal(observed.payload[qemu ? 'cipassword' : 'password'], canary)
      assert.equal(observed.payload[qemu ? 'scsi0' : 'rootfs'], `local-lvm:${qemu ? 'vm' : 'subvol'}-200-disk-0,size=8G`)
      if (!qemu) assert.equal(observed.payload.unprivileged, 1)
    })
    await t.test(`${release.name} records failed restore task without retry`, async () => {
      guests.delete(200)
      const preview = await command([...args, '--preview'])
      failNext = true
      requests.length = 0
      const result = await command([...args, '--confirm', preview.data.confirmation])
      assert.equal(result.data.status, 'accepted')
      const failed = await command(['task', 'wait', '--api-node', result.data.node, '--api-upid', result.data.upid, '--journal', result.data.id])
      assert.equal(failed.code, 1)
      assert.equal(failed.data.status, 'failed')
      assert.equal((await command(['journal', 'show', result.data.id])).data.journal.status, 'failed')
      assert.equal(requests.filter(row => row.startsWith('POST')).length, 1)
    })
    await t.test(`${release.name} refuses existing-ID overwrite and preserves the guest`, async () => {
      const collision = args.map(value => value === '200' ? '100' : value)
      const collisionPreview = await command([...collision, '--preview'])
      const rejected = await command([...collision, '--confirm', collisionPreview.data.confirmation])
      assert.equal(rejected.code, 1)
      assert.equal((await command(['journal', 'show', collisionPreview.data.id])).data.journal.status, 'failed')
      const existing = await command(['get', configPath, ...node, '--api-vmid', '100'], true)
      assert.equal(existing.code, 0, JSON.stringify(existing.data))
      assert.deepEqual(existing.payload, saved)
    })
  }
  await t.test('backup config requires its private pipe before provider access', async () => {
    requests.length = 0
    const missing = await command(['get', extractPath, ...node, '--api-volume', archive])
    assert.equal(missing.data.error.code, 'PRIVATE_SINK_REQUIRED')
    assert.deepEqual(requests, [])
  })
  await t.test('backup config validates returned text before private delivery', async () => {
    malformed = true
    const invalid = await command(['get', extractPath, ...node, '--api-volume', archive], true)
    assert.equal(invalid.data.error.code, 'INVALID_RESPONSE')
    assert.equal(invalid.payload, undefined)
    malformed = false
  })
  await t.test('backup config refuses host paths before provider access', async () => {
    requests.length = 0
    const invalid = await command(['get', extractPath, ...node, '--api-volume', '/host/backup'], true)
    assert.notEqual(invalid.code, 0)
    assert.deepEqual(requests, [])
  })
  for (const input of [
    { ...values, force: true }, { ...values, [sourceName]: '-' }, { ...values, [sourceName]: '/host/backup' },
    { ...values, [sourceName]: qemu ? 'pbs:backup/ct/100/2026-11-03T06:00:00Z' : 'pbs:backup/vm/100/2026-11-03T06:00:00Z' },
    ...(qemu ? [{ ...values, 'live-restore': true }, { node: 'node-a', vmid: 200, storage: 'local-lvm' }] :
      [{ ...values, restore: false }, { ...values, unprivileged: false }, { ...values, ostemplate: 'local:vztmpl/base.tar.zst' }, { node: 'node-a', vmid: 200, storage: 'local-lvm', ostemplate: archive }]),
    { node: 'node-a', vmid: 200, [sourceName]: archive, ...(!qemu ? { restore: true } : {}) },
  ]) await t.test(`refuses unsafe or incomplete restore ${JSON.stringify(input)}`, async () => {
    const body = join(scratch, 'invalid.json')
    await writeFile(body, JSON.stringify(input), { mode: 0o600 })
    requests.length = 0
    const result = await command(['create', createPath, '--body-file', body, '--preview'])
    assert.notEqual(result.code, 0)
    assert.deepEqual(requests, [])
  })
  const records = await Promise.all((await readdir(`${log}.d`)).filter(name => name.endsWith('.json')).map(name => readFile(join(`${log}.d`, name), 'utf8')))
  assert.equal(records.join('').includes(canary), false)
})

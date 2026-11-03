import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Readable } from 'node:stream'
import test from 'node:test'
import { Ajv } from 'ajv'

const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PROXMOX_AXI_')))
const canary = 'CANARY-new-guest-password'
const digest = '0123456789012345678901234567890123456789'
const publicKey = await readFile(new URL('../../test/fixtures/ssh-public-key.pub', import.meta.url), 'utf8')

for (const family of ['qemu', 'lxc']) test(`${family} provisioning retains task acceptance, completion and failure`, async t => {
  const qemu = family === 'qemu', createPath = `/nodes/{node}/${family}`, clonePath = `${createPath}/{vmid}/clone`
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-qemu-provision-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  const guests = new Map<number, Record<string, unknown>>()
  const locations = new Map<number, string>()
  const tasks = new Map<string, { id: number, pid: number, node: string, config: Record<string, unknown>, failed: boolean }>()
  const requests: string[] = []
  let version = '8.2.7', failNext = false, sequence = 0
  const template = qemu ? { digest, template: 1, name: 'base-template', memory: '2048', cores: 2, scsi0: 'local-lvm:vm-100-disk-0,size=8G' } :
    { digest, template: 1, hostname: 'base-template', memory: 2048, cores: 2, unprivileged: 1, rootfs: 'local-lvm:subvol-100-disk-0,size=8G' }
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const path = request.url!.split('?')[0]!
    requests.push(`${request.method} ${path}`)
    if (request.method === 'POST') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))
      const id = Number(body.newid ?? body.vmid), source = /\/(?:qemu|lxc)\/(\d+)\/clone$/.exec(path)
      if (guests.has(id)) { response.statusCode = 400; response.end(JSON.stringify({ message: 'VMID already exists' })); return }
      if (!qemu && !source && (body.unprivileged !== '1' || body.password !== canary || body['ssh-public-keys'] !== publicKey)) {
        response.statusCode = 400; response.end(JSON.stringify({ message: 'Missing unprivileged onboarding inputs' })); return
      }
      const config: Record<string, unknown> = source ? { ...guests.get(Number(source[1])), template: 0, [qemu ? 'name' : 'hostname']: body[qemu ? 'name' : 'hostname'] } :
        { ...body, digest, cores: Number(body.cores), ...(qemu ? { scsi0: `local-lvm:vm-${id}-disk-0,size=8G` } :
          { memory: Number(body.memory), swap: Number(body.swap), unprivileged: Number(body.unprivileged), rootfs: `local-lvm:subvol-${id}-disk-0,size=8G` }) }
      delete config.vmid
      delete config.password
      delete config['ssh-public-keys']
      delete config.ostemplate
      sequence++
      const upid = `UPID:node-a:${sequence.toString(16).padStart(8, '0')}:00000001:00000001:${qemu ? 'qm' : 'vz'}${source ? 'clone' : 'create'}:${id}:synthetic@pve:`
      tasks.set(upid, { id, pid: sequence, node: body.target ?? 'node-a', config, failed: failNext })
      failNext = false
      response.end(JSON.stringify({ data: upid }))
      return
    }
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    const task = /\/tasks\/([^/]+)\/status$/.exec(path)
    if (task) {
      const upid = decodeURIComponent(task[1]!), current = tasks.get(upid)!
      if (!current.failed) { guests.set(current.id, current.config); locations.set(current.id, current.node) }
      response.end(JSON.stringify({ data: { node: 'node-a', upid, id: String(current.id), pid: current.pid, pstart: 1, starttime: 1,
        type: `${qemu ? 'qm' : 'vz'}${upid.includes('clone:') ? 'clone' : 'create'}`, user: 'synthetic@pve', status: 'stopped', exitstatus: current.failed ? 'ERROR: storage unavailable' : 'OK' } }))
      return
    }
    const selected = /\/nodes\/([^/]+)\/(?:qemu|lxc)\/(\d+)\/config$/.exec(path), id = Number(selected?.[2])
    const data = locations.get(id) === selected?.[1] ? guests.get(id) : undefined
    if (!data) response.statusCode = 404
    response.end(JSON.stringify({ data: data ?? null }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, tokenId: 'synthetic@pve!test',
    token: { env: 'PROVISION_TOKEN' }, caBundle: caFile, writes: { operations: [createPath, clonePath].map(path =>
      `OP-POST-${createHash('sha256').update(`POST ${path}`).digest('hex').slice(0, 10)}`) },
  } } }), { mode: 0o600 })
  const command = async (args: string[], privateResult = false) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, PROVISION_TOKEN: 'synthetic-token', VM_INITIAL_PASSWORD: canary, PROXMOX_AXI_WRITE_LOG: join(scratch, 'writes.log'),
        PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' }, stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', frame = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { frame = Buffer.concat([frame, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal((stdout + stderr).includes(canary), false)
    if (frame.length) assert.equal(frame.readUInt32BE(0), frame.length - 4)
    return { code, data: JSON.parse(stdout), stderr, payload: frame.length ? JSON.parse(frame.subarray(4).toString()).payload : undefined }
  }
  const body = join(scratch, 'new-vm.json')
  const settings = qemu ? { name: 'new-guest', cores: 2, memory: '2048', cpu: 'x86-64-v2-AES', scsihw: 'virtio-scsi-single', ostype: 'l26', bios: 'seabios',
    scsi0: 'local-lvm:8', ide2: 'local:iso/installer.iso,media=cdrom', net0: 'virtio,bridge=vmbr0', boot: 'order=ide2;scsi0', agent: '1',
    ciuser: 'deployer', cipassword: { env: 'VM_INITIAL_PASSWORD' } } :
    { hostname: 'new-guest', cores: 2, memory: 2048, swap: 512, ostemplate: 'local:vztmpl/base.tar.zst', rootfs: 'local-lvm:8',
      net0: 'name=eth0,bridge=vmbr0,ip=dhcp,type=veth', password: { env: 'VM_INITIAL_PASSWORD' }, 'ssh-public-keys': publicKey }
  await writeFile(body, JSON.stringify(settings), { mode: 0o600 })
  const createArgs = ['create', createPath, '--api-node', 'node-a', '--api-vmid', '200', '--body-file', body]
  const cloneArgs = ['create', clonePath, '--api-node', 'node-a', '--api-vmid', '100', '--api-newid', '201', qemu ? '--api-name' : '--api-hostname', 'cloned-guest', '--api-full', '1', '--api-storage', 'local-lvm',
    ...(qemu ? ['--api-format', 'raw'] : []), '--api-target', 'node-b']
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    guests.clear()
    guests.set(100, { ...template })
    locations.set(100, 'node-a')
    for (const { label, args, id, name, destination, password } of [
      { label: 'create', args: createArgs, id: 200, name: 'new-guest', destination: 'node-a', password: qemu ? canary : undefined },
      { label: 'clone', args: cloneArgs, id: 201, name: 'cloned-guest', destination: 'node-b', password: undefined },
    ]) {
      await t.test(`${release.name} ${label} confirms provisioning, waits for UPID and reads private configuration`, async () => {
        const source = await command(['get', `${createPath}/{vmid}/config`, '--api-node', 'node-a', '--api-vmid', '100'], true)
        assert.equal(source.code, 0, JSON.stringify(source.data))
        assert.equal(source.payload.template, 1)
        const schema = await command(['schema', 'create', label === 'create' ? createPath : clonePath, '--catalogue', release.name])
        assert.equal(schema.code, 0, schema.stderr)
        const validate = new Ajv({ strict: false }).compile(schema.data.invocation.schema)
        assert.equal(validate({ api: label === 'create' ? { node: 'node-a', vmid: id, ...settings } : { node: 'node-a', vmid: 100, newid: id, full: true } }), true)
        if (!qemu && label === 'create') {
          assert.equal(schema.data.invocation.schema.properties.api.properties.unprivileged.default, true)
          assert.equal(validate({ api: { node: 'node-a', vmid: id, ...settings, unprivileged: false } }), false)
        }
        requests.length = 0
        const preview = await command([...args, '--preview'])
        assert.equal(preview.code, 0, JSON.stringify(preview.data))
        assert.equal(requests.some(request => request.startsWith('POST')), false)
        const changed = await command([...args.map(value => value === String(id) ? String(id + 100) : value), '--confirm', preview.data.confirmation])
        assert.equal(changed.data.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(requests.some(request => request.startsWith('POST')), false)
        const result = await command([...args, '--confirm', preview.data.confirmation])
        assert.equal(result.code, 0, JSON.stringify(result.data))
        assert.equal(result.data.status, 'accepted')
        assert.equal(result.data.node, 'node-a')
        const completed = await command(['task', 'wait', '--api-node', result.data.node, '--api-upid', result.data.upid, '--journal', result.data.id])
        assert.equal(completed.code, 0, JSON.stringify(completed.data))
        assert.equal(completed.data.status, 'success')
        const observed = await command(['get', `${createPath}/{vmid}/config`, '--api-node', destination, '--api-vmid', String(id)], true)
        assert.equal(observed.code, 0, JSON.stringify(observed.data))
        assert.equal(observed.payload[qemu ? 'name' : 'hostname'], name)
        assert.equal(observed.payload.cores, 2)
        assert.equal(observed.payload.memory, qemu ? '2048' : 2048)
        assert.equal(observed.payload.cipassword, password)
        if (!qemu) assert.equal(observed.payload.unprivileged, 1)
      })
      await t.test(`${release.name} ${label} task failure is retained as failed rather than completed`, async () => {
        guests.delete(id)
        const preview = await command([...args, '--preview'])
        assert.equal(preview.code, 0)
        failNext = true
        const result = await command([...args, '--confirm', preview.data.confirmation])
        assert.equal(result.data.status, 'accepted')
        const failed = await command(['task', 'wait', '--api-node', result.data.node, '--api-upid', result.data.upid, '--journal', result.data.id])
        assert.equal(failed.code, 1)
        assert.equal(failed.data.status, 'failed')
        const journal = await command(['journal', 'show', result.data.id])
        assert.equal(journal.data.journal.status, 'failed')
      })
    }
    await t.test(`${release.name} existing VMID rejection preserves the template`, async () => {
      const args = createArgs.map(value => value === '200' ? '100' : value)
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0)
      const result = await command([...args, '--confirm', preview.data.confirmation])
      assert.equal(result.code, 1)
      const journal = await command(['journal', 'show', preview.data.id])
      assert.equal(journal.data.journal.status, 'failed')
      const source = await command(['get', `${createPath}/{vmid}/config`, '--api-node', 'node-a', '--api-vmid', '100'], true)
      assert.equal(source.code, 0, JSON.stringify(source.data))
      assert.deepEqual(source.payload, template)
    })
  }
  for (const { path, field, value } of [
    ...(qemu ? [{ path: createPath, field: 'archive', value: 'backup.vma' }, { path: createPath, field: 'args', value: 'unreviewed' }, { path: createPath, field: 'efidisk0', value: 'local-lvm:1' }] :
      [{ path: createPath, field: 'restore', value: '1' }, { path: createPath, field: 'unprivileged', value: '0' }, { path: createPath, field: 'features', value: 'nesting=1' },
        { path: createPath, field: 'rootfs', value: '/host/path' }, { path: createPath, field: 'ostemplate', value: 'local:backup/archive.tar.zst' },
        { path: createPath, field: 'ssh-public-keys', value: `${publicKey}command="run" ${publicKey}` },
        { path: createPath, field: 'password', value: 'literal-password' }, { path: createPath, field: 'description', value: 'line one\nline two' }]),
    { path: createPath, field: 'force', value: '1' },
    { path: clonePath, field: 'snapname', value: 'snapshot' },
  ]) {
    await t.test(`refuses unreviewed ${path} ${field} before provider access`, async () => {
      const invalid = join(scratch, 'invalid.json')
      const base = path === createPath ? settings : { newid: 300, full: true }
      const input = ['unprivileged', 'force', 'restore'].includes(field) ? value === '1' : value
      await writeFile(invalid, JSON.stringify({ ...base, [field]: input }), { mode: 0o600 })
      requests.length = 0
      const result = await command(['create', path, '--api-node', 'node-a', '--api-vmid', '300', '--body-file', invalid, '--preview'])
      assert.notEqual(result.code, 0)
      assert.deepEqual(requests, [])
    })
  }
})

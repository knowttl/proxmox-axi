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
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const hash = (value: string) => createHash('sha256').update(value).digest('hex')
const configPath = (family: string) => `/nodes/{node}/${family}/{vmid}/config`
const canary = 'CANARY-private-guest-credential'
const cloudPassword = 'CANARY-cloud-init+password/with space'
const publicKey = (await readFile(new URL('../../test/fixtures/ssh-public-key.pub', import.meta.url), 'utf8')).trimEnd()
const digest = '0123456789012345678901234567890123456789'
const releases = [{ release: 'legacy-8.2.7', version: '8.2.7' }, { release: 'published-current', version: '9.2.1' }]
const guests = [
  { family: 'qemu', initial: { digest, memory: '512', cipassword: canary }, settings: {
    cores: 4, sockets: 2, vcpus: 6, memory: 'current=2048', balloon: 1024, cpu: 'cputype=x86-64-v2-AES',
    cpulimit: 2.5, cpuunits: 100, onboot: 1, startup: 'order=2,up=10,down=15', name: 'guest-01', description: 'managed guest',
  } },
  { family: 'lxc', initial: { digest, memory: 512, password: canary }, settings: {
    cores: 2, memory: 2048, swap: 512, cpulimit: 1.5, cpuunits: 200, onboot: 1,
    startup: 'up=10,down=15', hostname: 'container-01', description: 'managed container',
  } },
]

test('guest settings use private reads and confirmed configuration writes', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-guest-settings-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', malformed = false, rejectCloudPassword = false, imagePassword = canary
  const requests: { method: string, path: string }[] = []
  const state: Record<string, Record<string, unknown>> = Object.fromEntries(guests.map(guest => [guest.family, { ...guest.initial }]))
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    requests.push({ method: request.method!, path: request.url! })
    const family = request.url!.includes('/lxc/') ? 'lxc' : 'qemu'
    if (request.method === 'PUT') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const inputs = new URLSearchParams(Buffer.concat(chunks).toString())
      if (rejectCloudPassword && inputs.has('cipassword')) {
        response.statusCode = 400
        response.end(JSON.stringify({ message: `Rejected ${cloudPassword} ${encodeURIComponent(cloudPassword)} ${Buffer.from(cloudPassword).toString('base64')}` }))
        return
      }
      if (request.url!.endsWith('/cloudinit')) imagePassword = String(state.qemu!.cipassword)
      for (const [name, value] of inputs) {
        if (name === 'delete') { for (const slot of value.split(',')) delete state[family]![slot]; continue }
        state[family]![name] = ['cores', 'sockets', 'vcpus', 'balloon', 'swap', 'cpulimit', 'cpuunits', 'onboot'].includes(name) || (name === 'memory' && family === 'lxc') ? Number(value) : value
      }
      response.end(JSON.stringify({ data: null }))
      return
    }
    const data = request.url!.endsWith('/version') ? { version, release: 'synthetic', repoid: 'synthetic' } :
      request.url!.endsWith('/config') ? malformed ? { digest: 123, password: canary } : state[family] :
      request.url!.endsWith('/pending') ? [{ key: malformed ? 123 : 'cipassword', value: canary, pending: `${canary}-pending` }] :
      request.url!.endsWith('/cloudinit') ? [{ key: malformed ? 123 : 'cipassword', value: imagePassword,
        ...(imagePassword !== state.qemu!.cipassword ? { pending: String(state.qemu!.cipassword) } : {}) }] :
      { ha: {}, status: 'running', vmid: malformed ? '100' : 100, cpus: 2, maxmem: 536870912 }
    response.end(JSON.stringify({ data }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`
  const config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin, tokenId: 'synthetic@pve!test', token: { env: 'GUEST_SETTINGS_TOKEN' }, caBundle: caFile,
    writes: { operations: [...['qemu', 'lxc'].map(family => `OP-PUT-${hash(`PUT ${configPath(family)}`).slice(0, 10)}`),
      `OP-PUT-${hash('PUT /nodes/{node}/qemu/{vmid}/cloudinit').slice(0, 10)}`] },
  } } }), { mode: 0o600 })
  const command = async (args: string[], privateResult = false) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, GUEST_SETTINGS_TOKEN: 'synthetic-token', CLOUD_INIT_PASSWORD: cloudPassword, PROXMOX_AXI_WRITE_LOG: log, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' },
      stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', bytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { bytes = Buffer.concat([bytes, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    let frame: { binding: Record<string, string>, payload: unknown } | undefined
    if (bytes.length) {
      assert.equal(bytes.readUInt32BE(0), bytes.length - 4)
      frame = JSON.parse(bytes.subarray(4).toString()) as typeof frame
    }
    return { code, stdout, stderr, frame }
  }
  const target = ['--api-node', 'node-a', '--api-vmid', '100']
  for (const contract of releases) for (const family of ['qemu', 'lxc']) {
    const { release } = contract
    version = contract.version
    for (const { suffix, expected } of [
      { suffix: 'config', expected: state[family] },
      { suffix: 'pending', expected: [{ key: 'cipassword', value: canary, pending: `${canary}-pending` }] },
      ...(family === 'qemu' ? [{ suffix: 'cloudinit', expected: [{ key: 'cipassword', value: canary }] }] : []),
    ]) {
      const path = `/nodes/{node}/${family}/{vmid}/${suffix}`
      await t.test(`${release} ${family} ${suffix} requires a private pipe before network access`, async () => {
        requests.length = 0
        const result = await command(['get', path, ...target])
        assert.equal(result.code, 1, result.stderr)
        assert.equal(JSON.parse(result.stdout).error.code, 'PRIVATE_SINK_REQUIRED')
        assert.deepEqual(requests, [])
      })
      await t.test(`${release} ${family} ${suffix} delivers protected values only privately`, async () => {
        const result = await command(['get', path, ...target, '--catalogue', release, '--full'], true)
        assert.equal(result.code, 0, result.stdout + result.stderr)
        assert.deepEqual(JSON.parse(result.stdout).data, { privateResult: true })
        assert.doesNotMatch(result.stdout + result.stderr, /CANARY-private-guest-credential/)
        assert.deepEqual(result.frame?.payload, expected)
        assert.equal(result.frame?.binding.origin, origin)
        assert.equal(result.frame?.binding.identity, 'synthetic@pve!test')
        assert.equal(result.frame?.binding.operation, `OP-GET-${hash(`GET ${path}`).slice(0, 10)}`)
        assert.equal(result.frame?.binding.request, hash(`${release} /api2/json/nodes/node-a/${family}/100/${suffix}`))
      })
      await t.test(`${release} ${family} ${suffix} rejects malformed protected responses without delivery`, async () => {
        malformed = true
        const result = await command(['get', path, ...target, '--catalogue', release], true)
        malformed = false
        assert.equal(result.code, 1, result.stderr)
        assert.equal(JSON.parse(result.stdout).error.code, 'INVALID_RESPONSE')
        assert.equal(result.frame, undefined)
        assert.doesNotMatch(result.stdout + result.stderr, /CANARY-private-guest-credential/)
      })
    }
    await t.test(`${release} ${family} status is an ordinary bounded read`, async () => {
      const result = await command(['get', `/nodes/{node}/${family}/{vmid}/status/current`, ...target])
      assert.equal(result.code, 0, result.stderr)
      assert.deepEqual(JSON.parse(result.stdout).data, { ha: {}, status: 'running', vmid: 100, cpus: 2, maxmem: 536870912 })
      assert.equal(JSON.parse(result.stdout).compatibility.catalogue, release)
    })
  }
  await assert.rejects(readdir(`${log}.d`), { code: 'ENOENT' })
  for (const contract of releases) {
    await t.test(`${contract.release} onboards cloud-init and regenerates media without exposing password inputs`, async () => {
      version = contract.version
      state.qemu = { ...guests[0]!.initial }
      imagePassword = canary
      const settings = { ciuser: 'deployer', cipassword: { env: 'CLOUD_INIT_PASSWORD' }, sshkeys: encodeURIComponent(`${publicKey}\n${publicKey}\n`),
        ipconfig31: 'ip=192.0.2.10/24,gw=192.0.2.1,ip6=auto', nameserver: '192.0.2.53 192.0.2.54', searchdomain: 'example.test lab.test', ide2: 'local-lvm:cloudinit' }
      const body = join(scratch, 'cloud-init.json')
      await writeFile(body, JSON.stringify(settings), { mode: 0o600 })
      const schema = await command(['schema', 'set', configPath('qemu'), '--catalogue', contract.release])
      assert.equal(schema.code, 0, schema.stdout + schema.stderr)
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      assert.equal(validate({ api: { node: 'node-a', vmid: 100, ...settings } }), true)
      assert.equal(validate({ api: { node: 'node-a', vmid: 100, ipconfig0: 'ip=dhcp,ip6=auto' } }), true)
      const args = ['set', configPath('qemu'), ...target, '--body-file', body]
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0, preview.stdout + preview.stderr)
      const result = await command([...args, '--confirm', JSON.parse(preview.stdout).confirmation])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      const observed = await command(['get', configPath('qemu'), ...target], true)
      assert.deepEqual(observed.frame?.payload, { ...guests[0]!.initial, ...settings, cipassword: cloudPassword })
      const route = '/nodes/{node}/qemu/{vmid}/cloudinit'
      const pending = await command(['get', route, ...target], true)
      assert.deepEqual(pending.frame?.payload, [{ key: 'cipassword', value: canary, pending: cloudPassword }])
      const regeneration = ['set', route, ...target]
      const regenerationPreview = await command([...regeneration, '--preview'])
      assert.equal(regenerationPreview.code, 0, regenerationPreview.stdout + regenerationPreview.stderr)
      assert.equal(imagePassword, canary)
      const regenerated = await command([...regeneration, '--confirm', JSON.parse(regenerationPreview.stdout).confirmation])
      assert.equal(regenerated.code, 0, regenerated.stdout + regenerated.stderr)
      const current = await command(['get', route, ...target], true)
      assert.deepEqual(current.frame?.payload, [{ key: 'cipassword', value: cloudPassword }])
      const journal = await command(['journal', 'show', JSON.parse(result.stdout).id])
      assert.equal(JSON.parse(journal.stdout).journal.status, 'success')
      const rejectedPreview = await command([...args, '--preview'])
      assert.equal(rejectedPreview.code, 0, rejectedPreview.stdout + rejectedPreview.stderr)
      rejectCloudPassword = true
      const rejected = await command([...args, '--confirm', JSON.parse(rejectedPreview.stdout).confirmation])
      rejectCloudPassword = false
      assert.notEqual(rejected.code, 0)
      const failed = await command(['journal', 'show', JSON.parse(rejectedPreview.stdout).id])
      assert.equal(JSON.parse(failed.stdout).journal.status, 'failed')
      const durable = await Promise.all((await readdir(`${log}.d`)).filter(name => name.endsWith('.json')).map(name => readFile(join(`${log}.d`, name), 'utf8')))
      const publicOutput = [preview, result, observed, pending, regenerationPreview, regenerated, current, journal, rejectedPreview, rejected, failed].map(value => value.stdout + value.stderr).join('') + durable.join('')
      for (const secret of [cloudPassword, encodeURIComponent(cloudPassword), Buffer.from(cloudPassword).toString('base64')]) assert.equal(publicOutput.includes(secret), false)
    })
  }
  for (const contract of releases) for (const { family, initial, settings } of guests) {
    const { release } = contract
    version = contract.version
    await t.test(`${release} ${family} compute settings change only after exact confirmation`, async () => {
      state[family] = { ...initial }
      const before = { ...initial }
      const args = ['set', configPath(family), ...target, '--api-digest', digest,
        ...Object.entries(settings).flatMap(([name, value]) => [`--api-${name}`, String(value)])]
      requests.length = 0
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0, preview.stdout + preview.stderr)
      assert.equal(JSON.parse(preview.stdout).status, 'preview')
      assert.deepEqual(state[family], before)
      assert.ok(requests.every(request => request.method === 'GET'))
      const result = await command([...args, '--confirm', JSON.parse(preview.stdout).confirmation])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).status, 'success')
      const observed = await command(['get', configPath(family), ...target], true)
      assert.equal(observed.code, 0, observed.stderr)
      assert.deepEqual(observed.frame?.payload, { ...before, ...settings })
      assert.doesNotMatch(observed.stdout + observed.stderr, /CANARY-private-guest-credential/)
    })
  }
  for (const contract of releases) for (const { family, initial } of guests) {
    await t.test(`${contract.release} ${family} reconciles a string cpulimit`, async () => {
      version = contract.version
      state[family] = { ...initial }
      const args = ['set', configPath(family), ...target, '--api-cpulimit', '1']
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0, preview.stdout + preview.stderr)
      const written = await command([...args, '--confirm', JSON.parse(preview.stdout).confirmation])
      assert.equal(written.code, 0, written.stdout + written.stderr)
      state[family]!.cpulimit = '1'
      const reconciled = await command(['journal', 'reconcile', JSON.parse(written.stdout).id])
      assert.equal(reconciled.code, 0, reconciled.stdout + reconciled.stderr)
      assert.equal(JSON.parse(reconciled.stdout).journal.observation.desiredStateObserved, true)
      state[family]!.cpulimit = '2'
      const mismatch = await command(['journal', 'reconcile', JSON.parse(written.stdout).id])
      assert.equal(mismatch.code, 0, mismatch.stdout + mismatch.stderr)
      assert.equal(JSON.parse(mismatch.stdout).journal.observation.desiredStateObserved, false)
    })
  }
  const refusals: [string, string, string, string, number][] = [
    ['qemu', 'cpu', 'host', 'INVALID_INPUT', 2], ['qemu', 'cpu', 'qemu64,flags=+aes', 'INVALID_INPUT', 2],
    ['qemu', 'memory', '15', 'INVALID_INPUT', 2], ['lxc', 'memory', '15', 'INVALID_INPUT', 2],
    ['qemu', 'startup', 'order=1,up=2,up=3', 'INVALID_INPUT', 2], ['lxc', 'startup', 'order=1,hookscript=x', 'INVALID_INPUT', 2],
    ['qemu', 'name', 'bad/name', 'INVALID_INPUT', 2], ['qemu', 'hookscript', 'local:snippets/script', 'CONTRACT_UNRESOLVED', 1],
    ['qemu', 'hostpci0', '0000:00:00.0', 'INVALID_INPUT', 2],
  ]
  for (const contract of releases) for (const { family, initial } of guests) {
    const settings: Record<string, string> = family === 'qemu' ? {
      net31: 'virtio=02:00:00:00:00:10,bridge=vmbr0,firewall=1,link_down=0,rate=10.5,tag=42',
      ide2: 'local:iso/installer.iso,media=cdrom', boot: 'order=ide2;net31', agent: 'enabled=1',
    } : { net31: 'name=eth1,bridge=vmbr0,firewall=1,gw=192.0.2.1,hwaddr=02:00:00:00:00:11,ip=192.0.2.10/24,ip6=auto,link_down=0,rate=10.5,tag=42,type=veth',
      nameserver: '192.0.2.53 192.0.2.54', searchdomain: 'example.test lab.test' }
    await t.test(`${contract.release} ${family} confirms reviewed NIC and boot settings and refuses changed network inputs`, async () => {
      version = contract.version
      state[family] = { ...initial }
      const schema = await command(['schema', 'set', configPath(family), '--catalogue', contract.release])
      assert.equal(schema.code, 0, schema.stdout + schema.stderr)
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      assert.equal(validate({ api: { node: 'node-a', vmid: 100, ...settings } }), true)
      assert.equal(validate({ api: { node: 'node-a', vmid: 100, net31: settings.net31!.replace('tag=42', 'tag=4095') } }), false)
      const args = ['set', configPath(family), ...target, '--api-digest', digest,
        ...Object.entries(settings).flatMap(([name, value]) => [`--api-${name}`, value])]
      const preview = await command([...args, '--preview'])
      assert.equal(preview.code, 0, preview.stdout + preview.stderr)
      assert.deepEqual(state[family], initial)
      const changedArgs = args.map(value => value.replace('bridge=vmbr0', 'bridge=vmbr1'))
      const changed = await command([...changedArgs, '--confirm', JSON.parse(preview.stdout).confirmation])
      assert.equal(JSON.parse(changed.stdout).error.code, 'CONFIRMATION_MISMATCH')
      assert.deepEqual(state[family], initial)
      const result = await command([...args, '--confirm', JSON.parse(preview.stdout).confirmation])
      assert.equal(result.code, 0, result.stdout + result.stderr)
      const observed = await command(['get', configPath(family), ...target], true)
      assert.deepEqual(observed.frame?.payload, { ...initial, ...settings })
      const remove = ['set', configPath(family), ...target, '--api-delete', 'net31',
        ...(family === 'qemu' ? ['--api-boot', 'order=ide2', '--api-agent', '0'] : [])]
      const removePreview = await command([...remove, '--preview'])
      assert.equal(removePreview.code, 0, removePreview.stdout + removePreview.stderr)
      assert.equal((state[family] as Record<string, unknown>).net31, settings.net31)
      const removed = await command([...remove, '--confirm', JSON.parse(removePreview.stdout).confirmation])
      assert.equal(removed.code, 0, removed.stdout + removed.stderr)
      assert.equal(Object.hasOwn(state[family]!, 'net31'), false)
    })
  }
  refusals.push(
    ['qemu', 'net32', 'virtio,bridge=vmbr0', 'INVALID_INPUT', 2],
    ['qemu', 'net0', 'virtio=01:00:00:00:00:10,bridge=vmbr0', 'INVALID_INPUT', 2],
    ['qemu', 'net0', 'virtio,bridge=vmbr0,tag=4095', 'INVALID_INPUT', 2],
    ['qemu', 'net0', 'virtio,bridge=vmbr0,bridge=vmbr1', 'INVALID_INPUT', 2],
    ['qemu', 'net0', 'virtio,host-tunnel=1', 'INVALID_INPUT', 2],
    ['lxc', 'net0', 'name=eth0,bridge=vmbr0,ip=999.0.0.1/24', 'INVALID_INPUT', 2],
    ['lxc', 'net0', 'name=eth0,ip6=2001:db8::1/64', 'INVALID_INPUT', 2],
    ['qemu', 'boot', 'order=hostpci0;ide2', 'INVALID_INPUT', 2],
    ['qemu', 'agent', '1,freeze-fs=0', 'INVALID_INPUT', 2],
    ['qemu', 'ide2', 'local:iso/../installer.iso,media=cdrom', 'INVALID_INPUT', 2],
    ['qemu', 'ide2', '/host/installer.iso,media=cdrom', 'INVALID_INPUT', 2],
    ['qemu', 'ciuser', 'bad:user', 'INVALID_INPUT', 2],
    ['qemu', 'sshkeys', encodeURIComponent(`command="run" ${publicKey}`), 'INVALID_INPUT', 2],
    ['qemu', 'sshkeys', encodeURIComponent(`${publicKey}\ncommand="run" ${publicKey}`), 'INVALID_INPUT', 2],
    ['qemu', 'ipconfig32', 'ip=dhcp', 'INVALID_INPUT', 2],
    ['qemu', 'ipconfig0', 'ip=dhcp,gw=192.0.2.1', 'INVALID_INPUT', 2],
    ['qemu', 'ipconfig0', 'ip=999.0.0.1/24', 'INVALID_INPUT', 2],
    ['qemu', 'nameserver', '999.0.0.1', 'INVALID_INPUT', 2],
    ['lxc', 'searchdomain', 'bad/domain', 'INVALID_INPUT', 2],
  )
  for (const contract of releases) for (const { family } of guests) {
    const added = family === 'qemu' ? { scsi30: 'local-lvm:8,backup=1,cache=none,discard=on,format=raw,iothread=1' } :
      { rootfs: 'local-lvm:subvol-100-disk-0,acl=1', mp255: 'local-lvm:8,mp=/mnt/data,backup=1' }
    const replacement = family === 'qemu' ? { scsi30: 'local:100/vm-100-disk-1.qcow2,backup=1,cache=writeback' } :
      { mp255: 'local-lvm:subvol-100-disk-1,mp=/mnt/data,backup=1,ro=1' }
    const slot = family === 'qemu' ? 'scsi30' : 'mp255'
    await t.test(`${contract.release} ${family} discovers and confirms managed disk add, replace and removal`, async () => {
      version = contract.version
      state[family] = { ...guests.find(guest => guest.family === family)!.initial }
      const schema = await command(['schema', 'set', configPath(family), '--catalogue', contract.release])
      assert.equal(schema.code, 0, schema.stderr)
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      assert.equal(validate({ api: { node: 'node-a', vmid: 100, ...added } }), true)
      assert.equal(validate({ api: { node: 'node-a', vmid: 100, [slot]: '/dev/sda' } }), false)
      const update = async (settings: Record<string, string>) => {
        const before = { ...state[family] }
        const args = ['set', configPath(family), ...target, '--api-digest', digest,
          ...Object.entries(settings).flatMap(([name, value]) => [`--api-${name}`, value])]
        const preview = await command([...args, '--preview'])
        assert.equal(preview.code, 0, preview.stdout + preview.stderr)
        assert.deepEqual(state[family], before)
        const written = await command([...args, '--confirm', JSON.parse(preview.stdout).confirmation])
        assert.equal(written.code, 0, written.stdout + written.stderr)
        assert.equal(JSON.parse(written.stdout).status, 'success')
      }
      await update(added)
      const first = await command(['get', configPath(family), ...target], true)
      assert.deepEqual(first.frame?.payload, { ...guests.find(guest => guest.family === family)!.initial, ...added })
      await update(replacement)
      const second = await command(['get', configPath(family), ...target], true)
      assert.deepEqual(second.frame?.payload, { ...guests.find(guest => guest.family === family)!.initial, ...added, ...replacement })
      await update({ delete: slot })
      const removed = await command(['get', configPath(family), ...target], true)
      assert.equal(Object.hasOwn(removed.frame!.payload as object, slot), false)
    })
  }
  refusals.push(
    ['qemu', 'scsi31', 'local-lvm:8', 'INVALID_INPUT', 2], ['lxc', 'mp256', 'local-lvm:8,mp=/mnt/data', 'INVALID_INPUT', 2],
    ['qemu', 'scsi0', '/dev/disk/by-id/device', 'INVALID_INPUT', 2], ['lxc', 'rootfs', '/host/path', 'INVALID_INPUT', 2],
    ['qemu', 'scsi0', 'local-lvm:8,import-from=/source', 'INVALID_INPUT', 2],
    ['qemu', 'scsi0', 'local-lvm:8,cache=unsafe', 'INVALID_INPUT', 2],
    ['lxc', 'mp0', 'local-lvm:8,mp=/mnt/../data', 'INVALID_INPUT', 2],
    ['qemu', 'delete', 'scsi0,hookscript', 'INVALID_INPUT', 2], ['qemu', 'delete', 'unused0', 'INVALID_INPUT', 2],
    ['lxc', 'delete', 'rootfs', 'INVALID_INPUT', 2],
  )
  for (const [family, field, value, error, exit] of refusals) {
    await t.test(`${family} rejects unreviewed ${field} value ${value} before network access`, async () => {
      requests.length = 0
      const result = await command(['set', configPath(family), ...target, `--api-${field}`, value, '--preview'])
      assert.equal(result.code, exit, result.stdout + result.stderr)
      assert.equal(JSON.parse(result.stdout).error.code, error)
      assert.deepEqual(requests, [])
    })
  }
  await t.test('changing a reviewed compute value invalidates its confirmation', async () => {
    const before = { ...state.qemu }
    const args = ['set', configPath('qemu'), ...target, '--api-vcpus', '2']
    const preview = await command([...args, '--preview'])
    assert.equal(preview.code, 0, preview.stdout + preview.stderr)
    requests.length = 0
    const result = await command(['set', configPath('qemu'), ...target, '--api-vcpus', '3', '--confirm', JSON.parse(preview.stdout).confirmation])
    assert.equal(result.code, 1, result.stderr)
    assert.equal(JSON.parse(result.stdout).error.code, 'CONFIRMATION_MISMATCH')
    assert.deepEqual(state.qemu, before)
    assert.ok(requests.every(request => request.method === 'GET'))
  })
})

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
const canary = 'CANARY-private-snapshot-credential'

for (const family of ['qemu', 'lxc']) test(`${family} snapshots retain protected configuration and confirmed task outcomes`, async t => {
  const base = `/nodes/{node}/${family}/{vmid}`, listPath = `${base}/snapshot`, namedPath = `${listPath}/{snapname}`
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-snapshots-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  const initial = { digest: '0123456789012345678901234567890123456789', memory: family === 'qemu' ? '512' : 512, [family === 'qemu' ? 'cipassword' : 'password']: canary, description: canary }
  let current = { ...initial }, version = '8.2.7', failNext = false, sequence = 0
  const snapshots = new Map<string, typeof initial>()
  const tasks = new Map<string, { failed: boolean, apply: () => void }>()
  const requests: string[] = []
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), path = url.pathname
    requests.push(`${request.method} ${path}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (request.method === 'PUT') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = new URLSearchParams(Buffer.concat(chunks).toString())
      current.memory = family === 'qemu' ? body.get('memory')! : Number(body.get('memory'))
      response.end(JSON.stringify({ data: null })); return
    }
    if (request.method === 'POST' || request.method === 'DELETE') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = new URLSearchParams(Buffer.concat(chunks).toString())
      const name = body.get('snapname') ?? decodeURIComponent(/\/snapshot\/([^/]+)/.exec(path)![1]!)
      const action = request.method === 'DELETE' ? 'delete' : path.endsWith('/rollback') ? 'rollback' : 'create'
      const saved = { ...current }
      const upid = `UPID:node-a:${(++sequence).toString(16).padStart(8, '0')}:00000001:00000001:snapshot:100:synthetic@pve:`
      tasks.set(upid, { failed: failNext, apply: () => {
        if (action === 'create') snapshots.set(name, saved)
        else if (action === 'delete') snapshots.delete(name)
        else current = { ...snapshots.get(name)! }
      } })
      failNext = false
      response.end(JSON.stringify({ data: upid })); return
    }
    const task = /\/tasks\/([^/]+)\/status$/.exec(path)
    if (task) {
      const upid = decodeURIComponent(task[1]!), pending = tasks.get(upid)!
      if (!pending.failed) pending.apply()
      response.end(JSON.stringify({ data: { node: 'node-a', upid, id: '100', pid: sequence, pstart: 1, starttime: 1,
        type: 'snapshot', user: 'synthetic@pve', status: 'stopped', exitstatus: pending.failed ? 'ERROR: snapshot storage unavailable' : 'OK' } })); return
    }
    const name = /\/snapshot\/([^/]+)/.exec(path)?.[1]
    const data = path.endsWith('/snapshot') ? [...snapshots.keys(), 'current'].map(name => ({ name, description: canary, extra: canary,
      ...(name === 'current' ? {} : { snaptime: 1, ...(family === 'qemu' ? { vmstate: 1 } : {}) }) })) :
      path.endsWith('/config') ? name ? snapshots.get(decodeURIComponent(name)) : current : [{ cmd: 'config', extra: canary }, { cmd: 'rollback', extra: canary }]
    response.end(JSON.stringify({ data }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!test', token: { env: 'SNAPSHOT_TOKEN' }, writes: { operations: [
      ['POST', listPath], ['DELETE', namedPath], ['POST', `${namedPath}/rollback`], ['PUT', `${base}/config`],
    ].map(([method, path]) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`) },
  } } }), { mode: 0o600 })
  const command = async (args: string[], privateResult = false) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, SNAPSHOT_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: join(scratch, 'writes.log'), PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '' },
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
  const guest = ['--api-node', 'node-a', '--api-vmid', '100'], selected = [...guest, '--api-snapname', 'before-upgrade']
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    current = { ...initial }
    snapshots.clear()
    for (const { action, args } of [
      { action: 'create', args: ['create', listPath, ...selected, ...(family === 'qemu' ? ['--api-vmstate', '1'] : [])] },
      { action: 'rollback', args: ['create', `${namedPath}/rollback`, ...selected, '--api-start', '0'] },
      { action: 'delete', args: ['delete', namedPath, ...selected] },
    ]) {
      await t.test(`${release.name} failed ${action} task remains failed without retry`, async () => {
        const preview = await command([...args, '--preview'])
        failNext = true
        requests.length = 0
        const result = await command([...args, '--confirm', preview.data.confirmation])
        assert.equal(result.data.status, 'accepted')
        const failed = await command(['task', 'wait', '--api-node', result.data.node, '--api-upid', result.data.upid, '--journal', result.data.id])
        assert.equal(failed.code, 1)
        assert.equal(failed.data.status, 'failed')
        assert.equal(requests.filter(row => /^(POST|DELETE) /.test(row)).length, 1)
        const journal = await command(['journal', 'show', result.data.id])
        assert.equal(journal.data.journal.status, 'failed')
      })
      await t.test(`${release.name} ${action} requires exact snapshot confirmation and reports task success`, async () => {
        const schema = await command(['schema', args[0]!, args[1]!, '--catalogue', release.name])
        assert.equal(schema.code, 0)
        const validate = new Ajv({ strict: false }).compile(schema.data.invocation.schema)
        assert.equal(validate({ api: { node: 'node-a', vmid: 100, snapname: 'before-upgrade' } }), true)
        assert.equal(validate({ api: { node: 'node-a', vmid: 100, snapname: 'current' } }), false)
        requests.length = 0
        const preview = await command([...args, '--preview'])
        assert.equal(preview.code, 0, JSON.stringify(preview.data))
        assert.equal(requests.some(row => /^(POST|DELETE) /.test(row)), false)
        const changed = await command([...args.map(value => value === 'before-upgrade' ? 'another-snapshot' : value), '--confirm', preview.data.confirmation])
        assert.equal(changed.data.error.code, 'CONFIRMATION_MISMATCH')
        if (action === 'rollback') {
          const changedStart = await command([...args.map(value => value === '0' ? '1' : value), '--confirm', preview.data.confirmation])
          assert.equal(changedStart.data.error.code, 'CONFIRMATION_MISMATCH')
        }
        assert.equal(requests.some(row => /^(POST|DELETE) /.test(row)), false)
        const result = await command([...args, '--confirm', preview.data.confirmation])
        assert.equal(result.code, 0, JSON.stringify(result.data))
        assert.equal(result.data.status, 'accepted')
        const completed = await command(['task', 'wait', '--api-node', result.data.node, '--api-upid', result.data.upid, '--journal', result.data.id])
        assert.equal(completed.code, 0, JSON.stringify(completed.data))
        assert.equal(completed.data.status, 'success')
        const listed = await command(['get', listPath, ...guest, '--full'])
        assert.equal(listed.code, 0)
        assert.deepEqual(listed.data.data, action === 'delete' ? [{ name: 'current' }] : [
          { name: 'before-upgrade', snaptime: 1, ...(family === 'qemu' ? { vmstate: 1 } : {}) }, { name: 'current' },
        ])
        if (action !== 'delete') {
          const inspected = await command(['get', action === 'rollback' ? `${base}/config` : `${namedPath}/config`, ...(action === 'rollback' ? guest : selected)], true)
          assert.equal(inspected.code, 0, JSON.stringify(inspected.data))
          assert.deepEqual(inspected.payload, initial)
        }
      })
      if (action === 'create') await t.test(`${release.name} snapshot configuration stays private before provider access`, async () => {
        requests.length = 0
        const missing = await command(['get', `${namedPath}/config`, ...selected])
        assert.equal(missing.data.error.code, 'PRIVATE_SINK_REQUIRED')
        assert.deepEqual(requests, [])
        const index = await command(['get', namedPath, ...selected, '--full'])
        assert.deepEqual(index.data.data, [{ cmd: 'config' }, { cmd: 'rollback' }])
        const update = ['set', `${base}/config`, ...guest, '--api-memory', '2048']
        const preview = await command([...update, '--preview'])
        assert.equal((await command([...update, '--confirm', preview.data.confirmation])).code, 0)
      })
    }
  }
  for (const args of [
    ['delete', namedPath, ...selected, '--api-force', '1', '--preview'],
    ['create', listPath, ...guest, '--api-snapname', 'current', '--preview'],
    ['create', `${namedPath}/rollback`, ...guest, '--api-snapname', 'current', '--preview'],
    ['delete', namedPath, ...guest, '--api-snapname', 'current', '--preview'],
    ['set', `${namedPath}/config`, ...selected, '--api-description', 'changed', '--preview'],
    ['get', listPath, ...guest, '--fields', 'description', '--catalogue', 'published-current'],
  ]) await t.test(`refuses unreviewed snapshot input ${args[0]} ${args[args.length - 2]}`, async () => {
    requests.length = 0
    const refused = await command(args)
    assert.notEqual(refused.code, 0)
    assert.deepEqual(requests, [])
  })
  const journal = join(scratch, 'writes.log.d')
  const records = await Promise.all((await readdir(journal)).filter(name => name.endsWith('.json')).map(name => readFile(join(journal, name), 'utf8')))
  assert.equal(records.join('').includes(canary), false)
})

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

type Row = { name?: string, cidr?: string, comment?: string, nomatch?: boolean }
const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const scopes = [{ label: 'cluster', path: '/cluster/firewall', target: {} }, ...['qemu', 'lxc'].map(label =>
  ({ label, path: `/nodes/{node}/${label}/{vmid}/firewall`, target: { node: 'node-a', vmid: 100 } }))]
const id = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const variants = [['POST', '/aliases'], ['PUT', '/aliases/{name}'], ['DELETE', '/aliases/{name}'], ['POST', '/ipset'],
  ['DELETE', '/ipset/{name}'], ['POST', '/ipset/{name}'], ['PUT', '/ipset/{name}/{cidr}'], ['DELETE', '/ipset/{name}/{cidr}']]
const canary = 'CANARY-protected-firewall-comment', comment = { env: 'OBJECT_COMMENT' }
const digest = (rows: Row[]) => createHash('sha1').update(JSON.stringify(rows)).digest('hex')

test('scoped firewall aliases and literal IP sets retain confirmation and private comments', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-firewall-objects-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  const aliases = new Map<string, Row[]>(), sets = new Map<string, Map<string, Row[]>>()
  let version = '8.2.7', mode = 'success'
  const writes: { method: string, path: string, fields: Record<string, string> }[] = [], requests: string[] = []
  const wire = (path: string) => `/api2/json${path.replace('{node}', 'node-a').replace('{vmid}', '100')}`
  const rows = (list: Row[]) => list.map(row => ({ ...row, digest: digest(list) }))
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), path = url.pathname
    requests.push(`${request.method} ${path}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    const match = /^(.*\/firewall)\/(aliases|ipset)(?:\/([^/]+))?(?:\/([^/]+))?$/.exec(path)!
    assert.ok(match)
    const [, scope, kind, encodedName, encodedCidr] = match, name = encodedName && decodeURIComponent(encodedName), cidr = encodedCidr && decodeURIComponent(encodedCidr)
    const list = aliases.get(scope!)!, collection = sets.get(scope!)!, members = collection.get(name ?? '')
    const index = [...collection.keys()].sort().map(name => ({ name }))
    if (request.method === 'GET') {
      const data = kind === 'aliases' ? name ? list.find(row => row.name === name) : rows(list) :
        !name ? rows(index) : !cidr ? rows(members!) : rows(members!).find(row => row.cidr === cidr)
      response.end(JSON.stringify({ data })); return
    }
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const fields = Object.fromEntries(request.method === 'DELETE' ? url.searchParams : new URLSearchParams(Buffer.concat(chunks).toString()))
    writes.push({ method: request.method!, path, fields })
    const guarded = (kind === 'aliases' || cidr) && request.method !== 'POST'
    if (guarded && (mode === 'conflict' || fields.digest !== digest(kind === 'aliases' ? list : members!))) {
      response.writeHead(400).end(JSON.stringify({ message: `digest conflict ${fields.comment ?? ''}` })); return
    }
    if (kind === 'aliases') {
      if (request.method === 'POST') list.push({ name: fields.name!, cidr: fields.cidr!, ...(fields.comment ? { comment: fields.comment } : {}) })
      else if (request.method === 'PUT') Object.assign(list.find(row => row.name === name)!, { cidr: fields.cidr, ...(fields.comment !== undefined ? { comment: fields.comment } : {}) })
      else list.splice(list.findIndex(row => row.name === name), 1)
    } else if (!name) collection.set(fields.name!, [])
    else if (request.method === 'DELETE' && !cidr) {
      if (members!.length) { response.writeHead(400).end(JSON.stringify({ message: 'IPSet is not empty' })); return }
      collection.delete(name)
    } else if (request.method === 'POST') members!.unshift({ cidr: fields.cidr!, ...(fields.nomatch === '1' ? { nomatch: true } : {}), ...(fields.comment ? { comment: fields.comment } : {}) })
    else if (request.method === 'PUT') {
      const selected = members!.find(row => row.cidr === cidr)!
      selected.nomatch = fields.nomatch === '1'
      delete selected.comment
      if (fields.comment !== undefined) selected.comment = fields.comment
    } else members!.splice(members!.findIndex(row => row.cidr === cidr), 1)
    if (mode === 'uncertain') { response.writeHead(500).end(JSON.stringify({ message: canary })); return }
    response.end(JSON.stringify({ data: null }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!objects', token: { env: 'OBJECT_TOKEN' }, writes: { operations: scopes.flatMap(scope => variants.map(([method, suffix]) => id(method!, `${scope.path}${suffix}`))) },
  } } }), { mode: 0o600 })
  const command = async (verb: string, path: string, api: Record<string, unknown>, flags: string[] = [], privateResult = true, extraEnv: Record<string, string> = {}) => {
    const body = join(scratch, 'request.json')
    await writeFile(body, JSON.stringify(api), { mode: 0o600 })
    const child = spawn(process.execPath, [executable, verb, path, '--body-file', body, ...flags, '--config', config, '--format', 'json'], {
      env: { ...environment, OBJECT_TOKEN: 'synthetic-token', OBJECT_COMMENT: canary, PROXMOX_AXI_WRITE_LOG: log, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '', ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe', ...(privateResult ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = '', bytes = Buffer.alloc(0)
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    if (privateResult) (child.stdio[3] as Readable).on('data', chunk => { bytes = Buffer.concat([bytes, chunk]) })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal(stderr, '')
    assert.equal((stdout + stderr).includes(canary), false)
    if (bytes.length) assert.equal(bytes.readUInt32BE(0), bytes.length - 4)
    return { code, value: JSON.parse(stdout), payload: bytes.length ? JSON.parse(bytes.subarray(4).toString()).payload : undefined }
  }
  const confirm = async (verb: string, path: string, api: Record<string, unknown>) => {
    const count = writes.length, preview = await command(verb, path, api, ['--preview'])
    assert.equal(preview.code, 0)
    assert.match(preview.value.warnings[0].messages.join(' '), /management access/)
    assert.equal(writes.length, count)
    return command(verb, path, api, ['--confirm', preview.value.confirmation])
  }
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7', cidr: '192.0.2.0/24' }, { name: 'published-current', version: '9.2.1', cidr: '2001:db8::/64' }]) {
    version = release.version
    for (const scope of scopes) {
      const aliasPath = `${scope.path}/aliases`, setPath = `${scope.path}/ipset`, memberPath = `${setPath}/{name}/{cidr}`
      const reset = () => { aliases.set(wire(scope.path), []); sets.set(wire(scope.path), new Map()); mode = 'success' }
      await t.test(`${release.name} ${scope.label} alias CRUD retains protected comments and native digest`, async () => {
        reset()
        const api = { ...scope.target, name: 'trusted', cidr: release.cidr, comment }
        assert.equal((await confirm('create', aliasPath, api)).value.status, 'success')
        const read = await command('get', `${aliasPath}/{name}`, { ...scope.target, name: 'trusted' })
        assert.deepEqual(read.payload, { name: 'trusted', cidr: release.cidr, comment: canary })
        const list = await command('get', aliasPath, scope.target)
        const changed = { ...api, cidr: '198.51.100.0/24', digest: list.payload[0].digest }
        assert.equal((await confirm('set', `${aliasPath}/{name}`, changed)).value.status, 'success')
        assert.equal((await command('get', `${aliasPath}/{name}`, { ...scope.target, name: 'trusted' })).payload.cidr, '198.51.100.0/24')
        const current = await command('get', aliasPath, scope.target)
        assert.equal((await confirm('delete', `${aliasPath}/{name}`, { ...scope.target, name: 'trusted', digest: current.payload[0].digest })).value.status, 'success')
        assert.deepEqual((await command('get', aliasPath, scope.target)).payload, [])
      })
      await t.test(`${release.name} ${scope.label} set/member CRUD encodes CIDRs once and deletes only empty sets`, async () => {
        reset()
        const target = { ...scope.target, name: 'trusted' }, member = { ...target, cidr: release.cidr }
        assert.equal((await confirm('create', setPath, target)).value.status, 'success')
        assert.equal((await command('get', setPath, scope.target)).payload[0].name, 'trusted')
        assert.equal((await confirm('create', `${setPath}/{name}`, { ...member, comment })).value.status, 'success')
        let list = await command('get', `${setPath}/{name}`, target)
        assert.equal(list.payload[0].comment, canary)
        const blocked = await confirm('delete', `${setPath}/{name}`, target)
        assert.equal(blocked.code, 1)
        assert.equal(sets.get(wire(scope.path))!.get('trusted')!.length, 1)
        assert.equal((await confirm('set', memberPath, { ...member, nomatch: false, comment, digest: list.payload[0].digest })).value.status, 'success')
        list = await command('get', `${setPath}/{name}`, target)
        assert.equal(list.payload[0].comment, canary)
        assert.equal((await confirm('set', memberPath, { ...member, nomatch: true, digest: list.payload[0].digest })).value.status, 'success')
        const read = await command('get', memberPath, member)
        assert.deepEqual(read.payload, { cidr: release.cidr, nomatch: true, digest: digest([{ cidr: release.cidr, nomatch: true }]) })
        assert.ok(requests.includes(`GET ${wire(setPath)}/trusted/${encodeURIComponent(release.cidr)}`))
        assert.equal((await confirm('delete', memberPath, { ...member, digest: read.payload.digest })).value.status, 'success')
        assert.equal((await confirm('delete', `${setPath}/{name}`, target)).value.status, 'success')
        assert.deepEqual((await command('get', setPath, scope.target)).payload, [])
      })
      await t.test(`${release.name} ${scope.label} scope/CIDR changes cannot reuse confirmation`, async () => {
        reset()
        const api = { ...scope.target, name: 'trusted', cidr: release.cidr }, before = writes.length
        const preview = await command('create', aliasPath, api, ['--preview'])
        const changed = await command('create', aliasPath, { ...api, cidr: '203.0.113.0/24' }, ['--confirm', preview.value.confirmation])
        assert.equal(changed.value.error.code, 'CONFIRMATION_MISMATCH')
        const other = scope.label === 'cluster' ? scopes[1]! : scopes[0]!
        const wrongScope = await command('create', `${other.path}/aliases`, { ...other.target, name: 'trusted', cidr: release.cidr }, ['--confirm', preview.value.confirmation])
        assert.equal(wrongScope.value.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(writes.length, before)
      })
      await t.test(`${release.name} ${scope.label} stale alias digest fails without modifying the alias`, async () => {
        reset()
        aliases.get(wire(scope.path))!.push({ name: 'trusted', cidr: release.cidr })
        const api = { ...scope.target, name: 'trusted', digest: '0'.repeat(40) }
        const result = await confirm('delete', `${aliasPath}/{name}`, api)
        assert.equal(result.code, 1)
        assert.equal(aliases.get(wire(scope.path))![0]!.cidr, release.cidr)
      })
      await t.test(`${release.name} ${scope.label} reads require a private sink before provider access`, async () => {
        reset()
        const before = requests.length
        assert.equal((await command('get', aliasPath, scope.target, [], false)).value.error.code, 'PRIVATE_SINK_REQUIRED')
        assert.equal(requests.length, before)
      })
      await t.test(`${release.name} ${scope.label} member deletion binds its exact CIDR and native digest`, async () => {
        reset()
        const entries = [{ cidr: release.cidr }, { cidr: '203.0.113.0/24' }]
        sets.get(wire(scope.path))!.set('trusted', entries)
        const api = { ...scope.target, name: 'trusted', cidr: release.cidr, digest: digest(entries) }, before = writes.length
        const preview = await command('delete', memberPath, api, ['--preview'])
        const changed = await command('delete', memberPath, { ...api, cidr: '203.0.113.0/24' }, ['--confirm', preview.value.confirmation])
        assert.equal(changed.value.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(writes.length, before)
        mode = 'conflict'
        assert.equal((await command('delete', memberPath, api, ['--confirm', preview.value.confirmation])).code, 1)
        assert.deepEqual(entries, [{ cidr: release.cidr }, { cidr: '203.0.113.0/24' }])
        mode = 'success'
      })
    }
    await t.test(`${release.name} uncertain creation is never replayed and comments stay private`, async () => {
      const scope = scopes[0]!, path = `${scope.path}/aliases`, api = { name: 'trusted', cidr: release.cidr, comment }
      aliases.set(wire(scope.path), [])
      const preview = await command('create', path, api, ['--preview']), before = writes.length
      mode = 'uncertain'
      assert.equal((await command('create', path, api, ['--confirm', preview.value.confirmation])).value.error.code, 'WRITE_UNCERTAIN')
      assert.equal((await command('create', path, api, ['--confirm', preview.value.confirmation])).value.error.code, 'CONFIRMATION_USED')
      assert.equal(writes.length, before + 1)
      mode = 'success'
    })
  }
  for (const api of [{ name: 'trusted', cidr: '../escape' }, { name: 'trusted', cidr: '192.0.2.1%2F24' }, { name: 'trusted', cidr: 'dc/alias' },
    { name: 'trusted', cidr: '0.0.0.0/0' }, { name: 'trusted', cidr: '::/0' }]) {
    await t.test(`member selector ${api.cidr} is refused before HTTP`, async () => {
      const before = requests.length
      assert.equal((await command('get', '/cluster/firewall/ipset/{name}/{cidr}', api)).value.error.code, 'INVALID_INPUT')
      assert.equal(requests.length, before)
    })
  }
  await t.test('changed comment secret invalidates alias creation confirmation', async () => {
    const path = '/cluster/firewall/aliases', api = { name: 'trusted', cidr: '192.0.2.1', comment }, before = writes.length
    const preview = await command('create', path, api, ['--preview'])
    const changed = await command('create', path, api, ['--confirm', preview.value.confirmation], true, { OBJECT_COMMENT: 'changed protected value' })
    assert.equal(changed.value.error.code, 'CONFIRMATION_MISMATCH')
    assert.equal(writes.length, before)
  })
  await t.test('independent host denial refuses alias creation before HTTP', async () => {
    const path = '/cluster/firewall/aliases', api = { name: 'trusted', cidr: '192.0.2.1', comment }
    const requestsBefore = requests.length
    const denied = await command('create', path, api, ['--preview'], true, { PROXMOX_AXI_HOST_OPERATIONS: '[]' })
    assert.equal(denied.value.error.code, 'WRITE_DISABLED')
    assert.equal(requests.length, requestsBefore)
  })
  await t.test('comments containing a trailing newline are refused before HTTP', async () => {
    const before = requests.length
    const result = await command('create', '/cluster/firewall/aliases', { name: 'trusted', cidr: '192.0.2.1', comment }, ['--preview'], true, { OBJECT_COMMENT: `${canary}\n` })
    assert.equal(result.value.error.code, 'INVALID_INPUT')
    assert.equal(requests.length, before)
  })
  for (const [verb, path, api] of [
    ['create', '/cluster/firewall/aliases', { name: 'trusted', cidr: '192.0.2.1', rename: 'other' }],
    ['delete', '/cluster/firewall/ipset/{name}', { name: 'trusted', force: true }],
    ['create', '/cluster/firewall/aliases', { name: 'trusted', cidr: '192.0.2.1', comment: canary }],
    ['delete', '/cluster/firewall/aliases/{name}', { name: 'trusted' }],
  ] as const) {
    await t.test(`unreviewed ${verb} ${path} input is refused locally`, async () => {
      const before = requests.length
      assert.match((await command(verb, path, api, ['--preview'])).value.error.code, /^(INVALID_INPUT|CONTRACT_UNRESOLVED)$/)
      assert.equal(requests.length, before)
    })
  }
  const stored = await Promise.all((await readdir(`${log}.d`)).map(file => readFile(join(`${log}.d`, file), 'utf8')))
  assert.equal(stored.join('').includes(canary), false)
})

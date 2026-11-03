import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Readable } from 'node:stream'
import { promisify } from 'node:util'
import test from 'node:test'
import { Ajv } from 'ajv'

type Rule = Record<string, unknown>
const execute = promisify(execFile), executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PROXMOX_AXI_')))
const scopes = [
  { name: 'cluster', path: '/cluster/firewall/rules', target: {} },
  { name: 'node', path: '/nodes/{node}/firewall/rules', target: { node: 'node-a' } },
  ...['qemu', 'lxc'].map(name => ({ name, path: `/nodes/{node}/${name}/{vmid}/firewall/rules`, target: { node: 'node-a', vmid: 100 } })),
  { name: 'group', path: '/cluster/firewall/groups/{group}', target: { group: 'web' } },
]
const operationId = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const canary = 'CANARY-private-rule-comment', batch = '/nodes/{node}/execute', groups = '/cluster/firewall/groups'
const initial = (): Rule[] => [{ type: 'in', action: 'DROP', proto: 'tcp', dport: '1001', enable: 1, comment: canary },
  { type: 'out', action: 'ACCEPT', proto: 'udp', dport: '1002', enable: 1 }]

test('ordered firewall changes stage disabled creation and guard later mutations', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-firewall-rules-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), config = join(scratch, 'config.json'), log = join(scratch, 'writes.log')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  let version = '8.2.7', mode = 'success', applied = false
  const state = new Map<string, Rule[]>(), requests: string[] = [], writes: { method: string, path: string, fields: Record<string, string> }[] = []
  const groupComments = new Map<string, string>()
  const wire = (path: string, group = 'web') => `/api2/json${path.replace('{node}', 'node-a').replace('{vmid}', '100').replace('{group}', group)}`
  const digest = (rules: Rule[]) => createHash('sha1').update(JSON.stringify(rules.map(({ errors, ...settings }) => settings))).digest('hex')
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid'), path = url.pathname
    requests.push(`${request.method} ${path}`)
    if (path.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    const chunks: Buffer[] = []
    if (request.method !== 'GET') for await (const chunk of request) chunks.push(Buffer.from(chunk))
    const fields = Object.fromEntries(request.method === 'DELETE' ? url.searchParams : new URLSearchParams(Buffer.concat(chunks).toString()))
    if (request.method !== 'GET') writes.push({ method: request.method!, path, fields })
    if (path === wire(groups)) {
      if (request.method === 'GET') {
        const rows = [...state.keys()].filter(key => key.startsWith(`${wire(groups)}/`)).sort().map(key => {
          const group = key.slice(wire(groups).length + 1)
          return { group, ...(groupComments.has(group) ? { comment: groupComments.get(group) } : {}) }
        })
        response.end(JSON.stringify({ data: rows.map(row => ({ ...row, digest: digest(rows) })) })); return
      }
      if (mode === 'metadata-reject') { response.writeHead(400).end(JSON.stringify({ message: canary })); return }
      if (state.has(`${wire(groups)}/${fields.group}`)) { response.writeHead(400).end(JSON.stringify({ message: 'group already exists' })); return }
      const group = fields.group!.toLowerCase()
      state.set(`${wire(groups)}/${group}`, [])
      if (fields.comment !== undefined) groupComments.set(group, fields.comment)
      response.end(JSON.stringify({ data: null })); return
    }
    const match = /^(.*(?:\/rules|\/groups\/[^/]+))(?:\/(\d+))?$/.exec(path)!
    assert.ok(match)
    const rules = state.get(match[1]!)!, pos = match[2] === undefined ? undefined : Number(match[2])
    if (!rules) { response.writeHead(500).end(JSON.stringify({ message: 'no such security group' })); return }
    if (request.method === 'GET') {
      if (mode === 'verify-unavailable' && applied) { response.writeHead(403).end(JSON.stringify({ message: canary })); return }
      const rows = rules.map((rule, index) => ({ ...rule, pos: index, digest: digest(rules) }))
      response.end(JSON.stringify({ data: mode === 'malformed' ? [{ type: 'in', action: 'DROP', pos: 9, digest: 'bad' }] : pos === undefined ? rows : rows[pos] })); return
    }
    if (path.startsWith(`${wire(groups)}/`) && pos === undefined && request.method === 'DELETE') {
      if (rules.length) { response.writeHead(500).end(JSON.stringify({ message: 'Security group is not empty' })); return }
      state.delete(path)
      groupComments.delete(path.slice(wire(groups).length + 1))
      response.end(JSON.stringify({ data: null })); return
    }
    if (path.startsWith(`${wire(groups)}/`) && (fields.type === 'group' || fields.iface !== undefined)) { response.writeHead(400).end(JSON.stringify({ message: 'unsupported group rule' })); return }
    if (mode === 'native-race') rules.reverse()
    if (request.method !== 'POST' && fields.digest !== digest(rules)) { response.writeHead(400).end(JSON.stringify({ message: 'rules digest mismatch' })); return }
    if (request.method === 'POST') {
      // The real provider ignores the creation digest/position and prepends.
      if (mode === 'create-race') rules.push({ type: 'in', action: 'DROP', enable: 1 })
      const rule: Rule = Object.fromEntries(Object.entries(fields).filter(([key]) => !['digest', 'pos'].includes(key)))
      rule.enable = Number(rule.enable ?? 0)
      rules.unshift(rule)
    } else if (request.method === 'DELETE') rules.splice(pos!, 1)
    else if (fields.moveto !== undefined && Number(fields.moveto) !== pos) {
      const boundary = Number(fields.moveto), [rule] = rules.splice(pos!, 1)
      rules.splice(Math.min(boundary > pos! ? boundary - 1 : boundary, rules.length), 0, rule!)
    } else {
      Object.assign(rules[pos!]!, Object.fromEntries(Object.entries(fields).filter(([key]) => !['digest', 'moveto'].includes(key))))
      if (fields.enable !== undefined) rules[pos!]!.enable = Number(fields.enable)
    }
    for (const rule of rules) {
      delete rule.errors
      if (rule.type === 'group') {
        for (const name of Object.keys(rule)) if (!['type', 'action', 'enable', 'iface', 'comment'].includes(name)) delete rule[name]
        continue
      }
      for (const field of ['source', 'dest']) {
        if (rule[field] === 'missing-alias') rule.errors = { ...rule.errors as Record<string, string>, [field]: canary }
      }
      const address = rule.source ?? rule.dest
      if (address !== undefined && address !== 'missing-alias') rule.ipversion = String(address).includes(':') ? 6 : 4
      else if (rule.proto === 'icmp' || rule.proto === 'icmpv6') rule.ipversion = rule.proto === 'icmp' ? 4 : 6
      else delete rule.ipversion
    }
    if (mode === 'reference-race' && rules[pos ?? 0]?.type === 'group') state.get(`${wire(groups)}/${rules[pos ?? 0]!.action}`)!.push({ type: 'in', action: 'DROP', enable: 1 })
    applied = true
    response.end(JSON.stringify({ data: null }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!rules', token: { env: 'RULES_TOKEN' }, writes: { operations: [operationId('POST', batch), operationId('POST', groups), operationId('DELETE', `${groups}/{group}`), ...scopes.flatMap(scope =>
      [operationId('POST', scope.path), operationId('PUT', `${scope.path}/{pos}`), operationId('DELETE', `${scope.path}/{pos}`)])] },
  } } }), { mode: 0o600 })
  const command = async (verb: string, path: string, api: Record<string, unknown>, flags: string[] = [], privateResult = true, extraEnv: Record<string, string> = {}) => {
    const body = join(scratch, 'request.json')
    await writeFile(body, JSON.stringify(api), { mode: 0o600 })
    const child = spawn(process.execPath, [executable, verb, path, '--body-file', body, ...flags, '--config', config, '--format', 'json'], {
      env: { ...environment, RULES_TOKEN: 'synthetic-token', RULE_COMMENT: canary, PROXMOX_AXI_WRITE_LOG: log, PROXMOX_AXI_RESULT_FD: privateResult ? '3' : '', ...extraEnv },
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
    return { code, value: JSON.parse(stdout), frame: bytes.length ? JSON.parse(bytes.subarray(4).toString()) : undefined }
  }
  const saved = async (intent: string) => JSON.parse(await readFile(join(`${log}.d`, `${intent}.json`), 'utf8'))
  const confirmed = async (verb: string, path: string, api: Record<string, unknown>) => {
    const before = writes.length, preview = await command(verb, path, api, ['--preview'])
    assert.equal(preview.code, 0)
    assert.equal(writes.length, before)
    return command(verb, path, api, ['--confirm', preview.value.confirmation])
  }
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7', source: '192.0.2.0/24' }, { name: 'published-current', version: '9.2.1', source: '2001:db8::/64' }]) {
    version = release.version
    for (const scope of scopes) {
      state.set(wire(scope.path), initial())
      const item = `${scope.path}/{pos}`
      const create = { ...scope.target, type: 'in', action: 'ACCEPT', proto: 'tcp', dport: '2222', source: release.source }
      const staged: Rule = { type: 'in', action: 'ACCEPT', proto: 'tcp', dport: '2222', source: release.source, enable: 0, ipversion: release.source.includes(':') ? 6 : 4 }
      await t.test(`${release.name} ${scope.name} complete list and detail stay private`, async () => {
        const count = requests.length
        const absent = await command('get', scope.path, scope.target, [], false)
        assert.equal(absent.value.error.code, 'PRIVATE_SINK_REQUIRED')
        assert.equal(requests.length, count)
        const read = await command('get', scope.path, scope.target)
        assert.deepEqual(read.value.data, { privateResult: true })
        assert.deepEqual(read.frame.payload.map((rule: Rule) => rule.dport), ['1001', '1002'])
        const detail = await command('get', item, { ...scope.target, pos: 0 })
        assert.equal(detail.frame.payload.comment, canary)
      })
      await t.test(`${release.name} ${scope.name} creation previews and prepends a fixed disabled rule`, async () => {
        state.set(wire(scope.path), initial())
        const before = writes.length, preview = await command('create', scope.path, create, ['--preview'])
        assert.equal(preview.code, 0)
        assert.equal(preview.value.privatePlan, true)
        assert.equal(preview.frame.payload.nonAtomicCreate, true)
        assert.match(preview.value.warnings[0].messages.join(' '), /NON-ATOMIC CREATE/)
        assert.deepEqual(preview.frame.payload.after.map((rule: Rule) => rule.dport), ['2222', '1001', '1002'])
        assert.equal(preview.frame.payload.after[0].enable, 0)
        assert.equal(preview.frame.binding.request, createHash('sha256').update(preview.value.confirmation.split('.')[1]).digest('hex'))
        assert.equal(writes.length, before)
        const result = await command('create', scope.path, create, ['--confirm', preview.value.confirmation])
        assert.equal(result.code, 0)
        assert.equal(result.value.status, 'success')
        assert.equal(result.frame.payload, null)
        assert.equal(writes.length, before + 1)
        assert.equal(writes.at(-1)!.fields.enable, '0')
        const observed = await command('get', scope.path, scope.target)
        assert.deepEqual(observed.frame.payload.map((rule: Rule) => rule.dport), ['2222', '1001', '1002'])
        assert.equal(observed.frame.payload[0].enable, 0)
      })
      await t.test(`${release.name} ${scope.name} enabling and editing require a fresh digest-guarded confirmation`, async () => {
        state.set(wire(scope.path), [{ ...staged }, ...initial()])
        const api = { ...scope.target, pos: 0, enable: 1, dport: '2223' }, preview = await command('set', item, api, ['--preview'])
        assert.equal(preview.frame.payload.before[0].enable, 0)
        assert.equal(preview.frame.payload.after[0].enable, 1)
        const changed = await command('set', item, { ...api, pos: 1 }, ['--confirm', preview.value.confirmation])
        assert.equal(changed.value.error.code, 'CONFIRMATION_MISMATCH')
        const result = await command('set', item, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.value.status, 'success')
        assert.match(writes.at(-1)!.fields.digest!, /^[a-f0-9]{40}$/)
        const observed = await command('get', item, { ...scope.target, pos: 0 })
        assert.equal(observed.frame.payload.enable, 1)
        assert.equal(observed.frame.payload.dport, '2223')
      })
      for (const field of ['source', 'dest']) await t.test(`${release.name} ${scope.name} repairing ${field} succeeds after provider diagnostics are recomputed`, async () => {
        const errors = { [field]: canary }
        state.set(wire(scope.path), [{ type: 'in', action: 'DROP', enable: 1, [field]: 'missing-alias', errors },
          { type: 'out', action: 'DROP', enable: 1, source: 'missing-alias', errors: { source: canary } }, ...initial()])
        const api = { ...scope.target, pos: 0, [field]: release.source }
        const preview = await command('set', item, api, ['--preview'])
        assert.equal(preview.code, 0)
        assert.deepEqual(preview.frame.payload.before[0].errors, errors)
        assert.equal(preview.frame.payload.after.some((rule: Rule) => Object.hasOwn(rule, 'errors')), false)
        assert.equal(preview.frame.payload.after[0][field], release.source)
        const before = writes.length
        const result = await command('set', item, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.code, 0)
        assert.equal(result.value.status, 'success')
        assert.equal((await saved(preview.value.id)).status, 'success')
        assert.equal(writes.length, before + 1)
        const observed = await command('get', item, { ...scope.target, pos: 0 })
        assert.equal(observed.frame.payload[field], release.source)
        assert.equal(Object.hasOwn(observed.frame.payload, 'errors'), false)
        const remaining = await command('get', item, { ...scope.target, pos: 1 })
        assert.deepEqual(remaining.frame.payload.errors, { source: canary })
      })
      await t.test(`${release.name} ${scope.name} reorder uses the provider original-position boundary`, async () => {
        state.set(wire(scope.path), [{ ...staged, enable: 1, dport: '2223' }, ...initial()])
        const api = { ...scope.target, pos: 0, moveto: 2 }, preview = await command('set', item, api, ['--preview'])
        assert.deepEqual(preview.frame.payload.after.map((rule: Rule) => rule.dport), ['1001', '2223', '1002'])
        const result = await command('set', item, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.value.status, 'success')
        const observed = await command('get', scope.path, scope.target)
        assert.deepEqual(observed.frame.payload.map((rule: Rule) => rule.dport), ['1001', '2223', '1002'])
      })
      await t.test(`${release.name} ${scope.name} deleting the confirmed rule preserves the remaining order`, async () => {
        const [first, last] = initial()
        state.set(wire(scope.path), [first!, { ...staged, enable: 1, dport: '2223' }, last!])
        const api = { ...scope.target, pos: 1 }, preview = await command('delete', item, api, ['--preview'])
        assert.match(preview.value.warnings[0].messages.join(' '), /RULE DELETION/)
        const result = await command('delete', item, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.value.status, 'success')
        const observed = await command('get', scope.path, scope.target)
        assert.deepEqual(observed.frame.payload.map((rule: Rule) => rule.dport), ['1001', '1002'])
      })
    }
    const definition = `${groups}/{group}`, groupItem = `${definition}/{pos}`
    for (const guest of scopes.filter(scope => ['qemu', 'lxc'].includes(scope.name))) {
      const name = `onboard-${guest.name}`, groupKey = wire(definition, name), guestKey = wire(guest.path), item = `${guest.path}/{pos}`
      const reference = { ...guest.target, type: 'group', action: name, iface: 'net0' }
      await t.test(`${release.name} ${guest.name} provisions a group and independently stages and enables its reference`, async () => {
        mode = 'success'
        state.delete(groupKey)
        groupComments.delete(name)
        state.set(guestKey, initial())
        assert.equal((await confirmed('create', groups, { group: name, comment: { env: 'RULE_COMMENT' } })).value.status, 'success')
        const index = await command('get', groups, {})
        assert.equal(index.frame.payload.find((row: Rule) => row.group === name).comment, canary)
        assert.equal((await confirmed('create', definition, { group: name, type: 'in', action: 'ACCEPT', proto: 'tcp', dport: '443' })).value.status, 'success')
        assert.equal((await confirmed('set', groupItem, { group: name, pos: 0, enable: 1 })).value.status, 'success')
        const preview = await command('create', guest.path, reference, ['--preview'])
        assert.deepEqual(preview.frame.payload.after[0], { type: 'group', action: name, enable: 0, iface: 'net0', pos: 0 })
        assert.equal(preview.frame.payload.referencedGroup.group, name)
        assert.equal(preview.frame.payload.referencedGroup.rules[0].dport, '443')
        assert.match(JSON.stringify(preview.value.warnings), /NON-ATOMIC GROUP REFERENCE/)
        assert.equal((await command('create', guest.path, reference, ['--confirm', preview.value.confirmation])).value.status, 'success')
        assert.equal((await command('get', item, { ...guest.target, pos: 0 })).frame.payload.enable, 0)
        assert.equal((await confirmed('set', item, { ...guest.target, pos: 0, enable: 1 })).value.status, 'success')
        assert.equal((await command('get', item, { ...guest.target, pos: 0 })).frame.payload.enable, 1)
        const move = { ...guest.target, pos: 0, moveto: 2 }, ordered = await command('set', item, move, ['--preview'])
        assert.deepEqual(ordered.frame.payload.after.map((row: Rule) => row.type), ['in', 'group', 'out'])
        assert.equal((await command('set', item, { ...move, moveto: 3 }, ['--confirm', ordered.value.confirmation])).value.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal((await command('set', item, move, ['--confirm', ordered.value.confirmation])).value.status, 'success')
        assert.equal((await confirmed('delete', item, { ...guest.target, pos: 1 })).value.status, 'success')
        assert.equal((await confirmed('delete', groupItem, { group: name, pos: 0 })).value.status, 'success')
        assert.equal((await confirmed('delete', definition, { group: name })).value.status, 'success')
        assert.equal((await command('get', groups, {})).frame.payload.some((row: Rule) => row.group === name), false)
      })
      await t.test(`${release.name} ${guest.name} reference confirmation binds group identity and observed ordered content`, async () => {
        mode = 'success'
        state.set(groupKey, initial())
        state.set(wire(definition, 'other'), initial())
        state.set(guestKey, initial())
        const before = writes.length, preview = await command('create', guest.path, reference, ['--preview'])
        assert.equal(preview.frame.payload.referencedGroup.rules[0].comment, canary)
        const changed = await command('create', guest.path, { ...reference, action: 'other' }, ['--confirm', preview.value.confirmation])
        assert.equal(changed.value.error.code, 'CONFIRMATION_MISMATCH')
        state.get(groupKey)!.reverse()
        const stale = await command('create', guest.path, reference, ['--confirm', preview.value.confirmation])
        assert.equal(stale.value.error.code, 'CONFIRMATION_MISMATCH')
        assert.equal(writes.length, before)
        assert.deepEqual(state.get(guestKey), initial())
      })
      await t.test(`${release.name} ${guest.name} retargeting inspects the new group without rewriting either definition`, async () => {
        mode = 'success'
        state.set(groupKey, initial())
        state.set(wire(definition, 'other'), [{ type: 'out', action: 'DROP', enable: 1 }])
        state.set(guestKey, [{ type: 'group', action: name, enable: 1, iface: 'net0' }])
        const api = { ...guest.target, pos: 0, type: 'group', action: 'other', iface: 'net1' }, preview = await command('set', item, api, ['--preview'])
        assert.equal(preview.frame.payload.referencedGroup.group, 'other')
        assert.equal(preview.frame.payload.referencedGroup.rules[0].type, 'out')
        assert.equal((await command('set', item, api, ['--confirm', preview.value.confirmation])).value.status, 'success')
        assert.deepEqual((await command('get', item, { ...guest.target, pos: 0 })).frame.payload, { type: 'group', action: 'other', enable: 1, iface: 'net1', pos: 0, digest: digest([{ type: 'group', action: 'other', enable: 1, iface: 'net1' }]) })
        assert.deepEqual(state.get(groupKey), initial())
      })
      await t.test(`${release.name} ${guest.name} activation retains uncertainty when a shared group changes during dispatch`, async () => {
        mode = 'success'
        state.set(groupKey, initial())
        state.set(guestKey, [{ type: 'group', action: name, enable: 0 }])
        const api = { ...guest.target, pos: 0, enable: 1 }, preview = await command('set', item, api, ['--preview']), before = writes.length
        mode = 'reference-race'
        const result = await command('set', item, api, ['--confirm', preview.value.confirmation])
        assert.equal(result.value.error.code, 'WRITE_UNCERTAIN')
        assert.equal(state.get(guestKey)![0]!.enable, 1)
        assert.equal((await saved(preview.value.id)).status, 'uncertain')
        mode = 'success'
        assert.equal((await command('set', item, api, ['--confirm', preview.value.confirmation])).value.error.code, 'CONFIRMATION_USED')
        assert.equal(writes.length, before + 1)
      })
      await t.test(`${release.name} ${guest.name} orphan references can be disabled and removed without recreating the group`, async () => {
        mode = 'success'
        state.delete(groupKey)
        state.set(guestKey, [{ type: 'group', action: name, enable: 1 }])
        assert.equal((await confirmed('set', item, { ...guest.target, pos: 0, enable: 0 })).value.status, 'success')
        assert.equal((await confirmed('delete', item, { ...guest.target, pos: 0 })).value.status, 'success')
        assert.deepEqual(state.get(guestKey), [])
        assert.equal(state.has(groupKey), false)
      })
      await t.test(`${release.name} ${guest.name} missing definitions block reference activation`, async () => {
        mode = 'success'
        state.delete(groupKey)
        state.set(guestKey, [{ type: 'group', action: name, enable: 0 }])
        const before = writes.length, preview = await command('set', item, { ...guest.target, pos: 0, enable: 1 }, ['--preview'])
        assert.equal(preview.value.error.code, 'HTTP_ERROR')
        assert.equal(state.get(guestKey)![0]!.enable, 0)
        assert.equal(writes.length, before)
      })
      await t.test(`${release.name} ${guest.name} reported group errors prevent activation without exposing diagnostics`, async () => {
        mode = 'success'
        state.set(groupKey, [{ type: 'in', action: 'DROP', source: 'missing-alias', enable: 1, errors: { source: canary } }])
        state.set(guestKey, [{ type: 'group', action: name, enable: 0 }])
        const before = writes.length, result = await command('set', item, { ...guest.target, pos: 0, enable: 1 }, ['--preview'])
        assert.equal(result.value.error.code, 'INVALID_INPUT')
        assert.equal(state.get(guestKey)![0]!.enable, 0)
        assert.equal(writes.length, before)
      })
    }
    await t.test(`${release.name} group deletion retains its native nonempty guard and uncertain error semantics`, async () => {
      mode = 'success'
      state.set(wire(definition, 'protected'), initial())
      const result = await confirmed('delete', definition, { group: 'protected' })
      assert.equal(result.value.error.code, 'WRITE_UNCERTAIN')
      assert.deepEqual(state.get(wire(definition, 'protected')), initial())
    })
    await t.test(`${release.name} provider comment rejection does not expose a group creation secret`, async () => {
      mode = 'metadata-reject'
      state.delete(wire(definition, 'rejected'))
      const result = await confirmed('create', groups, { group: 'rejected', comment: { env: 'RULE_COMMENT' } })
      assert.equal(result.value.error.code, 'HTTP_ERROR')
      assert.equal(state.has(wire(definition, 'rejected')), false)
      mode = 'success'
    })
    await t.test(`${release.name} a canonical accept group survives discovery and reference staging`, async () => {
      mode = 'success'
      state.delete(wire(definition, 'accept'))
      assert.equal((await confirmed('create', groups, { group: 'accept' })).value.status, 'success')
      assert.equal((await command('get', groups, {})).frame.payload.some((row: Rule) => row.group === 'accept'), true)
      assert.equal((await confirmed('create', definition, { group: 'accept', type: 'in', action: 'DROP' })).value.status, 'success')
      state.set(wire(scopes[2]!.path), [])
      const api = { ...scopes[2]!.target, type: 'group', action: 'accept' }, preview = await command('create', scopes[2]!.path, api, ['--preview'])
      assert.equal(preview.frame.payload.referencedGroup.rules[0].action, 'DROP')
      assert.equal(JSON.stringify(preview.value.warnings).includes('ACCEPT-ALL RULE'), false)
      assert.equal((await command('create', scopes[2]!.path, api, ['--confirm', preview.value.confirmation])).value.status, 'success')
      assert.equal((await command('get', scopes[2]!.path, scopes[2]!.target)).frame.payload[0].type, 'group')
    })
    for (const [verb, path, api] of [
      ['create', groups, { group: 'Web' }],
      ['delete', definition, { group: 'Web' }],
      ['get', definition, { group: 'Web' }],
      ['get', groupItem, { group: 'Web', pos: 0 }],
      ['create', definition, { group: 'Web', type: 'in', action: 'ACCEPT' }],
      ['set', groupItem, { group: 'Web', pos: 0, enable: 0 }],
      ['delete', groupItem, { group: 'Web', pos: 0 }],
      ...scopes.slice(2, 4).flatMap(guest => [
        ['create', guest.path, { ...guest.target, type: 'group', action: 'Web' }],
        ['set', `${guest.path}/{pos}`, { ...guest.target, pos: 0, type: 'group', action: 'Web' }],
      ] as const),
    ] as const) await t.test(`${release.name} refuses noncanonical identity for ${verb} ${path}`, async () => {
      const before = requests.length
      const result = await command(verb, path, api, verb === 'get' ? [] : ['--preview'])
      assert.equal(result.value.error.code, 'INVALID_INPUT')
      assert.equal(requests.length, before)
      const schema = await execute(process.execPath, [executable, 'schema', verb, path, '--catalogue', release.name, '--format', 'json'], { env: environment })
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      assert.equal(validate({ api }), false)
    })
    for (const guest of scopes.slice(2, 4)) for (const verb of ['create', 'set']) await t.test(`${release.name} ${guest.name} ${verb} schema distinguishes packet actions from reference names`, async () => {
      const path = verb === 'create' ? guest.path : `${guest.path}/{pos}`
      const schema = await execute(process.execPath, [executable, 'schema', verb, path, '--catalogue', release.name, '--format', 'json'], { env: environment })
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      const target = { ...guest.target, ...(verb === 'set' ? { pos: 0 } : {}) }
      for (const type of ['in', 'out']) for (const action of ['ACCEPT', 'DROP', 'REJECT']) assert.equal(validate({ api: { ...target, type, action } }), true)
      assert.equal(validate({ api: { ...target, type: 'group', action: 'web' } }), true)
      assert.equal(validate({ api: { ...target, type: 'group', action: 'ACCEPT' } }), false)
    })
    const scope = scopes[2]!, item = `${scope.path}/{pos}`, create = { ...scope.target, type: 'in', action: 'ACCEPT' }
    for (const method of ['create', 'set', 'reorder', 'delete']) await t.test(`${release.name} diagnostic-only changes invalidate ${method} confirmation`, async () => {
      state.set(wire(scope.path), [{ ...initial()[0], errors: { source: canary } }, initial()[1]!])
      const path = method === 'create' ? scope.path : item, verb = method === 'reorder' ? 'set' : method
      const api = method === 'create' ? create : { ...scope.target, pos: 0, ...(method === 'set' ? { enable: 0 } : method === 'reorder' ? { moveto: 2 } : {}) }
      const preview = await command(verb, path, api, ['--preview'])
      assert.equal(preview.code, 0)
      assert.deepEqual(preview.frame.payload.before[0].errors, { source: canary })
      assert.equal(preview.frame.payload.after.some((rule: Rule) => Object.hasOwn(rule, 'errors')), false)
      const rules = state.get(wire(scope.path))!, before = writes.length, originalDigest = digest(rules)
      rules[0]!.errors = { source: `${canary}-changed` }
      assert.equal(digest(rules), originalDigest)
      const result = await command(verb, path, api, ['--confirm', preview.value.confirmation])
      assert.equal(result.value.error.code, 'CONFIRMATION_MISMATCH')
      assert.equal(writes.length, before)
    })
    await t.test(`${release.name} inherited unreviewed port selectors cannot be activated`, async () => {
      state.set(wire(scope.path), [{ type: 'in', action: 'ACCEPT', enable: 0, proto: 'tcp', dport: 'ssh' }])
      const before = writes.length
      const result = await command('set', item, { ...scope.target, pos: 0, enable: 1 }, ['--preview'])
      assert.equal(result.value.error.code, 'INVALID_INPUT')
      assert.equal(writes.length, before)
    })
    for (const move of [
      { name: 'append', pos: 0, moveto: 200, order: ['1002', '1001'] },
      { name: 'same-position', pos: 0, moveto: 0, order: ['1001', '1002'] },
      { name: 'upward', pos: 1, moveto: 0, order: ['1002', '1001'] },
    ]) await t.test(`${release.name} reorder ${move.name} boundary preserves the previewed sequence`, async () => {
      state.set(wire(scope.path), initial())
      const api = { ...scope.target, pos: move.pos, moveto: move.moveto }, preview = await command('set', item, api, ['--preview'])
      assert.deepEqual(preview.frame.payload.after.map((rule: Rule) => rule.dport), move.order)
      const result = await command('set', item, api, ['--confirm', preview.value.confirmation])
      assert.equal(result.value.status, 'success')
      const observed = await command('get', scope.path, scope.target)
      assert.deepEqual(observed.frame.payload.map((rule: Rule) => rule.dport), move.order)
    })
    await t.test(`${release.name} unverifiable rules metadata prevents preview and mutation`, async () => {
      state.set(wire(scope.path), initial())
      const before = writes.length
      mode = 'malformed'
      const result = await command('create', scope.path, create, ['--preview'])
      mode = 'success'
      assert.equal(result.value.error.code, 'INVALID_RESPONSE', JSON.stringify(result.value.error))
      assert.equal(writes.length, before)
    })
    for (const method of ['create', 'set', 'delete']) await t.test(`${release.name} changed ordered state invalidates ${method} before mutation`, async () => {
      state.set(wire(scope.path), initial())
      const path = method === 'create' ? scope.path : item, api = method === 'create' ? create : { ...scope.target, pos: 0, ...(method === 'set' ? { enable: 0 } : {}) }
      const preview = await command(method, path, api, ['--preview']), before = writes.length
      state.get(wire(scope.path))!.reverse()
      const result = await command(method, path, api, ['--confirm', preview.value.confirmation])
      assert.equal(result.value.error.code, 'CONFIRMATION_MISMATCH')
      assert.equal(writes.length, before)
    })
    for (const failure of ['create-race', 'verify-unavailable']) await t.test(`${release.name} ${failure} leaves creation uncertain without retry or deletion`, async () => {
      state.set(wire(scope.path), initial()); applied = false
      const before = writes.length, preview = await command('create', scope.path, create, ['--preview'])
      mode = failure
      const result = await command('create', scope.path, create, ['--confirm', preview.value.confirmation])
      mode = 'success'
      assert.equal(result.value.error.code, 'WRITE_UNCERTAIN')
      assert.equal((await saved(preview.value.id)).status, 'uncertain')
      assert.equal(writes.length, before + 1)
      assert.equal(writes.at(-1)!.method, 'POST')
      const observed = await command('get', scope.path, scope.target)
      assert.equal(observed.frame.payload[0].enable, 0)
      const replay = await command('create', scope.path, create, ['--confirm', preview.value.confirmation])
      assert.equal(replay.value.error.code, 'CONFIRMATION_USED')
      assert.equal(writes.length, before + 1)
    })
    for (const method of ['set', 'delete']) await t.test(`${release.name} provider digest rejects a last-moment ${method} race`, async () => {
      state.set(wire(scope.path), initial())
      const api = { ...scope.target, pos: 0, ...(method === 'set' ? { enable: 0 } : {}) }, preview = await command(method, item, api, ['--preview'])
      mode = 'native-race'
      const result = await command(method, item, api, ['--confirm', preview.value.confirmation])
      mode = 'success'
      assert.equal(result.code, 1)
      assert.equal((await saved(preview.value.id)).status, 'failed')
      const observed = await command('get', scope.path, scope.target)
      assert.deepEqual(observed.frame.payload.map((rule: Rule) => rule.dport), ['1002', '1001'])
      assert.equal(observed.frame.payload[1].enable, 1)
    })
    await t.test(`${release.name} an empty ruleset stages ACCEPT-all before separate guarded enable`, async () => {
      state.set(wire(scope.path), [])
      const broad = { ...create, source: release.name === 'legacy-8.2.7' ? '0.0.0.0/0' : '::/0', iface: 'net0' }
      const preview = await command('create', scope.path, broad, ['--preview'])
      assert.deepEqual(preview.frame.payload.before, [])
      assert.match(JSON.stringify(preview.value.warnings), /ACCEPT-ALL RULE/)
      const staged = await command('create', scope.path, broad, ['--confirm', preview.value.confirmation])
      assert.equal(staged.value.status, 'success')
      const observed = await command('get', scope.path, scope.target)
      assert.equal(observed.frame.payload[0].enable, 0)
      const enable = { ...scope.target, pos: 0, enable: 1 }, approved = await command('set', item, enable, ['--preview'])
      assert.match(JSON.stringify(approved.value.warnings), /ACCEPT-ALL RULE/)
      const enabled = await command('set', item, enable, ['--confirm', approved.value.confirmation])
      assert.equal(enabled.value.status, 'success')
      const active = await command('get', scope.path, scope.target)
      assert.equal(active.frame.payload[0].enable, 1)
      const help = await execute(process.execPath, [executable, 'create', scope.path, '--help', '--format', 'json'], { env: environment })
      assert.match(JSON.parse(help.stdout).policy.reason, /Non-atomic.*fixed disabled/)
      const schema = await execute(process.execPath, [executable, 'schema', 'create', scope.path, '--catalogue', release.name, '--format', 'json'], { env: environment })
      const validate = new Ajv({ strict: false }).compile(JSON.parse(schema.stdout).invocation.schema)
      assert.equal(validate({ api: create }), true)
      assert.equal(validate({ api: { ...create, enable: 1 } }), false)
      assert.equal(validate({ api: { ...create, source: '2001:db8::/128' } }), true)
      assert.equal(validate({ api: { ...create, source: '::/0' } }), true)
      assert.equal(validate({ api: { ...create, source: '2001:db8:0:0:0:0:0:1/64' } }), true)
      assert.equal(validate({ api: { ...create, source: '2001:::1' } }), false)
      assert.equal(validate({ api: { ...create, source: '::/129' } }), false)
      assert.equal(validate({ api: { ...create, source: '192.0.2.0/33' } }), false)
      assert.equal(validate({ api: { ...create, proto: 'tcp', dport: '65536' } }), false)
      assert.equal(validate({ api: { ...create, proto: 'tcp', dport: '0' } }), false)
    })
    for (const [verb, path, api, code] of [
      ['create', scope.path, { ...create, enable: 1 }, 'INVALID_INPUT'], ['create', scope.path, { ...create, pos: 1 }, 'CONTRACT_UNRESOLVED'],
      ['create', scope.path, { ...create, digest: 'ignored' }, 'CONTRACT_UNRESOLVED'], ['create', scope.path, { ...create, macro: 'SSH' }, 'CONTRACT_UNRESOLVED'],
      ['create', scope.path, { ...create, proto: 'tcp', dport: '0' }, 'INVALID_INPUT'],
      ['set', item, { ...scope.target, pos: 0, moveto: 1, enable: 0 }, 'INVALID_INPUT'],
      ['set', item, { ...scope.target, pos: 0, enable: 2 }, 'INVALID_INPUT'],
      ['create', batch, { node: 'node-a', commands: JSON.stringify([{ method: 'POST', path: 'qemu/100/firewall/rules', args: { type: 'in', action: 'ACCEPT' } }]) }, 'CONTRACT_UNRESOLVED'],
      ['create', '/cluster/sdn/vnets/{vnet}/firewall/rules', { vnet: 'net-a', type: 'forward', action: 'ACCEPT' }, 'CONTRACT_UNRESOLVED'],
      ['create', '/cluster/firewall/groups/{group}', { group: 'group-a', type: 'group', action: 'nested' }, 'INVALID_INPUT'],
      ['create', '/cluster/firewall/groups/{group}', { group: 'group-a', type: 'in', action: 'ACCEPT', iface: 'eth0' }, 'CONTRACT_UNRESOLVED'],
      ['create', scope.path, { ...scope.target, type: 'group', action: 'web', source: '192.0.2.0/24' }, 'INVALID_INPUT'],
      ['create', '/nodes/{node}/firewall/rules', { node: 'node-a', type: 'group', action: 'web' }, 'INVALID_INPUT'],
      ['create', groups, { group: 'web', rename: 'other' }, 'CONTRACT_UNRESOLVED'],
      ['create', groups, { group: 'web', comment: canary }, 'INVALID_INPUT'],
    ] as const) await t.test(`${release.name} refuses ${verb} ${path} ${Object.keys(api).at(-1)}`, async () => {
      const before = requests.length
      const result = await command(verb, path, api, ['--preview'])
      assert.equal(result.value.error.code, code)
      assert.equal(requests.length, before)
    })
    const before = requests.length
    const missing = await command('create', scope.path, create, ['--preview'], false)
    assert.equal(missing.value.error.code, 'PRIVATE_SINK_REQUIRED')
    assert.equal(requests.length, before)
    for (const extraEnv of [{ PROXMOX_AXI_READ_ONLY: '1' }, { PROXMOX_AXI_ACTOR: 'fixture', PROXMOX_AXI_HOST_OPERATIONS: '[]' }]) {
      const disabled = await command('create', scope.path, create, ['--preview'], true, extraEnv)
      assert.equal(disabled.value.error.code, 'WRITE_DISABLED')
      assert.equal(requests.length, before)
    }
  }
  for (const name of (await readdir(`${log}.d`)).filter(name => name.endsWith('.json'))) {
    const record = await readFile(join(`${log}.d`, name), 'utf8')
    assert.equal(record.includes(canary), false)
    assert.equal(record.includes('192.0.2.0/24'), false)
    assert.equal(record.includes('2001:db8::/64'), false)
  }
})

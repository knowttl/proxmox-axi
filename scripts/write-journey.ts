import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:https'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { spawn, type ChildProcess } from 'node:child_process'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { decode } from '@toon-format/toon'

interface CommandResult { code: number, stdout: string, stderr: string }
interface Journey {
  out: string
  scratch: string
  executable: string
  caFile: string
  env: Record<string, string>
  command: (executable: string, args: string[], options: { env: Record<string, string> }) => Promise<CommandResult>
  cases: Record<string, unknown>[]
  ledger: Record<string, unknown>[]
  transcripts: string[]
  hosted?: { log: string, otherActorEnv: Record<string, string>, configure: (origin: string, toolOperations: string[], hostOperations: string[], enabled: boolean) => Promise<void> }
}
const operationId = (method: string, path: string) => `OP-${method}-${createHash('sha256').update(`${method} ${path}`).digest('hex').slice(0, 10)}`
const upid = 'UPID:pve-test:00000001:00000002:00000003:qmstart:100:synthetic@pve:'
const version = { version: '8.2.7', release: '8.2', repoid: '3e0176e6bb2ade3b' }

export async function exerciseWriteJourney(options: Journey): Promise<void> {
  const { scratch, executable, caFile, cases, ledger, transcripts } = options
  const directory = join(scratch, options.hosted ? 'hosted-write-journey' : 'write-journey')
  await mkdir(directory, { mode: 0o700 })
  const log = options.hosted?.log ?? join(directory, 'writes.log')
  const config = join(directory, 'config.json')
  const guestState = new Map<string, Record<string, unknown>>([
    ['qemu', { status: 'stopped', memory: 512 }], ['lxc', { status: 'stopped', memory: 512 }],
  ])
  const pools = new Set<string>()
  let mode = 'success', taskState = 'running', taskReads = 0, mutationCount = 0
  let activeCase = ''
  let crashing: ChildProcess | undefined
  let bodyEvidence: Record<string, unknown>[] = []
  const snapshot = () => ({ guests: [...guestState].map(([family, state]) => ({ family, status: state.status, cores: state.cores, memory: state.memory })), pools: [...pools] })
  const journalRecords = async (): Promise<Record<string, unknown>[]> => {
    let names: string[]
    try { names = await readdir(`${log}.d`) } catch { return [] }
    return Promise.all(names.filter(name => name.endsWith('.json')).map(async name => JSON.parse(await readFile(join(`${log}.d`, name), 'utf8')) as Record<string, unknown>))
  }
  const apply = (method: string, path: string, args: Record<string, string>): unknown => {
    if (path.endsWith('/execute')) {
      const commands = JSON.parse(args.commands!) as { method: string, path: string, args?: Record<string, string> }[]
      return commands.map((child, index) => mode === 'partial-batch' && index === 1 ? { status: 500, message: 'controlled child failure' } :
        { status: 200, data: apply(child.method, `/api2/json/nodes/pve-test/${child.path}`, child.args ?? {}) })
    }
    if (path === '/api2/json/pools') {
      if (method === 'POST') pools.add(args.poolid!)
      if (method === 'DELETE') pools.delete(args.poolid!)
      return null
    }
    if (path.includes('/tasks/')) { taskState = 'cancelled'; return null }
    const family = path.includes('/lxc/') ? 'lxc' : 'qemu'
    if (path.endsWith('/config')) {
      for (const [name, value] of Object.entries(args)) guestState.get(family)![name] = name === 'cores' ? Number(value) : value
      return null
    }
    if (method === 'DELETE') { guestState.delete(family); return upid }
    guestState.get(family)!.status = path.endsWith('/start') ? 'running' : 'stopped'
    taskState = 'running'
    taskReads = 0
    return upid
  }
  const serve = async (request: IncomingMessage, reply: ServerResponse) => {
    const url = new URL(request.url!, 'https://fake.invalid')
    const path = decodeURIComponent(url.pathname)
    const method = request.method!
    const row: Record<string, unknown> = { case: activeCase, method, path: request.url }
    ledger.push(row)
    if (request.headers.authorization !== `PVEAPIToken=synthetic@pve!acceptance=${options.env.PROXMOX_AXI_TOKEN}`) {
      reply.writeHead(401).end(); return
    }
    let data: unknown
    if (method === 'GET') {
      if (path.endsWith('/version')) data = mode === 'unknown-major' ? { ...version, version: '77.0.0' } : version
      else if (path.endsWith('/status') && path.includes('/tasks/')) {
        taskReads++
        if (mode === 'task-completes' && taskReads >= 2) taskState = 'success'
        data = { upid: mode === 'wrong-upid' ? upid.replace('qmstart', 'qmstop') : upid, node: 'pve-test',
          status: taskState === 'running' ? 'running' : 'stopped', exitstatus: taskState === 'success' ? 'OK' : 'controlled task failure',
          starttime: 1, type: 'qmstart', pstart: 2, id: '100', user: 'synthetic@pve', pid: 1 }
      } else if (path.endsWith('/log')) data = [{ n: 1, t: 'started' }, { n: 2, t: 'TASK OK' }]
      else if (path.endsWith('/config')) data = mode === 'filtered' ? {} : guestState.get(path.includes('/lxc/') ? 'lxc' : 'qemu') ?? {}
      else if (path.endsWith('/status/current')) data = { ...guestState.get(path.includes('/lxc/') ? 'lxc' : 'qemu'), vmid: 100, ha: {} }
      else data = []
    } else {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const args = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))
      const records = await journalRecords()
      assert.ok(records.some(record => record.status === 'intent'), 'durable intent must precede transmission')
      row.intentBeforeTransmission = true
      row.parameterNames = Object.keys(args)
      const transmission: Record<string, unknown> = { method, path, args, before: snapshot() }
      bodyEvidence.push(transmission)
      mutationCount++
      if (mode === 'disconnect-before-acceptance') { reply.destroy(); return }
      data = apply(method, path, args)
      transmission.after = snapshot()
      if (mode === 'crash-after-commit') { crashing!.kill('SIGKILL'); reply.destroy(); return }
      if (mode === 'lost-response') { reply.destroy(); return }
    }
    reply.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ data }))
  }
  const server = createServer({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) }, (request, reply) => {
    void serve(request, reply).catch(error => { reply.destroy(); throw error })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  const origin = `https://127.0.0.1:${address.port}`
  const env: Record<string, string> = { ...options.env, PROXMOX_AXI_CONFIG: config, PROXMOX_AXI_PROFILE: 'writes', PROXMOX_AXI_WRITE_LOG: log }
  const ids = ['qemu', 'lxc'].flatMap(family => [
    operationId('POST', `/nodes/{node}/${family}/{vmid}/status/start`), operationId('POST', `/nodes/{node}/${family}/{vmid}/status/stop`),
    operationId('PUT', `/nodes/{node}/${family}/{vmid}/config`), operationId('DELETE', `/nodes/{node}/${family}/{vmid}`),
  ]).concat(operationId('POST', '/nodes/{node}/execute'), operationId('DELETE', '/nodes/{node}/tasks/{upid}'),
    operationId('POST', '/pools'), operationId('PUT', '/pools'), operationId('DELETE', '/pools'))
  const profile = async (operations: string[] = ids) => options.hosted ? options.hosted.configure(origin, operations, ids, true) : writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'writes', profiles: {
    writes: { auth: 'api-token', origin, tokenId: 'synthetic@pve!acceptance', token: { env: 'PROXMOX_AXI_TOKEN' }, caBundle: caFile, writes: { operations } },
  } }), { mode: 0o600 })
  await profile()
  const invoke = async (id: string, args: string[], expected: { code?: number, error?: string, status?: string, mutations?: number } = {}, environment = options.hosted ? options.env : env) => {
    activeCase = id
    const before = mutationCount
    const started = performance.now()
    const result = await options.command(process.execPath, [executable, ...(options.hosted ? ['proxmox-axi'] : []), ...args, '--format', 'json'], { env: environment })
    transcripts.push(`case: ${id}\nexit: ${result.code}\nstdout:\n${result.stdout}stderr:\n${result.stderr}`)
    assert.equal(result.code, expected.code ?? 0, `${id}: ${result.stdout}${result.stderr}`)
    const value = (result.stdout.startsWith('{') ? JSON.parse(result.stdout) : decode(result.stdout)) as Record<string, any>
    const hostBoundary = !!options.hosted && expected.code === 2 && expected.error === 'FLAG_BLOCKED'
    if (hostBoundary) { assert.equal(value.error?.source, 'artium-axi'); assert.equal(result.stderr, '', id) }
    else if (options.hosted && result.code !== 0) assert.match(result.stderr, /^artium-axi: request_id [0-9a-f-]{36}\n$/)
    else assert.equal(result.stderr, '', id)
    if (expected.error) assert.equal(value.error?.code, expected.error, id)
    if (expected.status) assert.equal(value.status, expected.status, id)
    assert.equal(mutationCount - before, expected.mutations ?? 0, `${id}: never retry a mutation`)
    assert.ok(performance.now() - started < 10_000, `${id}: bounded command runtime`)
    assert.ok(!result.stdout.includes(options.env.PROXMOX_AXI_TOKEN!), `${id}: credential leak`)
    cases.push({ id: `${options.hosted ? 'artium' : 'standalone'}/${id}`, hosted: !!options.hosted, expected: { hostBoundary },
      operation: ['create', 'set', 'delete'].includes(args[0]!) ? operationId(({ create: 'POST', set: 'PUT', delete: 'DELETE' } as Record<string, string>)[args[0]!]!, args[1]!) : args.slice(0, 2).join(' '),
      status: 'pass', actual: { exitCode: result.code, mutationTransmissions: mutationCount - before } })
    return value
  }
  const argsFor = (command: string, family: string, suffix = '') => [command, `/nodes/{node}/${family}/{vmid}${suffix}`, '--api-node', 'pve-test', '--api-vmid', '100']
  const start = argsFor('create', 'qemu', '/status/start')
  try {
    await profile([])
    await invoke('AC-WRITE/tool-default-off', [...start, '--preview'], { code: 1, error: 'WRITE_DISABLED' })
    await profile()
    if (options.hosted) {
      await options.hosted.configure(origin, ids, ids, false)
      await invoke('AC-WRITE/host-default-off', [...start, '--preview'], { code: 2, error: 'FLAG_BLOCKED' })
      await options.hosted.configure(origin, ids, [], true)
      await invoke('AC-WRITE/host-operation-denial', [...start, '--preview'], { code: 2, error: 'FLAG_BLOCKED' })
      await profile()
    } else {
      await invoke('AC-WRITE/host-default-off', [...start, '--preview'], { code: 1, error: 'WRITE_DISABLED' }, { ...env, PROXMOX_AXI_READ_ONLY: 'true' })
      await invoke('AC-WRITE/host-operation-denial', [...start, '--preview'], { code: 1, error: 'WRITE_DISABLED' }, { ...env, PROXMOX_AXI_ACTOR: 'actor-a', PROXMOX_AXI_HOST_OPERATIONS: '[]' })
    }
    await invoke('AC-WRITE/missing-confirmation', start, { code: 1, error: 'CONFIRMATION_REQUIRED' })
    mode = 'unknown-major'
    await invoke('AC-WRITE/unknown-major', [...start, '--preview'], { code: 1, error: 'CAPABILITY_UNSUPPORTED' })
    mode = 'success'
    if (!options.hosted) {
    const crashPreview = await invoke('AC-WRITES/crash-preview', [...start, '--preview'])
    activeCase = 'AC-WRITES/crash-after-commit'
    mode = 'crash-after-commit'
    crashing = spawn(process.execPath, [executable, ...start, '--confirm', crashPreview.confirmation, '--format', 'json'], { env, stdio: 'ignore' })
    const crashed = await new Promise<NodeJS.Signals | null>((resolve, reject) => { crashing!.once('error', reject); crashing!.once('close', (_code, signal) => resolve(signal)) })
    assert.equal(crashed, 'SIGKILL')
    mode = 'success'
    const restarted = await invoke('AC-WRITES/crash-restart', ['journal', 'show', crashPreview.id])
    assert.equal(restarted.journal.status, 'uncertain')
    await invoke('AC-WRITES/crash-replay-refused', [...start, '--confirm', crashPreview.confirmation], { code: 1, error: 'CONFIRMATION_USED' })
    }
    for (const family of ['qemu', 'lxc']) {
      for (const [action, expectedState] of [['start', 'running'], ['stop', 'stopped']]) {
        const args = argsFor('create', family, `/status/${action}`)
        const before = structuredClone(guestState.get(family))
        const preview = await invoke(`AC-WRITES/${family}-${action}-preview`, [...args, '--preview'], { status: 'preview' })
        assert.deepEqual(guestState.get(family), before, 'preview cannot alter independent business state')
        await invoke(`AC-WRITES/${family}-${action}-changed-target`, [...args.slice(0, -1), '101', '--confirm', preview.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' })
        await invoke(`AC-WRITES/${family}-${action}`, [...args, '--confirm', preview.confirmation], { status: 'accepted', mutations: 1 })
        assert.equal(guestState.get(family)!.status, expectedState)
        await invoke(`AC-WRITES/${family}-${action}-replay`, [...args, '--confirm', preview.confirmation], { code: 1, error: 'CONFIRMATION_USED' })
      }
      const args = [...argsFor('set', family, '/config'), '--api-cores', '2']
      const preview = await invoke(`AC-WRITES/${family}-config-preview`, [...args, '--preview'])
      await invoke(`AC-WRITES/${family}-config`, [...args, '--confirm', preview.confirmation], { status: 'success', mutations: 1 })
      assert.equal(guestState.get(family)!.cores, 2)
      const observation = await invoke(`AC-WRITES/${family}-config-reconcile`, ['journal', 'reconcile', preview.id])
      assert.equal(observation.journal.observation.desiredStateObserved, true)
    }
    if (!options.hosted) {
    const secret = join(directory, 'password.txt')
    const body = join(directory, 'config-body.json')
    await writeFile(secret, 'CANARY-operation-secret-v1', { mode: 0o600 })
    await writeFile(body, JSON.stringify({ node: 'pve-test', vmid: 100, cipassword: { file: secret } }))
    const secretArgs = ['set', '/nodes/{node}/qemu/{vmid}/config', '--body-file', body]
    const secretPreview = await invoke('AC-WRITES/secret-reference-preview', [...secretArgs, '--preview'])
    await writeFile(secret, 'CANARY-operation-secret-v2', { mode: 0o600 })
    await invoke('AC-WRITES/secret-revision-invalidates', [...secretArgs, '--confirm', secretPreview.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' })
    const secretFresh = await invoke('AC-WRITES/secret-reference-fresh', [...secretArgs, '--preview'])
    await invoke('AC-WRITES/secret-reference-executes', [...secretArgs, '--confirm', secretFresh.confirmation], { status: 'success', mutations: 1 })
    assert.equal(guestState.get('qemu')!.cipassword, 'CANARY-operation-secret-v2')
    const actorEnv = { ...env, PROXMOX_AXI_ACTOR: 'actor-a', PROXMOX_AXI_HOST_OPERATIONS: JSON.stringify(ids) }
    const actorPreview = await invoke('AC-WRITES/actor-preview', [...start, '--preview'], {}, actorEnv)
    await invoke('AC-WRITES/cross-actor', [...start, '--confirm', actorPreview.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' }, { ...actorEnv, PROXMOX_AXI_ACTOR: 'actor-b' })
    }
    if (options.hosted) {
      const revision = await invoke('AC-WRITES/credential-revision-preview', [...start, '--preview'])
      await profile()
      await invoke('AC-WRITES/credential-revision-invalidates', [...start, '--confirm', revision.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' })
      const actor = await invoke('AC-WRITES/authenticated-actor-preview', [...start, '--preview'])
      await invoke('AC-WRITES/authenticated-cross-actor', [...start, '--confirm', actor.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' }, options.hosted.otherActorEnv)
    }
    const expired = await invoke('AC-WRITES/stale-preview', [...start, '--preview'])
    const expiredPath = join(`${log}.d`, `${expired.id}.json`)
    const expiredRecord = JSON.parse(await readFile(expiredPath, 'utf8'))
    await writeFile(expiredPath, JSON.stringify({ ...expiredRecord, created: 0 }))
    await invoke('AC-WRITES/stale-confirmation', [...start, '--confirm', expired.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' })
    for (const failure of ['lost-response', 'disconnect-before-acceptance']) {
      const preview = await invoke(`AC-WRITES/${failure}-preview`, [...start, '--preview'])
      mode = failure
      await invoke(`AC-WRITES/${failure}`, [...start, '--confirm', preview.confirmation], { code: 1, error: 'WRITE_UNCERTAIN', mutations: 1 })
      mode = 'success'
      const retained = await invoke(`AC-WRITES/${failure}-restart`, ['journal', 'show', preview.id])
      assert.equal(retained.journal.status, 'uncertain')
      const reconciliation = await invoke(`AC-WRITES/${failure}-reconcile`, ['journal', 'reconcile', preview.id])
      assert.equal(reconciliation.journal.status, 'uncertain', 'observation cannot attribute an uncertain mutation')
    }
    const configArgs = [...argsFor('set', 'qemu', '/config'), '--api-cores', '4']
    const uncertainConfig = await invoke('AC-WRITES/filtered-preview', [...configArgs, '--preview'])
    mode = 'lost-response'
    await invoke('AC-WRITES/filtered-uncertain', [...configArgs, '--confirm', uncertainConfig.confirmation], { code: 1, error: 'WRITE_UNCERTAIN', mutations: 1 })
    mode = 'filtered'
    const filtered = await invoke('AC-WRITES/filtered-reconcile', ['journal', 'reconcile', uncertainConfig.id])
    assert.equal(filtered.journal.status, 'uncertain')
    assert.equal(filtered.journal.observation.desiredStateObserved, false)
    mode = 'success'
    const taskPreview = await invoke('AC-ASYNC/preview', [...start, '--preview'])
    await invoke('AC-ASYNC/accepted', [...start, '--confirm', taskPreview.confirmation], { status: 'accepted', mutations: 1 })
    const taskArgs = ['--api-node', 'pve-test', '--api-upid', upid, '--journal', taskPreview.id]
    await invoke('AC-ASYNC/running', ['task', 'status', ...taskArgs], { status: 'running' })
    const waiting = await invoke('AC-ASYNC/wait-bounded', ['task', 'wait', ...taskArgs, '--wait-ms', '1000'], { status: 'running' })
    assert.equal(waiting.wait, 'deadline-reached')
    mode = 'task-completes'
    await invoke('AC-ASYNC/success', ['task', 'wait', ...taskArgs], { status: 'success' })
    mode = 'success'; taskState = 'failed'
    await invoke('AC-ASYNC/failed', ['task', 'status', ...taskArgs], { code: 1, status: 'failed' })
    const logs = await invoke('AC-ASYNC/numbered-log', ['task', 'log', '--api-node', 'pve-test', '--api-upid', upid])
    assert.deepEqual(logs.data, [{ n: 1, t: 'started' }, { n: 2, t: 'TASK OK' }])
    mode = 'wrong-upid'
    await invoke('AC-ASYNC/matching-upid-required', ['task', 'status', ...taskArgs], { code: 1, error: 'INVALID_RESPONSE' })
    mode = 'success'
    const cancel = ['task', 'cancel', '--api-node', 'pve-test', '--api-upid', upid]
    const cancellation = await invoke('AC-ASYNC/cancel-preview', [...cancel, '--preview'])
    await invoke('AC-ASYNC/cancel', [...cancel, '--confirm', cancellation.confirmation], { status: 'success', mutations: 1 })
    await invoke('AC-ASYNC/cancelled-task-fails', ['task', 'status', ...taskArgs], { code: 1, status: 'failed' })
    const commands = JSON.stringify([{ method: 'POST', path: 'qemu/100/status/start' }, { method: 'POST', path: 'lxc/100/status/start' }])
    const batch = ['create', '/nodes/{node}/execute', '--api-node', 'pve-test', '--api-commands', commands]
    await profile(ids.filter(id => id !== operationId('POST', '/nodes/{node}/lxc/{vmid}/status/start')))
    await invoke('AC-SPECIAL-BATCH-POLICY/denied-child', [...batch, '--preview'], { code: 1, error: 'WRITE_DISABLED' })
    await profile()
    if (options.hosted) {
      await options.hosted.configure(origin, ids, ids.filter(id => id !== operationId('POST', '/nodes/{node}/lxc/{vmid}/status/start')), true)
      await invoke('AC-SPECIAL-BATCH-POLICY/host-denied-child', [...batch, '--preview'], { code: 2, error: 'FLAG_BLOCKED' })
      await profile()
    }
    const batchPreview = await invoke('AC-SPECIAL-BATCH-POLICY/preview', [...batch, '--preview'])
    const reordered = [...batch.slice(0, -1), JSON.stringify(JSON.parse(commands).reverse())]
    await invoke('AC-SPECIAL-BATCH-POLICY/ordered-binding', [...reordered, '--confirm', batchPreview.confirmation], { code: 1, error: 'CONFIRMATION_MISMATCH' })
    mode = 'partial-batch'
    const partial = await invoke('AC-SPECIAL-BATCH-RESULTS/partial', [...batch, '--confirm', batchPreview.confirmation], { code: 1, status: 'failed', mutations: 1 })
    assert.deepEqual(partial.children.map((child: { status: string }) => child.status), ['accepted', 'failed'])
    mode = 'success'
    const retainedPartial = await invoke('AC-SPECIAL-BATCH-RESULTS/restart', ['journal', 'show', batchPreview.id])
    assert.deepEqual(retainedPartial.journal.children.map((child: { status: string }) => child.status), ['accepted', 'failed'])
    taskState = 'success'
    const reconciledPartial = await invoke('AC-SPECIAL-BATCH-RESULTS/reconcile-children', ['journal', 'reconcile', batchPreview.id])
    assert.deepEqual(reconciledPartial.journal.children.map((child: { status: string }) => child.status), ['success', 'failed'])
    const nestedCommands = JSON.stringify([{ method: 'POST', path: 'execute', args: { commands } }])
    const nested = [...batch.slice(0, -1), nestedCommands]
    const nestedPreview = await invoke('AC-SPECIAL-BATCH-POLICY/nested-preview', [...nested, '--preview'])
    await invoke('AC-SPECIAL-BATCH-POLICY/nested', [...nested, '--confirm', nestedPreview.confirmation], { status: 'accepted', mutations: 1 })
    const configurationBatch = [...batch.slice(0, -1), JSON.stringify([
      { method: 'PUT', path: 'qemu/100/config', args: { cores: 3 } },
      { method: 'PUT', path: 'lxc/100/config', args: { cores: 4 } },
    ])]
    const uncertainBatch = await invoke('AC-SPECIAL-BATCH-RESULTS/uncertain-preview', [...configurationBatch, '--preview'])
    mode = 'lost-response'
    await invoke('AC-SPECIAL-BATCH-RESULTS/lost-response', [...configurationBatch, '--confirm', uncertainBatch.confirmation], { code: 1, error: 'WRITE_UNCERTAIN', mutations: 1 })
    mode = 'success'
    const recovered = await invoke('AC-SPECIAL-BATCH-RESULTS/reconcile-independent-children', ['journal', 'reconcile', uncertainBatch.id])
    assert.deepEqual(recovered.journal.children.map((child: { status: string, observation: { desiredStateObserved: boolean } }) =>
      ({ status: child.status, observed: child.observation.desiredStateObserved })), [{ status: 'uncertain', observed: true }, { status: 'uncertain', observed: true }])
    for (const method of ['POST', 'PUT', 'DELETE']) {
      const args = [method === 'POST' ? 'create' : method === 'PUT' ? 'set' : 'delete', '/pools', '--api-poolid', 'acceptance']
      const preview = await invoke(`AC-WRITES/pool-${method}-preview`, [...args, '--preview'])
      await invoke(`AC-WRITES/pool-${method}`, [...args, '--confirm', preview.confirmation], { status: 'success', mutations: 1 })
      assert.equal(pools.has('acceptance'), method !== 'DELETE')
    }
    for (const family of ['qemu', 'lxc']) {
      const args = argsFor('delete', family)
      const preview = await invoke(`AC-WRITES/${family}-delete-preview`, [...args, '--preview'])
      await invoke(`AC-WRITES/${family}-delete`, [...args, '--confirm', preview.confirmation], { status: 'accepted', mutations: 1 })
      assert.equal(guestState.has(family), false)
    }
    if (!options.hosted) {
    const broken = join(directory, 'unavailable.log.d')
    await writeFile(broken, 'not a directory')
    await invoke('AC-WRITES/journal-unavailable', [...start, '--preview'], { code: 1, error: 'JOURNAL_UNAVAILABLE' }, { ...env, PROXMOX_AXI_WRITE_LOG: broken.slice(0, -2) })
    }
    const records = await journalRecords()
    const serialized = JSON.stringify(records)
    assert.ok(!serialized.includes('CANARY-operation-secret'), 'operation secrets stay out of durable journals')
    assert.ok(!serialized.includes(options.env.PROXMOX_AXI_TOKEN!), 'credentials stay out of durable journals')
    await writeFile(join(options.out, `${options.hosted ? 'hosted-' : ''}journal-evidence.json`), JSON.stringify(records, null, 2))
    // Independent state evidence retains no credential or sensitive input values.
    bodyEvidence = bodyEvidence.map(row => ({ method: row.method, path: row.path, parameterNames: Object.keys(row.args as object), before: row.before, after: row.after ?? row.before }))
    await writeFile(join(options.out, `${options.hosted ? 'hosted-' : ''}business-evidence.json`), JSON.stringify({ guests: [...guestState], pools: [...pools], transmissions: bodyEvidence }, null, 2))
  } finally {
    await new Promise<void>(resolve => { server.close(() => resolve()); server.closeAllConnections() })
  }
}

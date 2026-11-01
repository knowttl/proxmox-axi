import { lstat } from 'node:fs/promises'
import { buildPath, contracts, selectContract, validateResponse, type Contract } from './contract.js'
import type { Credentials } from './credentials.js'
import { executeRequest, readVersion } from './transport.js'
import { readPrivateFile } from './private-file.js'
import { Failure } from './errors.js'
import { Journal, publicChildren, type JournalRecord } from './journal.js'
import { resultBinding } from './private-results.js'

interface Invocation {
  contract: Contract
  values: Record<string, unknown>
  wire: string
  children: Invocation[]
  revisions: unknown[]
}

function denied(): Failure {
  return new Failure('WRITE_DISABLED', 'The exact operation is not enabled by both applicable policies.', 'Enable only the required operation IDs in the selected profile and independent host policy.')
}

function checkPolicy(credentials: Credentials, contract: Contract): void {
  if (!contract.callable || !['write', 'batch', 'read'].includes(contract.policy.effect)) throw denied()
  if (!credentials.writeOperations.includes(contract.id) || /^(true|1)$/i.test(process.env.PROXMOX_AXI_READ_ONLY ?? '')) throw denied()
  if (process.env.PROXMOX_AXI_HOST_OPERATIONS !== undefined || process.env.PROXMOX_AXI_ACTOR !== undefined) {
    let operations: unknown
    try { operations = JSON.parse(process.env.PROXMOX_AXI_HOST_OPERATIONS ?? 'null') } catch { throw denied() }
    if (!Array.isArray(operations) || !operations.every(id => typeof id === 'string') || !operations.includes(contract.id)) throw denied()
  }
  if (contract.allowtoken === 0 && credentials.auth === 'api-token') throw new Failure('AUTH_SESSION_REQUIRED', 'This operation forbids API tokens.', 'Select an authorized user-session profile.')
}

async function invocation(credentials: Credentials, contract: Contract, input: Record<string, unknown>, budget = { count: 0 }, depth = 0): Promise<Invocation> {
  checkPolicy(credentials, contract)
  if (++budget.count > 64 || depth > 4) throw new Failure('INVALID_INPUT', 'Batch exceeds 64 total operations or four nesting levels.', 'Use a smaller reviewed batch.', 2)
  const values = { ...input }
  const revisions: unknown[] = []
  for (const [name, value] of Object.entries(values)) {
    if (contract.policy.allowedInputs && !contract.policy.allowedInputs.includes(name)) throw new Failure('CONTRACT_UNRESOLVED', 'Supplied parameter branch has not been admitted.', 'Inspect the operation policy and use reviewed branches only.')
    if (!contract.policy.sensitiveInputs?.includes(name)) continue
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 1) throw new Failure('INVALID_INPUT', 'Sensitive inputs require one env or file SecretRef.', 'Use --body-file with protected references.', 2)
    const ref = value as Record<string, unknown>
    let secret: string | undefined
    if (typeof ref.env === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(ref.env)) secret = process.env[ref.env]
    else if (typeof ref.file === 'string') {
      secret = (await readPrivateFile(ref.file, true)).trimEnd()
      const info = await lstat(ref.file)
      revisions.push({ file: ref.file, ino: info.ino, mtime: info.mtimeMs, size: info.size })
    } else throw new Failure('INVALID_INPUT', 'Unsupported secret reference.', 'Use an env or protected file reference.', 2)
    if (!secret) throw new Failure('AUTH_REQUIRED', 'An operation secret reference is empty.', 'Supply the selected secret source.')
    credentials.results.register(secret)
    revisions.push({ reference: value, secret })
    values[name] = secret
  }
  const children: Invocation[] = []
  if (contract.policy.effect === 'batch') {
    if (typeof values.commands !== 'string' || Buffer.byteLength(values.commands) > 32768) throw new Failure('INVALID_INPUT', 'Batch commands must be bounded JSON.', 'Supply at most 32768 bytes.', 2)
    let commands: unknown
    try { commands = JSON.parse(values.commands) } catch { throw new Failure('INVALID_INPUT', 'Batch commands are invalid JSON.', 'Use an ordered array of method, path and args objects.', 2) }
    if (!Array.isArray(commands) || !commands.length) throw new Failure('INVALID_INPUT', 'Batch must contain commands.', 'Use an ordered nonempty array.', 2)
    for (const command of commands) {
      if (!command || typeof command !== 'object' || Array.isArray(command) || Object.keys(command).some(key => !['method', 'path', 'args'].includes(key)) ||
        !['GET', 'POST', 'PUT', 'DELETE'].includes(command.method) || typeof command.path !== 'string' ||
        !/^[A-Za-z0-9._~/-]+$/.test(command.path) || command.path.startsWith('/') || command.path.split('/').some((part: string) => !part || part === '.' || part === '..') ||
        (command.args !== undefined && (!command.args || typeof command.args !== 'object' || Array.isArray(command.args)))) {
        throw new Failure('INVALID_INPUT', 'Invalid node-relative batch child.', 'Use canonical node-relative paths and explicit methods.', 2)
      }
      const literal = `/nodes/${values.node}/${command.path}`
      let found: Contract | undefined
      let pathValues: Record<string, unknown> = {}
      for (const candidate of contracts.filter(item => item.release === contract.release && item.method === command.method)) {
        const names: string[] = []
        const pattern = candidate.path.split('/').map(part => part.startsWith('{') ? (names.push(part.slice(1, -1)), '([^/]+)') : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('/')
        const match = new RegExp(`^${pattern}$`).exec(literal)
        if (!match) continue
        found = candidate
        pathValues = Object.fromEntries(names.map((name, index) => [name, candidate.parameters.properties?.[name]?.type === 'integer' ? Number(match[index + 1]) : match[index + 1]]))
        break
      }
      if (!found || Object.keys(command.args ?? {}).some(key => Object.hasOwn(pathValues, key))) throw new Failure('INVALID_INPUT', 'Unknown child route or duplicate path parameter.', 'Inspect the child schema.', 2)
      const child = await invocation(credentials, found, { ...pathValues, ...command.args }, budget, depth + 1)
      children.push(child)
      // The vendor gets resolved inputs only after the whole tree passes policy.
      command.args = Object.fromEntries(Object.entries(child.values).filter(([key]) => !Object.hasOwn(pathValues, key)))
      revisions.push(...child.revisions)
    }
    values.commands = JSON.stringify(commands)
  }
  const wire = buildPath(contract, values)
  if (Buffer.byteLength(wire) > 65536) throw new Failure('INVALID_INPUT', 'Resolved request exceeds 65536 bytes.', 'Reduce the complete input size.', 2)
  return { contract, values, wire, children, revisions }
}

export async function writeOperation(credentials: Credentials, initial: Contract, values: Record<string, unknown>, options: { preview: boolean, confirmation?: string }) {
  if (!['write', 'batch'].includes(initial.policy.effect)) throw denied()
  // All policy and input failures happen before any provider request.
  let call = await invocation(credentials, initial, values)
  checkPaths(call, credentials.results)
  const privateResult = (item: Invocation): boolean => item.contract.policy.secrets === 'private-result' || item.children.some(privateResult)
  if (!options.preview && privateResult(call)) credentials.results.sink()
  const journal = await openJournal()
  const tokenRevision = credentials.diagnostics.tokenSource.startsWith('file:') ? await lstat(credentials.diagnostics.tokenSource.slice(5)) : undefined
  const binding = () => journal.fingerprint({ origin: credentials.origin, identity: credentials.tokenId,
    actor: process.env.PROXMOX_AXI_ACTOR ?? `uid:${process.getuid?.() ?? 'native'}`, profile: credentials.diagnostics,
    token: credentials.token, tokenRevision: tokenRevision && { ino: tokenRevision.ino, mtime: tokenRevision.mtimeMs },
    operation: call.contract.id, release: call.contract.release, wire: call.wire, revisions: call.revisions,
    credentialRevision: process.env.PROXMOX_AXI_CREDENTIAL_REVISION,
    permissions: { tool: credentials.writeOperations, host: process.env.PROXMOX_AXI_HOST_OPERATIONS, readOnly: process.env.PROXMOX_AXI_READ_ONLY },
    trust: { ca: credentials.ca, pin: credentials.certificatePin }, policy: call.contract.policy })
  // Version selectors are never a write bypass, even for explicit --catalogue.
  const version = await readVersion(credentials, typeof values.node === 'string' ?
    buildPath(selectContract('GET', '/nodes/{node}/version', 'published-current'), { node: values.node }) : '/api2/json/version')
  if (!/^(8|9)\./.test(version.version!)) throw new Failure('CAPABILITY_UNSUPPORTED', 'Writes are disabled on an unknown major.', 'Review the target catalogue before enabling writes.')
  const release = version.version!.startsWith('8.') ? 'legacy-8.2.7' : 'published-current'
  if (release !== initial.release) call = await invocation(credentials, selectContract(initial.method, initial.path, release), values)
  checkPaths(call, credentials.results)
  const fingerprint = binding()
  if (options.preview) {
    if (options.confirmation) throw new Failure('INVALID_INPUT', 'Preview cannot consume confirmation.', 'Choose preview or execution.', 2)
    const id = journal.newId()
    const record: JournalRecord = { version: 1, id, fingerprint, owner: journalOwner(journal, credentials), origin: credentials.origin, identity: credentials.tokenId,
      operation: call.contract.id, path: call.contract.path, target: call.wire.split('?')[0]!, ...(typeof values.node === 'string' ? { node: values.node } : {}),
      status: 'preview', created: Date.now(), updated: Date.now(), reconciliation: call.contract.policy.reconciliation!,
      children: childRecords(call, journal) }
    const check = reconciliationCheck(call, journal)
    if (check) record.check = check
    await journal.save(record)
    return { status: 'preview', id, operation: record.operation, confirmation: `${id}.${fingerprint}`,
      expiresInSeconds: 300, reconciliation: record.reconciliation, children: publicChildren(record.children) }
  }
  const [id, approval, extra] = (options.confirmation ?? '').split('.')
  if (!id || !approval || extra) throw new Failure('CONFIRMATION_REQUIRED', 'Execution requires an exact preview confirmation.', 'Run the same command with --preview first.')
  const record = await journal.read(id)
  if (record.owner !== journalOwner(journal, credentials)) throw new Failure('CONFIRMATION_MISMATCH', 'Confirmation belongs to another actor or credential revision.', 'Create a preview with the current identity.')
  if (record.status !== 'preview') throw new Failure('CONFIRMATION_USED', 'Confirmation has already been consumed.', 'Inspect the retained journal; never replay an uncertain request.')
  if (record.fingerprint !== fingerprint || approval !== fingerprint || Date.now() - record.created > 300_000) throw new Failure('CONFIRMATION_MISMATCH', 'Confirmation is stale or bound to a different request or secret revision.', 'Create and approve a new preview.')
  await journal.claim(id)
  await journal.update(id, current => { current.status = 'intent' })
  const saveOutcome = async (outcome: Outcome) => {
    try {
      return await journal.update(id, current => {
        current.status = outcome.status
        if (outcome.upid) current.upid = outcome.upid
        mergeOutcomes(current.children, outcome.children)
      })
    }
    catch { throw new Failure('WRITE_UNCERTAIN', `Terminal journal update failed; intent ${id} remains durable.`, `Run proxmox-axi journal reconcile ${id}; do not repeat the mutation.`) }
  }
  let data: unknown
  let outcome: Outcome
  try {
    const [path, body] = call.wire.split('?')
    const query = call.contract.method === 'DELETE' || call.contract.method === 'GET'
    data = await executeRequest(credentials, query ? call.wire : path!, { method: call.contract.method, ...(!query && body ? { body } : {}) })
    if (privateResult(call)) registerResults(call, data, credentials.results)
    validateResponse(data, call.contract.returns)
    outcome = resultStatus(call, data, credentials.results)
    if (privateResult(call)) await credentials.results.deliver(resultBinding(credentials.origin, credentials.tokenId, call.contract.id, fingerprint), data)
  } catch (error) {
    // Even HTTP failures may follow a partial server-side action. No retry is safe.
    await saveOutcome({ status: 'uncertain' })
    throw new Failure(error instanceof Failure && error.code === 'DELIVERY_UNCERTAIN' ? 'DELIVERY_UNCERTAIN' : 'WRITE_UNCERTAIN',
      `Write or private delivery outcome is uncertain; journal ${id}.`, `Run proxmox-axi journal reconcile ${id}; do not repeat the mutation.`)
  }
  const saved = await saveOutcome(outcome)
  if (saved.status === 'failed' || saved.status === 'uncertain') process.exitCode = 1
  return { id, status: saved.status, ...(saved.upid ? { node: saved.node, upid: saved.upid } : {}), children: publicChildren(saved.children),
    ...(call.contract.method === 'GET' && !privateResult(call) ? { data: credentials.results.sanitize(data) } : {}),
    reconciliation: saved.reconciliation, help: saved.upid ? [taskCommand('status'), taskCommand('wait')] : [] }
}

function checkPaths(call: Invocation, results: Credentials['results']): void {
  for (const [name, value] of Object.entries(call.values)) {
    if ((call.contract.path.includes(`{${name}}`) || call.contract.policy.reconciliation?.path?.includes(`{${name}}`)) && results.redact(String(value)) !== String(value)) {
      throw new Failure('INVALID_INPUT', 'A path identifier contains protected data.', 'Select a non-secret resource identifier.', 2)
    }
  }
  for (const child of call.children) checkPaths(child, results)
}

function registerResults(call: Invocation, data: unknown, results: Credentials['results']): void {
  if (call.contract.policy.effect === 'batch' && Array.isArray(data)) {
    for (const [index, child] of call.children.entries()) registerResults(child, data[index]?.data, results)
  } else if (call.contract.policy.secrets === 'private-result') results.registerMinted(data)
}

function reconciliationCheck(call: Invocation, journal: Journal): JournalRecord['check'] {
  if (call.contract.policy.reconciliation?.kind !== 'read') return
  const target = call.contract.policy.reconciliation.path!
  const paths = Object.fromEntries(Object.entries(call.values).filter(([name]) => target.includes(`{${name}}`)))
  const read = selectContract('GET', target, call.contract.release)
  const expected = target.endsWith('/status/current') ?
    call.contract.path.endsWith('/start') ? { status: 'running' } : /\/(stop|shutdown)$/.test(call.contract.path) ? { status: 'stopped' } : {} :
    Object.fromEntries(Object.entries(call.values).filter(([name]) => !['node', 'vmid', 'digest'].includes(name)))
  return { path: buildPath(read, paths), expected: Object.fromEntries(Object.entries(expected).map(([name, value]) => [name, journal.fingerprint(value)])),
    booleans: Object.keys(expected).filter(name => read.returns.properties?.[name]?.type === 'boolean') }
}

function childRecords(call: Invocation, journal: Journal): NonNullable<JournalRecord['children']> {
  return call.children.map(child => {
    const check = reconciliationCheck(child, journal)
    return { operation: child.contract.id, target: child.wire.split('?')[0]!, status: 'not-sent', children: childRecords(child, journal),
      ...(child.contract.policy.reconciliation ? { reconciliation: child.contract.policy.reconciliation } : {}), ...(check ? { check } : {}) }
  })
}

interface Outcome { status: JournalRecord['status'], upid?: string, children?: Outcome[] }

function mergeOutcomes(records: JournalRecord['children'], outcomes: Outcome[] | undefined): void {
  for (const [index, record] of (records ?? []).entries()) {
    const outcome = outcomes?.[index]
    record.status = outcome?.status ?? 'uncertain'
    if (outcome?.upid) record.upid = outcome.upid
    mergeOutcomes(record.children, outcome?.children)
  }
}

function resultStatus(call: Invocation, data: unknown, results: Credentials['results']): Outcome {
  if (call.contract.policy.effect !== 'batch') {
    if (typeof data === 'string') {
      if (!/^UPID:[A-Za-z0-9.-]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[^:\s]+:[^:\s]*:[^:\s]+:$/.test(data) || results.redact(data) !== data) throw new Failure('INVALID_RESPONSE', 'Mutation returned an unsafe task identifier.', 'Inspect the uncertain journal.')
      return { status: 'accepted', upid: data, children: [] }
    }
    return { status: 'success', children: [] }
  }
  if (!Array.isArray(data) || data.length !== call.children.length) throw new Failure('INVALID_RESPONSE', 'Batch child count does not match.', 'Reconcile partial outcomes independently.')
  const children = call.children.map((child, index): Outcome => {
    const item = data[index] as { status?: unknown, data?: unknown }
    if (!item || typeof item.status !== 'number') return { status: 'uncertain' }
    if (item.status !== 200) return { status: 'failed' }
    try { validateResponse(item.data, child.contract.returns); return resultStatus(child, item.data, results) }
    catch { return { status: 'uncertain' } }
  })
  const statuses = children.map(child => child.status)
  return { status: statuses.includes('failed') ? 'failed' : statuses.includes('uncertain') ? 'uncertain' : statuses.includes('accepted') ? 'accepted' : 'success', children }
}

export async function openJournal(): Promise<Journal> {
  const journal = new Journal()
  try { await journal.initialize(); return journal }
  catch { throw new Failure('JOURNAL_UNAVAILABLE', 'Protected durable journal is unavailable.', 'Restore the private state directory before executing writes.') }
}

export function journalOwner(journal: Journal, credentials: Credentials): string {
  return journal.fingerprint({ origin: credentials.origin, identity: credentials.tokenId,
    actor: process.env.PROXMOX_AXI_ACTOR ?? `uid:${process.getuid?.() ?? 'native'}`, profile: credentials.diagnostics.profile })
}

export function taskCommand(command: string): string {
  return `proxmox-axi task ${command} --api-node <node> --api-upid <UPID>`
}

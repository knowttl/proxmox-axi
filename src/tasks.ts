import { setTimeout } from 'node:timers/promises'
import type { Credentials } from './credentials.js'
import { buildPath, selectContract, validateResponse } from './contract.js'
import { executeRead } from './transport.js'
import { Failure } from './errors.js'
import { journalOwner, openJournal, taskCommand } from './writes.js'
import { publicChildren, type JournalRecord } from './journal.js'

type TaskStatus = 'running' | 'success' | 'failed'

function outcome(data: unknown, node: string, upid: string): TaskStatus {
  if (!data || typeof data !== 'object') throw invalid()
  const status = data as Record<string, unknown>
  if (status.upid !== upid || status.node !== node || !['running', 'stopped'].includes(String(status.status))) throw invalid()
  if (status.status === 'running') return 'running'
  if (typeof status.exitstatus !== 'string' || !status.exitstatus) throw invalid()
  return status.exitstatus === 'OK' ? 'success' : 'failed'
}

const invalid = () => new Failure('INVALID_RESPONSE', 'Task response does not match the requested UPID and node.', 'Inspect the selected task using the exact identifier.')

export async function taskOperation(credentials: Credentials, command: string, values: Record<string, unknown>, waitMs: number, journalId?: string) {
  const contract = selectContract('GET', `/nodes/{node}/tasks/{upid}/${command === 'log' ? 'log' : 'status'}`, 'published-current')
  const path = buildPath(contract, values)
  const node = String(values.node), upid = String(values.upid)
  const journal = journalId ? await openJournal() : undefined
  const record = journal ? await ownedRecord(credentials, journalId!, journal) : undefined
  if (record && record.upid !== upid && !containsUpid(record.children, upid)) throw new Failure('INVALID_INPUT', 'Task is not associated with this intent.', 'Use the UPID in the retained journal.', 2)
  const deadline = performance.now() + waitMs
  let status: TaskStatus = 'running'
  let data: unknown
  do {
    try {
      data = await executeRead(credentials, path, false, command === 'wait' ? Math.max(1, Math.min(5000, deadline - performance.now())) : 5000)
    } catch (error) {
      if (command === 'wait' && data !== undefined && error instanceof Failure && error.code === 'TIMEOUT' && performance.now() >= deadline) break
      throw error
    }
    validateResponse(data, contract.returns)
    if (command === 'log') return { upid, data: credentials.results.sanitize(data) }
    status = outcome(data, node, upid)
    if (record && journal) {
      await journal.update(record.id, current => {
        if (current.upid === upid) current.status = status = mergeTaskStatus(current.status, status)
        else {
          status = updateChildren(current.children, upid, status)
          if (current.status !== 'failed') current.status = aggregate(current.children)
        }
      })
    }
    if (command !== 'wait' || status !== 'running' || performance.now() >= deadline) break
    await setTimeout(Math.min(250, Math.max(0, deadline - performance.now())))
  } while (performance.now() < deadline)
  if (status === 'failed') process.exitCode = 1
  return { upid, status, data: credentials.results.sanitize(data), ...(command === 'wait' && status === 'running' ? { wait: 'deadline-reached' } : {}),
    help: status === 'running' ? [taskCommand('status')] : [] }
}

function containsUpid(children: JournalRecord['children'], upid: string): boolean {
  return !!children?.some(child => child.upid === upid || containsUpid(child.children, upid))
}

function mergeTaskStatus(current: string, observed: TaskStatus): TaskStatus {
  return current === 'failed' || observed === 'failed' ? 'failed' : current === 'success' ? 'success' : observed
}

function updateChildren(children: JournalRecord['children'], upid: string, status: TaskStatus): TaskStatus {
  for (const child of children ?? []) {
    if (child.upid === upid) child.status = status = mergeTaskStatus(child.status, status)
    if (child.children?.length) {
      status = updateChildren(child.children, upid, status)
      if (child.status !== 'failed') child.status = aggregate(child.children)
    }
  }
  return status
}

function aggregate(children: JournalRecord['children']): JournalRecord['status'] {
  const statuses = children?.map(child => child.status) ?? []
  return statuses.includes('failed') ? 'failed' : statuses.includes('uncertain') ? 'uncertain' :
    statuses.some(status => status === 'accepted' || status === 'running') ? 'running' : 'success'
}

async function ownedRecord(credentials: Credentials, id: string, journal: Awaited<ReturnType<typeof openJournal>>) {
  const record = await journal.read(id)
  if (record.owner !== journalOwner(journal, credentials)) throw new Failure('PERMISSION_DENIED', 'Journal belongs to another actor or credential revision.', 'Use the identity and origin that created the intent.')
  return record
}

export async function journalOperation(credentials: Credentials, command: string, id: string) {
  const journal = await openJournal()
  const record = await ownedRecord(credentials, id, journal)
  if (command === 'reconcile') {
    if (record.status === 'preview') throw new Failure('INVALID_INPUT', 'A preview has not been transmitted.', 'Execute its exact confirmation first.', 2)
    let taskUnavailable = false
    if (record.upid) {
      taskUnavailable = !await reconcileTask(credentials, record, record.upid)
      if (!taskUnavailable) return journalOperation(credentials, 'show', id)
    }
    if (record.children?.length) {
      const collect = (children: JournalRecord['children']): string[] => (children ?? []).flatMap(child => [
        ...(child.upid ? [child.upid] : []), ...collect(child.children),
      ])
      const unavailable = new Set<string>()
      for (const upid of new Set(collect(record.children))) {
        if (!await reconcileTask(credentials, record, upid)) unavailable.add(upid)
      }
      const observations: { path: number[], value: unknown }[] = []
      const observe = async (children: JournalRecord['children'], parent: number[] = []): Promise<void> => {
        for (const [index, child] of (children ?? []).entries()) {
          const path = [...parent, index]
          const taskUnavailable = child.upid && unavailable.has(child.upid)
          if (child.check && Object.keys(child.check.expected).length) {
            const value = await observeCheck(credentials, child.check, journal)
            observations.push({ path, value: { ...value, ...(taskUnavailable ? { task: inconclusive() } : {}) } })
          } else if (taskUnavailable) observations.push({ path, value: inconclusive() })
          await observe(child.children, path)
        }
      }
      await observe(record.children)
      await journal.update(id, current => {
        for (const observation of observations) {
          let children = current.children
          for (const [depth, index] of observation.path.entries()) {
            const child = children![index]!
            if (depth === observation.path.length - 1) child.observation = observation.value
            children = child.children
          }
        }
      })
      return journalOperation(credentials, 'show', id)
    }
    const observation = record.check && Object.keys(record.check.expected).length ? await observeCheck(credentials, record.check, journal) :
      { at: Date.now(), result: 'no-safe-automated-reconciliation; retain current outcome' }
    Object.assign(record, await journal.update(id, current => {
      current.observation = { ...observation, ...(taskUnavailable ? { task: inconclusive() } : {}) }
    }))
  }
  const { owner, fingerprint, check, ...safe } = record
  return { journal: { ...safe, children: publicChildren(record.children) } }
}

async function reconcileTask(credentials: Credentials, record: JournalRecord, upid: string): Promise<boolean> {
  try { await taskOperation(credentials, 'status', { node: record.node, upid }, 1, record.id); return true }
  catch (error) {
    if (!(error instanceof Failure) || !['AUTH_REQUIRED', 'PERMISSION_DENIED', 'NOT_FOUND_OR_HIDDEN', 'HTTP_ERROR',
      'CONNECTION_FAILED', 'TIMEOUT', 'OUTPUT_LIMIT', 'INVALID_RESPONSE'].includes(error.code)) throw error
    return false
  }
}

async function observeCheck(credentials: Credentials, check: NonNullable<JournalRecord['check']>, journal: Awaited<ReturnType<typeof openJournal>>) {
  let data: unknown
  try { data = await executeRead(credentials, check.path) }
  catch { return inconclusive() }
  const matched = !!data && typeof data === 'object' && Object.entries(check.expected).every(([name, digest]) => {
    if (!Object.hasOwn(data, name)) return false
    const value = (data as Record<string, unknown>)[name]
    const normalized = check.booleans?.includes(name) && (value === 0 || value === 1) ? value === 1 : value
    return journal.fingerprint(normalized) === digest
  })
  return { at: Date.now(), desiredStateObserved: matched,
    result: matched ? 'requested-state-observed; attribution not established' : 'inconclusive; absence never proves failure' }
}

function inconclusive() {
  return { at: Date.now(), result: 'inconclusive; reconciliation read unavailable; retain current outcome' }
}

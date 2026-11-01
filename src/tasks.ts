import { setTimeout } from 'node:timers/promises'
import type { Credentials } from './credentials.js'
import { buildPath, selectContract, validateResponse } from './contract.js'
import { executeRead } from './transport.js'
import { Failure } from './errors.js'
import { journalOwner, openJournal, taskCommand } from './writes.js'
import { publicChildren, type JournalRecord } from './journal.js'

function outcome(data: unknown, node: string, upid: string): 'running' | 'success' | 'failed' {
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
  let status: 'running' | 'success' | 'failed' = 'running'
  let data: unknown
  do {
    try {
      data = await executeRead(credentials, path, false, command === 'wait' ? Math.max(1, Math.min(5000, deadline - performance.now())) : 5000)
    } catch (error) {
      if (command === 'wait' && data !== undefined && error instanceof Failure && error.code === 'TIMEOUT' && performance.now() >= deadline) break
      throw error
    }
    validateResponse(data, contract.returns)
    if (command === 'log') return { upid, data }
    status = outcome(data, node, upid)
    if (record && journal) {
      if (record.upid === upid) record.status = status
      else {
        updateChildren(record.children, upid, status)
        record.status = aggregate(record.children)
      }
      await journal.save(record)
    }
    if (command !== 'wait' || status !== 'running' || performance.now() >= deadline) break
    await setTimeout(Math.min(250, Math.max(0, deadline - performance.now())))
  } while (performance.now() < deadline)
  if (status === 'failed') process.exitCode = 1
  return { upid, status, data, ...(command === 'wait' && status === 'running' ? { wait: 'deadline-reached' } : {}),
    help: status === 'running' ? [taskCommand('status')] : [] }
}

function containsUpid(children: JournalRecord['children'], upid: string): boolean {
  return !!children?.some(child => child.upid === upid || containsUpid(child.children, upid))
}

function updateChildren(children: JournalRecord['children'], upid: string, status: string): void {
  for (const child of children ?? []) {
    if (child.upid === upid) child.status = status
    if (child.children?.length) { updateChildren(child.children, upid, status); child.status = aggregate(child.children) }
  }
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
    if (record.upid) {
      await taskOperation(credentials, 'status', { node: record.node, upid: record.upid }, 1, id)
      return journalOperation(credentials, 'show', id)
    }
    if (record.children?.length) {
      const collect = (children: JournalRecord['children']): string[] => (children ?? []).flatMap(child => [
        ...(child.upid ? [child.upid] : []), ...collect(child.children),
      ])
      for (const upid of new Set(collect(record.children))) await taskOperation(credentials, 'status', { node: record.node, upid }, 1, id)
      const fresh = await journal.read(id)
      const observe = async (children: JournalRecord['children']): Promise<void> => {
        for (const child of children ?? []) {
          if (child.check && Object.keys(child.check.expected).length) child.observation = await observeCheck(credentials, child.check, journal)
          await observe(child.children)
        }
      }
      await observe(fresh.children)
      await journal.save(fresh)
      return journalOperation(credentials, 'show', id)
    }
    if (record.check && Object.keys(record.check.expected).length) {
      record.observation = await observeCheck(credentials, record.check, journal)
      // Observation cannot establish task completion or attribute an uncertain write.
      await journal.save(record)
    } else {
      record.observation = { at: Date.now(), result: 'no-safe-automated-reconciliation; retain current outcome' }
      await journal.save(record)
    }
  }
  const { owner, fingerprint, check, ...safe } = record
  return { journal: { ...safe, children: publicChildren(record.children) } }
}

async function observeCheck(credentials: Credentials, check: NonNullable<JournalRecord['check']>, journal: Awaited<ReturnType<typeof openJournal>>) {
  const data = await executeRead(credentials, check.path)
  const matched = !!data && typeof data === 'object' && Object.entries(check.expected).every(([name, digest]) =>
    Object.hasOwn(data, name) && journal.fingerprint((data as Record<string, unknown>)[name]) === digest)
  return { at: Date.now(), desiredStateObserved: matched,
    result: matched ? 'requested-state-observed; attribution not established' : 'inconclusive; absence never proves failure' }
}

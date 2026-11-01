import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import { lstat, mkdir, open, readFile, readdir, rename, rm, rmdir, unlink } from 'node:fs/promises'
import { constants, watch } from 'node:fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { Failure } from './errors.js'
import { readPrivateFile, replacePrivateFile } from './private-file.js'
import { windowsProtection } from './windows-acl.js'

export interface JournalRecord {
  version: 1
  id: string
  fingerprint: string
  owner: string
  origin: string
  identity: string
  operation: string
  path: string
  target: string
  node?: string
  status: 'preview' | 'intent' | 'accepted' | 'running' | 'success' | 'failed' | 'uncertain'
  created: number
  updated: number
  upid?: string
  children?: { operation: string, target: string, status: string, upid?: string, children?: JournalRecord['children'],
    check?: JournalRecord['check'], observation?: unknown, reconciliation?: JournalRecord['reconciliation'] }[]
  reconciliation?: { kind: string, path?: string, reason: string }
  observation?: unknown
  check?: { path: string, expected: Record<string, string>, booleans?: string[] }
}

export function journalPath(): string {
  const env = process.env
  const state = process.platform === 'win32' ? env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local') :
    env.XDG_STATE_HOME && isAbsolute(env.XDG_STATE_HOME) ? env.XDG_STATE_HOME : join(homedir(), '.local', 'state')
  const path = env.PROXMOX_AXI_WRITE_LOG ?? join(state, 'proxmox-axi', 'writes.log')
  if (!isAbsolute(path)) throw unavailable()
  return path
}

const unavailable = () => new Failure('JOURNAL_UNAVAILABLE', 'Protected durable journal is unavailable.', 'Restore the owned private state directory before executing a write.')
const execute = promisify(execFile)

async function processStart(pid: number): Promise<string | undefined> {
  try {
    process.kill(pid, 0)
    if (process.platform === 'linux') {
      const stat = await readFile(`/proc/${pid}/stat`, 'utf8')
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ')
      if (fields[0] === 'Z') return
      return `${(await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim()}:${fields[19]}`
    }
    const result = process.platform === 'win32' ? await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      `[Diagnostics.Process]::GetProcessById(${pid}).StartTime.ToUniversalTime().Ticks`], { timeout: 5000, windowsHide: true }) :
      await execute('ps', ['-p', String(pid), '-o', 'lstart='], { timeout: 5000, env: { ...process.env, LC_ALL: 'C' } })
    if (!result.stdout.trim()) throw unavailable()
    return result.stdout.trim()
  } catch {
    try { process.kill(pid, 0) } catch (gone) { if ((gone as NodeJS.ErrnoException).code === 'ESRCH') return }
    throw unavailable()
  }
}

async function removeLockOwner(path: string, owner?: string): Promise<void> {
  if (owner) {
    try { await unlink(join(path, owner)) }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
  }
  try { await rmdir(path) }
  catch (error) { if (!['ENOENT', 'ENOTEMPTY', 'EEXIST'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error }
}

// One record per intent avoids lost updates between independent hosted calls.
// An exclusive durable claim consumes a confirmation even if the caller crashes.
export class Journal {
  private readonly directory = `${journalPath()}.d`
  private key = ''

  async initialize(): Promise<void> {
    const firstCreated = await mkdir(this.directory, { recursive: true, mode: 0o700 })
    const info = await lstat(this.directory)
    if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' &&
      (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) throw unavailable()
    if (process.platform === 'win32') await windowsProtection(this.directory, 'write', true)
    if (firstCreated && process.platform !== 'win32') {
      for (let path = this.directory;; path = dirname(path)) {
        const directory = await open(path, constants.O_RDONLY | constants.O_DIRECTORY)
        try { await directory.sync() } finally { await directory.close() }
        if (path === dirname(firstCreated)) break
      }
    }
    const path = join(this.directory, 'binding.key')
    try {
      const file = await open(path, 'wx', 0o600)
      try {
        if (process.platform === 'win32') await windowsProtection(path, 'write')
        await file.writeFile(randomBytes(32).toString('hex'))
        await file.sync()
      } finally { await file.close() }
      await this.syncDirectory()
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error }
    this.key = await readPrivateFile(path, true)
    if (!/^[a-f0-9]{64}$/.test(this.key)) throw unavailable()
  }

  fingerprint(value: unknown): string {
    const canonical = (item: unknown): unknown => Array.isArray(item) ? item.map(canonical) : item && typeof item === 'object' ?
      Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)).map(([name, child]) => [name, canonical(child)])) : item
    return createHmac('sha256', this.key).update(JSON.stringify(canonical(value))).digest('hex')
  }

  newId(): string { return randomUUID() }

  async save(record: JournalRecord): Promise<void> {
    await this.locked(record.id, () => this.replace(record))
  }

  async update(id: string, change: (record: JournalRecord) => void): Promise<JournalRecord> {
    return this.locked(id, async () => {
      const record = await this.read(id)
      change(record)
      await this.replace(record)
      return record
    })
  }

  private async replace(record: JournalRecord): Promise<void> {
    record.updated = Date.now()
    await replacePrivateFile(this.path(record.id), JSON.stringify(record) + '\n')
    await this.syncDirectory()
  }

  private async locked<T>(id: string, action: () => Promise<T>): Promise<T> {
    const path = `${this.path(id)}.lock`
    const candidate = `${path}.${randomUUID()}`
    const owner = Buffer.from(JSON.stringify({ pid: process.pid, start: await processStart(process.pid), nonce: randomUUID() })).toString('base64url')
    await mkdir(candidate, { mode: 0o700 })
    let notify = () => {}, expired = false, watchError: Error | undefined
    const watcher = watch(this.directory, (_event, name) => { if (name === `${id}.json.lock`) notify() })
    watcher.on('error', error => { watchError = error; notify() })
    const deadline = setTimeout(() => { expired = true; notify() }, 5000)
    let acquired = false
    try {
      const marker = await open(join(candidate, owner), 'wx', 0o600)
      await marker.close()
      while (!acquired) {
        if (watchError) throw unavailable()
        const changed = new Promise<void>(resolve => { notify = resolve })
        try { await rename(candidate, path); acquired = true }
        catch (error) {
          if (!['EEXIST', 'ENOTEMPTY', ...(process.platform === 'win32' ? ['EPERM'] : [])].includes((error as NodeJS.ErrnoException).code ?? '')) throw error
          let owners: string[]
          try { owners = await readdir(path) }
          catch (missing) { if ((missing as NodeJS.ErrnoException).code === 'ENOENT') continue; throw missing }
          if (!owners.length) { await removeLockOwner(path); continue }
          if (owners.length !== 1) throw unavailable()
          const retained = JSON.parse(Buffer.from(owners[0]!, 'base64url').toString()) as { pid: number, start: string }
          if (!Number.isSafeInteger(retained.pid) || retained.pid <= 0 || typeof retained.start !== 'string') throw unavailable()
          if (await processStart(retained.pid) !== retained.start) { await removeLockOwner(path, owners[0]); continue }
          if (expired) throw unavailable()
          await changed
        }
      }
      return await action()
    } finally {
      clearTimeout(deadline)
      watcher.close()
      if (acquired) await removeLockOwner(path, owner)
      else await rm(candidate, { recursive: true, force: true })
    }
  }

  async read(id: string): Promise<JournalRecord> {
    const record = JSON.parse(await readPrivateFile(this.path(id), true)) as JournalRecord
    if (record.version !== 1 || record.id !== id) throw unavailable()
    // A claim without a terminal record means a crash, never permission to replay.
    if (record.status === 'preview' || record.status === 'intent') {
      try {
        await lstat(join(this.directory, `${id}.claim`))
        record.status = 'uncertain'
        markUncertain(record.children)
      }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    }
    return record
  }

  async claim(id: string): Promise<void> {
    let file
    try { file = await open(join(this.directory, `${id}.claim`), 'wx', 0o600) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Failure('CONFIRMATION_USED', 'Confirmation has already been consumed.', 'Inspect the journal and reconcile; never repeat an uncertain mutation.')
      throw error
    }
    try {
      if (process.platform === 'win32') await windowsProtection(join(this.directory, `${id}.claim`), 'write')
      await file.writeFile('consumed\n')
      await file.sync()
    } finally { await file.close() }
    await this.syncDirectory()
  }

  private path(id: string): string {
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id)) throw new Failure('INVALID_INPUT', 'Invalid journal identifier.', 'Use the identifier returned by preview.', 2)
    return join(this.directory, `${id}.json`)
  }

  private async syncDirectory(): Promise<void> {
    // Windows has no portable directory fsync; replacement and file handles are flushed.
    if (process.platform === 'win32') return
    const directory = await open(dirname(join(this.directory, 'binding.key')), constants.O_RDONLY | constants.O_DIRECTORY)
    try { await directory.sync() } finally { await directory.close() }
  }
}

export function markUncertain(children: JournalRecord['children']): void {
  for (const child of children ?? []) { child.status = 'uncertain'; markUncertain(child.children) }
}

export function publicChildren(children: JournalRecord['children']): unknown[] {
  return (children ?? []).map(child => {
    const { check, ...safe } = child
    return { ...safe, children: publicChildren(child.children) }
  })
}

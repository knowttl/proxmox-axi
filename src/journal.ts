import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import { lstat, mkdir, open } from 'node:fs/promises'
import { constants } from 'node:fs'
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
  check?: { path: string, expected: Record<string, string> }
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
    await replacePrivateFile(this.path(record.id), JSON.stringify({ ...record, updated: Date.now() }) + '\n')
    await this.syncDirectory()
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

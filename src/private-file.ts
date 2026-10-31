import { constants } from 'node:fs'
import { chmod, lstat, mkdir, open, rename, rm } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { dirname, isAbsolute, join } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import { Failure } from './errors.js'
import { windowsProtection } from './windows-acl.js'

const insecure = () => new Failure('CONFIG_INSECURE', 'File is not a protected owned regular file.', 'Use an owned absolute regular file, chmod 600 on Linux, or re-create it with a protected Windows DACL.')

export async function readPrivateFile(path: string, secret = false, verifyAcl = false): Promise<string> {
  if (!isAbsolute(path) || (process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(path))) throw insecure()
  const info = await lstat(path)
  const safe = (stat: typeof info) => stat.isFile() && !stat.isSymbolicLink() &&
    (process.platform === 'win32' || (stat.uid === process.getuid?.() && (stat.mode & (secret ? 0o077 : 0o022)) === 0))
  if (!safe(info)) throw insecure()
  if (process.platform === 'win32') await windowsProtection(path, verifyAcl ? 'verify' : 'read')
  const file = await open(path, constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW))
  try {
    const opened = await file.stat()
    if (!safe(opened) || opened.ino !== info.ino || opened.dev !== info.dev || opened.size > 1_048_576) throw insecure()
    const bytes = Buffer.alloc(1_048_577)
    let length = 0
    while (length < bytes.length) {
      const read = await file.read(bytes, length, bytes.length - length)
      if (!read.bytesRead) break
      length += read.bytesRead
    }
    if (length > 1_048_576) throw insecure()
    return bytes.subarray(0, length).toString('utf8')
  } finally { await file.close() }
}

// ACL handling is injectable so both replacement paths can be exercised offline.
export async function replacePrivateFile(path: string, content: string, options: {
  platform?: NodeJS.Platform, restrictAcl?: (path: string, directory: boolean) => Promise<void>
} = {}): Promise<void> {
  const platform = options.platform ?? process.platform
  const restrictAcl = options.restrictAcl ?? (process.platform === 'win32' ? (path: string, directory: boolean) => windowsProtection(path, 'write', directory) : undefined)
  if (!isAbsolute(path) || (platform === 'win32' && !restrictAcl)) throw insecure()
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const info = await lstat(directory)
  if (!info.isDirectory() || info.isSymbolicLink() || (platform !== 'win32' && info.uid !== process.getuid?.())) throw insecure()
  if (platform === 'win32') await restrictAcl!(directory, true)
  else await chmod(directory, 0o700)
  const temporary = join(directory, `.${randomUUID()}.tmp`)
  try {
    const file = await open(temporary, 'wx', 0o600)
    try {
      if (platform === 'win32') await restrictAcl!(temporary, false)
      await file.writeFile(content, 'utf8')
      await file.sync()
    } finally { await file.close() }
    const deadline = performance.now() + 1000
    for (;;) {
      try { await rename(temporary, path); break }
      catch (error) {
        if (platform !== 'win32' || !['EPERM', 'EBUSY', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '') || performance.now() >= deadline) throw error
        await setTimeout(50)
      }
    }
  } finally { await rm(temporary, { force: true }) }
}

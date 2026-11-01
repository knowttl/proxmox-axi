import assert from 'node:assert/strict'
import { lstat, mkdir, readFile, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

interface Result { code: number | null, stdout: string, stderr: string }
interface Journey {
  scratch: string
  installed: string
  executable: string
  env: Record<string, string>
  command: (executable: string, args: string[], options: { env: Record<string, string> }) => Promise<Result>
  cases: Record<string, unknown>[]
}

export async function exerciseNativeJourney(options: Journey): Promise<void> {
  assert.equal(process.platform, 'linux', 'This gate requires actual native Linux')
  const home = join(options.scratch, 'native-home')
  await mkdir(home, { mode: 0o700 })
  const environment = { ...options.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config'), XDG_STATE_HOME: join(home, 'state') }
  for (const [id, overrides, expected, state] of [
    ['xdg', {}, join(home, 'config/proxmox-axi/config.json'), join(home, 'state/proxmox-axi/writes.log')],
    ['home', { XDG_CONFIG_HOME: '', XDG_STATE_HOME: '' }, join(home, '.config/proxmox-axi/config.json'), join(home, '.local/state/proxmox-axi/writes.log')],
    ['relative-xdg', { XDG_CONFIG_HOME: 'relative', XDG_STATE_HOME: 'relative' }, join(home, '.config/proxmox-axi/config.json'), join(home, '.local/state/proxmox-axi/writes.log')],
  ] as const) {
    const result = await options.command(process.execPath, [options.executable, 'config', 'path', '--format', 'json'],
      { env: { ...environment, ...overrides } })
    assert.equal(result.code, 0, result.stdout)
    assert.equal(result.stderr, '')
    assert.equal((JSON.parse(result.stdout) as { path: string }).path, expected)
    const journal = await options.command(process.execPath, ['--input-type=module', '-e',
      `const { journalPath } = await import(${JSON.stringify(pathToFileURL(join(options.installed, 'dist/journal.js')).href)}); console.log(journalPath())`],
    { env: { ...environment, ...overrides } })
    assert.equal(journal.code, 0, journal.stderr)
    assert.equal(journal.stdout.trim(), state)
    options.cases.push({ id: `standalone/CRED-08/${id}`, status: 'pass', path: expected, journal: state })
  }
  const { replacePrivateFile, readPrivateFile } = await import(pathToFileURL(join(options.installed, 'dist/private-file.js')).href) as typeof import('../src/private-file.js')
  const path = join(home, 'private/config.json')
  await replacePrivateFile(path, 'old-complete-state')
  // An open reader must retain the previous inode across atomic publication.
  const { open } = await import('node:fs/promises')
  const reader = await open(path, 'r')
  try {
    await replacePrivateFile(path, 'new-complete-state')
    assert.equal(await reader.readFile('utf8'), 'old-complete-state')
    assert.equal(await readPrivateFile(path, true), 'new-complete-state')
  } finally { await reader.close() }
  for (const [target, mode] of [[home, 0o700], [join(home, 'private'), 0o700], [path, 0o600]] as const) {
    const info = await lstat(target)
    assert.equal(info.uid, process.getuid!())
    assert.equal(info.mode & 0o777, mode)
  }
  const link = join(home, 'linked')
  await symlink(path, link)
  await assert.rejects(readPrivateFile(link, true), { code: 'CONFIG_INSECURE' })
  const directoryLink = join(home, 'linked-directory')
  await symlink(join(home, 'private'), directoryLink)
  await assert.rejects(replacePrivateFile(join(directoryLink, 'config.json'), 'replacement'), { code: 'CONFIG_INSECURE' })
  assert.equal(await readFile(path, 'utf8'), 'new-complete-state')
  options.cases.push({ id: 'standalone/CRED-08/private-mode-and-owner', status: 'pass' },
    { id: 'standalone/CRED-09/native-symlink', status: 'pass' },
    { id: 'standalone/CRED-10/native-atomic-replacement', status: 'pass' })
}

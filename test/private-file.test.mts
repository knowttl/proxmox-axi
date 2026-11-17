import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import fileSystem, { chmod, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { readPrivateFile, replacePrivateFile } from '../dist/private-file.js'

test('private read returns the replacement when the file is atomically replaced before it is opened', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'proxmox-private-'))
  const path = join(directory, 'journal.json')
  const open = fileSystem.open
  let replaced = false
  t.after(async () => { await rm(directory, { recursive: true, force: true }) })
  try {
    await replacePrivateFile(path, 'before-replacement')
    t.mock.method(fileSystem, 'open', async (...args: Parameters<typeof open>) => {
      if (args[0] === path && !replaced) {
        replaced = true
        await replacePrivateFile(path, 'after-replacement')
      }
      return open(...args)
    })
    syncBuiltinESMExports()
    assert.equal(await readPrivateFile(path, true), 'after-replacement')
    assert.equal(replaced, true)
  } finally {
    t.mock.restoreAll()
    syncBuiltinESMExports()
  }
})

test('private read refuses', { skip: process.platform === 'win32' }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'proxmox-private-'))
  t.after(async () => { await rm(directory, { recursive: true, force: true }) })
  await replacePrivateFile(join(directory, 'target.json'), 'private-value')
  const make = {
    'a symlink to a private file': (path: string) => symlink(join(directory, 'target.json'), path),
    'a group readable file': async (path: string) => { await writeFile(path, 'value'); await chmod(path, 0o640) },
    'a world readable file': async (path: string) => { await writeFile(path, 'value'); await chmod(path, 0o604) },
    'a directory': (path: string) => mkdir(path),
    'a named pipe': (path: string) => promisify(execFile)('mkfifo', [path]),
  }
  for (const [name, create] of Object.entries(make)) {
    await t.test(name, async () => {
      const path = join(directory, name.replaceAll(' ', '-'))
      await create(path)
      await assert.rejects(readPrivateFile(path, true), { code: 'CONFIG_INSECURE' })
    })
  }
})

test('private replacement commits one complete value and preserves it when protection fails', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'proxmox-private-'))
  const path = join(directory, 'config.json')
  try {
    await replacePrivateFile(path, 'prior-valid-state')
    await assert.rejects(replacePrivateFile(path, 'incomplete-replacement', {
      platform: 'win32', restrictAcl: async (_path, directory) => { if (!directory) throw new Error('Controlled ACL failure') },
    }), /Controlled ACL failure/)
    assert.equal(await readPrivateFile(path, true), 'prior-valid-state')
    assert.deepEqual(await readdir(directory), ['config.json'])
    await replacePrivateFile(path, 'new-complete-state')
    assert.equal(await readPrivateFile(path, true), 'new-complete-state')
  } finally { await rm(directory, { recursive: true, force: true }) }
})

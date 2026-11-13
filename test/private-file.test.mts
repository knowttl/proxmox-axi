import assert from 'node:assert/strict'
import { mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { readPrivateFile, replacePrivateFile } from '../dist/private-file.js'

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

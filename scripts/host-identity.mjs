import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import pin from '../test/artium-fixture.json' with { type: 'json' }

export async function verifyHostRuntime(fixture) {
  for (const [path, expected] of Object.entries(pin.runtimeHashes)) {
    const bytes = await readFile(join(fixture, path))
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expected, `Host runtime pin: ${path}`)
  }
  return pin.runtimeHashes
}

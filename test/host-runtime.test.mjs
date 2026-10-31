import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { verifyHostRuntime } from '../scripts/host-identity.mjs'
import pin from './artium-fixture.json' with { type: 'json' }

const root = fileURLToPath(new URL('../', import.meta.url))
const fixture = process.env.PROXMOX_AXI_ARTIUM_FIXTURE
const skip = fixture ? false : 'Artium fixture not supplied'

test('built host runtime matches the retained identity', { skip }, async () => {
  assert.deepEqual(await verifyHostRuntime(fixture), pin.runtimeHashes)
})

for (const path of [
  'dist/src/server/app.js',
  'dist/src/server/adapters/proxmox.js',
  'dist/src/server/adapters/credential-profile.js',
  'dist/src/server/runner/runner.js',
  'dist/src/server/runner/run.js',
  'dist/src/server/store/db.js',
  'dist/src/server/store/credential-store.js',
  'dist/test/fixtures/tokens.js',
  'dist/src/cli/session.js',
  'dist/cli/artium-axi.mjs',
]) for (const mutation of ['substituted', 'missing']) {
  test(`host bootstrap rejects ${mutation} ${path} with unchanged TypeScript`, { skip }, async () => {
    const temporary = await mkdtemp(join(root, 'node_modules/host-runtime-test-'))
    try {
      await cp(join(fixture, 'dist'), join(temporary, 'dist'), { recursive: true })
      await cp(join(fixture, 'src'), join(temporary, 'src'), { recursive: true })
      await mkdir(join(temporary, 'test/fixtures'), { recursive: true })
      await cp(join(fixture, 'test/fixtures/tokens.ts'), join(temporary, 'test/fixtures/tokens.ts'))
      await writeFile(join(temporary, 'package.json'), '{"type":"module"}\n')
      if (mutation === 'substituted') await writeFile(join(temporary, path), 'throw new Error("Substituted runtime executed")\n')
      else await rm(join(temporary, path))
      const actual = spawnSync(process.execPath, [join(root, 'scripts/artium-host.mjs'), temporary],
        { encoding: 'utf8', timeout: 10_000 })
      assert.equal(actual.error, undefined)
      assert.equal(actual.status, 1, actual.stderr)
      assert.ok(actual.stderr.includes(mutation === 'substituted' ? `Host runtime pin: ${path}` : `ENOENT`), actual.stderr)
      assert.ok(actual.stderr.includes(path), actual.stderr)
      assert.ok(!actual.stderr.includes('Substituted runtime executed'), actual.stderr)
      assert.deepEqual(await readFile(join(temporary, 'src/server/app.ts')), await readFile(join(fixture, 'src/server/app.ts')))
    } finally {
      await rm(temporary, { recursive: true, force: true })
    }
  })
}

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'

const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex')
async function files(directory: string, prefix = ''): Promise<Record<string, string>> {
  const result: Record<string, string> = {}
  for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
    const path = join(prefix, entry.name)
    if (entry.isDirectory()) Object.assign(result, await files(directory, path))
    else {
      assert.ok(entry.isFile(), `Package contains a nonregular entry: ${path}`)
      result[path] = hash(await readFile(join(directory, path)))
    }
  }
  return result
}

export async function verifyPackageAdmission(root: string, installed: string, archive: string) {
  const current = await files(installed)
  for (const directory of ['bin', 'dist']) assert.deepEqual(await files(join(installed, directory)),
    await files(join(root, directory)), `Installed ${directory} matches the current build`)
  for (const path of ['axi-credential.schema.json', 'inventory.json', 'help.json', 'artium-invocations.json', 'write-policy.json']) {
    assert.equal(current[path], hash(await readFile(join(root, path))), `Installed admission source: ${path}`)
  }
  // pnpm normalizes the manifest and removes development-only packaging fields.
  const manifest = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8')) as Record<string, unknown>
  const source = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as Record<string, unknown>
  for (const field of ['name', 'version', 'type', 'bin', 'dependencies', 'engines']) assert.deepEqual(manifest[field], source[field], `Installed runtime metadata: ${field}`)
  const profile = await readFile(join(installed, 'axi-credential.schema.json'))
  assert.deepEqual(JSON.parse(profile.toString()), JSON.parse(await readFile(join(installed, 'dist/profile-schema.json'), 'utf8')))
  const baseline = JSON.parse(await readFile(join(root, 'test/artium-fixture.json'), 'utf8')) as {
    revision: string, packageSha256: string, packageIntegrity: string
  }
  const bytes = await readFile(archive)
  const inventory = JSON.parse(await readFile(join(installed, 'inventory.json'), 'utf8')) as {
    operations: { variants: { callable: boolean }[] }[]
  }
  const variants = inventory.operations.flatMap(row => row.variants)
  const unresolved = variants.filter(row => !row.callable).length
  assert.ok(variants.length > 0, 'Admission cannot select zero variants')
  return {
    status: 'pass', files: current, sha256: hash(bytes),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    baseline: { revision: baseline.revision, sha256: baseline.packageSha256, integrity: baseline.packageIntegrity },
    artium: { status: 'pending', reason: 'Current-package S6 hosted journeys deferred to the Artium fold once per release candidate; no fixture re-pin performed.',
      packageChanged: hash(bytes) !== baseline.packageSha256 },
    completeness: { status: unresolved ? 'pending' : 'pass', routes: inventory.operations.length, variants: variants.length, unresolved,
      reason: 'Unreviewed variants stay uncallable; refusal coverage does not establish full runtime admission.' },
    windows: { status: 'pending', reason: 'Actual native Windows machine required.' },
    commissioning: { status: 'pending', reason: 'Offline fake-only evidence; no live controller exercised.' },
  }
}

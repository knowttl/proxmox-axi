import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { delimiter, join } from 'node:path'
import { promisify } from 'node:util'

const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex')
const execute = promisify(execFile)
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

export async function verifyPackageAdmission(root: string, installed: string, archive: string, scratch: string) {
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
  const baselineBytes = Buffer.from(await readFile(join(root, 'test/fixtures/proxmox-axi-0.0.1.tgz.base64'), 'utf8'), 'base64')
  assert.equal(hash(baselineBytes), 'e7ab445c20c13151772ab1f29ee9d1a68537b01763d46d7cd92a96f1cb890cde', 'Sealed offline baseline archive identity')
  const consumer = join(scratch, 'baseline-consumer')
  const ownedConsumer = join(scratch, 'owned-consumer')
  const baselineArchive = join(scratch, 'baseline.tgz')
  await writeFile(baselineArchive, baselineBytes)
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !key.startsWith('PROXMOX_AXI_') && key !== 'NODE_OPTIONS' && key !== 'NODE_PATH'))
  for (const [directory, tarball] of [[consumer, baselineArchive], [ownedConsumer, archive]] as const) {
    await mkdir(directory)
    await writeFile(join(directory, 'package.json'), JSON.stringify({ private: true,
      dependencies: { '@knowttl/proxmox-axi': `file:${tarball}` }, pnpm: source.pnpm }))
    await execute('pnpm', ['install', '--offline', '--prod', '--ignore-scripts'], { cwd: directory, env, timeout: 15000 })
  }
  const baselineInstalled = join(consumer, 'node_modules/@knowttl/proxmox-axi')
  const baselineManifest = JSON.parse(await readFile(join(baselineInstalled, 'package.json'), 'utf8')) as {
    name: string, version: string, bin: Record<string, string>
  }
  assert.equal(baselineManifest.name, manifest.name)
  assert.equal(baselineManifest.version, '0.0.1')
  assert.deepEqual(baselineManifest.bin, { 'proxmox-axi': 'bin/proxmox-axi.mjs' })
  assert.notEqual(manifest.version, baselineManifest.version, 'Coexisting versions must be observably distinct')
  const baselineBin = join(consumer, 'node_modules/.bin')
  const ownedBin = join(ownedConsumer, 'node_modules/.bin')
  const ownedInstalled = join(ownedConsumer, 'node_modules/@knowttl/proxmox-axi')
  const ownedExecutable = join(ownedInstalled, 'bin/proxmox-axi.mjs')
  assert.equal(hash(await readFile(ownedExecutable)), current['bin/proxmox-axi.mjs'], 'Coexisting owned executable identity')
  const baselineExecutable = join(baselineInstalled, 'bin/proxmox-axi.mjs')
  const version = async (executable: string, args: string[], path = env.PATH) => {
    const result = await execute(executable, args, { cwd: consumer, env: { ...env, PATH: path ?? '' }, timeout: 15000 })
    assert.equal(result.stderr, '')
    return result.stdout.trim()
  }
  assert.equal(await version(process.execPath, [baselineExecutable, '--version']), baselineManifest.version)
  const selections = []
  for (const [order, bins, expected] of [
    ['baseline-first', [baselineBin, ownedBin], baselineManifest.version],
    ['owned-first', [ownedBin, baselineBin], manifest.version],
  ] as const) {
    const path = [...bins, env.PATH ?? ''].join(delimiter)
    const unqualified = await version('proxmox-axi', ['--version'], path)
    assert.equal(unqualified, expected)
    const owned = await version(process.execPath, [ownedExecutable, '--version'], path)
    assert.equal(owned, manifest.version)
    selections.push({ order, unqualified, owned })
  }
  return {
    status: 'pass', files: current, sha256: hash(bytes),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    baseline: { name: baselineManifest.name, version: baselineManifest.version, sha256: hash(baselineBytes),
      integrity: `sha512-${createHash('sha512').update(baselineBytes).digest('base64')}`,
      executableSha256: hash(await readFile(baselineExecutable)) },
    coexistence: { status: 'pass', mechanism: 'node <absolute-owned-package>/bin/proxmox-axi.mjs --version',
      ownedVersion: manifest.version, ownedExecutableSha256: hash(await readFile(ownedExecutable)), selections },
    artium: { status: 'pending', reason: 'Current-package S6 hosted journeys deferred to the Artium fold once per release candidate; no fixture re-pin performed.',
      baseline: { revision: baseline.revision, sha256: baseline.packageSha256, integrity: baseline.packageIntegrity },
      packageChanged: hash(bytes) !== baseline.packageSha256 },
    completeness: { status: unresolved ? 'pending' : 'pass', routes: inventory.operations.length, variants: variants.length, unresolved,
      reason: 'Unreviewed variants stay uncallable; refusal coverage does not establish full runtime admission.' },
    windows: { status: 'pending', reason: 'Actual native Windows machine required.' },
    commissioning: { status: 'pending', reason: 'Offline fake-only evidence; no live controller exercised.' },
  }
}

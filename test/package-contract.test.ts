import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'

const execute = promisify(execFile)
const root = fileURLToPath(new URL('../../', import.meta.url))
// Published modules and data from the admission inventory's pinned sources.
// redact.js belonged to an older release; redaction now lives in private-results.js.
const modules = ['cli', 'contract', 'credentials', 'errors', 'journal', 'tasks', 'writes',
  'presentation', 'private-file', 'reads', 'transport', 'windows-acl']
const data = ['artium-invocations.json', 'write-policy.json', 'axi-credential.schema.json',
  'dist/contracts.json', 'dist/operation-policy.json', 'dist/operations.json',
  'dist/profile-schema.json', 'dist/vendor-constraints.json']

test('packed package installs offline and exposes the CLI and admission contracts', { timeout: 25000 }, async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-package-'))
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as {
    name: string, version: string, bin: Record<string, string>, pnpm: { overrides: Record<string, string> }
  }
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !key.startsWith('PROXMOX_AXI_') && key !== 'NODE_OPTIONS' && key !== 'NODE_PATH'))
  const run = (command: string, args: string[], cwd = scratch) => execute(command, args,
    { cwd, env, timeout: 15000, maxBuffer: 8 * 1024 * 1024 })
  try {
    // The configured test command already built dist; do not rebuild during pack.
    const packed = await run('npm', ['pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', scratch], root)
    const [pack] = JSON.parse(packed.stdout) as { filename: string }[]
    assert.ok(pack)
    const tarball = join(scratch, pack.filename)
    const listing = await run('tar', ['-tzf', tarball])
    const files = listing.stdout.trim().split('\n').map(path => {
      assert.ok(path.startsWith('package/'), `unexpected archive path: ${path}`)
      return path.slice('package/'.length)
    })
    const licenses = (await readdir(root)).filter(path => /^(?:LICENSE|LICENCE|NOTICE|THIRD_PARTY_NOTICES)(?:\.|$)|-LICENSE\.txt$/i.test(path))
    for (const required of ['package.json', 'README.md', ...licenses, ...Object.values(manifest.bin),
      ...modules.map(name => `dist/${name}.js`), ...data]) assert.ok(files.includes(required), `missing ${required}`)
    const allowedRoot = new Set(['package.json', 'README.md', ...licenses, ...data.filter(path => !path.includes('/')),
      'inventory.json', 'catalogue-diff.json', 'help.json'])
    for (const path of files) {
      assert.ok(allowedRoot.has(path) || path === 'bin/proxmox-axi.mjs' || path === 'docs/s4-contract.md' ||
        /^dist\/[a-z][a-z-]*(?:\.js|\.d\.ts|\.json)$/.test(path), `unexpected published file: ${path}`)
      assert.doesNotMatch(path, /(?:^|\/)(?:test|tests|node_modules|src)(?:\/|$)|\.map$|\.test\./)
    }
    await writeFile(join(scratch, 'package.json'), JSON.stringify({ private: true, type: 'module',
      dependencies: { [manifest.name]: `file:${tarball}` }, pnpm: manifest.pnpm }))
    await run('pnpm', ['install', '--offline', '--prod', '--ignore-scripts', '--lockfile=false'])
    const installed = join(scratch, 'node_modules', manifest.name)
    const published = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8')) as typeof manifest
    assert.equal(published.name, '@knowttl/proxmox-axi')
    assert.equal(published.version, manifest.version)
    assert.deepEqual(published.bin, { 'proxmox-axi': 'bin/proxmox-axi.mjs' })
    const bin = join(scratch, 'node_modules', '.bin', 'proxmox-axi')
    const help = await run(bin, ['--help'])
    assert.match(help.stdout, /proxmox-axi/)
    assert.match(help.stdout, /--help/)
    assert.equal(help.stderr, '')
    const version = await run(bin, ['--version'])
    assert.equal(version.stdout.trim(), manifest.version)
    assert.equal(version.stderr, '')
    // Resolve as a consumer, without the checkout's dependencies or build tree.
    await run(process.execPath, ['--input-type=module', '-e', `
      for (const name of ${JSON.stringify(modules)}) {
        const url = import.meta.resolve(${JSON.stringify(manifest.name)} + '/dist/' + name + '.js');
        await import(url);
      }
      for (const path of ${JSON.stringify(data)}) {
        const url = import.meta.resolve(${JSON.stringify(manifest.name)} + '/' + path);
        await import(url, { with: { type: 'json' } });
      }
    `])
  } finally { await rm(scratch, { recursive: true, force: true }) }
})

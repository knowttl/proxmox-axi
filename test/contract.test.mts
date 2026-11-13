import type { SpawnSyncReturns } from 'node:child_process'
import type { VendorSchema } from '../src/contract.ts'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { decode } from '@toon-format/toon'
import { buildPath, selectContract } from '../dist/contract.js'
import { captures, replay } from '../scripts/catalogue.ts'
import { verifyDiscovery } from '../scripts/route-cases.ts'
import policy from '../src/operation-policy.json' with { type: 'json' }

interface Invocations { commands: { command: string, flags: Record<string, string> }[] }
interface SchemaPage { parameters: VendorSchema, page: { offset: number, total: number, nextOffset: number | null } }


for (const args of [
  [], ['get'], ['get', '/version'], ['ls'], ['ls', '/nodes'],
  ['create'], ['set'], ['delete'], ['post'], ['put'],
  ['set', '/nodes/{node}/qemu/{vmid}/resize'], ['task'], ['task', 'status'], ['task', 'cancel'],
  ['journal', 'show', 'synthetic'], ['auth'], ['auth', 'status'], ['auth', 'acquire'],
  ['home'], ['doctor'], ['inventory'], ['config', 'path'], ['profile', 'list'], ['transfer'], ['duplex'],
]) {
  test(`${args.join(' ') || 'root'} help excludes schema-only flags`, () => {
    const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', ...args, '--help', '--format', 'json'], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    const flags = JSON.parse(result.stdout).flags.map((flag: string) => flag.split(' ')[0])
    assert.equal(flags.includes('--view'), false)
    assert.equal(flags.includes('--offset'), false)
  })
  for (const flag of [['--view', 'vendor'], ['--offset', '10']]) {
    test(`${args.join(' ') || 'root'} refuses schema-only ${flag[0]}`, () => {
      const result: SpawnSyncReturns<string> = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', ...args, ...flag, '--format', 'json'], { encoding: 'utf8' })
      assert.equal(result.status, 2, result.stdout + result.stderr)
      assert.deepEqual(JSON.parse(result.stdout).error, { code: 'INVALID_INPUT', message: '--view and --offset apply to schema only.' })
    })
  }
}

for (const args of [['schema'], ['schema', 'get', '/nodes'], ['help', 'schema']]) {
  test(`${args.join(' ')} help includes schema-only flags`, () => {
    const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', ...args, '--help', '--format', 'json'], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    const flags = JSON.parse(result.stdout).flags.map((flag: string) => flag.split(' ')[0])
    assert.equal(flags.includes('--view'), true)
    assert.equal(flags.includes('--offset'), true)
  })
}

test('vendor schema refuses a cursor outside its parameter list', () => {
  const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', 'schema', 'set', '/nodes/{node}/qemu/{vmid}/config',
    '--view', 'vendor', '--offset', String(Number.MAX_SAFE_INTEGER), '--format', 'json'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' })
  assert.equal(result.status, 2)
  assert.equal(JSON.parse(result.stdout).error.code, 'INVALID_INPUT')
})

for (const capture of captures) for (const format of ['json', 'toon']) {
  test(`${capture.release} ${format} vendor schema pages reconstruct the complete pinned parameters within the output cap`, async () => {
    const catalogue = replay(await readFile(new URL(`../vendor/${capture.file}`, import.meta.url)), capture)
    const expected = catalogue.operations.find(operation => operation.method === 'PUT' && operation.path === '/nodes/{node}/qemu/{vmid}/config')!.parameters
    let offset: number | null = 0, actual: VendorSchema | undefined
    do {
      const result: SpawnSyncReturns<string> = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', 'schema', 'set', '/nodes/{node}/qemu/{vmid}/config',
        '--catalogue', capture.release, '--view', 'vendor', '--offset', String(offset), '--format', format], { cwd: new URL('..', import.meta.url), encoding: 'utf8' })
      assert.equal(result.status, 0, result.stdout + result.stderr)
      assert.ok(Buffer.byteLength(result.stdout.trimEnd()) <= 65536)
      const value = (format === 'json' ? JSON.parse(result.stdout) : decode(result.stdout)) as SchemaPage
      actual ??= { ...value.parameters, properties: {} }
      Object.assign(actual.properties!, value.parameters.properties)
      assert.equal(value.page.offset, offset)
      assert.equal(value.page.total, Object.keys(expected.properties!).length)
      assert.ok(value.page.nextOffset === null || value.page.nextOffset > offset)
      offset = value.page.nextOffset
    } while (offset !== null)
    assert.deepEqual(actual, expected)
  })
}

test('discovery retains every release route and its exact vendor parameters', async () => {
  const catalogues = await Promise.all(captures.map(async capture => replay(await readFile(new URL(`../vendor/${capture.file}`, import.meta.url)), capture)))
  const { contracts } = JSON.parse(await readFile(new URL('../dist/contracts.json', import.meta.url), 'utf8'))
  verifyDiscovery(JSON.parse(await readFile(new URL('../inventory.json', import.meta.url), 'utf8')), catalogues, contracts, policy)
})

test('canonical path preserves the task identifier while encoding it once', () => {
  const contract = selectContract('GET', '/nodes/{node}/tasks/{upid}/status', 'legacy-8.2.7')
  assert.equal(buildPath(contract, { node: 'pve-test', upid: 'UPID:pve-test:1:2:3:vzdump:100:synthetic@pve:' }),
    '/api2/json/nodes/pve-test/tasks/UPID%3Apve-test%3A1%3A2%3A3%3Avzdump%3A100%3Asynthetic%40pve%3A/status')
})

test('canonical path rejects traversal', () => {
  assert.throws(() => buildPath(selectContract('GET', '/nodes/{node}/tasks/{upid}/status', 'legacy-8.2.7'), { node: 'pve-test', upid: '../other' }), { code: 'INVALID_INPUT' })
})

test('parameter boundary rejects a task limit below the vendor minimum', () => {
  assert.throws(() => buildPath(selectContract('GET', '/nodes/{node}/tasks', 'legacy-8.2.7'), { node: 'pve-test', limit: -1 }), { code: 'INVALID_INPUT' })
})

test('unknown route has no invocation contract', () => {
  assert.throws(() => selectContract('GET', '/unknown-new-route', 'published-current'), { code: 'INVALID_INPUT' })
})

for (const args of [['inventory'], ['schema', 'get', '/version']]) {
  test(`D7 ${args[0]} accepts the common config flag without loading credentials`, () => {
    const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', ...args, '--config', '/synthetic-unused-config.json', '--format', 'json'], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.equal(JSON.parse(result.stdout).release, 'legacy-8.2.7')
  })
}

for (const release of ['legacy-8.2.7', 'published-current']) {
  test(`provider-side download remains discoverable but refused in ${release}`, () => {
    const path = '/nodes/{node}/storage/{storage}/download-url'
    const contract = selectContract('POST', path, release)
    assert.equal(contract.callable, false)
    const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', 'create', path, '--catalogue', release, '--preview', '--format', 'json'], { encoding: 'utf8' })
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.equal(JSON.parse(result.stdout).error.code, 'CONTRACT_UNRESOLVED')
  })
}

for (const row of [
  { release: 'legacy-8.2.7', count: 605 },
  { release: 'published-current', count: 680 },
]) for (const mode of [
  { name: 'full', kind: 'boolean', args: ['--full'], rows: row.count },
  { name: 'limit', kind: 'value', args: ['--limit', '2'], rows: 2 },
]) test(`#11 hosted inventory admits --${mode.name} in ${row.release}`, async () => {
  const { commands } = JSON.parse(await readFile(new URL('../artium-invocations.json', import.meta.url), 'utf8')) as Invocations
  assert.equal(commands.find(command => command.command === 'inventory')!.flags[mode.name], mode.kind)
  const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', 'inventory', ...mode.args, '--catalogue', row.release, '--format', 'json'], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  const value = JSON.parse(result.stdout)
  assert.equal(value.count, row.count)
  assert.equal(value.operations.length, mode.rows)
})

for (const verb of ['get', 'ls']) test(`#6 ordinary hosted ${verb} does not admit the task-log download flag`, async () => {
  const { commands } = JSON.parse(await readFile(new URL('../artium-invocations.json', import.meta.url), 'utf8')) as Invocations
  assert.equal(Object.hasOwn(commands.find(command => command.command === `${verb} /nodes/{node}/tasks/{upid}/log`)!.flags, 'api-download'), false)
})

test('#6 hosted private task-log transfer preserves its download flag', async () => {
  const { commands } = JSON.parse(await readFile(new URL('../artium-invocations.json', import.meta.url), 'utf8')) as Invocations
  assert.equal(commands.find(command => command.command === 'transfer get /nodes/{node}/tasks/{upid}/log')!.flags['api-download'], 'value')
})

test('#11 inventory help accepts and discloses full and limit flags without credentials', () => {
  const result = spawnSync(process.execPath, ['bin/proxmox-axi.mjs', 'inventory', '--full', '--limit', '2', '--help', '--format', 'json'], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.deepEqual(JSON.parse(result.stdout).flags.filter((flag: string) => flag.startsWith('--full') || flag.startsWith('--limit'))
    .map((flag: string) => flag.split(' ')[0]), ['--limit', '--full'])
})

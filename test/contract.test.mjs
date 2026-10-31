import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { buildPath, selectContract } from '../dist/contract.js'
import { captures, replay } from '../scripts/catalogue.mjs'
import { verifyDiscovery } from '../scripts/route-cases.mjs'
import policy from '../src/operation-policy.json' with { type: 'json' }

test('discovery retains every release route and its exact vendor parameters', async () => {
  const catalogues = await Promise.all(captures.map(async capture => replay(await readFile(new URL(`../vendor/${capture.file}`, import.meta.url)), capture)))
  const { contracts } = JSON.parse(await readFile(new URL('../dist/contracts.json', import.meta.url)))
  verifyDiscovery(JSON.parse(await readFile(new URL('../inventory.json', import.meta.url))), catalogues, contracts, policy)
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

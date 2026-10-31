import assert from 'node:assert/strict'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { captures, replay, routeKey } from './catalogue.mjs'

const source = process.argv[2]
assert.ok(source?.startsWith('/'), 'Supply the absolute vendor evidence input directory')
const target = new URL('../vendor/', import.meta.url)
await mkdir(target, { recursive: true })
const union = new Map()
for (const capture of captures) {
  const bytes = await readFile(join(source, 'docs', capture.file))
  const catalogue = replay(bytes, capture)
  const expected = JSON.parse(await readFile(join(source, capture.release === 'legacy-8.2.7' ? 'host-api-catalogue.json' : 'api-catalogue.json')))
  assert.deepEqual(new Set(catalogue.operations.map(routeKey)), new Set(expected.operations.map(routeKey)))
  // Retain only unchanged vendor bytes, never private planning or observation notes.
  await writeFile(new URL(capture.file, target), bytes)
  for (const operation of catalogue.operations) union.set(routeKey(operation), operation)
}
assert.equal(union.size, 681)
console.log(`Verified and retained ${union.size} vendor routes in ${resolve(target.pathname)}`)

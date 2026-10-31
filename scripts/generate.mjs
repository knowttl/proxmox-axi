import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const root = new URL('../', import.meta.url)
const read = path => readFileSync(new URL(path, root), 'utf8')
const operations = JSON.parse(read('src/operations.json'))
const sourceSha256 = createHash('sha256').update(read('src/operations.json')).digest('hex')
const outputs = {
  'axi-credential.schema.json': JSON.parse(read('src/profile-schema.json')),
  'inventory.json': { generated: true, source: 'src/operations.json', sourceSha256, operations },
  'help.json': { generated: true, source: 'src/operations.json', sourceSha256,
    commands: operations.map(operation => ({ command: operation.command.join(' '), purpose: operation.help })) },
}
for (const [path, value] of Object.entries(outputs)) {
  const expected = `${JSON.stringify(value, null, 2)}\n`
  if (process.argv.includes('--check')) {
    if (read(path) !== expected) throw new Error(`${path} is stale; run pnpm generate`)
  } else writeFileSync(new URL(path, root), expected)
}

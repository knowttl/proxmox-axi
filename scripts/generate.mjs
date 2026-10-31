import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { captures, replay, routeKey, compareCatalogues } from './catalogue.mjs'

const root = new URL('../', import.meta.url)
const read = path => readFileSync(new URL(path, root), 'utf8')
const constraints = JSON.parse(read('src/vendor-constraints.json'))
function parameterSchema(vendor = {}) {
  const result = Object.fromEntries(Object.entries(vendor).filter(([key, value]) => key === 'type' ?
    ['object', 'array', 'string', 'integer', 'number', 'boolean', 'null'].includes(value) :
    key === 'enum' && Array.isArray(value)))
  const unresolved = reason => ({ ...result, not: {}, 'x-untranslated': reason })
  if (vendor.enum === null) return unresolved('unresolved vendor enumeration')
  for (const key of ['minimum', 'maximum', 'minLength', 'maxLength']) if (vendor[key] !== undefined) {
    const raw = vendor[key]
    const bound = typeof raw === 'number' ? raw : typeof raw === 'string' && /^-?\d+(?:\.\d+)?$/.test(raw) ? Number(raw) : NaN
    if (!Number.isFinite(bound)) return unresolved('vendor numeric bound')
    result[key] = bound
  }
  if (vendor['instance-types'] || vendor['type-property']) return unresolved('input-dependent vendor type')
  if (vendor.pattern) {
    if (constraints.unsupportedPatternMarkers.some(marker => vendor.pattern.includes(marker))) return unresolved('Perl pattern')
    try { new RegExp(`^(?:${vendor.pattern})$`, 'u') } catch { return unresolved('vendor pattern') }
    result.pattern = `^(?:${vendor.pattern})$`
  }
  if (vendor.format) {
    const pattern = typeof vendor.format === 'string' ? constraints.formats[vendor.format] : undefined
    if (!pattern) return unresolved('vendor format or property string')
    if (result.pattern) result.allOf = [{ pattern }]
    else result.pattern = pattern
  }
  if (vendor.oneOf) result.oneOf = vendor.oneOf.map(parameterSchema)
  if (vendor.items) result.items = parameterSchema(vendor.items)
  if (vendor.type === 'object' || vendor.properties || vendor.additionalProperties !== undefined) {
    result.type = 'object'
    result.additionalProperties = false
    result.properties = Object.fromEntries(Object.entries(vendor.properties ?? {}).map(([name, value]) => [name,
      name.includes('[n]') ? { not: {}, 'x-untranslated': 'numbered vendor parameter' } : parameterSchema(value)]))
    result.required = Object.entries(vendor.properties ?? {}).filter(([, value]) => !value.optional).map(([name]) => name)
    result.dependencies = Object.fromEntries(Object.entries(vendor.properties ?? {}).filter(([, value]) => value.requires).map(([name, value]) => [name, [value.requires]]))
  }
  return result
}
const operations = JSON.parse(read('src/operations.json'))
const sourceSha256 = createHash('sha256').update(read('src/operations.json')).digest('hex')
const catalogues = captures.map(capture => replay(Buffer.from(read(`vendor/${capture.file}`)), capture))
const policy = JSON.parse(read('src/operation-policy.json'))
const keys = new Set(catalogues.flatMap(catalogue => catalogue.operations.map(routeKey)))
if (keys.size !== 681 || Object.keys(policy.reviewed).some(key => !keys.has(key))) throw new Error('Policy route coverage mismatch')
const contracts = catalogues.flatMap(catalogue => catalogue.operations.map(operation => {
  const review = policy.reviewed[routeKey(operation)] ?? policy.default
  const callable = policy.captureBindings[catalogue.release] === catalogue.captureSha256 && review.effect === 'read' && review.transport === 'json' && review.secrets === 'none' && operation.allowtoken !== 0
  return { ...operation, release: catalogue.release, policy: review, callable,
    command: [operation.method.toLowerCase(), operation.path],
    invocation: { method: operation.method, path: operation.path, catalogue: catalogue.release,
      schema: { type: 'object', additionalProperties: false, properties: { api: parameterSchema(operation.parameters) }, required: ['api'] },
      parameterNamespace: '--api-', body: { flag: '--body-file', encoding: 'json', maxBytes: 65536 },
      untranslatedPatterns: 'Perl patterns and named formats are retained in parameters; unsupported supplied values fail closed.' } }
}))
const outputs = {
  'axi-credential.schema.json': JSON.parse(read('src/profile-schema.json')),
  'inventory.json': { generated: true, captures, unionRoutes: keys.size, variants: contracts.length,
    operations: [...keys].sort().map(key => {
      const variants = contracts.filter(operation => routeKey(operation) === key)
      const operation = variants[0]
      return { id: operations.find(item => routeKey(item) === key)?.id ?? `OP-${operation.method}-${createHash('sha256').update(key).digest('hex').slice(0, 10)}`,
        method: operation.method, path: operation.path, command: operation.command,
        variants: variants.map(variant => ({ release: variant.release, callable: variant.callable, policy: variant.policy,
          contract: `dist/contracts.json#/contracts/${contracts.indexOf(variant)}` })) }
    }) },
  'help.json': { generated: true, sources: ['src/operations.json', ...captures.map(capture => `vendor/${capture.file}`)], operationsSha256: sourceSha256, captures,
    commands: [...keys].sort().map(key => {
      const contract = contracts.find(operation => routeKey(operation) === key)
      return { command: contract.command.join(' '), purpose: operations.find(operation => routeKey(operation) === key)?.help ?? contract.description }
    }) },
  'src/contracts.json': { generated: true, captures, contracts },
  'catalogue-diff.json': compareCatalogues(catalogues[0], catalogues[1]),
  'artium-invocations.json': { generated: true, commands: [
    { command: 'home', effect: 'read', flags: { help: 'boolean', format: 'value' } },
    { command: 'inventory', effect: 'read', flags: { help: 'boolean', format: 'value', catalogue: 'value' } },
    ...[...keys].sort().map(key => {
      const operation = contracts.find(operation => routeKey(operation) === key)
      return { command: `schema ${operation.method.toLowerCase()} ${operation.path}`, effect: 'read', flags: { help: 'boolean', format: 'value', catalogue: 'value' } }
    }),
    ...[...keys].sort().flatMap(key => {
    const variants = contracts.filter(operation => routeKey(operation) === key && operation.callable)
    if (!variants.length) return []
    const flags = Object.fromEntries([...new Set(variants.flatMap(operation => Object.keys(operation.parameters.properties ?? {})))].map(name => [`api-${name}`, 'value']))
    return [{ command: variants[0].command.join(' '), effect: 'read', flags: { help: 'boolean', format: 'value', catalogue: 'value', ...flags },
      catalogues: variants.map(operation => operation.release) }]
  })] },
}
for (const [path, value] of Object.entries(outputs)) {
  const expected = `${JSON.stringify(value, null, 2)}\n`
  if (process.argv.includes('--check')) {
    if (read(path) !== expected) throw new Error(`${path} is stale; run pnpm generate`)
  } else writeFileSync(new URL(path, root), expected)
}

import assert from 'node:assert/strict'
import { Ajv } from 'ajv'
import { routeKey } from './catalogue.mjs'

function responseFixture(schema) {
  if (schema.enum) return schema.enum[0]
  if (schema.type === 'array') return schema.items ? [responseFixture(schema.items)] : []
  if (schema.type === 'object') return Object.fromEntries(Object.entries(schema.properties ?? {})
    .filter(([, constraint]) => !constraint.optional || constraint.type === 'boolean').map(([name, constraint]) => [name, responseFixture(constraint)]))
  if (schema.type === 'string') return 'fixture'
  if (schema.type === 'integer' || schema.type === 'number') return schema.minimum ?? 1
  if (schema.type === 'boolean') return 0
  return null
}

// Only vendor constraints and the checked admission policy supply the expected wire contract.
export function* routeCases(catalogues, policy) {
  for (const catalogue of catalogues) for (const operation of catalogue.operations) {
    const review = policy.reviewed[routeKey(operation)] ?? policy.default
    const callable = policy.captureBindings[catalogue.release] === catalogue.captureSha256 && review.effect === 'read' && review.transport === 'json' && review.secrets === 'none' && operation.allowtoken !== 0
    const values = {}
    const properties = operation.parameters?.properties ?? {}
    for (const [name, schema] of Object.entries(properties)) if (!schema.optional) {
      if (name === 'node') values[name] = 'pve-test'
      else if (name === 'upid') values[name] = 'UPID:pve-test:00000001:00000002:00000003:vzdump:100:synthetic@pve:'
      else if (schema.enum) values[name] = schema.enum[0]
      else if (schema.type === 'integer' || schema.type === 'number') values[name] = schema.minimum ?? 1
      else if (schema.type === 'boolean') values[name] = false
      else values[name] = 'fixture'
    }
    const variants = [{ branch: 'required', values }]
    if (callable) for (const [name, schema] of Object.entries(properties)) if (schema.optional) {
      if (schema.enum) for (const value of schema.enum) variants.push({ branch: `${name}=${value}`, values: { ...values, [name]: value } })
      else if (schema.type === 'boolean') for (const value of [false, true]) variants.push({ branch: `${name}=${value}`, values: { ...values, [name]: value } })
      else if (schema.type === 'integer') variants.push({ branch: `${name}=minimum`, values: { ...values, [name]: schema.minimum ?? 1 } })
    }
    for (const variant of variants) {
      const args = [operation.method.toLowerCase(), operation.path, '--catalogue', catalogue.release, '--format', 'json', '--full']
      const response = operation.path.endsWith('/version') ? { version: '8.2.7', release: '8.2', repoid: '3e0176e6bb2ade3b' } : responseFixture(operation.returns ?? {})
      if (callable) for (const [name, value] of Object.entries(variant.values)) args.push(`--api-${name}`, String(value))
      let path = operation.path
      const query = []
      for (const [name, value] of Object.entries(variant.values)) {
        const placeholder = `{${name}}`
        const encoded = encodeURIComponent(String(value))
        if (path.includes(placeholder)) path = path.replace(placeholder, encoded)
        else query.push(`${encodeURIComponent(name)}=${encodeURIComponent(typeof value === 'boolean' ? (value ? '1' : '0') : String(value))}`)
      }
      yield { id: `${catalogue.release}/${routeKey(operation)}/${variant.branch}`, operation, release: catalogue.release, callable, args,
        values: variant.values,
        response,
        expectedPath: `/api2/json${path}${query.length ? `?${query.join('&')}` : ''}` }
    }
  }
}

export function verifyDiscovery(inventory, catalogues, contracts, policy) {
  const ajv = new Ajv({ strict: false })
  const validators = new Map(contracts.map(contract => [`${contract.release}/${routeKey(contract)}`, ajv.compile(contract.invocation.schema)]))
  assert.equal(inventory.operations.length, 681)
  assert.deepEqual(new Set(inventory.operations.map(routeKey)), new Set(catalogues.flatMap(catalogue => catalogue.operations.map(routeKey))))
  for (const catalogue of catalogues) for (const operation of catalogue.operations) {
    const route = inventory.operations.find(entry => routeKey(entry) === routeKey(operation))
    const variant = route.variants.find(entry => entry.release === catalogue.release)
    const contract = contracts.find(entry => entry.release === catalogue.release && routeKey(entry) === routeKey(operation))
    assert.equal(variant.contract, `dist/contracts.json#/contracts/${contracts.indexOf(contract)}`)
    assert.deepEqual(contract.parameters, operation.parameters, `${catalogue.release}/${routeKey(operation)} preserves vendor constraints`)
    assert.deepEqual(contract.returns, operation.returns, `${catalogue.release}/${routeKey(operation)} preserves vendor response metadata`)
  }
  for (const route of routeCases(catalogues, policy)) if (route.callable) {
    const validate = validators.get(`${route.release}/${routeKey(route.operation)}`)
    assert.equal(validate({ api: route.values }), true, `${route.id}: generated schema accepts the reviewed branch`)
    assert.equal(validate({ api: { ...route.values, constructor: 'invalid' } }), false, `${route.id}: generated schema refuses unknown parameters`)
  }
}

import { readFileSync } from 'node:fs'
import { createPrivateKey, X509Certificate } from 'node:crypto'
import { Failure } from './errors.js'
import constraints from './vendor-constraints.json' with { type: 'json' }

export interface VendorSchema {
  type?: string
  optional?: number
  enum?: unknown[]
  minimum?: number
  maximum?: number
  minLength?: number
  maxLength?: number
  pattern?: string
  format?: string | Record<string, VendorSchema>
  properties?: Record<string, VendorSchema>
  additionalProperties?: number
  requires?: string
  oneOf?: VendorSchema[]
  items?: VendorSchema
  [key: string]: unknown
}
export interface Contract {
  id: string
  method: string
  path: string
  release: string
  callable: boolean
  allowtoken?: number
  description: string
  parameters: VendorSchema
  returns: VendorSchema
  policy: { effect: string, transport: string, secrets: string, reason: string,
    allowedInputs?: string[], sensitiveInputs?: string[], reconciliation?: { kind: string, path?: string, reason: string } }
  invocation: unknown
}
export const contracts: Contract[] = JSON.parse(readFileSync(new URL('./contracts.json', import.meta.url), 'utf8')).contracts
const invalid = () => new Failure('INVALID_INPUT', 'Input does not match the selected vendor contract.', 'Use schema <method> <template> --catalogue <release> to inspect parameters.', 2)

export function selectContract(method: string, path: string, release: string): Contract {
  const verb = ({ create: 'POST', set: 'PUT' } as Record<string, string>)[method.toLowerCase()] ?? method.toUpperCase()
  const contract = contracts.find(operation => operation.method === verb && operation.path === path && operation.release === release)
  if (!contract) throw invalid()
  return contract
}

const formats: Record<string, RegExp> = Object.fromEntries(Object.entries(constraints.formats).map(([name, pattern]) => [name, new RegExp(pattern)]))

export function validateValue(value: unknown, schema: VendorSchema): void {
  if (schema['instance-types'] || schema['type-property']) throw unsupported()
  if (schema.oneOf) {
    let matches = 0
    const { oneOf, ...common } = schema
    for (const branch of schema.oneOf) {
      try { validateValue(value, { ...common, ...branch }); matches++ }
      catch (error) { if (!(error instanceof Failure) || error.code === 'CONTRACT_UNRESOLVED') throw error }
    }
    if (matches !== 1) throw invalid()
    return
  }
  if (schema.enum && !schema.enum.includes(value)) throw invalid()
  if (schema.type === 'integer' && (!Number.isSafeInteger(value))) throw invalid()
  if (schema.type === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) throw invalid()
  if (schema.type === 'boolean' && typeof value !== 'boolean') throw invalid()
  if (typeof value === 'number' && ((schema.minimum !== undefined && value < schema.minimum) || (schema.maximum !== undefined && value > schema.maximum))) throw invalid()
  if (schema.type === 'string') {
    const pem = schema.format === 'pem-string' || schema.format === 'pem-certificate-chain'
    if (typeof value !== 'string' || (pem ? /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/ : /[\x00-\x1f\x7f]/).test(value)) throw invalid()
    if ((schema.minLength !== undefined && value.length < schema.minLength) || (schema.maxLength !== undefined && value.length > schema.maxLength)) throw invalid()
    if (schema.pattern) {
      // Perl syntax requires a reviewed translation when ECMAScript cannot represent it directly.
      const translated = (constraints.patterns as Record<string, string>)[schema.pattern] ?? schema.pattern
      if (constraints.unsupportedPatternMarkers.some(marker => translated.includes(marker))) throw unsupported()
      let pattern: RegExp
      try { pattern = new RegExp(`^(?:${translated})$`, 'u') } catch { throw unsupported() }
      if (!pattern.test(value)) throw invalid()
    }
    if (typeof schema.format === 'string') {
      if (pem) {
        try {
          if (schema.format === 'pem-string') createPrivateKey(value)
          else {
            const certificates = value.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
            if (!certificates?.length || value.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g, '').trim()) throw invalid()
            for (const certificate of certificates) new X509Certificate(certificate)
          }
        } catch { throw invalid() }
        return
      }
      if (schema.format === 'pve-command-batch') {
        let batch: unknown
        try { batch = JSON.parse(value) } catch { throw invalid() }
        if (!Array.isArray(batch) || batch.length === 0 || batch.length > 64 || Buffer.byteLength(value) > 32768) throw invalid()
        return
      }
      const format = formats[schema.format]
      if (!format) throw unsupported()
      if (!format.test(value)) throw invalid()
    } else if (schema.format) throw unsupported()
  }
  if (schema.type === 'array') {
    if (!Array.isArray(value) || !schema.items) throw invalid()
    for (const item of value) validateValue(item, schema.items)
  }
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid()
    validateParameters(value as Record<string, unknown>, schema)
  }
}

function unsupported(): Failure {
  return new Failure('CONTRACT_UNRESOLVED', 'The supplied parameter requires an untranslated vendor constraint.', 'Use a reviewed parameter branch or wait for its validator to be reviewed.')
}

export function validateParameters(values: Record<string, unknown>, schema: VendorSchema): void {
  const properties = schema.properties ?? {}
  for (const [name, constraint] of Object.entries(properties)) {
    if (!constraint.optional && !Object.hasOwn(values, name)) throw invalid()
  }
  for (const [name, value] of Object.entries(values)) {
    const constraint = Object.hasOwn(properties, name) ? properties[name] : undefined
    if (!constraint) throw invalid()
    validateValue(value, constraint)
    if (constraint.requires && !Object.hasOwn(values, constraint.requires)) throw invalid()
  }
}

export function buildPath(contract: Contract, values: Record<string, unknown>): string {
  validateParameters(values, contract.parameters)
  const used = new Set<string>()
  const path = contract.path.replace(/\{([^}]+)\}/g, (_, name: string) => {
    used.add(name)
    const value = String(values[name])
    if (!value || value === '.' || value === '..' || /[\\/\x00-\x1f\x7f]/.test(value) || /%[0-9a-f]{2}/i.test(value)) throw invalid()
    return encodeURIComponent(value)
  })
  const query = new URLSearchParams()
  for (const [name, value] of Object.entries(values)) if (!used.has(name)) {
    if (Array.isArray(value)) for (const item of value) query.append(name, String(item))
    else query.append(name, typeof value === 'boolean' ? (value ? '1' : '0') : String(value))
  }
  return `/api2/json${path}${query.size ? `?${query}` : ''}`
}

export function parseParameter(value: string, schema: VendorSchema): unknown {
  if (schema.type === 'integer' || schema.type === 'number') {
    if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(value)) throw invalid()
    return Number(value)
  }
  if (schema.type === 'boolean') {
    if (!/^(1|0|true|false)$/i.test(value)) throw invalid()
    return /^(1|true)$/i.test(value)
  }
  return value
}

export function validateResponse(value: unknown, schema: VendorSchema): void {
  const fail = () => new Failure('INVALID_RESPONSE', 'Response does not match the selected vendor shape.', 'Check the selected catalogue and server response.')
  if (schema.type === 'array') {
    if (!Array.isArray(value)) throw fail()
    if (schema.items) for (const item of value) validateResponse(item, schema.items)
  } else if (schema.type === 'object' || schema.properties) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail()
    for (const [name, constraint] of Object.entries(schema.properties ?? {})) {
      if (!Object.hasOwn(value, name)) { if (!constraint.optional) throw fail(); continue }
      validateResponse((value as Record<string, unknown>)[name], constraint)
    }
  } else if (schema.type === 'integer') {
    if (!Number.isSafeInteger(value)) throw fail()
  } else if (schema.type === 'null') {
    if (value !== null) throw fail()
  } else if (schema.type === 'boolean') {
    // Proxmox's JSON boolean fields also use numeric 0/1 in recorded responses.
    if (typeof value !== 'boolean' && value !== 0 && value !== 1) throw fail()
  } else if (schema.type && schema.type !== 'any' && typeof value !== schema.type) throw fail()
  if (schema.enum && !schema.enum.includes(value)) throw fail()
}

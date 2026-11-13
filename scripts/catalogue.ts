import type { VendorSchema } from '../src/contract.ts'
import { createHash } from 'node:crypto'

export interface Capture { release: string, sha256: string, count?: number }
export interface Operation {
  method: string
  path: string
  allowtoken: number
  permissions: unknown
  protected: unknown
  description: string
  parameters: VendorSchema & { properties?: Record<string, VendorSchema & { description?: string }> }
  returns: VendorSchema
  vendorMetadata: { name?: string, [key: string]: unknown }
}
export interface Catalogue { release: string, captureSha256: string, operations: Operation[] }
interface VendorNode { path?: string, text: string, info?: Record<string, Operation>, children?: VendorNode[] }


export const captures = [
  { release: 'legacy-8.2.7', file: 'proxmox-host-api-schema.txt', sha256: '61100b5ee3ec822c5ee54906bbe6354d6296468fbd00aed9ad032cfad184258d', count: 605 },
  { release: 'published-current', file: 'proxmox-api-schema.txt', sha256: '68a8ac7b4994525a1df5530e2d96f4fc76b6401f07861ac8a51635a0b9ce7c53', count: 680 },
]
export const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex')

export function replay(bytes: Buffer, capture: Capture): Catalogue {
  if (sha256(bytes) !== capture.sha256) throw new Error(`Capture hash mismatch: ${capture.release}`)
  const text = bytes.toString('utf8')
  // The capture is a JSON array assigned to apiSchema; never execute vendor JavaScript.
  const start = text.indexOf('[')
  let depth = 0, quoted = false, escaped = false, end = -1
  for (let index = start; index < text.length; index++) {
    const character = text[index]
    if (quoted) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') quoted = false
    } else if (character === '"') quoted = true
    else if (character === '[') depth++
    else if (character === ']' && --depth === 0) { end = index + 1; break }
  }
  if (end < 0) throw new Error('Incomplete vendor schema')
  const operations: Operation[] = []
  function visit(node: VendorNode, parent = '') {
    const path = node.path ?? `${parent.replace(/\/$/, '')}/${node.text.replace(/^\/+|\/+$/g, '')}`
    for (const [method, operation] of Object.entries(node.info ?? {})) {
      if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].includes(method)) throw new Error('Unknown vendor method')
      const { method: ignored, allowtoken = null, permissions = null, protected: protectedFlag = null,
        description = null, parameters = null, returns = null, ...vendorMetadata } = operation
      operations.push({ method, path, allowtoken, permissions, protected: protectedFlag, description, parameters, returns, vendorMetadata } as Operation)
    }
    for (const child of node.children ?? []) visit(child, path)
  }
  for (const node of JSON.parse(text.slice(start, end)) as VendorNode[]) visit(node)
  operations.sort((a, b) => a.path.localeCompare(b.path, 'en') || a.method.localeCompare(b.method, 'en'))
  if ((capture.count !== undefined && operations.length !== capture.count) || new Set(operations.map(routeKey)).size !== operations.length) throw new Error('Vendor route count mismatch')
  return { release: capture.release, captureSha256: capture.sha256, operations }
}

export const routeKey = (operation: { method: string, path: string }) => `${operation.method} ${operation.path}`

export function compareCatalogues(previous: Catalogue, current: Catalogue) {
  const before = new Map(previous.operations.map(operation => [routeKey(operation), operation]))
  const after = new Map(current.operations.map(operation => [routeKey(operation), operation]))
  return {
    added: [...after.keys()].filter(key => !before.has(key)),
    removed: [...before.keys()].filter(key => !after.has(key)),
    changed: [...after].filter(([key]) => before.has(key)).flatMap(([key, operation]) => {
      const fields = ['parameters', 'returns', 'permissions', 'allowtoken', 'protected', 'vendorMetadata']
        .filter(field => JSON.stringify(before.get(key)![field as keyof Operation]) !== JSON.stringify(operation[field as keyof Operation]))
      return fields.length ? [{ route: key, fields }] : []
    }),
  }
}

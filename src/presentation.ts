import { Failure } from './errors.js'

export function presentRead(result: { data: unknown, visibility?: string, providerTotal?: number }, path: string,
  options: { limit: number, full: boolean, fields?: string[], next: string }) {
  if (!Array.isArray(result.data)) return result
  const received = result.data.length
  const rows = result.data.slice(0, options.full ? received : options.limit)
  const defaults = path.endsWith('/log') ? ['n', 't'] : path.endsWith('/tasks') ? ['upid', 'type', 'status'] :
    path.endsWith('/storage') ? ['storage', 'type', 'active', 'avail'] : path.endsWith('/nodes') ? ['node', 'status', 'maxcpu'] :
      path === '/cluster/resources' ? ['id', 'type', 'status', 'name'] : ['vmid', 'name', 'status']
  const fields = options.fields ?? defaults
  const data = options.full && !options.fields ? rows : rows.map(row => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Failure('INVALID_RESPONSE', 'Expected object rows.', 'Check the selected read response.')
    return Object.fromEntries(fields.filter(field => Object.hasOwn(row, field)).map(field => [field, row[field]]))
  })
  return { ...result, data, count: data.length, received, total: result.visibility && result.visibility !== 'complete' ? null : result.providerTotal ?? null,
    empty: received === 0 ? result.visibility === 'complete' ? 'verified-empty' : 'visibility-unverified' : false,
    displayTruncated: data.length < received, providerPagination: result.providerTotal === undefined ? 'unknown' : result.providerTotal > received ? 'partial' : 'complete',
    help: [options.next, ...(data.length < received ? ['Repeat with --full for all received fields and rows (65536-byte output cap).'] : [])] }
}

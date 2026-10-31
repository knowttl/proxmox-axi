import type { Credentials } from './credentials.js'
import { buildPath, contracts, selectContract, validateResponse, type Contract } from './contract.js'
import { executeRead, readVersion } from './transport.js'
import { Failure } from './errors.js'

export function capability(version: string) {
  const major = Number(/^(\d+)\./.exec(version)?.[1])
  return { version, catalogue: major === 8 ? 'legacy-8.2.7' : 'published-current',
    status: major === 9 && /^9\.2(?:\.|$)/.test(version) ? 'supported' : 'unverified',
    evidence: major === 8 ? 'legacy regression fixtures' : major === 9 ? 'published schema; live commissioning pending' : 'unknown major; known reads only',
    writes: 'disabled' }
}

const inventoryRoutes = new Set(['/nodes', '/cluster/resources', '/nodes/{node}/qemu', '/nodes/{node}/lxc', '/nodes/{node}/storage', '/nodes/{node}/tasks'])

function inventoryVisibility(path: string, permissions: unknown): string {
  const root = (permissions as Record<string, Record<string, unknown>>)['/']
  const required = path.includes('storage') ? ['Datastore.Audit'] : /qemu|lxc/.test(path) ? ['VM.Audit'] :
    path === '/cluster/resources' ? ['Sys.Audit', 'VM.Audit', 'Datastore.Audit'] : ['Sys.Audit']
  return root && required.every(privilege => root[privilege] === 1 || root[privilege] === true) ? 'complete' : 'permission-filtered'
}

export async function readOperation(credentials: Credentials, initial: Contract, values: Record<string, unknown>, explicitCatalogue?: string) {
  // Validate before any version or permission request.
  buildPath(initial, values)
  let selected = initial
  let compatibility: ReturnType<typeof capability> | undefined
  if (!explicitCatalogue && initial.path !== '/version') {
    const entry = await readVersion(credentials, '/api2/json/version')
    const version = typeof values.node === 'string' ? await readVersion(credentials,
      buildPath(selectContract('GET', '/nodes/{node}/version', 'published-current'), { node: values.node })) : entry
    compatibility = capability(version.version!)
    const found = contracts.find(contract => contract.release === compatibility!.catalogue && contract.method === initial.method && contract.path === initial.path)
    if (!found) throw new Failure('CAPABILITY_UNSUPPORTED', 'Route is absent from the target catalogue.', 'Use proxmox-axi inventory --catalogue ' + compatibility.catalogue)
    selected = found
  }
  if (!selected.callable) throw new Failure('CAPABILITY_UNSUPPORTED', 'Operation is not admitted for this target.', `Inspect proxmox-axi schema ${selected.method.toLowerCase()} ${selected.path}`)
  let visibility: string | undefined
  if (inventoryRoutes.has(selected.path)) {
    visibility = 'unknown'
    if (!explicitCatalogue) {
      const permissions = await executeRead(credentials, '/api2/json/access/permissions')
      validateResponse(permissions, selectContract('GET', '/access/permissions', selected.release).returns)
      visibility = inventoryVisibility(selected.path, permissions)
    }
  }
  const envelope = await executeRead(credentials, buildPath(selected, values), true) as { data: unknown, total?: number }
  validateResponse(envelope.data, selected.returns)
  if (selected.path === '/version' || selected.path === '/nodes/{node}/version') {
    const data = envelope.data as Record<string, unknown>
    if (['version', 'release', 'repoid'].some(key => typeof data[key] !== 'string' || !data[key])) throw new Failure('INVALID_RESPONSE', 'Missing version metadata.', 'Check the target version response.')
    compatibility = capability(data.version as string)
  }
  return { data: envelope.data, ...(envelope.total === undefined ? {} : { providerTotal: envelope.total }),
    ...(visibility ? { visibility } : {}), ...(compatibility ? { compatibility } : {}) }
}

export async function doctor(credentials: Credentials, node?: string) {
  const checks: Record<string, unknown>[] = []
  let release = 'published-current'
  const run = async (path: string, values: Record<string, unknown> = {}) => {
    const result = await readOperation(credentials, selectContract('GET', path, release), values, release)
    checks.push({ path, ...result })
    return result.data
  }
  const entry = await run('/version') as Record<string, string>
  release = capability(entry.version!).catalogue
  const permissions = await run('/access/permissions')
  const nodes = await run('/nodes') as Record<string, unknown>[]
  const selectedNode = node ?? nodes[0]?.node
  if (typeof selectedNode === 'string') {
    const target = await run('/nodes/{node}/version', { node: selectedNode }) as Record<string, string>
    release = capability(target.version!).catalogue
    for (const resource of ['qemu', 'lxc', 'storage']) await run(`/nodes/{node}/${resource}`, { node: selectedNode })
    const tasks = await run('/nodes/{node}/tasks', { node: selectedNode, limit: 1 }) as Record<string, unknown>[]
    if (tasks[0]) await run('/nodes/{node}/tasks/{upid}/status', { node: selectedNode, upid: tasks[0].upid })
  }
  for (const check of checks) if (inventoryRoutes.has(check.path as string)) check.visibility = inventoryVisibility(check.path as string, permissions)
  return { compatibility: capability(entry.version!), permissions, checks,
    bounds: { maximumRequests: 9, requestDeadlineMs: 5000, maximumResponseBytes: 65536 },
    help: ['Run proxmox-axi doctor before and after an upgrade.', 'Review certificate changes explicitly; trust is never renewed automatically.'] }
}

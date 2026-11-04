import type { Credentials } from './credentials.js'
import { buildPath, contracts, selectContract, validateResponse, type Contract } from './contract.js'
import { executeRead, executeRequest, readVersion } from './transport.js'
import { Failure } from './errors.js'
import { resultBinding } from './private-results.js'
import { networkObservation, normalizeNetworkResponse } from './node-network.js'

export function capability(version: string) {
  const major = Number(/^(\d+)\./.exec(version)?.[1])
  return { version, catalogue: major === 8 ? 'legacy-8.2.7' : 'published-current',
    status: major === 9 && /^9\.2(?:\.|$)/.test(version) ? 'supported' : 'unverified',
    evidence: major === 8 ? 'legacy regression fixtures' : major === 9 ? 'published schema; live commissioning pending' : 'unknown major; known reads only',
    writeVerification: 'unverified' }
}

const inventoryRoutes = new Set(['/nodes', '/cluster/resources', '/cluster/status', '/storage', '/nodes/{node}/qemu', '/nodes/{node}/lxc', '/nodes/{node}/storage', '/nodes/{node}/tasks'])

function inventoryVisibility(path: string, permissions: unknown): string {
  const root = (permissions as Record<string, Record<string, unknown>>)['/']
  const required = path.includes('storage') ? ['Datastore.Audit'] : /qemu|lxc/.test(path) ? ['VM.Audit'] :
    path === '/cluster/resources' ? ['Sys.Audit', 'VM.Audit', 'Datastore.Audit'] : ['Sys.Audit']
  return root && required.every(privilege => root[privilege] === 1 || root[privilege] === true) ? 'complete' : 'permission-filtered'
}

export function validateFields(contract: Contract, fields?: string[]): void {
  const known = contract.policy.outputFields ?? Object.keys(contract.returns.items?.properties ?? contract.returns.properties ?? {})
  const unknown = fields?.filter(field => !known.includes(field)) ?? []
  if (unknown.length) throw new Failure('INVALID_INPUT', `Unknown fields: ${unknown.join(', ')}.`, known.length ? `Available fields: ${known.join(', ')}.` : 'This response has no selectable fields.', 2)
}

export async function readOperation(credentials: Credentials, initial: Contract, values: Record<string, unknown>, explicitCatalogue?: string, fields?: string[]) {
  if (initial.policy.transport !== 'json') throw new Failure('INVALID_INPUT', 'This operation requires managed transport.', 'Use proxmox-axi transfer --help.', 2)
  if (initial.policy.effect !== 'read') throw new Failure('WRITE_DISABLED', 'Operation requires the write execution policy.', 'Use create, set or delete with a preview and exact confirmation.')
  if (initial.policy.allowedInputs && Object.keys(values).some(name => !initial.policy.allowedInputs!.includes(name))) {
    throw new Failure('CONTRACT_UNRESOLVED', 'Supplied read parameter branch has not been admitted.', 'Inspect the invocation schema and use reviewed inputs only.')
  }
  // Validate before any version or permission request.
  buildPath(initial, values)
  const privateResult = initial.policy.secrets === 'private-result'
  if (privateResult) credentials.results.sink()
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
  validateFields(selected, fields)
  let visibility: string | undefined
  if (inventoryRoutes.has(selected.path)) {
    visibility = 'unknown'
    if (!explicitCatalogue) {
      const permissions = await executeRead(credentials, '/api2/json/access/permissions')
      validateResponse(permissions, selectContract('GET', '/access/permissions', selected.release).returns)
      visibility = inventoryVisibility(selected.path, permissions)
    }
  }
  let envelope: { data: unknown, total?: number, changes?: unknown }
  try {
    envelope = await executeRequest(credentials, buildPath(selected, values), { method: selected.method, envelope: true,
      ...(selected.path === '/nodes/{node}/aplinfo' ? { maxResponseBytes: 262_144 } : {}) }) as typeof envelope
  } catch (error) {
    if (selected.path.startsWith('/nodes/{node}/qemu/{vmid}/agent/') && error instanceof Failure &&
      (error.code === 'TIMEOUT' || (error.httpStatus ?? 0) >= 500)) {
      throw new Failure(error.code, error.message,
        'Check guest power state, QEMU agent enablement, the guest-agent service and supported commands. This request did not establish readiness; it does not prove the VM is unhealthy.',
        error.exitCode, error.httpStatus)
    }
    throw error
  }
  if (selected.path === '/nodes/{node}/network' || selected.path === '/nodes/{node}/network/{iface}') {
    envelope.data = normalizeNetworkResponse(envelope.data)
  }
  let responseSchema = selected.returns
  if (/^\/nodes\/\{node\}\/(?:qemu|lxc)\/\{vmid\}\/pending$/.test(selected.path)) {
    const items = responseSchema.items!
    responseSchema = { ...responseSchema, items: { ...items, properties: { ...items.properties,
      value: { ...items.properties!.value, type: 'scalar' }, pending: { ...items.properties!.pending, type: 'scalar' } } } }
  }
  envelope.data = validateResponse(envelope.data, responseSchema)
  if (selected.policy.outputFields) {
    const names = selected.policy.outputFields
    const properties = selected.returns.items?.properties ?? selected.returns.properties ?? {}
    const project = (value: unknown) => {
      const row = value as Record<string, unknown>
      const projected = Object.fromEntries(names.filter(name => Object.hasOwn(row, name)).map(name => [name, row[name]]))
      // Some vendor indexes declare no row properties; reviewed identifiers are strings.
      validateResponse(projected, { type: 'object', properties: Object.fromEntries(names.map(name =>
        [name, properties[name] ?? { type: 'string', optional: 1 }])) })
      return projected
    }
    envelope.data = Array.isArray(envelope.data) ? envelope.data.map(project) : project(envelope.data)
  }
  if (privateResult) {
    if (selected.path === '/nodes/{node}/network') envelope.data = networkObservation(envelope, selected.release)
    await credentials.results.deliver(resultBinding(credentials.origin, credentials.tokenId, selected.id,
      `${selected.release} ${buildPath(selected, values)}`), envelope.data)
    envelope.data = { privateResult: true }
  }
  // The storage index can include backend configuration beyond its declared identifier.
  if (selected.path === '/storage') envelope.data = (envelope.data as { storage: string }[]).map(({ storage }) => ({ storage }))
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
    const { data, ...metadata } = result
    checks.push({ path, ...metadata, ...(path === '/access/permissions' ? {} : { data: credentials.results.sanitize(data) }),
      ...(result.compatibility ? { compatibility: { ...result.compatibility, version: credentials.results.redact(result.compatibility.version) } } : {}) })
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
  return { compatibility: { ...capability(entry.version!), version: credentials.results.redact(entry.version!) },
    permissions: credentials.results.sanitize(permissions), checks,
    bounds: { maximumRequests: 9, requestDeadlineMs: 5000, maximumResponseBytes: 65536 },
    help: ['Run proxmox-axi doctor before and after an upgrade.', 'Review certificate changes explicitly; trust is never renewed automatically.'] }
}

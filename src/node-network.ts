import { buildPath, selectContract, validateResponse, type Contract } from './contract.js'
import type { Credentials } from './credentials.js'
import { Failure } from './errors.js'
import { executeRead } from './transport.js'

type Interface = Record<string, unknown>
const path = '/nodes/{node}/network'
const invalid = () => new Failure('INVALID_RESPONSE', 'Pending network configuration could not be verified.', 'Inspect the complete network configuration privately; never retry an uncertain change.')
const input = () => new Failure('INVALID_INPUT', 'Interface settings are outside the reviewed Linux bridge branch.', 'Use a vmbr identifier, reviewed ports and manual/static address configuration.', 2)
export interface NetworkObservation { interfaces: Interface[], pendingDiff: string | null, activeConfiguration: 'unverified', visibility: 'unknown' }
export interface NetworkPlan { before: NetworkObservation, after: Interface[], management: { classification: 'unknown', affected: string[], addressed: string[] } }

export function networkObservation(envelope: { data: unknown, changes?: unknown, total?: number }, release: string): NetworkObservation {
  validateResponse(envelope.data, selectContract('GET', path, release).returns)
  const interfaces = envelope.data as Interface[]
  if ((envelope.changes != null && typeof envelope.changes !== 'string') ||
    (envelope.total !== undefined && envelope.total !== interfaces.length) ||
    new Set(interfaces.map(row => row.iface)).size !== interfaces.length) throw invalid()
  return { interfaces, pendingDiff: envelope.changes as string | null ?? null, activeConfiguration: 'unverified', visibility: 'unknown' }
}

async function observe(credentials: Credentials, node: unknown, release: string): Promise<NetworkObservation> {
  const envelope = await executeRead(credentials, buildPath(selectContract('GET', path, release), { node }), true)
  return networkObservation(envelope as { data: unknown }, release)
}

// Compare persisted settings, excluding runtime flags and derived address/family fields.
function settings(row: Interface): Interface {
  const value = Object.fromEntries(Object.entries(row).filter(([name]) =>
    !['active', 'exists', 'priority', 'altnames', 'link-type', 'address', 'netmask', 'address6', 'netmask6', 'families'].includes(name)))
  value.autostart = row.autostart === true || row.autostart === 1
  value.method ??= 'manual'
  value.method6 ??= 'manual'
  if (row.type === 'bridge') {
    value.bridge_ports = [...new Set(String(row.bridge_ports ?? '').split(/\s+/).filter(Boolean))].sort().join(' ')
    value.bridge_stp ??= 'off'
    value.bridge_fd = String(row.bridge_fd ?? 0)
  }
  if (row.type === 'bond') {
    value.slaves = [...new Set(String(row.slaves ?? '').split(/\s+/).filter(Boolean))].sort().join(' ')
    value.bond_mode ??= 'balance-rr'
    value.bond_miimon = String(row.bond_miimon ?? 100)
  }
  return value
}

function canonical(rows: Interface[]): string {
  return JSON.stringify(rows.map(settings).sort((a, b) => String(a.iface).localeCompare(String(b.iface)))
    .map(row => Object.fromEntries(Object.entries(row).sort(([a], [b]) => a.localeCompare(b)))))
}

export async function prepareNetwork(credentials: Credentials, contract: Contract, values: Interface): Promise<NetworkPlan | undefined> {
  if (contract.policy.stateBinding?.kind !== 'node-network') return
  const before = await observe(credentials, values.node, contract.release)
  const selected = before.interfaces.find(row => row.iface === values.iface)
  if (contract.method === 'POST' ? selected : !selected || selected.type !== 'bridge') throw input()
  if (selected && [selected.method, selected.method6].some(method => method !== undefined && !['manual', 'static'].includes(String(method)))) throw input()
  // The provider replaces methods/families on PUT; preserve existing static families explicitly.
  if (contract.method === 'PUT') for (const name of ['cidr', 'cidr6']) {
    if (values[name] === undefined && selected?.[name] !== undefined) values[name] = selected[name]
    if (selected?.[name === 'cidr' ? 'address' : 'address6'] && values[name] === undefined) throw input()
  }
  const patch = Object.fromEntries(Object.entries(values).filter(([name]) => !['node', 'iface'].includes(name)))
  const proposed: Interface = { ...selected, ...patch, iface: values.iface, method: (values.cidr ?? selected?.cidr) ? 'static' : 'manual',
    method6: (values.cidr6 ?? selected?.cidr6) ? 'static' : 'manual' }
  if (contract.method !== 'DELETE') for (const port of String(proposed.bridge_ports ?? '').split(' ').filter(Boolean)) {
    if (port === values.iface || !before.interfaces.some(row => row.iface === port && ['eth', 'bond', 'vlan'].includes(String(row.type)))) throw input()
  }
  const after = before.interfaces.filter(row => row.iface !== values.iface)
  if (contract.method !== 'DELETE') after.push(proposed)
  const affected = new Set([String(values.iface)])
  const rows = [...before.interfaces, ...after]
  // Include both old and proposed edges; indirect management dependencies matter too.
  let changed = true
  while (changed) {
    changed = false
    for (const row of rows) {
      const dependencies = ['bridge_ports', 'slaves', 'vlan-raw-device'].flatMap(name => String(row[name] ?? '').split(/[\s,;]+/).filter(Boolean))
      const inferred = /^(.*)\.[0-9]+$/.exec(String(row.iface))?.[1]
      const names = [String(row.iface), ...dependencies, ...(inferred ? [inferred] : [])]
      if (names.some(name => affected.has(name))) for (const name of names) if (!affected.has(name)) { affected.add(name); changed = true }
    }
  }
  const addressed = [...new Set(rows.filter(row => affected.has(String(row.iface)) &&
    ['address', 'address6', 'cidr', 'cidr6', 'gateway', 'gateway6'].some(name => row[name])).map(row => String(row.iface)))].sort()
  return { before, after: after.map(settings), management: { classification: 'unknown', affected: [...affected].sort(), addressed } }
}

export async function verifyNetwork(credentials: Credentials, contract: Contract, values: Interface, plan: NetworkPlan): Promise<void> {
  let observed: NetworkObservation
  try { observed = await observe(credentials, values.node, contract.release) }
  catch { throw invalid() }
  if (canonical(observed.interfaces) !== canonical(plan.after)) throw invalid()
}

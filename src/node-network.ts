import { selectContract, validateResponse } from './contract.js'
import { Failure } from './errors.js'

type Interface = Record<string, unknown>
const path = '/nodes/{node}/network'
const invalid = () => new Failure('INVALID_RESPONSE', 'Pending network configuration could not be verified.', 'Inspect the selected catalogue and network response privately.')
export interface NetworkObservation { interfaces: Interface[], pendingDiff: string | null, activeConfiguration: 'unverified', visibility: 'unknown' }

export function normalizeNetworkResponse(data: unknown): unknown {
  if (Array.isArray(data)) return data.map(normalizeNetworkResponse)
  if (!data || typeof data !== 'object') return data
  const row = { ...data } as Interface
  for (const name of ['mtu', 'netmask6', 'vlan-id', 'vxlan-id', 'bridge-access', 'ovs_tag']) {
    const value = row[name]
    if (typeof value === 'string') {
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) throw invalid()
      row[name] = Number(value)
    }
  }
  for (const name of ['bridge-learning', 'bridge-arp-nd-suppress', 'bridge-unicast-flood', 'bridge-multicast-flood']) {
    const value = row[name]
    if (typeof value === 'string') {
      if (!['0', '1', 'on', 'off'].includes(value)) throw invalid()
      row[name] = value === '1' || value === 'on' ? 1 : 0
    }
  }
  return row
}

export function networkObservation(envelope: { data: unknown, changes?: unknown, total?: number }, release: string): NetworkObservation {
  const data = normalizeNetworkResponse(envelope.data)
  validateResponse(data, selectContract('GET', path, release).returns)
  const interfaces = (data as Interface[]).sort((a, b) => String(a.iface).localeCompare(String(b.iface)))
  if ((envelope.changes != null && typeof envelope.changes !== 'string') ||
    (envelope.total !== undefined && envelope.total !== interfaces.length) ||
    new Set(interfaces.map(row => row.iface)).size !== interfaces.length) throw invalid()
  return { interfaces, pendingDiff: envelope.changes as string | null ?? null, activeConfiguration: 'unverified', visibility: 'unknown' }
}

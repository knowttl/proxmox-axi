import { buildPath, selectContract, validateResponse, type Contract } from './contract.js'
import type { Credentials } from './credentials.js'
import { Failure } from './errors.js'
import { executeRead } from './transport.js'
import { namedFormatPattern } from './property-format.js'

type Rule = Record<string, unknown>
export interface RulesPlan { before: Rule[], after: Rule[], path: string, warnings: string[] }
const invalid = () => new Failure('INVALID_RESPONSE', 'The complete ordered firewall rules and digest could not be verified.', 'Inspect the selected rules privately; do not modify an incomplete ruleset.')
const input = () => new Failure('INVALID_INPUT', 'Rule inputs or position are outside the reviewed branch.', 'Use basic in/out rules, a valid position and a separate reorder request.', 2)

async function readRules(credentials: Credentials, path: string, values: Record<string, unknown>, release: string): Promise<Rule[]> {
  const contract = selectContract('GET', path, release)
  const target = Object.fromEntries(Object.entries(values).filter(([name]) => path.includes(`{${name}}`)))
  const data = await executeRead(credentials, buildPath(contract, target))
  validateResponse(data, contract.returns)
  const rules = data as Rule[]
  if (rules.some((rule, pos) => rule.pos !== pos || typeof rule.digest !== 'string' ||
    !/^[a-f0-9]{40}$/i.test(rule.digest) || rule.digest !== rules[0]!.digest)) throw invalid()
  return rules
}

// Positions are verified separately; a future provider digest is not predicted.
function settings(rule: Rule): Rule {
  return Object.fromEntries(Object.entries(rule).filter(([name]) => !['digest', 'pos', 'errors'].includes(name)))
}

function canonical(value: unknown): string {
  const ordered = (item: unknown): unknown => Array.isArray(item) ? item.map(ordered) : item && typeof item === 'object' ?
    Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, ordered(child)])) : item
  return JSON.stringify(ordered(value))
}

// Attach the verified native digest to position-based request values.
export async function prepareRules(credentials: Credentials, contract: Contract, values: Record<string, unknown>): Promise<RulesPlan | undefined> {
  if (!contract.policy.stateBinding) return
  const path = contract.policy.stateBinding.path, before = await readRules(credentials, path, values, contract.release)
  const after = before.map(settings), pos = Number(values.pos)
  const fields = Object.fromEntries(Object.entries(values).filter(([name]) => !['node', 'vmid', 'pos', 'moveto', 'digest'].includes(name)))
  let selected: Rule
  if (contract.method === 'POST') {
    selected = fields
    after.unshift(selected)
  } else {
    if (!Number.isSafeInteger(pos) || !after[pos]) throw input()
    selected = after[pos]!
    if (!['in', 'out'].includes(String(selected.type)) || !['ACCEPT', 'DROP', 'REJECT'].includes(String(selected.action))) throw input()
    const digest = before[0]!.digest
    if (values.digest !== undefined && values.digest !== digest) throw new Failure('CONFIRMATION_MISMATCH', 'The supplied rules digest is stale.', 'Read and preview the current ordered rules again.')
    values.digest = digest
    if (contract.method === 'DELETE') after.splice(pos, 1)
    else if (values.moveto !== undefined) {
      const boundary = Number(values.moveto)
      if (boundary !== pos) {
        after.splice(pos, 1)
        after.splice(Math.min(boundary > pos ? boundary - 1 : boundary, after.length), 0, selected)
      }
    } else Object.assign(selected, fields)
  }
  if (contract.method !== 'DELETE' && values.moveto === undefined) {
    const addresses = [selected.source, selected.dest].filter(value => value !== undefined)
    if (selected.macro !== undefined || selected['icmp-type'] !== undefined ||
      addresses.some(value => !new RegExp(namedFormatPattern('pve-firewall-address')!).test(String(value))) ||
      (selected.proto !== undefined && !['tcp', 'udp', 'icmp', 'icmpv6'].includes(String(selected.proto)))) throw input()
    const ports = [selected.sport, selected.dport].filter(value => value !== undefined)
    if (ports.some(value => !new RegExp(namedFormatPattern('pve-firewall-port')!).test(String(value))) ||
      (ports.length && !['tcp', 'udp'].includes(String(selected.proto)))) throw input()
    const versions = [...addresses.map(value => String(value).includes(':') ? 6 : 4), ...(selected.proto === 'icmp' ? [4] : selected.proto === 'icmpv6' ? [6] : [])]
    if (versions.some(value => value !== versions[0])) throw input()
    if (versions.length) selected.ipversion = versions[0]
    else delete selected.ipversion
  }
  const restrictedAddress = ['source', 'dest'].some(name => selected[name] !== undefined && !String(selected[name]).endsWith('/0'))
  const warnings = selected.action === 'ACCEPT' && !restrictedAddress && !['proto', 'sport', 'dport', 'macro', 'icmp-type'].some(name => selected[name] !== undefined) ?
    ['ACCEPT-ALL RULE: inspect its disabled/active state and direction explicitly before confirming.'] : []
  return { before, after: after.map((rule, index) => ({ ...rule, pos: index })), path, warnings }
}

export async function verifyRules(credentials: Credentials, contract: Contract, values: Record<string, unknown>, plan: RulesPlan): Promise<void> {
  let observed: Rule[]
  try { observed = await readRules(credentials, plan.path, values, contract.release) }
  catch { throw new Failure('INVALID_RESPONSE', 'Post-write ordered-rule verification is unavailable.', 'Retain uncertainty; inspect rules privately without retry or automatic deletion.') }
  if (canonical(observed.map(settings)) !== canonical(plan.after.map(settings))) {
    throw new Failure('INVALID_RESPONSE', 'Observed ordered rules differ from the confirmed plan.', 'Retain uncertainty; inspect rules privately without retrying or automatically deleting anything.')
  }
}

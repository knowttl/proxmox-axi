// These names and paths identify reviewed vendor operations, not method-based admission.
// The generated table retains every other route with an explicit refusal.
import { backupVolumePattern, cloudInitSshKeysPattern, namedFormatPattern } from '../src/property-format.ts'
import type { Contract } from '../src/contract.ts'
type InputCase = NonNullable<Contract['policy']['inputCases']>[number]
interface Operation {
  method: string
  path: string
  vendorMetadata: { name?: string }
  parameters: { properties?: Record<string, { description?: string }> }
  returns: { type?: string }
  permissions: unknown
  allowtoken?: number
}

const lifecycle = new Set(['vm_start', 'vm_stop', 'vm_shutdown', 'vm_reboot', 'vm_reset', 'vm_resume', 'vm_suspend'])
const pool = new Set(['create_pool', 'update_pool', 'delete_pool'])

export function reviewWrite(operation: Operation) {
  const { path, method } = operation
  const name = operation.vendorMetadata.name
  if (operation.allowtoken !== 0 && ((method === 'POST' && path === '/nodes/{node}/network' && name === 'create_network') ||
    (path === '/nodes/{node}/network/{iface}' && ((method === 'PUT' && name === 'update_network') || (method === 'DELETE' && name === 'delete_network'))))) {
    return { effect: 'write', transport: 'json', secrets: 'private-result', stateBinding: { kind: 'node-network', path: '/nodes/{node}/network' },
      allowedInputs: ['node', 'iface', ...(method !== 'DELETE' ? ['type', 'autostart', 'bridge_ports', 'mtu', 'cidr', 'cidr6', 'gateway', 'gateway6'] : [])],
      ...(method !== 'DELETE' ? { fixedInputs: { type: 'bridge' } } : {}),
      inputFormats: { iface: 'pve-node-bridge', bridge_ports: 'pve-node-ports', cidr: 'pve-firewall-address', cidr6: 'pve-firewall-address', gateway: 'pve-firewall-address', gateway6: 'pve-firewall-address' },
      ...(method !== 'DELETE' ? { inputPatterns: { cidr: '^[^:]+/[1-9][0-9]*$(?![\\s\\S])', cidr6: '^[^/]*:[^/]*/[1-9][0-9]*$(?![\\s\\S])', gateway: '^[^:/]+$(?![\\s\\S])', gateway6: '^[^/]*:[^/]*$(?![\\s\\S])' } } : {}),
      confirmationWarnings: [{ message: 'MANAGEMENT ACCESS AT RISK: this pending change can cut host access when applied or on reboot. Classification is UNKNOWN: active addresses, hidden interfaces and external configuration are unverified. Inspect the private affected/addressed bridge, bond and VLAN dependencies before explicitly confirming.' },
        { message: 'PENDING ONLY, NON-ATOMIC: no native digest guards dispatch. Confirm the private pending diff and proposed configuration; application/revert are separate refused operations. Unexpected observations remain uncertain without retry or automatic recovery.' },
        ...(method === 'DELETE' ? [{ message: 'BRIDGE DELETION: explicitly confirm removal of this pending bridge configuration and inspect its consumers.' }] : [])],
      reason: 'Confirmed pending Linux bridge CRUD only, with private native diff and state binding. Physical/OVS/VLAN/bond mutations, custom options, setting deletion and apply/revert remain refused.',
      reconciliation: { kind: 'none', reason: 'Inspect pending configuration privately without retry or automatic apply/revert; runtime reachability and active addresses are unverified.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned Network.pm shadow-file CRUD and common INotify/Interfaces serialization; no native optimistic digest.' }
  }
  if (operation.allowtoken !== 0 && ((method === 'POST' && path === '/cluster/firewall/groups' && name === 'create_security_group') ||
    (method === 'DELETE' && path === '/cluster/firewall/groups/{group}' && name === 'delete_security_group'))) {
    return { effect: 'write', transport: 'json', secrets: 'private-result', allowedInputs: ['group', ...(method === 'POST' ? ['comment'] : [])],
      sensitiveInputs: method === 'POST' ? ['comment'] : [], inputFormats: { group: 'pve-firewall-group', ...(method === 'POST' ? { comment: 'pve-firewall-comment' } : {}) },
      confirmationWarnings: [{ message: 'Shared security groups affect existing cluster, node and guest references, including management traffic. Inspect dependencies before confirming.' },
        ...(method === 'DELETE' ? [{ message: 'GROUP DELETION: the provider permits only empty groups; remove guest references separately. Empty does not mean unreferenced.' }] : [])],
      reason: 'Confirmed creation or native empty-only security-group deletion. Comments use SecretRefs; rename, metadata-update and cross-scope reference rewrites remain refused.',
      reconciliation: { kind: 'none', reason: 'Inspect the group and references privately; never retry, detach references or recreate a group automatically after uncertainty.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned Groups.pm creation and Rules.pm empty-group deletion under the cluster lock.' }
  }
  const firewallObjects = /^(?:\/cluster|\/nodes\/\{node\}\/(?:qemu|lxc)\/\{vmid\})\/firewall\/(aliases|ipset)(?:\/\{name\})?(?:\/\{cidr\})?$/.exec(path)
  if (firewallObjects && operation.allowtoken !== 0 && ['create_alias', 'update_alias', 'remove_alias', 'create_ipset', 'delete_ipset', 'create_ip', 'update_ip', 'remove_ip'].includes(name ?? '')) {
    const alias = firewallObjects[1] === 'aliases', member = path.endsWith('/{cidr}') || name === 'create_ip'
    const guarded = (alias || member) && ['PUT', 'DELETE'].includes(method)
    const comment = method !== 'DELETE'
    return { effect: 'write', transport: 'json', secrets: 'private-result',
      allowedInputs: ['node', 'vmid', 'name', ...(alias || member ? ['cidr'] : []), ...(comment ? ['comment'] : []),
        ...(member && comment ? ['nomatch'] : []), ...(guarded ? ['digest'] : [])].filter(key => operation.parameters.properties?.[key]),
      requiredInputs: [...(guarded ? ['digest'] : []), ...(method === 'PUT' && member ? ['nomatch'] : [])],
      sensitiveInputs: comment ? ['comment'] : [],
      inputPatterns: { name: '^[a-z][a-z0-9_-]{1,63}$(?![\\s\\S])', ...(guarded ? { digest: '^[a-fA-F0-9]{40}$(?![\\s\\S])' } : {}) },
      inputFormats: { ...(alias || member ? { cidr: member ? 'pve-firewall-member' : 'pve-firewall-address' } : {}), ...(comment ? { comment: 'pve-firewall-comment' } : {}) },
      confirmationWarnings: [{ message: 'Firewall alias or IP-set changes can alter referencing rules, guest IP filtering and management access. Confirm the exact scope, name and literal CIDR.' },
        ...(method === 'DELETE' ? [{ message: 'DELETION: explicitly confirm the selected alias, member or empty set. Force deletion of nonempty sets is refused.' }] : []),
        ...(method === 'PUT' && member ? [{ message: 'MEMBER UPDATE replaces nomatch and comment; omitting comment clears it. Supply the existing comment through a SecretRef to preserve it.' }] : [])],
      reason: 'Confirmed named firewall objects and literal members only; native digests required where supported, empty-only set deletion, no rename/force/member-alias branches. Comments use SecretRefs and reads remain private.',
      reconciliation: { kind: 'none', reason: 'Inspect the selected scope privately; do not retry uncertain operations. Creation and empty-set deletion provide no native optimistic guard.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned schemas and reviewed Aliases.pm/IPSet.pm locks, digest guards, empty-set deletion and member replacement behavior.' }
  }
  const rulesPath = path.replace(/\/\{pos\}$/, '')
  const groupRules = rulesPath === '/cluster/firewall/groups/{group}', guestRules = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/firewall\/rules$/.test(rulesPath)
  const firewallRules = groupRules || rulesPath === '/cluster/firewall/rules' || /^\/nodes\/\{node\}(?:\/(qemu|lxc)\/\{vmid\})?\/firewall\/rules$/.test(rulesPath)
  if (firewallRules && operation.allowtoken !== 0 && ((method === 'POST' && path === rulesPath && name === 'create_rule') ||
    (method === 'PUT' && path !== rulesPath && name === 'update_rule') || (method === 'DELETE' && path !== rulesPath && name === 'delete_rule'))) {
    const fields = ['type', 'action', 'enable', 'source', 'dest', 'proto', 'sport', 'dport', ...(!groupRules ? ['iface'] : [])]
    const actions = '^(?:ACCEPT|DROP|REJECT)$(?![\\s\\S])'
    const selectors: InputCase[] = ['in', 'out'].map(type => ({ requiredValues: { type }, inputPatterns: { action: actions } }))
    selectors.push({ requiredValues: { type: 'group' }, forbiddenInputs: ['source', 'dest', 'proto', 'sport', 'dport'], inputPatterns: { action: namedFormatPattern('pve-firewall-group')! } })
    const edits: InputCase[] = guestRules ? [...selectors, { forbiddenInputs: ['type', 'action'] }, { requiredInputs: ['action'], forbiddenInputs: ['type'], inputPatterns: { action: actions } }] : [{}]
    const enableCases: InputCase[] = [{ forbiddenInputs: ['enable'] }, { requiredValues: { enable: 0 } }, { requiredValues: { enable: 1 } }]
    const inputCases = method === 'POST' ? guestRules ? selectors : undefined : method === 'PUT' ? [
      { requiredInputs: ['moveto'], forbiddenInputs: fields }, ...enableCases.flatMap(enable => edits.map(edit => ({ ...edit,
        requiredValues: { ...edit.requiredValues, ...enable.requiredValues }, forbiddenInputs: ['moveto', ...(edit.forbiddenInputs ?? []), ...(enable.forbiddenInputs ?? [])] }))),
    ] : undefined
    return { effect: 'write', transport: 'json', secrets: 'private-result', stateBinding: { kind: 'firewall-rules', path: rulesPath },
      allowedInputs: ['node', 'vmid', 'group', ...(method === 'POST' ? fields : ['pos', 'digest', ...(method === 'PUT' ? [...fields, 'moveto'] : [])])]
        .filter(key => operation.parameters.properties?.[key]), requiredInputs: path !== rulesPath ? ['pos'] : [],
      ...(method === 'POST' ? { fixedInputs: { enable: 0 } } : {}), ...(inputCases ? { inputCases } : {}),
      inputFormats: { group: 'pve-firewall-group', ...(method !== 'DELETE' ? {
        source: 'pve-firewall-address', dest: 'pve-firewall-address', proto: 'pve-firewall-protocol', sport: 'pve-firewall-port', dport: 'pve-firewall-port', iface: 'pve-firewall-interface',
      } : {}) },
      ...(method !== 'DELETE' ? { inputPatterns: { type: guestRules ? '^(?:in|out|group)$' : '^(?:in|out)$', ...(!guestRules ? { action: actions } : {}),
        ...(path.includes('/{vmid}/') ? { iface: '^net(?:[0-9]|[12][0-9]|3[01])$' } : {}) } } : {}),
      confirmationWarnings: [{ message: 'Firewall rule changes can cut off management access or change protection. Inspect the complete private ordered plan before confirming.' },
        ...(groupRules ? [{ message: 'SHARED GROUP: this ordered change affects every existing cluster, node or guest reference, including management traffic. Audit those dependencies explicitly.' }] : []),
        ...(method === 'POST' ? [{ message: 'NON-ATOMIC CREATE: the provider ignores creation digests and prepends this fixed disabled rule. Unexpected observed order remains uncertain; enabling requires a separate fresh digest-guarded confirmation.' }] :
          method === 'DELETE' ? [{ message: 'RULE DELETION: explicitly review the selected position and resulting ordered rules before confirming.' }] : [])],
      reason: method === 'POST' ? 'Non-atomic creation of a fixed disabled rule only: provider POST ignores digest and prepends; private before/after plan, state recheck and post-write comparison apply. Enable separately with a fresh digest-guarded confirmation.' :
        'Private state-bound ordered rule change with automatic provider digest guard; reorder is separate from field edits. No automatic retry or deletion after uncertainty.',
      reconciliation: { kind: 'none', reason: 'Inspect complete current rules privately; a matching later list cannot establish attribution. Never retry or automatically delete after uncertainty.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned rule schemas and reviewed provider Rules.pm creation, digest-guarded updates/deletes and reorder semantics.' }
  }
  const firewallOptions = path === '/cluster/firewall/options' || /^\/nodes\/\{node\}(?:\/(qemu|lxc)\/\{vmid\})?\/firewall\/options$/.test(path)
  if (method === 'PUT' && firewallOptions && name === 'set_options' && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none',
      allowedInputs: ['node', 'vmid', 'enable', 'policy_in', 'policy_out', 'policy_forward', 'digest'].filter(key => operation.parameters.properties?.[key]),
      ...(path === '/cluster/firewall/options' ? { inputCases: [
        { forbiddenInputs: ['enable'] }, { requiredValues: { enable: 0 } }, { requiredValues: { enable: 1 } },
      ] } : {}),
      confirmationWarnings: [
        { message: 'Firewall configuration changes can cut off management access. Review the exact target, settings and recovery access before confirming.' },
        { when: { input: 'enable', values: [false, 0] }, message: 'FIREWALL PROTECTION DISABLED: this request disables firewall protection at the selected scope.' },
        ...['policy_in', 'policy_out', 'policy_forward'].map(input => ({ when: { input, values: ['ACCEPT'] },
          message: `DEFAULT ACCEPT: ${input} will accept unmatched traffic at the selected scope. Explicitly authorize this default allowance.` })),
      ],
      reason: 'Confirmed firewall enable/default-policy configuration only; disabling protection and ACCEPT defaults are prominently disclosed. Backend, filter, delete and other selectors remain refused.',
      reconciliation: { kind: 'read', path, reason: 'Observe supplied firewall settings only; configuration equality does not establish effective filtering or management reachability.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned firewall get_options/set_options schemas and provider firewall documentation; shared exact confirmation and journal policy.' }
  }
  const guestExec = path === '/nodes/{node}/qemu/{vmid}/agent/exec' && method === 'POST' && name === 'exec'
  const guestExecStatus = path === '/nodes/{node}/qemu/{vmid}/agent/exec-status' && method === 'GET' && name === 'exec-status'
  if ((guestExec || guestExecStatus) && operation.allowtoken !== 0) return { effect: 'write', transport: 'json', secrets: 'private-result',
    allowedInputs: ['node', 'vmid', guestExec ? 'command' : 'pid'],
    ...(guestExec ? { sensitiveInputs: ['command'], inputFormats: { command: 'pve-guest-argv' } } : {}),
    reason: guestExec ? 'Confirmed guest execution using a SecretRef containing JSON argv; bounded private PID delivery, metadata-only journal, no stdin and no automatic retry.' :
      'Confirmed guest execution-status retrieval; completed queries reap the process record, so GET retains write grants and exact confirmation. Process output is private.',
    reconciliation: { kind: 'none', reason: 'Retain the private guest PID and execution result; status retrieval can consume completed output. Never repeat uncertain execution or retrieval automatically.' },
    privileges: operation.permissions, response: operation.returns, source: 'Pinned guest exec/status schemas, provider QEMU agent implementation and QEMU completed-process reaping contract.' }
  if (method === 'POST' && path === '/nodes/{node}/vzdump' && name === 'vzdump' && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none',
      allowedInputs: ['node', 'vmid', 'storage', 'mode', 'compress', 'bwlimit', 'protected', 'remove'], requiredInputs: ['node', 'vmid', 'storage'],
      fixedInputs: { remove: false }, inputFormats: { vmid: 'pve-backup-vmid-list' },
      reason: 'Confirmed backup of explicitly selected guests to managed storage; pruning is disabled and bulk selection, hooks and arbitrary paths remain refused.',
      reconciliation: { kind: 'none', reason: 'Track the returned backup UPID, then inspect backup content; never repeat uncertain backup creation automatically.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned vzdump schemas; explicit guest selection and no-pruning policy.' }
  }
  if (method === 'DELETE' && path === '/nodes/{node}/storage/{storage}/content/{volume}' && name === 'delete' && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none', allowedInputs: ['node', 'storage', 'volume'], requiredInputs: ['node', 'storage', 'volume'],
      inputFormats: { volume: 'pve-managed-volume' }, inputPatterns: { volume: backupVolumePattern() },
      reason: 'Confirmed deletion of one reviewed QEMU/LXC dump archive or PBS guest backup; other content and delayed/null-result variants remain refused.',
      reconciliation: { kind: 'none', reason: 'Track the returned deletion UPID; an absent or filtered inventory row never proves deletion, and uncertain deletion is never retried automatically.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned content-delete schemas; provider archive/PBS volume grammar and asynchronous deletion contract.' }
  }
  const snapshot = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/snapshot$/.test(path) && method === 'POST' && name === 'snapshot'
  const snapshotDelete = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/snapshot\/\{snapname\}$/.test(path) && method === 'DELETE' && name === 'delsnapshot'
  const rollback = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/snapshot\/\{snapname\}\/rollback$/.test(path) && method === 'POST' && name === 'rollback'
  if ((snapshot || snapshotDelete || rollback) && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none',
      allowedInputs: ['node', 'vmid', 'snapname', ...(snapshot ? ['description', ...(path.includes('/qemu/') ? ['vmstate'] : [])] : rollback ? ['start'] : [])],
      inputPatterns: { snapname: '^(?!current$)[A-Za-z][A-Za-z0-9._-]*$' },
      reason: 'Confirmed snapshot creation, deletion or rollback with exact guest/snapshot binding; force removal and the current pseudo-snapshot remain refused.',
      reconciliation: { kind: 'none', reason: 'Track the returned UPID and inspect the snapshot tree or protected configuration independently; never repeat uncertain snapshot mutations automatically.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned snapshot, delsnapshot and rollback schemas; existing effect, confirmation and task contracts.' }
  }
  if (method === 'POST' && path === '/nodes/{node}/aplinfo' && name === 'apl_download' && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none', allowedInputs: ['node', 'storage', 'template'],
      inputPatterns: { template: '^[A-Za-z0-9][A-Za-z0-9._-]*\\.tar\\.(?:zst|xz|gz)$' },
      reason: 'Confirmed installation of a provider-catalogue container template; URLs and arbitrary downloads remain refused.',
      reconciliation: { kind: 'none', reason: 'Track the returned download UPID and inspect storage content after success; never retry uncertain installation automatically.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned apl_download schemas and provider catalogue lookup; existing effect and task contracts.' }
  }
  const upload = path === '/nodes/{node}/storage/{storage}/upload' && method === 'POST'
  const transferRead = method === 'GET' && (/\/rrd$/.test(path) || ['/nodes/{node}/journal', '/nodes/{node}/qemu/{vmid}/agent/file-read', '/nodes/{node}/storage/{storage}/file-restore/download'].includes(path))
  const spice = method === 'POST' && /\/(spiceproxy|spiceshell)$/.test(path)
  if (upload || transferRead || spice) return { effect: transferRead ? 'read' : 'write', transport: 'managed', secrets: spice ? 'private-result' : 'none',
    reason: 'S5 operation-specific formatter and bounded private byte transport; ordinary output contains completion metadata only.',
    ...(upload ? { allowedInputs: ['node', 'storage', 'filename', 'content', 'checksum', 'checksum-algorithm'] } :
      spice && path.endsWith('/spiceshell') ? { allowedInputs: ['node'] } : {}),
    reconciliation: { kind: 'none', reason: 'Byte completion is distinct from provider task completion. Never repeat a partial transfer automatically.' },
    privileges: operation.permissions, response: operation.returns, source: 'Pinned API catalogues and S5 transport contracts.' }
  const protectedOperation = [
    'generate_token', 'update_token_info', 'add_tfa_entry', 'delete_tfa', 'update_tfa_entry',
    'change_password', 'cifsscan', 'pbsscan', 'upload_custom_cert', 'vncproxy', 'termproxy', 'mtunnel', 'vncshell',
  ].includes(name ?? '')
  if (protectedOperation) {
    const sensitiveInputs = Object.keys(operation.parameters.properties ?? {}).filter(key =>
      ['password', 'confirmation-password', 'key', 'value', 'totp', 'challenge'].includes(key))
    return { effect: 'write', transport: 'json', secrets: ['generate_token', 'update_token_info', 'add_tfa_entry', 'vncproxy', 'termproxy', 'mtunnel', 'vncshell'].includes(name!) ? 'private-result' : 'input-refs',
      ...(['termproxy', 'vncshell'].includes(name!) && /^\/nodes\/\{node\}\/[^/]+$/.test(path) ? { allowedInputs: name === 'vncshell' ? ['node', 'websocket'] : ['node'] } : {}),
      sensitiveInputs, reason: 'Explicitly authorized credential and sensitive-input operation; shared preview and confirmation controls apply, including effectful scans.',
      reconciliation: { kind: 'none', reason: 'Never recreate a one-time credential to determine delivery or outcome.' },
      privileges: operation.permissions, response: operation.returns, source: 'Retained versioned API schema and S4 protected credential contract.' }
  }
  const guest = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}$/.test(path)
  const lifecyclePath = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/status\/(start|stop|shutdown|reboot|reset|resume|suspend)$/.test(path)
  const config = /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/config$/.test(path)
  const create = method === 'POST' && /^\/nodes\/\{node\}\/(qemu|lxc)$/.test(path) && name === 'create_vm'
  const qemu = path === '/nodes/{node}/qemu' || path.includes('/qemu/')
  if (method === 'POST' && /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/clone$/.test(path) && name === 'clone_vm' && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none',
      allowedInputs: ['node', 'vmid', 'newid', 'description', 'full', 'storage', 'target', 'pool', 'bwlimit', ...(qemu ? ['name', 'format'] : ['hostname'])],
      reason: 'Confirmed guest clone with reviewed destination and storage settings; snapshot-source variants remain refused.',
      reconciliation: { kind: 'none', reason: 'Track the source-node UPID, then inspect the destination guest independently; never clone again after uncertain delivery.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned clone_vm schemas; existing effect and task contracts.' }
  }
  if (method === 'PUT' && path === '/nodes/{node}/qemu/{vmid}/cloudinit' && name === 'cloudinit_update' && operation.allowtoken !== 0) {
    return { effect: 'write', transport: 'json', secrets: 'none', allowedInputs: ['node', 'vmid'],
      reason: 'Confirmed regeneration of managed cloud-init media after reviewed configuration changes.',
      reconciliation: { kind: 'none', reason: 'Inspect private current/pending cloud-init values independently; never regenerate automatically after uncertain delivery.' },
      privileges: operation.permissions, response: operation.returns, source: 'Pinned cloudinit_update schemas; synchronous null response.' }
  }
  const resize = method === 'PUT' && /^\/nodes\/\{node\}\/(qemu|lxc)\/\{vmid\}\/resize$/.test(path) && name === 'resize_vm'
  if (resize && operation.allowtoken !== 0) return { effect: 'write', transport: 'json', secrets: 'none',
    allowedInputs: ['node', 'vmid', 'disk', 'size', 'digest'],
    inputPatterns: { size: '^\\+(?:[1-9][0-9]*(?:\\.[0-9]+)?|0\\.[0-9]*[1-9][0-9]*)[KMGT]$',
      ...(path.includes('/qemu/') ? { disk: '^(?:ide[0-3]|sata[0-5]|scsi(?:[0-9]|[12][0-9]|30)|virtio(?:[0-9]|1[0-5]))$' } : {}) },
    reason: 'Confirmed positive relative disk growth only; absolute sizes, shrink and lock bypass remain refused.',
    reconciliation: { kind: 'none', reason: 'Track the returned UPID; never repeat relative growth after uncertain delivery.' },
    privileges: operation.permissions, response: operation.returns, source: 'Pinned vendor resize schemas; supported growth only.' }
  const batch = path === '/nodes/{node}/execute' && method === 'POST' && name === 'execute'
  const cancel = path === '/nodes/{node}/tasks/{upid}' && method === 'DELETE' && name === 'stop_task'
  const admitted = operation.allowtoken !== 0 && (
    (method === 'POST' && lifecyclePath && lifecycle.has(name ?? '')) ||
    (method === 'DELETE' && guest && ['destroy_vm', 'destroy'].includes(name ?? '')) ||
    (method === 'PUT' && config && name === 'update_vm') ||
    (['/pools', '/pools/{poolid}'].includes(path) && pool.has(name ?? '') && ['POST', 'PUT', 'DELETE'].includes(method)) ||
    create || batch || cancel)
  if (!admitted) return undefined
  // Configuration has credentials, hardware passthrough and executable hooks.
  // Compute settings admit scalar values and narrowly reviewed property strings only.
  const disks = qemu ? [['ide', 4], ['sata', 6], ['scsi', 31], ['virtio', 16]] as const : [['mp', 256]] as const
  const slots = disks.flatMap(([prefix, count]) => Array.from({ length: count }, (_, index) => `${prefix}${index}`))
  const networkSlots = Array.from({ length: 32 }, (_, index) => `net${index}`)
  const ipconfigSlots = Array.from({ length: 32 }, (_, index) => `ipconfig${index}`)
  const removableSlots = [...slots, ...networkSlots]
  const settings = config || create
  const allowedInputs = settings ? ['node', 'vmid', 'description', 'name', 'hostname', 'memory', 'cores', 'sockets', 'vcpus', 'balloon', 'swap', 'cpu', 'cpulimit', 'cpuunits', 'onboot', 'startup', 'digest', 'cipassword', 'password'] :
    lifecyclePath ? ['node', 'vmid', 'timeout', 'forceStop', 'keepActive', 'skiplock', 'todisk'] :
    guest ? ['node', 'vmid', 'purge', 'destroy-unreferenced-disks', 'force'] : undefined
  const settingInputs = settings ? [...allowedInputs!, ...slots, ...networkSlots, 'nameserver', 'searchdomain',
    ...(qemu ? ['boot', 'agent', 'ciuser', 'sshkeys', ...ipconfigSlots] : ['rootfs'])] : []
  return { effect: batch ? 'batch' : 'write', transport: 'json', secrets: settings ? 'input-refs' : 'none',
    reason: batch ? 'Vendor execute resolves each ordered node-relative child and reports per-child status; no atomicity.' :
      cancel ? 'Stop an existing UPID; cancellation is a separately confirmed mutation.' :
      create ? 'Confirmed guest creation or fresh-ID restore from a reviewed backup to explicit managed storage; LXC stays unprivileged, and force, live restore, host paths and unreviewed host features remain refused.' :
      config ? 'Reviewed compute, managed disks, guest networking, boot/agent and cloud-init onboarding; numbered slots/removal selectors are explicit, host passthrough remains refused, and credentials require SecretRefs.' :
      lifecyclePath ? 'Guest power-state operation, asynchronous UPID acceptance does not prove completion.' :
      guest ? 'Destroy guest; absence or filtered inventory cannot prove the outcome.' : 'Pool configuration and membership mutation; no automatic retry.',
    allowedInputs: config ? [...settingInputs, 'delete'] : create ? qemu ?
      [...settingInputs.filter(name => !['hostname', 'swap', 'digest', 'password'].includes(name)), 'bios', 'scsihw', 'ostype', 'pool', 'start', 'archive', 'storage', 'bwlimit', 'unique'] :
      [...settingInputs.filter(name => !['name', 'sockets', 'vcpus', 'balloon', 'cpu', 'cipassword', 'digest'].includes(name)), 'ostemplate', 'storage', 'unprivileged', 'ssh-public-keys', 'pool', 'start', 'restore', 'bwlimit', 'unique'] : allowedInputs,
    ...(create ? { inputCases: qemu ? [
      { forbiddenInputs: ['archive', 'storage', 'bwlimit', 'unique'] }, { requiredInputs: ['archive', 'storage'], forbiddenInputs: slots },
    ] : [
      { forbiddenInputs: ['restore', 'bwlimit', 'unique'], inputPatterns: { ostemplate: '^[A-Za-z][A-Za-z0-9._-]*:vztmpl/[A-Za-z0-9][A-Za-z0-9._-]*\\.tar\\.(?:zst|xz|gz)$' } },
      { requiredInputs: ['storage'], requiredValues: { restore: true }, inputPatterns: { ostemplate: backupVolumePattern('lxc') } },
    ] } : {}),
    ...(create && !qemu ? { fixedInputs: { unprivileged: true }, inputFormats: { 'ssh-public-keys': 'openssh-public-keys', ostemplate: 'pve-managed-volume' } } : {}),
    ...(settings ? { inputPatterns: { ...(config ? { delete: `^(?:${removableSlots.join('|')})(?:,(?:${removableSlots.join('|')}))*$` } : {}),
      searchdomain: namedFormatPattern('dns-name-list')!, ...(qemu ? { ciuser: '^[a-z_][a-z0-9_-]{0,31}$', sshkeys: cloudInitSshKeysPattern,
        boot: `^order=(?:${removableSlots.join('|')})(?:;(?:${removableSlots.join('|')}))*$`, ...(create ? { archive: backupVolumePattern('qemu') } : {}) } : {}) } } : {}),
    sensitiveInputs: create ? [qemu ? 'cipassword' : 'password'] : config ? ['cipassword', 'password'] : [],
    reconciliation: config ? { kind: 'read', path, reason: 'Direct configuration observation may confirm supplied fields; missing fields never prove failure.' } :
      lifecyclePath ? { kind: 'read', path: path.replace(/\/status\/[^/]+$/, '/status/current'), reason: 'Direct guest status observation; only requested stable start/stop states can be confirmed.' } :
        { kind: 'none', reason: 'No safe automated business-outcome proof is admitted for this variant. Use the retained UPID when available; otherwise retain uncertainty and inspect independently.' },
    privileges: operation.permissions, response: operation.returns, source: 'Retained versioned API schema; design.md S3 write/outcome contract; pve-node-batch-source.txt for execute.' }
}

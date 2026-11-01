// These names and paths identify reviewed vendor operations, not method-based admission.
// The generated table retains every other route with an explicit refusal.
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
  const upload = path === '/nodes/{node}/storage/{storage}/upload' && method === 'POST'
  const transferRead = method === 'GET' && (/\/rrd$/.test(path) || ['/nodes/{node}/journal', '/nodes/{node}/qemu/{vmid}/agent/file-read', '/nodes/{node}/storage/{storage}/file-restore/download'].includes(path))
  const spice = method === 'POST' && /\/(spiceproxy|spiceshell)$/.test(path)
  if (method === 'POST' && path === '/nodes/{node}/storage/{storage}/download-url') return {
    effect: 'write', transport: 'json', secrets: 'none', allowedInputs: ['node', 'storage', 'content', 'filename', 'url', 'checksum', 'checksum-algorithm', 'verify-certificates'],
    reason: 'Confirmed provider-side download from the selected approved HTTPS origin; compression and disabled trust are refused.',
    reconciliation: { kind: 'none', reason: 'Follow the accepted UPID; never repeat a provider-side download after a lost response.' },
    privileges: operation.permissions, response: operation.returns, source: 'Pinned storage download-url schema and S5 reviewed target restrictions.' }
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
  const batch = path === '/nodes/{node}/execute' && method === 'POST' && name === 'execute'
  const cancel = path === '/nodes/{node}/tasks/{upid}' && method === 'DELETE' && name === 'stop_task'
  const admitted = operation.allowtoken !== 0 && (
    (method === 'POST' && lifecyclePath && lifecycle.has(name ?? '')) ||
    (method === 'DELETE' && guest && ['destroy_vm', 'destroy'].includes(name ?? '')) ||
    (method === 'PUT' && config && name === 'update_vm') ||
    (['/pools', '/pools/{poolid}'].includes(path) && pool.has(name ?? '') && ['POST', 'PUT', 'DELETE'].includes(method)) ||
    batch || cancel)
  if (!admitted) return undefined
  // Configuration has credentials, hardware passthrough and executable hooks.
  // Only these ordinary scalar branches have been positively reviewed for S3.
  const allowedInputs = config ? ['node', 'vmid', 'description', 'name', 'hostname', 'memory', 'cores', 'onboot', 'digest', 'cipassword', 'password'] :
    lifecyclePath ? ['node', 'vmid', 'timeout', 'forceStop', 'keepActive', 'skiplock', 'todisk'] :
    guest ? ['node', 'vmid', 'purge', 'destroy-unreferenced-disks', 'force'] : undefined
  return { effect: batch ? 'batch' : 'write', transport: 'json', secrets: config ? 'input-refs' : 'none',
    reason: batch ? 'Vendor execute resolves each ordered node-relative child and reports per-child status; no atomicity.' :
      cancel ? 'Stop an existing UPID; cancellation is a separately confirmed mutation.' :
      config ? 'Reviewed scalar configuration branches only; credential fields require SecretRefs. Other supplied branches stay refused.' :
      lifecyclePath ? 'Guest power-state operation, asynchronous UPID acceptance does not prove completion.' :
      guest ? 'Destroy guest; absence or filtered inventory cannot prove the outcome.' : 'Pool configuration and membership mutation; no automatic retry.',
    allowedInputs, sensitiveInputs: config ? ['cipassword', 'password'] : [],
    reconciliation: config ? { kind: 'read', path, reason: 'Direct configuration observation may confirm supplied fields; missing fields never prove failure.' } :
      lifecyclePath ? { kind: 'read', path: path.replace(/\/status\/[^/]+$/, '/status/current'), reason: 'Direct guest status observation; only requested stable start/stop states can be confirmed.' } :
        { kind: 'none', reason: 'No safe automated business-outcome proof is admitted for this variant. Use the retained UPID when available; otherwise retain uncertainty and inspect independently.' },
    privileges: operation.permissions, response: operation.returns, source: 'Retained versioned API schema; design.md S3 write/outcome contract; pve-node-batch-source.txt for execute.' }
}

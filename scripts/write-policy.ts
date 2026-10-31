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

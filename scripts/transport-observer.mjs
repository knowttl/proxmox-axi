import { subscribe } from 'node:diagnostics_channel'
import { appendFileSync } from 'node:fs'

// Observe the real client without replacing request, socket or TLS behavior.
function record(error, phase) {
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(error.code) ? error.code : 'UNKNOWN'
  appendFileSync(process.env.PROXMOX_AXI_TEST_DIAGNOSTICS, `${JSON.stringify({ code, phase, elapsedMs: Math.round(performance.now()) })}\n`)
}
subscribe('http.client.request.error', ({ error }) => record(error, 'http'))
subscribe('net.client.socket', ({ socket }) => socket.once('error', error => record(error, 'socket')))

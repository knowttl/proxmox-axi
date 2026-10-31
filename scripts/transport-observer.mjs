import { subscribe } from 'node:diagnostics_channel'
import { appendFileSync } from 'node:fs'

// Observe the real client without replacing request, socket or TLS behavior.
subscribe('http.client.request.error', ({ error }) => {
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(error.code) ? error.code : 'UNKNOWN'
  appendFileSync(process.env.PROXMOX_AXI_TEST_DIAGNOSTICS, `${JSON.stringify({ code, elapsedMs: Math.round(performance.now()) })}\n`)
})

import type { Socket } from 'node:net'
import { subscribe } from 'node:diagnostics_channel'
import { appendFileSync } from 'node:fs'

// Observe the real client without replacing request, socket or TLS behavior.
function record(error: NodeJS.ErrnoException | undefined, phase: string) {
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(error.code) ? error.code : 'UNKNOWN'
  appendFileSync(process.env.PROXMOX_AXI_TEST_DIAGNOSTICS!, `${JSON.stringify({ code, phase, elapsedMs: Math.round(performance.now()) })}\n`)
}
subscribe('http.client.request.error', message => record((message as { error: NodeJS.ErrnoException }).error, 'http'))
subscribe('net.client.socket', message => {
  const { socket } = message as { socket: Socket }
  const started = performance.now()
  socket.once('error', error => record(error, 'socket'))
  socket.once('close', () => appendFileSync(process.env.PROXMOX_AXI_TEST_DIAGNOSTICS!,
    `${JSON.stringify({ phase: 'socket-close', durationMs: Math.round(performance.now() - started) })}\n`))
})

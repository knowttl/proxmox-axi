import assert from 'node:assert/strict'

// The socket is observed in the actual CLI process. Startup and parent-process
// scheduling are excluded; TLS connection and the entire trickled body count.
export function assertRequestDeadline(events: { phase: string, durationMs?: number }[]): number {
  const sockets = events.filter(event => event.phase === 'socket-close')
  assert.equal(sockets.length, 1, 'Trickle deadline requires one completed client transport')
  const duration = sockets[0]!.durationMs
  assert.ok(duration !== undefined && Number.isFinite(duration) && duration >= 0 && duration < 6500,
    `Trickle exceeded the five-second request deadline plus measurement tolerance: ${duration} ms`)
  return duration
}

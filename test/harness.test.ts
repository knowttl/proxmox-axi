import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import test from 'node:test'
import { observePackaged } from '../scripts/packaged-process.ts'
import { assertRequestDeadline } from '../scripts/request-deadline.ts'

const syntheticChild = () => observePackaged(spawn(process.execPath, ['--input-type=module', '-e', `
  console.log(JSON.stringify({ ready: true }));
  process.on('message', () => console.log(JSON.stringify({ status: 'ready' })));
`], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'] }), { caseId: 'harness-ready', session: true })

test('expired response readers cannot consume the next packaged response (issue 63)', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const running = syntheticChild()
  try {
    assert.deepEqual(await running.lines.next(), { ready: true })
    running.begin('harness-missing')
    const missing = assert.rejects(running.lines.next(), /harness-missing: public response: response deadline exceeded; child=running/)
    t.mock.timers.tick(10_000)
    await missing
    running.begin('harness-next')
    running.child.send!('respond')
    assert.deepEqual(await running.lines.next(), { status: 'ready' })
  } finally { running.child.kill('SIGKILL'); await running.closed.catch(() => {}); t.mock.timers.reset() }
})

test('persistent packaged sessions rearm the command watchdog and report expiry (issue 63)', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const running = syntheticChild()
  try {
    await running.lines.next()
    running.begin('harness-first')
    t.mock.timers.tick(59_000)
    running.begin('harness-second')
    t.mock.timers.tick(59_000)
    running.child.send!('respond')
    assert.deepEqual(await running.lines.next(), { status: 'ready' })
    const closed = assert.rejects(running.closed, /harness-second: process: command watchdog exceeded; child=closed exit=none signal=SIGKILL/)
    const missing = assert.rejects(running.lines.next(), /harness-second: public response: command watchdog exceeded; child=watchdog expired/)
    t.mock.timers.tick(1000)
    await Promise.all([missing, closed])
  } finally { running.child.kill('SIGKILL'); await running.closed.catch(() => {}); t.mock.timers.reset() }
})

test('child closure ends missing private reads without exposing captured payloads (issue 63)', async () => {
  const running = observePackaged(spawn(process.execPath, ['--input-type=module', '-e', `
    console.log('CANARY-private-output'); console.error('CANARY-private-error');
  `], { stdio: ['pipe', 'pipe', 'pipe', 'pipe'] }), { caseId: 'harness-closed', privateFrames: true })
  const missing = assert.rejects(running.frames.next(), error => {
    assert.equal((error as Error).message, 'harness-closed: private frame: child closed before response; child=closed exit=0 signal=none')
    return true
  })
  assert.equal((await running.closed).code, 0)
  await missing
})

test('trickle measurement excludes startup but rejects a request beyond its deadline (issue 60)', () => {
  assert.equal(assertRequestDeadline([{ phase: 'socket', durationMs: 80_000 }, { phase: 'socket-close', durationMs: 5003 }]), 5003)
  assert.throws(() => assertRequestDeadline([{ phase: 'socket-close', durationMs: 7000 }]), /Trickle exceeded/)
  assert.throws(() => assertRequestDeadline([]), /one completed client transport/)
})

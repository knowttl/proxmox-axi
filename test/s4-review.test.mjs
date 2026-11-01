import assert from 'node:assert/strict'
import { spawn, execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { mkdtemp, open, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { exerciseSecretJourney } from '../scripts/secret-journey.ts'

const execute = promisify(execFile)
const root = new URL('../', import.meta.url)
const binding = { origin: 'https://pve.test', identity: 'test@pve', operation: 'test', request: 'test', actor: 'test', credentialRevision: 'test' }
const delivery = `import { PrivateResults } from './dist/private-results.js';
  const results = new PrivateResults();
  try { await results.deliver(${JSON.stringify(binding)}, 'x'.repeat(60000)); console.log('delivered') }
  catch (error) { console.log(error.code); process.exitCode = 1 }`

function collect(child) {
  let stdout = '', stderr = ''
  child.stdout.on('data', chunk => { stdout += chunk })
  child.stderr.on('data', chunk => { stderr += chunk })
  return new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }))
  })
}

for (const fd of [1, 2]) test(`private results refuse a descriptor duplicated from public fd ${fd}`, { skip: process.platform === 'win32' }, async () => {
  const child = spawn('sh', ['-c', `exec 3>&${fd}; exec "$@"`, 'private-result-test', process.execPath, '--input-type=module', '-e', delivery],
    { cwd: root, env: { ...process.env, PROXMOX_AXI_RESULT_FD: '3' }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 })
  const result = await collect(child)
  assert.equal(result.code, 1, result.stderr)
  assert.equal(result.stdout, 'DELIVERY_UNCERTAIN\n')
  assert.equal(result.stderr, '')
})

test('a blocking FIFO with an idle reader fails delivery within its deadline', { skip: process.platform === 'win32' }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'proxmox-result-'))
  let pipe
  try {
    const path = join(directory, 'result.pipe')
    await execute('mkfifo', [path])
    pipe = await open(path, constants.O_RDWR)
    const child = spawn(process.execPath, ['--input-type=module', '-e', delivery], { cwd: root,
      env: { ...process.env, PROXMOX_AXI_RESULT_FD: '3' }, stdio: ['ignore', 'pipe', 'pipe', pipe.fd], timeout: 10000 })
    const result = await collect(child)
    assert.equal(result.signal, null)
    assert.equal(result.code, 1, result.stderr)
    assert.equal(result.stdout, 'DELIVERY_UNCERTAIN\n')
  } finally { await pipe?.close(); await rm(directory, { recursive: true, force: true }) }
})

test('buffered session commands stop dispatching at the process deadline', async () => {
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import { main } from './dist/cli.js';
    let now = 0;
    Object.defineProperty(globalThis, 'performance', { value: { now: () => now } });
    const output = console.log;
    console.log = (...args) => { output(...args); now = 300001 };
    await main(['auth', 'session']);
  `], { cwd: root, stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000 })
  const result = collect(child)
  child.stdin.end(`${JSON.stringify(['config', 'path', '--format', 'json'])}\n`.repeat(3))
  const output = await result
  assert.equal(output.code, 1, output.stderr)
  const lines = output.stdout.trim().split('\n')
  assert.equal(lines.filter(line => line.startsWith('{"path":')).length, 1)
  assert.match(output.stdout, /AUTH_SESSION_INVALID/)
})

test('the process lifetime terminates an active session request', async () => {
  const server = createServer()
  const sockets = new Set()
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)) })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    const child = spawn(process.execPath, ['--input-type=module', '-e', `
      import { main } from './dist/cli.js';
      const timer = globalThis.setTimeout;
      globalThis.setTimeout = (callback, ms, ...args) => timer(callback, ms === 300000 ? 100 : ms, ...args);
      await main(['auth', 'session']);
    `], { cwd: root, env: { ...process.env, PROXMOX_AXI_PROFILE: '', PROXMOX_AXI_AUTH: 'api-token',
      PROXMOX_AXI_ORIGIN: `https://127.0.0.1:${server.address().port}`, PROXMOX_AXI_TOKEN_ID: 'test@pve!test', PROXMOX_AXI_TOKEN: 'synthetic-token' },
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 2000 })
    const result = collect(child)
    child.stdin.end(`${JSON.stringify(['get', '/version', '--format', 'json'])}\n`)
    const output = await result
    assert.equal(output.signal, null)
    assert.equal(output.code, 1, output.stderr)
    assert.match(output.stdout, /AUTH_SESSION_INVALID/)
    assert.doesNotMatch(output.stdout, /TIMEOUT|CONNECTION_FAILED/)
  } finally {
    for (const socket of sockets) socket.destroy()
    await new Promise(resolve => server.close(resolve))
  }
})

test('S4 secret and session journeys preserve custody and authenticated workflows', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-s4-review-'))
  try {
    const caFile = join(scratch, 'server.crt')
    await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(scratch, 'server.key'), '-out', caFile])
    await exerciseSecretJourney({ task: 'S4.2', scratch, out: scratch, caFile,
      executable: new URL('../bin/proxmox-axi.mjs', import.meta.url).pathname,
      env: { ...process.env, PROXMOX_AXI_TOKEN: 'synthetic-api-token' }, cases: [], ledger: [], transcripts: [] })
  } finally { await rm(scratch, { recursive: true, force: true }) }
})

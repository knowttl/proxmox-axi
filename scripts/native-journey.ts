import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:https'
import { lstat, mkdir, readFile, symlink } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'

interface Result { code: number | null, stdout: string, stderr: string }
interface Journey {
  scratch: string
  installed: string
  executable: string
  caFile: string
  env: Record<string, string>
  command: (executable: string, args: string[], options: { env: Record<string, string> }) => Promise<Result>
  cases: Record<string, unknown>[]
}

export async function exerciseNativeJourney(options: Journey): Promise<void> {
  assert.equal(process.platform, 'linux', 'This gate requires actual native Linux')
  const home = join(options.scratch, 'native-home')
  await mkdir(home, { mode: 0o700 })
  const { replacePrivateFile, readPrivateFile } = await import(pathToFileURL(join(options.installed, 'dist/private-file.js')).href) as typeof import('../src/private-file.js')
  const environment: Record<string, string> = { ...options.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config'), XDG_STATE_HOME: join(home, 'state') }
  delete environment.PROXMOX_AXI_CONFIG
  delete environment.PROXMOX_AXI_WRITE_LOG
  const route = '/nodes/{node}/qemu/{vmid}/config'
  const operation = `OP-PUT-${createHash('sha256').update(`PUT ${route}`).digest('hex').slice(0, 10)}`
  const requests: { method: string, path: string, authorization: string | undefined, body: string }[] = []
  const server = createServer({ key: await readFile(join(options.scratch, 'server.key')), cert: await readFile(options.caFile) }, (request, reply) => {
    const chunks: Buffer[] = []
    request.on('data', chunk => chunks.push(Buffer.from(chunk)))
    request.on('end', () => {
      requests.push({ method: request.method!, path: request.url!, authorization: request.headers.authorization, body: Buffer.concat(chunks).toString() })
      const version = request.method === 'GET' && request.url === '/api2/json/nodes/pve-test/version'
      const write = request.method === 'PUT' && request.url === '/api2/json/nodes/pve-test/qemu/100/config'
      reply.writeHead(version || write ? 200 : 404, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ data: version ? { version: '8.2.7', release: '8.2', repoid: '3e0176e6bb2ade3b' } : null }))
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  const origin = `https://127.0.0.1:${address.port}`
  try {
    for (const [id, overrides, expected, state] of [
      ['xdg', {}, join(home, 'config/proxmox-axi/config.json'), join(home, 'state/proxmox-axi/writes.log')],
      ['home', { XDG_CONFIG_HOME: '', XDG_STATE_HOME: '' }, join(home, '.config/proxmox-axi/config.json'), join(home, '.local/state/proxmox-axi/writes.log')],
      ['relative-xdg', { XDG_CONFIG_HOME: 'relative', XDG_STATE_HOME: 'relative' }, join(home, '.config/proxmox-axi/config.json'), join(home, '.local/state/proxmox-axi/writes.log')],
    ] as const) {
      const env: Record<string, string> = { ...environment, ...overrides, PROXMOX_AXI_PROFILE: 'native' }
      if (id === 'home') {
        delete env.XDG_CONFIG_HOME
        delete env.XDG_STATE_HOME
      }
      const result = await options.command(process.execPath, [options.executable, 'config', 'path', '--format', 'json'],
        { env })
      assert.equal(result.code, 0, result.stdout)
      assert.equal(result.stderr, '')
      assert.equal((JSON.parse(result.stdout) as { path: string }).path, expected)
      await replacePrivateFile(expected, JSON.stringify({ version: 1, defaultProfile: 'native', profiles: {
        native: { auth: 'api-token', origin, tokenId: 'synthetic@pve!acceptance', token: { env: 'PROXMOX_AXI_TOKEN' },
          caBundle: options.caFile, writes: { operations: [operation] } },
      } }))
      const invoke = async (args: string[]) => {
        const result = await options.command(process.execPath, [options.executable, ...args, '--format', 'json'], { env })
        assert.equal(result.code, 0, result.stdout + result.stderr)
        assert.equal(result.stderr, '')
        return JSON.parse(result.stdout)
      }
      const args = ['set', route, '--api-node', 'pve-test', '--api-vmid', '100', '--api-cores', '2']
      requests.length = 0
      const preview = await invoke([...args, '--preview'])
      assert.equal(preview.status, 'preview')
      assert.ok(requests.every(request => request.method === 'GET'))
      const record = join(`${state}.d`, `${preview.id}.json`)
      assert.equal(JSON.parse(await readFile(record, 'utf8')).status, 'preview')
      const reopened = await invoke(['journal', 'show', preview.id])
      assert.equal(reopened.journal.id, preview.id)
      assert.equal(reopened.journal.status, 'preview')
      const executed = await invoke([...args, '--confirm', preview.confirmation])
      assert.equal(executed.status, 'success')
      const restarted = await invoke(['journal', 'show', preview.id])
      assert.equal(restarted.journal.status, 'success')
      assert.equal(JSON.parse(await readFile(record, 'utf8')).status, 'success')
      assert.deepEqual(requests.filter(request => request.method !== 'GET').map(request => ({
        method: request.method, path: request.path, args: Object.fromEntries(new URLSearchParams(request.body)),
      })), [{ method: 'PUT', path: '/api2/json/nodes/pve-test/qemu/100/config', args: { cores: '2' } }])
      assert.ok(requests.every(request => request.authorization === `PVEAPIToken=synthetic@pve!acceptance=${env.PROXMOX_AXI_TOKEN}`))
      for (const [target, mode] of [[dirname(expected), 0o700], [expected, 0o600],
        [dirname(state), 0o700], [`${state}.d`, 0o700], [join(`${state}.d`, 'binding.key'), 0o600],
        [join(`${state}.d`, `${preview.id}.claim`), 0o600], [record, 0o600]] as const) {
        const info = await lstat(target)
        assert.equal(info.isSymbolicLink(), false)
        assert.equal(info.uid, process.getuid!())
        assert.equal(info.mode & 0o777, mode)
      }
      options.cases.push({ id: `standalone/CRED-08/${id}`, status: 'pass', path: expected, journal: record, restart: 'success' })
    }
  } finally { await new Promise<void>(resolve => server.close(() => resolve())) }
  const path = join(home, 'private/config.json')
  await replacePrivateFile(path, 'old-complete-state')
  // An open reader must retain the previous inode across atomic publication.
  const { open } = await import('node:fs/promises')
  const reader = await open(path, 'r')
  try {
    await replacePrivateFile(path, 'new-complete-state')
    assert.equal(await reader.readFile('utf8'), 'old-complete-state')
    assert.equal(await readPrivateFile(path, true), 'new-complete-state')
  } finally { await reader.close() }
  for (const [target, mode] of [[home, 0o700], [join(home, 'private'), 0o700], [path, 0o600]] as const) {
    const info = await lstat(target)
    assert.equal(info.uid, process.getuid!())
    assert.equal(info.mode & 0o777, mode)
  }
  const link = join(home, 'linked')
  await symlink(path, link)
  await assert.rejects(readPrivateFile(link, true), { code: 'CONFIG_INSECURE' })
  const directoryLink = join(home, 'linked-directory')
  await symlink(join(home, 'private'), directoryLink)
  await assert.rejects(replacePrivateFile(join(directoryLink, 'config.json'), 'replacement'), { code: 'CONFIG_INSECURE' })
  assert.equal(await readFile(path, 'utf8'), 'new-complete-state')
  options.cases.push({ id: 'standalone/CRED-08/private-mode-and-owner', status: 'pass' },
    { id: 'standalone/CRED-09/native-symlink', status: 'pass' },
    { id: 'standalone/CRED-10/native-atomic-replacement', status: 'pass' })
}

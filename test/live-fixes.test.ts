import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { exerciseWriteJourney } from '../scripts/write-journey.js'
import { exerciseStreamJourney } from '../scripts/stream-journey.js'

const execute = promisify(execFile)
const root = new URL('../../', import.meta.url)
const environment: Record<string, string> = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] =>
  entry[1] !== undefined && !entry[0].startsWith('PROXMOX_AXI_')))

test('live response regressions through offline public commands', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-live-fixes-'))
  const caFile = join(scratch, 'server.crt')
  try {
    await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(scratch, 'server.key'), '-out', caFile])
    await chmod(caFile, 0o600)
    const options = { scratch, out: scratch, caFile, executable: new URL('bin/proxmox-axi.mjs', root).pathname,
      env: { ...environment, PROXMOX_AXI_TOKEN: 'synthetic-api-token' }, cases: [], ledger: [], transcripts: [] }
    await t.test('confirmed write refusals preserve hints and descendant outcomes', async () => {
      await exerciseWriteJourney({ ...options, command: async (executable, args, { env }) => {
        try { return { code: 0, ...await execute(executable, args, { env }) } }
        catch (error) {
          const result = error as { code: number, stdout: string, stderr: string }
          return { code: result.code, stdout: result.stdout, stderr: result.stderr }
        }
      } })
    })
    await t.test('managed transports preserve refusal diagnostics and session targets', async () => {
      await exerciseStreamJourney({ ...options, task: 'S5.2' })
    })
    await t.test('inventory fields use the detected target catalogue', async () => {
      let requests = 0
      let data: unknown[] = []
      const server = createServer({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) }, (request, response) => {
        requests++
        response.end(JSON.stringify({ data: request.url!.endsWith('/version') ? { version: '9.2.0', release: '9.2', repoid: 'synthetic' } :
          request.url!.endsWith('/permissions') ? {} : data }))
      })
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      const address = server.address() as import('node:net').AddressInfo
      const env = { ...environment, PROXMOX_AXI_ORIGIN: `https://127.0.0.1:${address.port}`, PROXMOX_AXI_TOKEN_ID: 'synthetic@pve!test',
        PROXMOX_AXI_TOKEN: 'synthetic-token', PROXMOX_AXI_CA_BUNDLE: caFile }
      try {
        for (const [path, field, item] of [
          ['/cluster/resources', 'memhost', { id: 'qemu/100', type: 'qemu', memhost: 123 }],
          ['/nodes/{node}/qemu', 'memhost', { vmid: 100, status: 'running', memhost: 123 }],
          ['/nodes/{node}/lxc', 'pressurecpusome', { vmid: 100, status: 'running', pressurecpusome: 0 }],
          ['/nodes/{node}/storage', 'formats', { storage: 'local', type: 'dir', content: 'iso', formats: { default: 'raw', supported: ['raw'] } }],
        ] as const) {
          data = [item]
          requests = 0
          const args = ['get', path, ...(path.includes('{node}') ? ['--api-node', 'pve-test'] : []), '--fields', field, '--format', 'json']
          const result = await execute(process.execPath, [options.executable, ...args], { env })
          assert.deepEqual(JSON.parse(result.stdout).data, [{ [field]: item[field as keyof typeof item] }])
          assert.equal(requests, path.includes('{node}') ? 4 : 3)
          requests = 0
          await assert.rejects(execute(process.execPath, [options.executable, ...args, '--catalogue', 'legacy-8.2.7'], { env }),
            (error: unknown) => JSON.parse((error as { stdout: string }).stdout).error.code === 'INVALID_INPUT')
          assert.equal(requests, 0)
        }
      } finally { await new Promise<void>(resolve => server.close(() => resolve())) }
    })
  } finally { await rm(scratch, { recursive: true, force: true }) }
})

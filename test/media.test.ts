import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const executable = new URL('../../bin/proxmox-axi.mjs', import.meta.url).pathname
const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PROXMOX_AXI_')))
const contentPath = '/nodes/{node}/storage/{storage}/content'
const uploadPath = '/nodes/{node}/storage/{storage}/upload'
const cataloguePath = '/nodes/{node}/aplinfo'
const template = 'base_1_amd64.tar.zst'
const hidden = 'CANARY-media-private-metadata'

test('media discovery and confirmed installation through the CLI', async t => {
  const scratch = await mkdtemp(join(tmpdir(), 'proxmox-media-'))
  t.after(() => rm(scratch, { recursive: true, force: true }))
  const caFile = join(scratch, 'server.crt'), input = join(scratch, 'media.bin')
  await writeFile(caFile, await readFile(new URL('../../test/fixtures/localhost-cert.pem', import.meta.url)), { mode: 0o600 })
  const bytes = Buffer.from('synthetic media\0\xff', 'latin1')
  await writeFile(input, bytes, { mode: 0o600 })
  const volumes = ['iso/installer.iso', `vztmpl/${template}`, 'vm-100-disk-0', 'backup/vzdump-lxc-100.tar.zst'].map((name, index) =>
    ({ volid: `local:${name}`, format: ['iso', 'tzst', 'raw', 'tzst'][index], size: 4096, used: 2048, notes: hidden, extra: hidden }))
  const requests: string[] = []
  const tasks = new Map<string, { failed: boolean, volume: string }>()
  let version = '8.2.7', mode = 'success', sequence = 0
  const server = createServer({ key: await readFile(new URL('../../test/fixtures/localhost-key.pem', import.meta.url)), cert: await readFile(caFile) }, async (request, response) => {
    const url = new URL(request.url!, 'https://fake.invalid')
    requests.push(`${request.method} ${url.pathname}`)
    if (url.pathname.endsWith('/version')) { response.end(JSON.stringify({ data: { version, release: 'synthetic', repoid: 'synthetic' } })); return }
    if (request.method === 'POST') {
      const chunks: Buffer[] = []
      for await (const chunk of request) chunks.push(Buffer.from(chunk))
      const body = Buffer.concat(chunks)
      let volume = `local:vztmpl/${template}`
      if (url.pathname.endsWith('/upload')) {
        const boundary = /boundary=(.+)$/.exec(String(request.headers['content-type']))![1]!
        const start = body.indexOf(Buffer.from('Content-Type: application/octet-stream\r\n\r\n')) + Buffer.byteLength('Content-Type: application/octet-stream\r\n\r\n')
        assert.deepEqual(body.subarray(start, body.lastIndexOf(Buffer.from(`\r\n--${boundary}--\r\n`))), bytes)
        const filename = /filename="([^"]+)"/.exec(body.toString())![1]!
        const content = /name="content"\r\n\r\n(iso|vztmpl)\r\n/.exec(body.toString())![1]!
        volume = `local:${content}/${filename}`
        if (mode === 'interrupted') { response.writeHead(200, { 'content-length': 100 }); response.end('{"data":'); return }
      } else {
        assert.equal(url.pathname, '/api2/json/nodes/node-a/aplinfo')
        assert.deepEqual(Object.fromEntries(new URLSearchParams(body.toString())), { storage: 'local', template })
      }
      const upid = `UPID:node-a:${(++sequence).toString(16).padStart(8, '0')}:00000001:00000001:download:media:synthetic@pve:`
      tasks.set(upid, { failed: mode === 'task-failed', volume })
      response.end(JSON.stringify({ data: upid })); return
    }
    const task = /\/tasks\/([^/]+)\/status$/.exec(url.pathname)
    if (task) {
      const upid = decodeURIComponent(task[1]!), current = tasks.get(upid)!
      if (!current.failed && !volumes.some(row => row.volid === current.volume)) volumes.push({ volid: current.volume, format: 'tzst', size: 4096, used: 2048, notes: hidden, extra: hidden })
      response.end(JSON.stringify({ data: { node: 'node-a', upid, id: 'media', pid: sequence, pstart: 1, starttime: 1,
        type: 'download', user: 'synthetic@pve', status: 'stopped', exitstatus: current.failed ? 'ERROR: storage unavailable' : 'OK' } })); return
    }
    let data: unknown
    if (url.pathname.endsWith('/aplinfo')) data = [{ template: mode === 'malformed' ? {} : template, package: 'base', version: '1', type: 'lxc', os: 'base', location: hidden, source: hidden, description: mode === 'large' ? 'x'.repeat(95_000) : mode === 'oversize' ? 'x'.repeat(263_000) : hidden }]
    else if (url.pathname.endsWith('/content')) data = url.searchParams.get('content') === 'iso' ? volumes.filter(row => row.format === 'iso') : volumes
    else if (url.pathname.includes('/content/')) data = { format: 'iso', size: 4096, used: 2048, path: hidden, notes: hidden, extra: hidden }
    else { response.writeHead(404).end(); return }
    response.end(JSON.stringify({ data }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  const config = join(scratch, 'config.json')
  await writeFile(config, JSON.stringify({ version: 1, defaultProfile: 'lab', profiles: { lab: {
    auth: 'api-token', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, caBundle: caFile,
    tokenId: 'synthetic@pve!test', token: { env: 'MEDIA_TOKEN' }, writes: { operations: [uploadPath, cataloguePath].map(path =>
      `OP-POST-${createHash('sha256').update(`POST ${path}`).digest('hex').slice(0, 10)}`) },
  } } }), { mode: 0o600 })
  const command = async (args: string[], transfer = false) => {
    const child = spawn(process.execPath, [executable, ...args, '--config', config, '--format', 'json'], {
      env: { ...environment, MEDIA_TOKEN: 'synthetic-token', PROXMOX_AXI_WRITE_LOG: join(scratch, 'writes.log'), PROXMOX_AXI_STREAM_FD: transfer ? '3' : '' },
      stdio: ['ignore', 'pipe', 'pipe', ...(transfer ? ['pipe' as const] : [])],
    })
    let stdout = '', stderr = ''
    child.stdout!.on('data', chunk => { stdout += chunk.toString() })
    child.stderr!.on('data', chunk => { stderr += chunk.toString() })
    const code = await new Promise<number | null>((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal((stdout + stderr).includes(hidden), false)
    return { code, data: JSON.parse(stdout), stderr }
  }
  const node = ['--api-node', 'node-a'], storage = [...node, '--api-storage', 'local']
  for (const release of [{ name: 'legacy-8.2.7', version: '8.2.7' }, { name: 'published-current', version: '9.2.1' }]) {
    version = release.version
    await t.test(`${release.name} lists reviewed media metadata and excludes private fields with full output`, async () => {
      const catalogue = await command(['get', cataloguePath, ...node, '--full'])
      assert.equal(catalogue.code, 0, JSON.stringify(catalogue.data))
      assert.deepEqual(catalogue.data.data, [{ template, package: 'base', version: '1', type: 'lxc', os: 'base' }])
      const listed = await command(['get', contentPath, ...storage, '--full'])
      assert.equal(listed.code, 0, JSON.stringify(listed.data))
      assert.deepEqual(listed.data.data.slice(0, 4), volumes.slice(0, 4).map(({ volid, format, size, used }) => ({ volid, format, size, used })))
      const filtered = await command(['get', contentPath, ...storage, '--api-content', 'iso', '--fields', 'volid,format'])
      assert.deepEqual(filtered.data.data, [{ volid: 'local:iso/installer.iso', format: 'iso' }])
      const detail = await command(['get', `${contentPath}/{volume}`, ...storage, '--api-volume', 'local:iso/installer.iso', '--full'])
      assert.equal(detail.code, 0, JSON.stringify(detail.data))
      assert.deepEqual(detail.data.data, { format: 'iso', size: 4096, used: 2048 })
      const selected = await command(['get', `${contentPath}/{volume}`, ...storage, '--api-volume', 'local:iso/installer.iso', '--fields', 'size'])
      assert.deepEqual(selected.data.data, { size: 4096 })
    })
    for (const kind of ['catalogue', 'iso', 'vztmpl']) await t.test(`${release.name} confirms ${kind} installation and waits before storage inspection`, async () => {
      mode = 'success'
      const transfer = kind !== 'catalogue', filename = kind === 'iso' ? 'uploaded.iso' : 'uploaded.tar.zst'
      const args = transfer ? ['transfer', 'create', uploadPath, ...storage, '--api-content', kind, '--api-filename', filename, '--input-file', input, '--response-format', 'multipart'] :
        ['create', cataloguePath, ...storage, '--api-template', template]
      requests.length = 0
      const preview = await command([...args, '--preview'], transfer)
      assert.equal(preview.code, 0, JSON.stringify(preview.data))
      assert.equal(requests.some(row => row.startsWith('POST')), false)
      const changed = await command([...args.map(value => value === 'local' ? 'other' : value), '--confirm', preview.data.confirmation], transfer)
      assert.equal(changed.data.error.code, 'CONFIRMATION_MISMATCH')
      const result = await command([...args, '--confirm', preview.data.confirmation], transfer)
      assert.equal(result.code, 0, JSON.stringify(result.data))
      assert.equal(result.data.status, 'accepted')
      if (transfer) assert.equal(result.data.transfer.status, 'complete')
      const completed = await command(['task', 'wait', ...node, '--api-upid', result.data.upid, '--journal', result.data.id])
      assert.equal(completed.code, 0, JSON.stringify(completed.data))
      assert.equal(completed.data.status, 'success')
      const listed = await command(['get', contentPath, ...storage, '--fields', 'volid'])
      assert.equal(listed.data.data.some((row: { volid: string }) => row.volid === `local:${transfer ? `${kind}/${filename}` : `vztmpl/${template}`}`), true)
    })
    for (const kind of ['task-failed', 'interrupted']) await t.test(`${release.name} retains ${kind} installation without automatic retry`, async () => {
      mode = kind
      const transfer = kind === 'interrupted'
      const args = transfer ? ['transfer', 'create', uploadPath, ...storage, '--api-content', 'vztmpl', '--api-filename', 'interrupted.tar.zst', '--input-file', input, '--response-format', 'multipart'] :
        ['create', cataloguePath, ...storage, '--api-template', template]
      const preview = await command([...args, '--preview'], transfer)
      requests.length = 0
      const result = await command([...args, '--confirm', preview.data.confirmation], transfer)
      if (transfer) { assert.equal(result.code, 1); assert.equal(result.data.error.code, 'WRITE_UNCERTAIN') }
      else {
        assert.equal(result.data.status, 'accepted')
        const failed = await command(['task', 'wait', ...node, '--api-upid', result.data.upid, '--journal', result.data.id])
        assert.equal(failed.code, 1)
        assert.equal(failed.data.status, 'failed')
      }
      assert.equal(requests.filter(row => row.startsWith('POST')).length, 1)
      const journal = await command(['journal', 'show', preview.data.id])
      assert.equal(journal.data.journal.status, transfer ? 'uncertain' : 'failed')
      mode = 'success'
    })
  }
  await t.test('rejects a malformed catalogue identifier', async () => {
    mode = 'malformed'
    const result = await command(['get', cataloguePath, ...node])
    assert.equal(result.code, 1)
    assert.equal(result.data.error.code, 'INVALID_RESPONSE')
    mode = 'success'
  })
  await t.test('catalogue permits a large response but retains a hard bound', async () => {
    mode = 'large'
    assert.equal((await command(['get', cataloguePath, ...node, '--limit', '3'])).code, 0)
    mode = 'oversize'
    assert.equal((await command(['get', cataloguePath, ...node])).data.error.code, 'OUTPUT_LIMIT')
    mode = 'success'
  })
  for (const { args, transfer } of [
    { args: ['get', contentPath, ...storage, '--fields', 'notes', '--catalogue', 'published-current'], transfer: false },
    { args: ['get', `${contentPath}/{volume}`, ...storage, '--api-volume', 'local:iso/../secret'], transfer: false },
    { args: ['get', `${contentPath}/{volume}`, ...storage, '--api-volume', 'local:iso%2fsecret'], transfer: false },
    { args: ['create', cataloguePath, ...storage, '--api-template', 'https://remote.invalid/base.tar.zst', '--preview'], transfer: false },
    { args: ['transfer', 'create', uploadPath, ...storage, '--api-content', 'vztmpl', '--api-filename', '../base.tar.zst', '--input-file', input, '--response-format', 'multipart', '--preview'], transfer: true },
    { args: ['create', '/nodes/{node}/storage/{storage}/download-url', ...storage, '--preview'], transfer: false },
  ]) await t.test(`refuses unreviewed media input ${args[0]} ${args[1]} ${args[args.length - 2]}`, async () => {
    requests.length = 0
    const refused = await command(args, transfer)
    assert.notEqual(refused.code, 0)
    assert.deepEqual(requests, [])
  })
})

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash, X509Certificate } from 'node:crypto'
import { createServer } from 'node:https'
import { createConnection } from 'node:net'
import { networkInterfaces } from 'node:os'
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { isAbsolute, join, relative, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { decode } from '@toon-format/toon'
import { verifyHostRuntime } from './host-identity.mjs'
import { captures, replay, routeKey } from './catalogue.mjs'
import { routeCases, verifyDiscovery } from './route-cases.mjs'
import { exerciseReadJourney } from './read-journey.mjs'
import { exerciseWriteJourney } from './write-journey.ts'
import { exerciseSecretJourney } from './secret-journey.ts'

const root = fileURLToPath(new URL('../', import.meta.url))
const digest = (bytes, algorithm = 'sha256') => createHash(algorithm).update(bytes).digest(algorithm === 'sha512' ? 'base64' : 'hex')
const json = async path => JSON.parse(await readFile(path, 'utf8'))
const save = (path, value) => writeFile(path, `${JSON.stringify(value, null, 2)}\n`)

async function runtimeFiles(directory, prefix = '') {
  const files = {}
  for (const entry of (await readdir(join(directory, prefix), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(prefix, entry.name)
    if (entry.isDirectory()) Object.assign(files, await runtimeFiles(directory, path))
    else files[path] = digest(await readFile(join(directory, path)))
  }
  return files
}

async function command(executable, args, options = {}) {
  const { timeoutMs = 60_000, ...spawnOptions } = options
  const child = spawn(executable, args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], ...spawnOptions })
  const stdout = [], stderr = []
  let bytes = 0
  let terminationReason
  const timer = setTimeout(() => {
    terminationReason ??= `deadline of ${timeoutMs} ms`
    child.kill('SIGKILL')
  }, timeoutMs)
  for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', chunk => {
    bytes += chunk.length
    if (bytes > 1_048_576) {
      terminationReason ??= '1048576-byte output budget'
      child.kill('SIGKILL')
    }
    else chunks.push(chunk)
  })
  return await new Promise((resolve, reject) => {
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', (code, signal) => {
      clearTimeout(timer)
      const result = { code, signal, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }
      if (signal) reject(new Error(terminationReason ? `Command exceeded its ${terminationReason} (${signal}).` : `Command terminated by ${signal}.`))
      else resolve(result)
    })
  })
}

async function checked(executable, args, options) {
  const result = await command(executable, args, options)
  assert.equal(result.code, 0, `${executable} failed: ${result.stderr || result.stdout}`)
  return result.stdout.trim()
}

function hostMessage(child, event) {
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); child.off('message', message); child.off('exit', exited); child.off('error', failed) }
    const message = value => { if (value.event === event) { cleanup(); resolve(value) } }
    const exited = () => { cleanup(); reject(new Error(`Actual Artium server exited before ${event}`)) }
    const failed = error => { cleanup(); reject(error) }
    const timer = setTimeout(() => { cleanup(); reject(new Error(`Actual Artium server did not report ${event} within 30000 ms`)) }, 30_000)
    child.on('message', message)
    child.once('exit', exited)
    child.once('error', failed)
  })
}

function selection(args) {
  const values = {}
  for (let index = 0; index < args.length; index++) {
    const key = args[index]
    if (key === '--' && index === 0) continue
    assert.ok(['--task', '--pack', '--out', '--network', '--through', '--repeat-through', '--available-through', '--all-route-variants'].includes(key), `Unknown argument: ${key}`)
    assert.equal(values[key], undefined, `Duplicate argument: ${key}`)
    if (key === '--all-route-variants') { values[key] = true; continue }
    const value = args[++index]
    assert.ok(value && !value.startsWith('--'), `Missing value for ${key}`)
    values[key] = value
  }
  assert.ok(['S1.1', 'S1.2', 'S2.1', 'S2.2', 'S2.3', 'S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task']), 'Select a task from S1.1 through S4.2')
  if (values['--repeat-through']) assert.ok(['S1', 'S2', 'S3', 'S4'].includes(values['--repeat-through']))
  if (values['--available-through']) assert.equal(values['--available-through'], 'S2')
  assert.equal(values['--network'], 'fake-only', 'Only fake-only networking is permitted')
  assert.ok(['standalone', 'both'].includes(values['--through']), 'Select --through standalone or both')
  for (const key of ['--pack', '--out']) assert.ok(values[key] && isAbsolute(values[key]), `${key} must be absolute`)
  const outputRelative = relative(root, values['--out'])
  assert.ok(outputRelative === '..' || outputRelative.startsWith(`..${sep}`) || isAbsolute(outputRelative), '--out must be outside the source tree')
  return values
}

async function preparePackage(values, out, scratch) {
  const pkg = await json(join(root, 'package.json'))
  const archive = join(out, `knowttl-proxmox-axi-${pkg.version}.tgz`)
  let hostInput
  if (values['--through'] === 'both') {
    assert.ok(process.env.PROXMOX_AXI_ARTIUM_FIXTURE && process.env.PROXMOX_AXI_ARTIUM_MANIFEST,
      '--through both requires PROXMOX_AXI_ARTIUM_FIXTURE and PROXMOX_AXI_ARTIUM_MANIFEST')
    const pin = await json(join(root, 'test/artium-fixture.json'))
    const manifestBytes = await readFile(process.env.PROXMOX_AXI_ARTIUM_MANIFEST)
    assert.equal(digest(manifestBytes), pin.manifestSha256, 'Reviewed host fixture manifest digest')
    const manifest = JSON.parse(manifestBytes)
    assert.equal(manifest.fixtureCommit, pin.revision, 'Reviewed temporary admission revision')
    const fixture = await realpath(process.env.PROXMOX_AXI_ARTIUM_FIXTURE)
    for (const [path, hash] of Object.entries(pin.sourceHashes)) assert.equal(digest(await readFile(join(fixture, path))), hash, `Host source pin: ${path}`)
    const runtimeHashes = await verifyHostRuntime(fixture)
    const admitted = manifest.tools.find(tool => tool.tool === 'proxmox-axi')
    assert.equal(digest(await readFile(admitted.tarball)), pin.packageSha256, 'Admitted tool archive')
    assert.equal(`sha512-${digest(await readFile(admitted.tarball), 'sha512')}`, pin.packageIntegrity, 'Admitted tool archive integrity')
    await copyFile(admitted.tarball, archive)
    hostInput = { fixture, pin }
    hostInput.host = { status: 'starting', revision: pin.revision, manifestSha256: pin.manifestSha256,
      admission: pin.status, sourceHashes: pin.sourceHashes, runtimeHashes,
      clientSha256: runtimeHashes['dist/cli/artium-axi.mjs'] }
  } else await checked('pnpm', ['--config.ignore-scripts=true', 'pack', '--pack-destination', out])
  const consumer = join(scratch, 'consumer')
  await mkdir(consumer)
  await save(join(consumer, 'package.json'), { private: true, packageManager: pkg.packageManager,
    dependencies: { [pkg.name]: `file:${archive}` }, pnpm: pkg.pnpm })
  await checked('pnpm', ['install', '--offline', '--ignore-scripts'], { cwd: consumer })
  const installed = await realpath(join(consumer, 'node_modules', pkg.name))
  const executable = join(installed, 'bin/proxmox-axi.mjs')
  return { pkg, archive, consumer, installed, executable, hostInput }
}

async function verify(values, prepared, scratch) {
  const out = values['--out']
  const ledger = [], transcripts = [], tlsErrors = []
  const secrets = []
  const publicText = value => {
    for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1)]) {
      value = value.replaceAll(form, '[REDACTED]')
    }
    return value
  }
  const result = { task: values['--task'], through: values['--through'], platform: `${process.platform}/${process.arch}`,
    node: process.version, operation: 'OP-GET-version', catalogue: 'legacy-8.2.7',
    cases: [], status: 'fail', host: { status: 'pending', reason: 'Actual Artium fixture inputs were not selected.' } }
  let server
  let hostChild
  const hostLogs = []
  try {
    result.sourceHead = await checked('git', ['rev-parse', 'HEAD'])
    result.network = { mode: 'fake-only', namespace: await readlink('/proc/self/ns/net'), externalEgress: 'denied' }
    const interfaces = Object.keys(networkInterfaces())
    assert.ok(interfaces.every(name => name === 'lo'), 'Network namespace must contain only loopback')
    const egress = await new Promise(resolve => {
      const socket = createConnection({ host: '192.0.2.1', port: 443 })
      socket.setTimeout(1000, () => { socket.destroy(); resolve('timeout') })
      socket.once('connect', () => { socket.destroy(); resolve('connected') })
      socket.once('error', error => resolve(error.code))
    })
    assert.equal(egress, 'ENETUNREACH', 'External destination must be unreachable at the OS boundary')
    result.network.denial = egress
    const retained = await json(join(root, 'evidence/retained.json'))
    result.fixtures = []
    for (const fixture of retained) {
      const bytes = await readFile(join(values['--pack'], fixture.path))
      assert.equal(digest(bytes), fixture.sha256, `Fixture hash mismatch: ${fixture.path}`)
      result.fixtures.push(fixture)
    }
    const success = await json(join(values['--pack'], retained[0].path))
    const denied = await json(join(values['--pack'], retained[1].path))
    assert.equal(success.body.data.version, '8.2.7', 'Approved fixture version')
    assert.equal(denied.httpStatus, 401, 'Approved denial fixture')

    const { pkg, archive, consumer, installed, executable, hostInput } = prepared
    const archiveBytes = await readFile(archive)
    if (hostInput) result.host = hostInput.host
    assert.notEqual(installed, root, 'Must execute the installed archive, not source')
    const installedPackage = await json(join(installed, 'package.json'))
    assert.equal(installedPackage.name, pkg.name)
    assert.equal(installedPackage.version, pkg.version)
    if (hostInput) {
      for (const directory of ['bin', 'dist']) {
        assert.deepEqual(await runtimeFiles(join(root, directory)), await runtimeFiles(join(installed, directory)), `Complete shipped ${directory} tree must match the current build`)
      }
      const admittedInventory = await json(join(hostInput.fixture, 'tools/inventories/proxmox-axi.json'))
      for (const source of admittedInventory.sources) {
        assert.equal(digest(await readFile(join(installed, source.path))), source.sha256, `Admitted package source: ${source.path}`)
        if (source.path === 'package.json') {
          for (const field of ['name', 'version', 'type', 'bin', 'dependencies', 'engines']) {
            assert.deepEqual(pkg[field], installedPackage[field], `Current package runtime metadata: ${field}`)
          }
        } else assert.equal(digest(await readFile(join(root, source.path))), source.sha256, `Current runtime must match admitted package: ${source.path}`)
      }
      assert.equal(digest(await readFile(executable)), digest(await readFile(join(root, 'bin/proxmox-axi.mjs'))), 'Current executable matches admitted package')
    }
    const inventory = await json(join(installed, 'inventory.json'))
    const catalogues = await Promise.all(captures.map(async capture => replay(await readFile(join(root, 'vendor', capture.file)), capture)))
    assert.deepEqual(new Set(inventory.operations.map(routeKey)), new Set(catalogues.flatMap(catalogue => catalogue.operations.map(routeKey))), 'Inventory covers the exact independent vendor union')
    const helpMetadata = await json(join(installed, 'help.json'))
    assert.deepEqual(new Set(helpMetadata.commands.map(entry => entry.command)), new Set(inventory.operations.map(entry => entry.command.join(' '))), 'Generated help covers the inventory')
    result.package = { name: pkg.name, version: pkg.version, archive, sha256: digest(archiveBytes),
      integrity: `sha512-${digest(archiveBytes, 'sha512')}`, executable,
      executableSha256: digest(await readFile(executable)), inventorySha256: digest(await readFile(join(installed, 'inventory.json'))),
      lockSha256: digest(await readFile(join(root, 'pnpm-lock.yaml'))),
      consumerLockSha256: digest(await readFile(join(consumer, 'pnpm-lock.yaml'))) }
    await save(join(out, 'package-identity.json'), result.package)
    await writeFile(join(out, 'installed-lock.yaml'), await readFile(join(consumer, 'pnpm-lock.yaml')))

    await checked('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-keyout', join(scratch, 'server.key'), '-out', join(scratch, 'server.crt'),
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE'])
    const caFile = join(scratch, 'server.crt')
    await chmod(caFile, 0o600)
    const token = 'CANARY-proxmox+token/S1-1?value="x"'
    const fileToken = 'CANARY-proxmox-file-token-S1-1'
    const decoy = 'CANARY-developer-profile-S1-1'
    const hostedToken = 'CANARY-proxmox-hosted-token-S1-1'
    secrets.push(token, fileToken, decoy, hostedToken, 'CANARY-local-password')
    const tokenId = 'synthetic@pve!acceptance'
    let response = success
    let activeCase = ''
    server = createServer({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) }, (request, reply) => {
      const vendor = typeof response === 'function' ? response(request.url) : response
      const authorization = request.headers.authorization
      const identity = authorization === `PVEAPIToken=${tokenId}=${token}` ? 'environment-canary' :
        authorization === `PVEAPIToken=${tokenId}=${fileToken}` ? 'protected-file-canary' :
          authorization === `PVEAPIToken=${tokenId}=${hostedToken}` ? 'hosted-canary' : 'unexpected'
      ledger.push({ case: activeCase, method: request.method, path: request.url, identity,
        host: request.headers.host, status: identity === 'unexpected' ? 401 : vendor.httpStatus })
      if (identity === 'unexpected') { reply.writeHead(401); reply.end(); return }
      reply.writeHead(vendor.httpStatus, { 'Content-Type': 'application/json', ...(vendor.headers ?? {}) })
      if (vendor.disconnect) {
        reply.write('{"data":', () => reply.socket.end())
        return
      }
      if (vendor.stall) { reply.write('{"data":'); return }
      if (vendor.trickle) {
        const timer = setInterval(() => reply.write(' '), 100)
        reply.once('close', () => clearInterval(timer))
        return
      }
      const payload = typeof vendor.body === 'string' ? vendor.body : JSON.stringify(vendor.body)
      if (vendor.split) {
        const split = Math.floor(payload.length / 2)
        reply.write(payload.slice(0, split))
        setImmediate(() => reply.end(payload.slice(split)))
      } else reply.end(payload)
    })
    server.on('tlsClientError', error => {
      const code = typeof error.code === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(error.code) ? error.code : 'UNKNOWN'
      tlsErrors.push({ case: activeCase, code })
    })
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
    const origin = `https://127.0.0.1:${server.address().port}`
    const home = join(scratch, 'home')
    const config = join(scratch, 'selected.json')
    const secretFile = join(scratch, 'token.txt')
    await mkdir(join(home, '.config/proxmox-axi'), { recursive: true, mode: 0o700 })
    await mkdir(join(scratch, 'decoy-bin'))
    await writeFile(join(scratch, 'decoy-bin/proxmox-axi'), '#!/bin/sh\nexit 97\n', { mode: 0o700 })
    await save(join(home, '.config/proxmox-axi/config.json'), { version: 1, defaultProfile: 'developer', profiles: {
      developer: { auth: 'api-token', origin, tokenId: 'developer@pve!decoy', token: { env: 'DEVELOPER_TOKEN' } },
    } })
    await chmod(join(home, '.config/proxmox-axi/config.json'), 0o600)
    await writeFile(secretFile, `\uFEFF${fileToken}\r\n`, { mode: 0o600 })
    await save(config, { version: 1, defaultProfile: 'selected', profiles: {
      selected: { auth: 'api-token', origin, tokenId, token: { file: secretFile }, caBundle: caFile },
    } })
    await chmod(config, 0o600)
    const base = { HOME: home, XDG_CONFIG_HOME: join(home, '.config'), XDG_STATE_HOME: join(home, '.local/state'),
      TMPDIR: scratch, PATH: `${join(scratch, 'decoy-bin')}:/usr/bin:/bin`, DEVELOPER_TOKEN: decoy }
    const env = { ...base, PROXMOX_AXI_ORIGIN: origin, PROXMOX_AXI_TOKEN_ID: tokenId,
      PROXMOX_AXI_TOKEN: token, PROXMOX_AXI_CA_BUNDLE: caFile }

    const runCase = async (id, args, environment, expected, vendor = success, entry = executable) => {
      activeCase = id
      response = vendor
      const before = ledger.length
      const diagnostics = join(scratch, 'transport.jsonl')
      await writeFile(diagnostics, '')
      const invocation = ['--import', fileURLToPath(new URL('./transport-observer.mjs', import.meta.url)), entry, ...args]
      const start = performance.now()
      if (entry !== executable) await verifyHostRuntime(hostInput.fixture)
      const actual = await command(process.execPath, invocation,
        { env: { ...environment, PROXMOX_AXI_TEST_DIAGNOSTICS: diagnostics }, cwd: scratch })
      const record = { id, hosted: entry !== executable, status: 'fail', expected, actual: { exitCode: actual.code, requests: ledger.length - before },
        invocation: { executable: process.execPath, args: invocation.map(publicText) }, elapsedMs: Math.round(performance.now() - start),
        transportDiagnostics: (await readFile(diagnostics, 'utf8')).split('\n').filter(Boolean).map(line => JSON.parse(line)) }
      result.cases.push(record)
      for (const value of secrets) {
        assert.ok(!`${actual.stdout}${actual.stderr}`.includes(value), `${id}: secret leaked to public output`)
      }
      transcripts.push(`case: ${id}\nexit: ${actual.code}\nstdout:\n${actual.stdout}stderr:\n${actual.stderr}`)
      const value = expected.bareVersion ? undefined : expected.hostBoundary ? decode(actual.stdout) : args.includes('json') ? JSON.parse(actual.stdout) : decode(actual.stdout)
      record.actual.output = value
      if (entry !== executable && expected.exitCode !== 0) {
        assert.ok((expected.hostBoundary && actual.stderr === '') || /^artium-axi: request_id [0-9a-f-]{36}\n$/.test(actual.stderr), `${id}: only the host's safe request ID diagnostic`)
      } else assert.equal(actual.stderr, '', `${id}: no raw diagnostics on stderr`)
      assert.equal(actual.code, expected.exitCode, `${id}: exit code; stdout=${actual.stdout}`)
      if (expected.error) assert.equal(value.error?.code, expected.error, `${id}: observed public code ${value.error?.code ?? 'none'}`)
      assert.equal(record.actual.requests, expected.requests,
        `${id}: request count; observed public code ${value?.error?.code ?? 'none'}; transport codes ${record.transportDiagnostics.map(entry => entry.code).join(',')}`)
      assert.ok(record.elapsedMs < 10_000, `${id}: elapsed budget`)
      assert.ok(Buffer.byteLength(actual.stdout) <= 65537, `${id}: public output budget`)
      if (expected.data) assert.deepEqual(value.data, expected.data, `${id}: semantic response`)
      if (expected.version || expected.error || expected.profile) {
        if (expected.version) assert.deepEqual(value.version, success.body.data, `${id}: reviewed version fields`)
        if (expected.profile) assert.equal(value.credential.profile, expected.profile, `${id}: credential source`)
        if (expected.tokenSource) assert.equal(value.credential.tokenSource, expected.tokenSource, `${id}: secret reference source`)
      } else if (expected.bareVersion) assert.equal(actual.stdout, `${pkg.version}\n`)
      else if (expected.help) {
        assert.equal(value.purpose, helpMetadata.commands.find(entry => entry.command === 'get /version').purpose, `${id}: help matches admitted command`)
        assert.ok(value.usage.startsWith('proxmox-axi get /version '), `${id}: invocable version help`)
      }
      for (const [index, request] of ledger.slice(before).entries()) {
        assert.equal(request.method, 'GET', `${id}: method`)
        assert.equal(request.path, expected.paths?.[index] ?? expected.path ?? '/api2/json/version', `${id}: exact wire route`)
        assert.equal(request.identity, expected.identity ?? 'environment-canary', `${id}: credential at vendor boundary`)
      }
      record.status = 'pass'
      return value
    }

    await runCase('AC-VERIFIED-VERSION/toon', ['get', '/version'], env, { exitCode: 0, requests: 1, version: true, profile: 'environment' })
    await runCase('AC-VERIFIED-VERSION/json', ['get', '/version', '--format', 'json'], env, { exitCode: 0, requests: 1, version: true })
    await runCase('CRED-05/protected-file', ['get', '/version', '--config', config, '--profile', 'selected'], env,
      { exitCode: 0, requests: 1, version: true, profile: 'selected', tokenSource: `file:${secretFile}`, identity: 'protected-file-canary' })
    await runCase('CRED-21/exact-package', ['get', '/version', '--config', config, '--profile', 'selected'],
      { ...env, PROXMOX_AXI_ORIGIN: 'https://competing.example.test' },
      { exitCode: 0, requests: 1, version: true, profile: 'selected', identity: 'protected-file-canary' })
    await runCase('AC-VERSION-AUTH/401', ['get', '/version', '--format', 'json'], env,
      { exitCode: 1, requests: 1, error: 'AUTH_REQUIRED' }, denied)
    await runCase('response-disconnect', ['get', '/version', '--format', 'json'], env,
      { exitCode: 1, requests: 1, error: 'CONNECTION_FAILED' }, { httpStatus: 200, disconnect: true })
    await runCase('response-timeout', ['get', '/version', '--format', 'json'], env,
      { exitCode: 1, requests: 1, error: 'TIMEOUT' }, { httpStatus: 200, stall: true })
    await runCase('response-output-limit', ['get', '/version', '--format', 'json'], env,
      { exitCode: 1, requests: 1, error: 'OUTPUT_LIMIT' }, { httpStatus: 200, body: 'x'.repeat(65_537) })
    for (const body of [{ data: null }, { data: { version: '8.2.7' } }, { data: [] }, 'invalid-json']) {
      await runCase(`AC-VERSION-AUTH/shape-${result.cases.length}`, ['get', '/version', '--format', 'json'], env,
        { exitCode: 1, requests: 1, error: 'INVALID_RESPONSE' }, { httpStatus: 200, body })
    }
    await runCase('redirect-denied', ['get', '/version', '--format', 'json'], env,
      { exitCode: 1, requests: 1, error: 'HTTP_ERROR' }, { httpStatus: 302, headers: { Location: 'https://outside.example.test' }, body: '' })
    const { PROXMOX_AXI_CA_BUNDLE: _ca, ...untrusted } = env
    await runCase('trust-failure', ['get', '/version', '--format', 'json'], untrusted,
      { exitCode: 1, requests: 0, error: 'CONNECTION_FAILED' })
    await runCase('unknown-flag', ['get', '/version', '--token', token], env,
      { exitCode: 2, requests: 0, error: 'INVALID_INPUT' })
    await runCase('unknown-route', ['get', '/unknown-route'], env, { exitCode: 2, requests: 0, error: 'INVALID_INPUT' })
    await runCase('source-diagnostics', ['auth', 'status', '--format', 'json'], env,
      { exitCode: 0, requests: 0, profile: 'environment', tokenSource: 'env:PROXMOX_AXI_TOKEN' })
    await runCase('missing-profile', ['get', '/version', '--format', 'json'],
      { ...base, PROXMOX_AXI_CONFIG: join(scratch, 'absent.json') }, { exitCode: 1, requests: 0, error: 'AUTH_REQUIRED' })
    await runCase('partial-environment', ['get', '/version', '--format', 'json'],
      { ...base, PROXMOX_AXI_ORIGIN: origin }, { exitCode: 1, requests: 0, error: 'CONFIG_INVALID' })
    for (const flag of ['-v', '-V', '--version']) await runCase(`package-version/${flag}`, [flag], base,
      { exitCode: 0, requests: 0, bareVersion: true })
    await runCase('offline-help', ['get', '--help'], base, { exitCode: 0, requests: 0, help: true })
    if (values['--task'] !== 'S1.1') {
      const selectedProfile = { auth: 'api-token', origin, tokenId, caBundle: caFile }
      const writeProfile = async profile => {
        await save(config, { version: 1, profiles: { selected: profile } })
        await chmod(config, 0o600)
      }
      const fileArgs = ['get', '/version', '--config', config, '--profile', 'selected', '--format', 'json']
      await runCase('CRED-01', ['auth', 'status', '--format', 'json'], env,
        { exitCode: 0, requests: 0, profile: 'environment', tokenSource: 'env:PROXMOX_AXI_TOKEN' })
      await runCase('CRED-02', ['get', '/version', '--format', 'json'], { ...base, PROXMOX_AXI_TOKEN_ID: tokenId },
        { exitCode: 1, requests: 0, error: 'CONFIG_INVALID' })
      await runCase('CRED-03', fileArgs, { ...env, PROXMOX_AXI_ORIGIN: 'https://competing.example.test' },
        { exitCode: 0, requests: 1, version: true, profile: 'selected', identity: 'protected-file-canary' })
      for (const reference of [token, { env: 'BAD NAME' }, { env: 'PROXMOX_AXI_TOKEN', file: secretFile }, { stored: true }]) {
        await writeProfile({ ...selectedProfile, token: reference })
        await runCase(`CRED-04/${result.cases.length}`, fileArgs, env, { exitCode: 1, requests: 0, error: 'CONFIG_INVALID' })
      }
      await writeProfile(selectedProfile)
      await runCase('CRED-06/default', fileArgs, env, { exitCode: 0, requests: 1, version: true, profile: 'selected' })
      await runCase('CRED-06/missing', fileArgs, base, { exitCode: 1, requests: 0, error: 'AUTH_REQUIRED' })
      await symlink(secretFile, join(scratch, 'linked-token'))
      await writeProfile({ ...selectedProfile, token: { file: join(scratch, 'linked-token') } })
      await runCase('CRED-09/link', fileArgs, env, { exitCode: 1, requests: 0, error: 'CONFIG_INSECURE' })
      await chmod(secretFile, 0o644)
      await writeProfile({ ...selectedProfile, token: { file: secretFile } })
      await runCase('CRED-09/mode', fileArgs, env, { exitCode: 1, requests: 0, error: 'CONFIG_INSECURE' })
      await chmod(secretFile, 0o600)
      await writeProfile({ ...selectedProfile, userId: 'wrong@pve' })
      await runCase('CRED-11/mixed', fileArgs, env, { exitCode: 1, requests: 0, error: 'CONFIG_INVALID' })
      await runCase('CRED-11/profile', ['get', '/version', '--config', config, '--profile', 'wrong', '--format', 'json'], env,
        { exitCode: 1, requests: 0, error: 'PROFILE_NOT_FOUND' })
      await runCase('CRED-12', ['get', '/version', '--format', 'json'],
        { ...base, PROXMOX_AXI_CONFIG: join(scratch, 'missing') }, { exitCode: 1, requests: 0, error: 'AUTH_REQUIRED' })
      await runCase('CRED-13', ['get', '/version', '--format', 'json'], env, { exitCode: 0, requests: 1 },
        { httpStatus: 200, split: true, body: { data: { version: token, release: encodeURIComponent(token), repoid: token } } })
      await runCase('elapsed-deadline/trickle', ['get', '/version', '--format', 'json'], env,
        { exitCode: 1, requests: 1, error: 'TIMEOUT' }, { httpStatus: 200, trickle: true })
      assert.ok(result.cases.at(-1).elapsedMs < 6500, 'Trickle stops within the total elapsed deadline plus process startup budget')
      const pin = new X509Certificate(await readFile(caFile)).fingerprint256.replaceAll(':', '').toLowerCase()
      await writeProfile({ auth: 'api-token', origin, tokenId, certificatePin: { origin, sha256: pin } })
      await runCase('CRED-20/valid', fileArgs, env, { exitCode: 0, requests: 1, version: true })
      await writeProfile({ auth: 'api-token', origin, tokenId, certificatePin: { origin, sha256: '0'.repeat(64) } })
      await runCase('CRED-20/changed', fileArgs, env, { exitCode: 1, requests: 0, error: 'CONNECTION_FAILED' })
      await checked('openssl', ['req', '-new', '-key', join(scratch, 'server.key'), '-out', join(scratch, 'expired.csr'),
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'])
      await checked('openssl', ['x509', '-req', '-in', join(scratch, 'expired.csr'), '-signkey', join(scratch, 'server.key'),
        '-out', join(scratch, 'expired.crt'), '-days', '-1', '-copy_extensions', 'copy'])
      const expired = await readFile(join(scratch, 'expired.crt'))
      server.setSecureContext({ key: await readFile(join(scratch, 'server.key')), cert: expired })
      const expiredPin = new X509Certificate(expired).fingerprint256.replaceAll(':', '').toLowerCase()
      await writeProfile({ auth: 'api-token', origin, tokenId, certificatePin: { origin, sha256: expiredPin } })
      await runCase('CRED-20/expired', fileArgs, env, { exitCode: 1, requests: 0, error: 'CONNECTION_FAILED' })
      server.setSecureContext({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) })
      const { replacePrivateFile, readPrivateFile } = await import(pathToFileURL(join(installed, 'dist/private-file.js')))
      const atomicPath = join(scratch, 'atomic.json')
      await replacePrivateFile(atomicPath, 'prior-valid-state')
      await assert.rejects(replacePrivateFile(atomicPath, 'replacement', { platform: 'win32',
        restrictAcl: async (_path, directory) => { if (!directory) throw new Error('controlled protection failure') } }), /controlled protection failure/)
      assert.equal(await readPrivateFile(atomicPath, true), 'prior-valid-state')
      await replacePrivateFile(atomicPath, 'new-complete-state')
      assert.equal(await readPrivateFile(atomicPath, true), 'new-complete-state')
      result.cases.push({ id: 'CRED-10/atomic-replacement', status: 'pass', basis: 'Installed private-file interface; interrupted protection retains old state, successful replacement publishes complete state; native Windows rename contention remains S6.1' })
      await writeProfile(selectedProfile)
    }
    const operationPolicy = await json(join(root, 'src/operation-policy.json'))
    const readJourney = (environment, entry = executable) => exerciseReadJourney({ runCase, pack: values['--pack'], retained,
      contracts: catalogues.flatMap(catalogue => catalogue.operations.map(operation => ({ ...operation, release: catalogue.release }))),
      env: environment, entry, hosted: entry !== executable, task: ['S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task']) ? 'S2.3' : values['--task'] })
    const exerciseRoutes = async (environment, entry = executable) => {
      const hosted = entry !== executable
      const coverage = { union: 681, variants: 1285, admitted: 0, denied: 0 }
      for (const route of routeCases(catalogues, operationPolicy)) {
        const args = hosted ? ['proxmox-axi', ...route.args] : route.args
        const identity = hosted ? 'hosted-canary' : 'environment-canary'
        const expected = route.callable ? route.operation.path === '/version' ?
          { exitCode: 0, requests: 1, version: true, identity } :
          { exitCode: 0, requests: 1, path: route.expectedPath, data: route.response, identity } :
          { exitCode: hosted ? 2 : 1, requests: 0, error: hosted ? 'INVALID_INPUT' : route.reviewedWrite ? 'WRITE_DISABLED' : 'CONTRACT_UNRESOLVED', hostBoundary: hosted }
        await runCase(`${hosted ? 'artium' : 'standalone'}/contract/${route.id}/valid`, args, environment, expected,
          route.operation.path === '/version' ? success : { httpStatus: 200, body: { data: route.response } }, entry)
        await runCase(`${hosted ? 'artium' : 'standalone'}/contract/${route.id}/invalid`, [...args, '--api-constructor', 'invalid'], environment,
          { exitCode: 2, requests: 0, error: 'INVALID_INPUT', hostBoundary: hosted }, success, entry)
        coverage[route.callable ? 'admitted' : 'denied']++
      }
      return coverage
    }
    if (values['--task'] === 'S2.1' || (['S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task']) && ['S3', 'S4'].includes(values['--repeat-through']))) {
      verifyDiscovery(inventory, catalogues, (await json(join(installed, 'dist/contracts.json'))).contracts, operationPolicy)
      const bodyRoute = [...routeCases(catalogues, operationPolicy)].find(route => route.callable && route.operation.path === '/nodes/{node}/tasks')
      const bodyFile = join(scratch, 'parameters.json')
      await save(bodyFile, { node: 'pve-test', limit: 1 })
      await runCase('body-file/valid', ['get', '/nodes/{node}/tasks', '--body-file', bodyFile, '--format', 'json', '--catalogue', 'legacy-8.2.7', '--full'], env,
        { exitCode: 0, requests: 1, path: '/api2/json/nodes/pve-test/tasks?limit=1', data: bodyRoute.response },
        { httpStatus: 200, body: { data: bodyRoute.response } })
      await save(bodyFile, JSON.parse('{"node":"pve-test","__proto__":{"ignored":true}}'))
      await runCase('body-file/unknown-field', ['get', '/nodes/{node}/tasks', '--body-file', bodyFile, '--format', 'json', '--catalogue', 'legacy-8.2.7'], env,
        { exitCode: 2, requests: 0, error: 'INVALID_INPUT' })
      result.routeCoverage = await exerciseRoutes(env)
    }
    if (['S2.2', 'S2.3', 'S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task'])) await readJourney(env)
    if (['S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task'])) {
      await exerciseWriteJourney({ scratch, out, executable, caFile, env, command, cases: result.cases, ledger, transcripts })
    }
    if (values['--task'].startsWith('S4.')) await exerciseSecretJourney({ task: values['--task'], scratch, out, executable, caFile, env, cases: result.cases, ledger, transcripts })
    result.outcomes = [
      { id: 'AC-VERIFIED-VERSION', journey: 'standalone', status: 'pass', basis: 'Reviewed 8.2.7 fixture' },
      { id: 'AC-VERSION-AUTH', journey: 'standalone', status: 'pass', basis: 'Controlled 401 and invalid shapes fail' },
      { id: 'CRED-05', journey: 'standalone', status: 'pass', basis: 'Environment and protected-file canaries reach only fake HTTPS' },
      { id: 'CRED-21', journey: 'standalone', status: 'pass', basis: 'Exact installed executable and explicit profile override competing binary/config/fields' },
      { id: 'AC-HOST', journey: 'artium', status: 'pending', reason: result.host.reason },
      { id: 'CRED-19', journey: 'artium', status: 'pending', reason: result.host.reason },
    ]
    if (['S3.1', 'S3.2'].includes(values['--task'])) for (const id of ['AC-WRITES', 'AC-WRITE', 'AC-SPECIAL-BATCH-POLICY', 'AC-ASYNC', 'AC-SPECIAL-BATCH-RESULTS']) {
      result.outcomes.push({ id, journey: 'standalone', status: 'pass', basis: 'Packaged executable with durable intents and independent fake business state under process-level outbound denial.' })
    }
    if (values['--task'] !== 'S1.1') {
      for (const id of ['AC-CREDENTIALS', 'CRED-01', 'CRED-02', 'CRED-03', 'CRED-04', 'CRED-06', 'CRED-09', 'CRED-10', 'CRED-11', 'CRED-12', 'CRED-13', 'CRED-20']) {
        result.outcomes.push({ id, journey: 'standalone', status: 'pass', basis: 'Offline package cases; native platform proof remains S6.1' })
      }
    }
    if (values['--task'] === 'S2.1') for (const id of ['AC-FULL', 'AC-COVERAGE', 'VP-03', 'VP-07']) {
      result.outcomes.push({ id, journey: 'standalone', status: 'pass', basis: 'Pinned catalogue union, preserved schema constraints, generated admitted wire cases and unresolved-route zero-request refusals; deferred runtime capabilities remain blocked' })
    }
    if (hostInput) {
      const hostDirectory = join(scratch, 'host')
      await mkdir(join(hostDirectory, 'tools'), { recursive: true, mode: 0o700 })
      await symlink(join(consumer, 'node_modules'), join(hostDirectory, 'tools/node_modules'))
      const startupArgs = [fileURLToPath(new URL('./artium-host.mjs', import.meta.url)), hostInput.fixture, hostDirectory, origin, caFile]
      result.host.startup = { executable: process.execPath, args: startupArgs, cwd: hostDirectory }
      hostChild = spawn(process.execPath, startupArgs, { cwd: hostDirectory,
        env: { ...env, PROXMOX_AXI_ACCEPTANCE_HOST_TOKEN: hostedToken }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
      hostChild.stdout.on('data', chunk => hostLogs.push(chunk))
      hostChild.stderr.on('data', chunk => hostLogs.push(chunk))
      const ready = await hostMessage(hostChild, 'ready')
      result.host.ready = ready
      assert.equal(ready.namespace, result.network.namespace, 'Actual host shares the fake-only network namespace')
      assert.equal(await realpath(ready.executable), executable, 'Actual host must execute the same pinned installed package')
      const login = await fetch(`${ready.url}/v1/auth/login`, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'synthetic-user', password: 'CANARY-local-password' }) })
      assert.equal(login.status, 200, 'Real local Artium authentication')
      const session = await login.json()
      assert.equal(session.status, 'authenticated')
      secrets.push(session.accessToken, session.refreshToken)
      await verifyHostRuntime(hostInput.fixture)
      const { SessionStore } = await import(pathToFileURL(join(hostInput.fixture, 'dist/src/cli/session.js')))
      new SessionStore(ready.url, join(base.XDG_CONFIG_HOME, 'artium-axi/session.json')).write(session)
      const client = join(hostInput.fixture, 'dist/cli/artium-axi.mjs')
      const clientEnvironment = { ...env, ARTIUM_AXI_URL: ready.url, ARTIUM_AXI_TEST_HTTP: '1' }
      const secondaryLogin = await fetch(`${ready.url}/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'synthetic-secondary', password: 'CANARY-local-password' }) })
      assert.equal(secondaryLogin.status, 200)
      const secondarySession = await secondaryLogin.json()
      secrets.push(secondarySession.accessToken, secondarySession.refreshToken)
      const secondaryConfig = join(scratch, 'secondary-config')
      new SessionStore(ready.url, join(secondaryConfig, 'artium-axi/session.json')).write(secondarySession)
      const secondaryEnvironment = { ...clientEnvironment, XDG_CONFIG_HOME: secondaryConfig }
      const hostExpected = { exitCode: 0, requests: 1, version: true, profile: 'artium',
        tokenSource: 'env:ARTIUM_SECRET_0', identity: 'hosted-canary' }
      await runCase('AC-HOST/version', ['proxmox-axi', 'get', '/version', '--format', 'json'], clientEnvironment, hostExpected, success, client)
      await runCase('AC-HOST/401', ['proxmox-axi', 'get', '/version', '--format', 'json'], clientEnvironment,
        { exitCode: 1, requests: 1, error: 'AUTH_REQUIRED', identity: 'hosted-canary' }, denied, client)
      await runCase('AC-HOST/invalid-shape', ['proxmox-axi', 'get', '/version', '--format', 'json'], clientEnvironment,
        { exitCode: 1, requests: 1, error: 'INVALID_RESPONSE', identity: 'hosted-canary' }, { httpStatus: 200, body: { data: null } }, client)
      if (values['--task'] === 'S2.1' || (['S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task']) && ['S3', 'S4'].includes(values['--repeat-through']))) result.host.routeCoverage = await exerciseRoutes(clientEnvironment, client)
      if (['S2.2', 'S2.3', 'S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task'])) await readJourney(clientEnvironment, client)
      if (['S3.1', 'S3.2', 'S4.1', 'S4.2'].includes(values['--task'])) {
        await exerciseWriteJourney({ scratch, out, executable: client, caFile, env: { ...clientEnvironment, PROXMOX_AXI_TOKEN: hostedToken },
          command, cases: result.cases, ledger, transcripts, hosted: { log: join(hostDirectory, 'writes.log'), otherActorEnv: secondaryEnvironment,
            configure: async (origin, toolOperations, hostOperations, enabled) => {
              const configured = hostMessage(hostChild, 'configured-writes')
              hostChild.send({ event: 'configure-writes', origin, toolOperations, hostOperations, enabled })
              await configured
            } } })
        for (const id of ['AC-WRITES', 'AC-WRITE', 'AC-SPECIAL-BATCH-POLICY', 'AC-ASYNC', 'AC-SPECIAL-BATCH-RESULTS']) {
          result.outcomes.push({ id, journey: 'artium', status: 'pass', basis: 'Actual public client/server/runner, independent host policy and retained native journals across disposable calls.' })
        }
      }
      if (values['--task'].startsWith('S4.')) await exerciseSecretJourney({ task: values['--task'], scratch, out, executable: client, caFile,
        env: { ...clientEnvironment, PROXMOX_AXI_TOKEN: hostedToken }, cases: result.cases, ledger, transcripts,
        hosted: { otherActorEnv: secondaryEnvironment, stateDirectory: hostDirectory,
          configure: async (origin, auth, operations) => {
            const configured = hostMessage(hostChild, 'configured-s4')
            hostChild.send({ event: 'configure-s4', origin, auth, operations })
            await configured
          }, clock: async offset => {
            const changed = hostMessage(hostChild, 'clock-changed')
            hostChild.send({ event: 'clock', offset })
            await changed
          } } })
      const snapshot = hostMessage(hostChild, 'snapshot')
      hostChild.send('snapshot')
      result.host.evidence = await snapshot
      assert.deepEqual(result.host.evidence.callsRemaining, [], 'Actual runner cleans its private call directories')
      assert.deepEqual(result.host.evidence.audit.filter(row => row.event === 'run-terminal').map(row => row.exit_code),
        result.cases.filter(row => row.hosted && (!row.expected.hostBoundary || Object.hasOwn(row.expected, 'auditExit')))
          .map(row => Object.hasOwn(row.expected, 'auditExit') ? row.expected.auditExit : row.actual.exitCode), 'Actual host audit records public command outcomes')
      result.host.status = 'pass'
      result.outcomes = result.outcomes.filter(row => row.journey !== 'artium' || row.status !== 'pending')
      for (const id of ['AC-HOST', 'AC-VERSION-AUTH', 'AC-VERIFIED-VERSION', 'CRED-05', 'CRED-19', 'CRED-21']) {
        result.outcomes.push({ id, journey: 'artium', status: 'pass', basis: 'Actual public client/server/runner with private injected artium profile and distinct vendor canary' })
      }
      if (values['--task'] === 'S2.1') for (const id of ['AC-FULL', 'AC-COVERAGE', 'VP-03', 'VP-07']) {
        result.outcomes.push({ id, journey: 'artium', status: 'pass', basis: 'Same generated table through the actual public client, adapter and runner; unresolved calls refused by the closed host inventory' })
      }
    }
    if (['S2.2', 'S2.3'].includes(values['--task'])) {
      for (const journey of hostInput ? ['standalone', 'artium'] : ['standalone']) for (const id of
        values['--task'] === 'S2.3' ? ['AC-READ', 'AC-PERMISSIONS', 'AC-VERSIONS', 'VP-01', 'VP-02', 'VP-03', 'VP-04', 'VP-05', 'VP-06', 'VP-07', 'VP-08'] : ['AC-READ', 'AC-PERMISSIONS']) {
        result.outcomes.push({ id, journey, status: 'pass', basis: 'Retained fixture replay, bounded presentation, permission visibility and version capability cases; TLS rotation remains explicit.' })
      }
    }
    result.status = 'pass'
    result.scope = hostInput ? `${result.task} through both journeys using the unmerged admission fixture; stock Artium is unsupported.` : `Standalone subset only; full ${result.task} requires --through both.`
  } catch (error) {
    result.failure = publicText(error.message)
    process.exitCode = 1
  } finally {
    if (hostChild && hostChild.exitCode === null && hostChild.signalCode === null) {
      const stopped = new Promise(resolve => hostChild.once('close', resolve))
      if (hostChild.connected) hostChild.send('stop')
      else hostChild.kill('SIGTERM')
      await stopped
    }
    if (server) await new Promise(resolve => { server.close(resolve); server.closeAllConnections() })
    await writeFile(join(out, 'result.json'), publicText(`${JSON.stringify(result, null, 2)}\n`))
    await writeFile(join(out, 'requests.jsonl'), ledger.map(row => JSON.stringify(row)).join('\n') + (ledger.length ? '\n' : ''))
    await save(join(out, 'tls-errors.json'), tlsErrors)
    await writeFile(join(out, 'host-startup.txt'), publicText(Buffer.concat(hostLogs).toString()))
    await writeFile(join(out, 'public-output.txt'), publicText(transcripts.join('\n')))
  }
  console.log(JSON.stringify({ task: result.task, scope: result.scope, status: result.status, cases: result.cases.length,
    failure: result.failure, evidence: join(out, 'result.json') }))
}

let scratch
let values
try {
  values = selection(process.argv.slice(2))
  if (!process.env.PROXMOX_AXI_ACCEPTANCE_NETNS) {
    // Install dependencies before denying network access to the product journeys.
    await mkdir(values['--out'], { recursive: false, mode: 0o700 })
    scratch = await mkdtemp(join(values['--out'], '.private-'))
    const prepared = await preparePackage(values, values['--out'], scratch)
    await save(join(scratch, 'prepared.json'), prepared)
    const parentNamespace = await readlink('/proc/self/ns/net')
    const isolated = await command('unshare', ['--user', '--map-root-user', '--net', process.execPath,
      fileURLToPath(import.meta.url), ...process.argv.slice(2)],
    // Full S3.2 replays have run close to the former aggregate 30-minute cap.
    { timeoutMs: values['--task'].startsWith('S4.') ? 3_600_000 : values['--task'] === 'S3.2' && values['--repeat-through'] === 'S3' ? 2_700_000 :
      values['--task'] === 'S2.1' || values['--repeat-through'] === 'S3' ? 1_800_000 : 300_000,
      env: { ...process.env, PROXMOX_AXI_ACCEPTANCE_NETNS: parentNamespace, PROXMOX_AXI_ACCEPTANCE_SCRATCH: scratch } })
    process.stdout.write(isolated.stdout)
    process.stderr.write(isolated.stderr)
    process.exitCode = isolated.code
  } else {
    assert.notEqual(await readlink('/proc/self/ns/net'), process.env.PROXMOX_AXI_ACCEPTANCE_NETNS, 'Must create a new network namespace')
    assert.ok(Object.keys(networkInterfaces()).every(name => name === 'lo'), 'Must isolate networking before configuring loopback')
    await checked('ip', ['link', 'set', 'lo', 'up'])
    const preparedScratch = process.env.PROXMOX_AXI_ACCEPTANCE_SCRATCH
    await verify(values, await json(join(preparedScratch, 'prepared.json')), preparedScratch)
  }
} catch (error) {
  if (scratch) {
    await save(join(values['--out'], 'result.json'), { status: 'fail', failure: error.message, cases: [], host: { status: 'pending' } })
  }
  console.log(JSON.stringify({ status: 'fail', error: error.message }))
  process.exitCode = 1
} finally {
  if (scratch) await rm(scratch, { recursive: true, force: true })
}

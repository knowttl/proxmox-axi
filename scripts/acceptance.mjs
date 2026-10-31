import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:https'
import { createConnection } from 'node:net'
import { networkInterfaces } from 'node:os'
import { chmod, mkdir, mkdtemp, readFile, readlink, realpath, rm, writeFile } from 'node:fs/promises'
import { isAbsolute, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decode } from '@toon-format/toon'

const root = fileURLToPath(new URL('../', import.meta.url))
const digest = (bytes, algorithm = 'sha256') => createHash(algorithm).update(bytes).digest(algorithm === 'sha512' ? 'base64' : 'hex')
const json = async path => JSON.parse(await readFile(path, 'utf8'))
const save = (path, value) => writeFile(path, `${JSON.stringify(value, null, 2)}\n`)

async function command(executable, args, options = {}) {
  const child = spawn(executable, args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], ...options })
  const stdout = [], stderr = []
  let bytes = 0
  const timer = setTimeout(() => child.kill('SIGKILL'), 60_000)
  for (const [stream, chunks] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', chunk => {
    bytes += chunk.length
    if (bytes > 1_048_576) child.kill('SIGKILL')
    else chunks.push(chunk)
  })
  return await new Promise((resolve, reject) => {
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', (code, signal) => {
      clearTimeout(timer)
      const result = { code, signal, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }
      if (signal) reject(new Error(`Command terminated by ${signal}`))
      else resolve(result)
    })
  })
}

async function checked(executable, args, options) {
  const result = await command(executable, args, options)
  assert.equal(result.code, 0, `${executable} failed: ${result.stderr || result.stdout}`)
  return result.stdout.trim()
}

function selection(args) {
  const values = {}
  for (let index = 0; index < args.length; index++) {
    const key = args[index]
    if (key === '--' && index === 0) continue
    assert.ok(['--task', '--pack', '--out', '--network', '--through'].includes(key), `Unknown argument: ${key}`)
    assert.equal(values[key], undefined, `Duplicate argument: ${key}`)
    const value = args[++index]
    assert.ok(value && !value.startsWith('--'), `Missing value for ${key}`)
    values[key] = value
  }
  assert.equal(values['--task'], 'S1.1', 'Only task S1.1 is implemented')
  assert.equal(values['--network'], 'fake-only', 'Only fake-only networking is permitted')
  assert.ok(['standalone', 'both'].includes(values['--through']), 'Select --through standalone or both')
  for (const key of ['--pack', '--out']) assert.ok(values[key] && isAbsolute(values[key]), `${key} must be absolute`)
  const outputRelative = relative(root, values['--out'])
  assert.ok(outputRelative === '..' || outputRelative.startsWith(`..${sep}`) || isAbsolute(outputRelative), '--out must be outside the source tree')
  return values
}

async function verify(values) {
  const out = values['--out']
  // Refuse reuse so stale evidence cannot be mistaken for this run.
  await mkdir(out, { recursive: false, mode: 0o700 })
  const scratch = await mkdtemp(join(out, '.private-'))
  const ledger = [], transcripts = [], tlsErrors = []
  const secrets = []
  const publicText = value => {
    for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1)]) {
      value = value.replaceAll(form, '[REDACTED]')
    }
    return value
  }
  const result = { task: 'S1.1', through: values['--through'], platform: `${process.platform}/${process.arch}`,
    node: process.version, operation: 'OP-GET-version', catalogue: 'legacy-8.2.7',
    cases: [], status: 'fail', host: { status: 'pending', reason: 'Actual Artium admission is awaiting the host owner; no adapter substitute is used.' } }
  let server
  try {
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

    await checked('pnpm', ['pack', '--pack-destination', out], { env: { ...process.env, npm_config_offline: 'true' } })
    const pkg = await json(join(root, 'package.json'))
    const archive = join(out, `knowttl-proxmox-axi-${pkg.version}.tgz`)
    const archiveBytes = await readFile(archive)
    const consumer = join(scratch, 'consumer')
    await mkdir(consumer)
    await save(join(consumer, 'package.json'), { private: true, packageManager: pkg.packageManager,
      dependencies: { [pkg.name]: `file:${archive}` }, pnpm: pkg.pnpm })
    await checked('pnpm', ['install', '--offline', '--ignore-scripts'], { cwd: consumer })
    const installed = await realpath(join(consumer, 'node_modules/@knowttl/proxmox-axi'))
    const executable = join(installed, 'bin/proxmox-axi.mjs')
    assert.notEqual(installed, root, 'Must execute the installed archive, not source')
    const installedPackage = await json(join(installed, 'package.json'))
    assert.equal(installedPackage.name, pkg.name)
    assert.equal(installedPackage.version, pkg.version)
    const inventory = await json(join(installed, 'inventory.json'))
    assert.deepEqual(inventory.operations.map(({ id, method, path, command }) => ({ id, method, path, command })),
      [{ id: 'OP-GET-version', method: 'GET', path: '/version', command: ['get', '/version'] }], 'Admit exactly the reviewed version read')
    const helpMetadata = await json(join(installed, 'help.json'))
    assert.deepEqual(helpMetadata.commands.map(entry => entry.command), ['get /version'], 'Generated help command boundary')
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
    const token = 'CANARY-proxmox-token-S1-1'
    const fileToken = 'CANARY-proxmox-file-token-S1-1'
    const decoy = 'CANARY-developer-profile-S1-1'
    secrets.push(token, fileToken, decoy)
    const tokenId = 'synthetic@pve!acceptance'
    let response = success
    let activeCase = ''
    server = createServer({ key: await readFile(join(scratch, 'server.key')), cert: await readFile(caFile) }, (request, reply) => {
      const authorization = request.headers.authorization
      const identity = authorization === `PVEAPIToken=${tokenId}=${token}` ? 'environment-canary' :
        authorization === `PVEAPIToken=${tokenId}=${fileToken}` ? 'protected-file-canary' : 'unexpected'
      ledger.push({ case: activeCase, method: request.method, path: request.url, identity,
        host: request.headers.host, status: identity === 'unexpected' ? 401 : response.httpStatus })
      if (identity === 'unexpected') { reply.writeHead(401); reply.end(); return }
      reply.writeHead(response.httpStatus, { 'Content-Type': 'application/json', ...(response.headers ?? {}) })
      reply.end(typeof response.body === 'string' ? response.body : JSON.stringify(response.body))
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
    await writeFile(secretFile, `\uFEFF${fileToken}\r\n`, { mode: 0o600 })
    await save(config, { version: 1, defaultProfile: 'selected', profiles: {
      selected: { auth: 'api-token', origin, tokenId, token: { file: secretFile }, caBundle: caFile },
    } })
    await chmod(config, 0o600)
    const base = { HOME: home, XDG_CONFIG_HOME: join(home, '.config'), XDG_STATE_HOME: join(home, '.local/state'),
      TMPDIR: scratch, PATH: `${join(scratch, 'decoy-bin')}:/usr/bin:/bin`, DEVELOPER_TOKEN: decoy }
    const env = { ...base, PROXMOX_AXI_ORIGIN: origin, PROXMOX_AXI_TOKEN_ID: tokenId,
      PROXMOX_AXI_TOKEN: token, PROXMOX_AXI_CA_BUNDLE: caFile }

    const runCase = async (id, args, environment, expected, vendor = success) => {
      activeCase = id
      response = vendor
      const before = ledger.length
      const diagnostics = join(scratch, 'transport.jsonl')
      await writeFile(diagnostics, '')
      const invocation = ['--import', fileURLToPath(new URL('./transport-observer.mjs', import.meta.url)), executable, ...args]
      const start = performance.now()
      const actual = await command(process.execPath, invocation,
        { env: { ...environment, PROXMOX_AXI_TEST_DIAGNOSTICS: diagnostics }, cwd: scratch })
      const record = { id, status: 'fail', expected, actual: { exitCode: actual.code, requests: ledger.length - before },
        invocation: { executable: process.execPath, args: invocation.map(publicText) }, elapsedMs: Math.round(performance.now() - start),
        transportDiagnostics: (await readFile(diagnostics, 'utf8')).split('\n').filter(Boolean).map(line => JSON.parse(line)) }
      result.cases.push(record)
      for (const value of [token, fileToken, decoy]) {
        assert.ok(!`${actual.stdout}${actual.stderr}`.includes(value), `${id}: secret leaked to public output`)
      }
      transcripts.push(`case: ${id}\nexit: ${actual.code}\nstdout:\n${actual.stdout}stderr:\n${actual.stderr}`)
      const value = expected.bareVersion ? undefined : args.includes('json') ? JSON.parse(actual.stdout) : decode(actual.stdout)
      record.actual.output = value
      assert.equal(actual.stderr, '', `${id}: no raw diagnostics on stderr`)
      assert.equal(actual.code, expected.exitCode, `${id}: exit code; stdout=${actual.stdout}`)
      if (expected.error) assert.equal(value.error?.code, expected.error, `${id}: observed public code ${value.error?.code ?? 'none'}`)
      assert.equal(record.actual.requests, expected.requests,
        `${id}: request count; observed public code ${value?.error?.code ?? 'none'}; transport codes ${record.transportDiagnostics.map(entry => entry.code).join(',')}`)
      assert.ok(record.elapsedMs < 10_000, `${id}: elapsed budget`)
      assert.ok(Buffer.byteLength(actual.stdout) < 8192, `${id}: public output budget`)
      if (expected.version || expected.error || expected.profile) {
        if (expected.version) assert.deepEqual(value.version, success.body.data, `${id}: reviewed version fields`)
        if (expected.profile) assert.equal(value.credential.profile, expected.profile, `${id}: credential source`)
        if (expected.tokenSource) assert.equal(value.credential.tokenSource, expected.tokenSource, `${id}: secret reference source`)
      } else if (expected.bareVersion) assert.equal(actual.stdout, `${pkg.version}\n`)
      else if (expected.help) {
        assert.equal(value.purpose, helpMetadata.commands[0].purpose, `${id}: help matches admitted command`)
        assert.ok(value.usage.startsWith('proxmox-axi get /version '), `${id}: invocable version help`)
      }
      for (const request of ledger.slice(before)) {
        assert.equal(request.method, 'GET', `${id}: method`)
        assert.equal(request.path, '/api2/json/version', `${id}: exact wire route`)
        assert.equal(request.identity, expected.identity ?? 'environment-canary', `${id}: credential at vendor boundary`)
      }
      record.status = 'pass'
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
    await runCase('unknown-route', ['get', '/nodes'], env, { exitCode: 2, requests: 0, error: 'INVALID_INPUT' })
    await runCase('source-diagnostics', ['auth', 'status', '--format', 'json'], env,
      { exitCode: 0, requests: 0, profile: 'environment', tokenSource: 'env:PROXMOX_AXI_TOKEN' })
    await runCase('missing-profile', ['get', '/version', '--format', 'json'],
      { ...base, PROXMOX_AXI_CONFIG: join(scratch, 'absent.json') }, { exitCode: 1, requests: 0, error: 'AUTH_REQUIRED' })
    await runCase('partial-environment', ['get', '/version', '--format', 'json'],
      { ...base, PROXMOX_AXI_ORIGIN: origin }, { exitCode: 1, requests: 0, error: 'CONFIG_INVALID' })
    for (const flag of ['-v', '-V', '--version']) await runCase(`package-version/${flag}`, [flag], base,
      { exitCode: 0, requests: 0, bareVersion: true })
    await runCase('offline-help', ['get', '--help'], base, { exitCode: 0, requests: 0, help: true })
    result.outcomes = [
      { id: 'AC-VERIFIED-VERSION', journey: 'standalone', status: 'pass', basis: 'Reviewed 8.2.7 fixture' },
      { id: 'AC-VERSION-AUTH', journey: 'standalone', status: 'pass', basis: 'Controlled 401 and invalid shapes fail' },
      { id: 'CRED-05', journey: 'standalone', status: 'pass', basis: 'Environment and protected-file canaries reach only fake HTTPS' },
      { id: 'CRED-21', journey: 'standalone', status: 'pass', basis: 'Exact installed executable and explicit profile override competing binary/config/fields' },
      { id: 'AC-HOST', journey: 'artium', status: 'pending', reason: result.host.reason },
      { id: 'CRED-19', journey: 'artium', status: 'pending', reason: result.host.reason },
    ]
    if (values['--through'] === 'both') throw new Error('Actual Artium journey is pending host admission; --through both cannot pass.')
    result.status = 'pass'
    result.scope = 'Standalone subset only; full S1.1 remains pending.'
  } catch (error) {
    result.failure = publicText(error.message)
    process.exitCode = 1
  } finally {
    if (server) await new Promise(resolve => { server.close(resolve); server.closeAllConnections() })
    await writeFile(join(out, 'result.json'), publicText(`${JSON.stringify(result, null, 2)}\n`))
    await writeFile(join(out, 'requests.jsonl'), ledger.map(row => JSON.stringify(row)).join('\n') + (ledger.length ? '\n' : ''))
    await save(join(out, 'tls-errors.json'), tlsErrors)
    await writeFile(join(out, 'public-output.txt'), publicText(transcripts.join('\n')))
    await rm(scratch, { recursive: true, force: true })
  }
  console.log(JSON.stringify({ task: result.task, scope: result.scope, status: result.status, cases: result.cases.length,
    failure: result.failure, evidence: join(out, 'result.json') }))
}

try {
  const values = selection(process.argv.slice(2))
  if (!process.env.PROXMOX_AXI_ACCEPTANCE_NETNS) {
    const parentNamespace = await readlink('/proc/self/ns/net')
    const isolated = await command('unshare', ['--user', '--map-root-user', '--net', process.execPath,
      fileURLToPath(import.meta.url), ...process.argv.slice(2)],
    { env: { ...process.env, PROXMOX_AXI_ACCEPTANCE_NETNS: parentNamespace } })
    process.stdout.write(isolated.stdout)
    process.stderr.write(isolated.stderr)
    process.exitCode = isolated.code
  } else {
    assert.notEqual(await readlink('/proc/self/ns/net'), process.env.PROXMOX_AXI_ACCEPTANCE_NETNS, 'Must create a new network namespace')
    assert.ok(Object.keys(networkInterfaces()).every(name => name === 'lo'), 'Must isolate networking before configuring loopback')
    await checked('ip', ['link', 'set', 'lo', 'up'])
    await verify(values)
  }
} catch (error) {
  console.log(JSON.stringify({ status: 'fail', error: error.message }))
  process.exitCode = 1
}

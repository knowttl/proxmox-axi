import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { copyFile, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

interface Coverage { id: string, status: string, evidence: string[] }
interface AcceptanceResult {
  status: string
  failure?: string
  host: { status: string }
  cases: { id: string, status: string }[]
  routeCoverage: { union: number, variants: number }
  native: { linux: string, windows: string, reason: string }
  admission: { status: string, baseline: { version: string }, coexistence: { status: string, ownedVersion: string }, completeness: { variants: number, status: string, unresolved: number } }
  package: { version: string }
  caseCoverage: Coverage[]
  outcomeCoverage: Coverage[]
  outcomes: { id: string, journey: string, status: string }[]
}


for (const scenario of [
  { name: 'native Linux paths and private files satisfy S6.1 with outbound networking denied', task: 'S6.1', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'immutable installed package records S6.2 admission gaps with outbound networking denied', task: 'S6.2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'packaged byte transfers satisfy S5.1 with outbound networking denied', task: 'S5.1', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'packaged console and migration messages satisfy S5.2 with outbound networking denied', task: 'S5.2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'installed tarball satisfies canonical credentials with external egress denied', task: 'S1.2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'generated route cases satisfy the checked catalogue and admission policy', task: 'S2.1', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: '#12 S2 repeat records every release route during read acceptance', task: 'S2.3', repeat: 'S2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'retained reads preserve permission visibility and bounded output', task: 'S2.2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'mixed node capabilities and bounded doctor use selected contracts', task: 'S2.3', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'packaged writes preserve confirmations and durable outcomes with outbound networking denied', task: 'S3.2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'packaged private results and memory authentication satisfy S4 with outbound networking denied', task: 'S4.2', through: 'standalone', exitCode: 0, status: 'pass', host: 'pending' },
  { name: 'actual pinned Artium private results and memory authentication satisfy S4', task: 'S4.2', through: 'both', exitCode: 0, status: 'pass', host: 'pass' },
  { name: 'actual pinned Artium write policy and durable journals satisfy S3', task: 'S3.2', through: 'both', exitCode: 0, status: 'pass', host: 'pass' },
  { name: 'actual pinned Artium client server and runner satisfy S1.1', through: 'both', exitCode: 0, status: 'pass', host: 'pass' },
  { name: 'both journeys reject missing host fixture inputs', through: 'both', exitCode: 1, status: 'fail', host: 'pending', missingHost: true,
    failure: '--through both requires PROXMOX_AXI_ARTIUM_FIXTURE and PROXMOX_AXI_ARTIUM_MANIFEST' },
]) test(scenario.name, {
  skip: scenario.through === 'both' && !scenario.missingHost && !process.env.PROXMOX_AXI_ARTIUM_FIXTURE
    ? 'Artium fixture not supplied' : false,
}, async () => {
  const root = fileURLToPath(new URL('../', import.meta.url))
  const temporary = await mkdtemp(join(tmpdir(), 'proxmox-axi-test-'))
  const out = join(temporary, 'S1.1')
  try {
    const child = spawn(process.execPath, [join(root, 'scripts/acceptance.ts'), '--task', scenario.task ?? 'S1.1',
      '--pack', join(root, 'evidence'), '--out', out, '--network', 'fake-only', '--through', scenario.through,
      ...(scenario.repeat ? ['--repeat-through', scenario.repeat] : [])],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env,
      ...(scenario.missingHost ? { PROXMOX_AXI_ARTIUM_FIXTURE: '', PROXMOX_AXI_ARTIUM_MANIFEST: '' } : {}) } })
    const output: Buffer[] = []
    child.stdout.on('data', chunk => output.push(chunk))
    child.stderr.on('data', chunk => output.push(chunk))
    const exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal(exitCode, scenario.exitCode, Buffer.concat(output).toString())
    const result = JSON.parse(await readFile(join(out, 'result.json'), 'utf8')) as AcceptanceResult
    assert.equal(result.status, scenario.status, result.failure)
    assert.equal(result.failure, scenario.failure)
    assert.equal(result.host.status, scenario.host)
    assert.equal(result.cases.every(entry => entry.status === 'pass'), true, result.failure)
    if (scenario.repeat === 'S2') {
      assert.equal(result.routeCoverage.union, 681)
      assert.equal(result.routeCoverage.variants, 1285)
      for (const [release, count] of [['legacy-8.2.7', 605], ['published-current', 680]] as const) {
        assert.equal(result.cases.filter(row => row.id.startsWith(`standalone/contract/${release}/`) && row.id.endsWith('/required/valid')).length, count)
        assert.equal(result.cases.filter(row => row.id.startsWith(`standalone/contract/${release}/`) && row.id.endsWith('/required/invalid')).length, count)
      }
    }
    if (scenario.task?.startsWith('S6.')) {
      assert.deepEqual(result.native, { linux: 'pass', windows: 'pending', reason: 'Native Windows machine unavailable; Linux is not a substitute.' })
      assert.equal(result.admission.status, 'pass')
      assert.equal(result.admission.baseline.version, '0.0.1')
      assert.equal(result.admission.coexistence.status, 'pass')
      assert.equal(result.admission.coexistence.ownedVersion, result.package.version)
      assert.equal(result.admission.completeness.variants, 1285)
      assert.equal(result.admission.completeness.status, 'pending')
      assert.ok(result.admission.completeness.unresolved > 0)
      assert.equal(result.caseCoverage.find(row => row.id === 'CRED-08')!.status, 'pass')
      assert.equal(result.caseCoverage.find(row => row.id === 'CRED-07')!.status, 'pending')
      for (const id of ['CRED-01', 'CRED-02', 'CRED-03', 'CRED-12']) {
        const coverage = result.caseCoverage.find(row => row.id === id)!
        assert.equal(coverage.status, 'pass', `#31 executed exact ID ${id}`)
        assert.ok(coverage.evidence.includes(id))
      }
      for (const [id, evidence] of [
        ['AC-TRANSFER', 'S5.2/upload-confirm'],
        ['AC-TRANSPORT', 'S5.2/upload-confirm'],
        ['AC-SPECIAL-GUEST-FILE', 'S5.2/guest-16777216-bytes'],
        ['AC-STREAM', 'S5.2/qemu/{vmid}/vncproxy-frames'],
        ['AC-SPECIAL-BATCH-POLICY', 'S5.2/batch-cannot-open-byte-channel'],
      ] as const) {
        const coverage = result.outcomeCoverage.find(row => row.id === id)!
        assert.equal(coverage.status, 'pass', `#31 mapped transport outcome ${id}`)
        assert.ok(coverage.evidence.includes(evidence))
      }
      for (const id of ['AC-HOST', 'AC-FULL', 'AC-COVERAGE', 'AC-PLATFORM']) assert.equal(result.outcomeCoverage.find(row => row.id === id)!.status, 'pending')
    }
    if (scenario.task === 'S3.2' && scenario.through === 'both') {
      assert.deepEqual(result.outcomes.filter(row => row.journey === 'artium' && [
        'AC-WRITES', 'AC-WRITE', 'AC-SPECIAL-BATCH-POLICY', 'AC-ASYNC', 'AC-SPECIAL-BATCH-RESULTS',
      ].includes(row.id)).map(row => ({ id: row.id, status: row.status })), [
        { id: 'AC-WRITES', status: 'pass' }, { id: 'AC-WRITE', status: 'pass' },
        { id: 'AC-SPECIAL-BATCH-POLICY', status: 'pass' }, { id: 'AC-ASYNC', status: 'pass' },
        { id: 'AC-SPECIAL-BATCH-RESULTS', status: 'pass' },
      ])
    }
  } catch (error) {
    if (process.env.PROXMOX_AXI_TEST_FAILURE_DIR) {
      await mkdir(process.env.PROXMOX_AXI_TEST_FAILURE_DIR, { recursive: true, mode: 0o700 })
      const failure = await mkdtemp(join(process.env.PROXMOX_AXI_TEST_FAILURE_DIR, `${scenario.through}-`))
      for (const name of ['result.json', 'public-output.txt', 'requests.jsonl', 'tls-errors.json']) {
        await copyFile(join(out, name), join(failure, name))
      }
      console.error(`Sanitized failure evidence: ${failure}`)
    }
    throw error
  } finally { await rm(temporary, { recursive: true, force: true }) }
})

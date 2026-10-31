import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { copyFile, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

for (const scenario of [
  { name: 'installed tarball satisfies the standalone S1.1 journey with external egress denied', through: 'standalone', exitCode: 0, status: 'pass' },
  { name: 'both journeys cannot pass without actual Artium admission', through: 'both', exitCode: 1, status: 'fail',
    failure: 'Actual Artium journey is pending host admission; --through both cannot pass.' },
]) test(scenario.name, async () => {
  const root = fileURLToPath(new URL('../', import.meta.url))
  const temporary = await mkdtemp(join(tmpdir(), 'proxmox-axi-test-'))
  const out = join(temporary, 'S1.1')
  try {
    const child = spawn(process.execPath, [join(root, 'scripts/acceptance.mjs'), '--task', 'S1.1',
      '--pack', join(root, 'evidence'), '--out', out, '--network', 'fake-only', '--through', scenario.through],
    { stdio: ['ignore', 'pipe', 'pipe'] })
    const output = []
    child.stdout.on('data', chunk => output.push(chunk))
    child.stderr.on('data', chunk => output.push(chunk))
    const exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve) })
    assert.equal(exitCode, scenario.exitCode, Buffer.concat(output).toString())
    const result = JSON.parse(await readFile(join(out, 'result.json'), 'utf8'))
    assert.equal(result.status, scenario.status, result.failure)
    assert.equal(result.failure, scenario.failure)
    assert.equal(result.host.status, 'pending')
    assert.equal(result.cases.every(entry => entry.status === 'pass'), true, result.failure)
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

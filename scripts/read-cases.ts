import type { VendorResponse } from './acceptance.ts'
import type { Contract } from '../src/contract.ts'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

// Reconstruct commands from retained requests, rather than a second route table.
export async function retainedReads(pack: string, retained: { path: string }[], contracts: Pick<Contract, 'method' | 'path' | 'release'>[]) {
  const cases = []
  for (const fixture of retained.filter(row => /-request\.json$/.test(row.path))) {
    const request: { path: string, method: string } = JSON.parse(await readFile(join(pack, fixture.path), 'utf8'))
    const response: VendorResponse & { body: { data: unknown } } = JSON.parse(await readFile(join(pack, fixture.path.replace('-request', '-response')), 'utf8'))
    const url = new URL(request.path, 'https://fixture.invalid')
    const path = url.pathname.replace('/api2/json', '')
    const contract = contracts.find(contract => contract.release === 'legacy-8.2.7' && contract.method === request.method &&
      new RegExp('^' + contract.path.replace(/\{[^}]+\}/g, '[^/]+') + '$').test(path))
    assert.ok(contract, fixture.path)
    const names = [...contract.path.matchAll(/\{([^}]+)\}/g)].map(match => match[1]!)
    const match = new RegExp('^' + contract.path.replace(/\{[^}]+\}/g, '([^/]+)') + '$').exec(path)
    const values: Record<string, string> = Object.fromEntries([...names.map((name, index) => [name, decodeURIComponent(match![index + 1]!)] as const), ...url.searchParams])
    const args = ['get', contract.path, ...Object.entries(values).flatMap(([key, value]) => [`--api-${key}`, value])]
    const query = url.searchParams.toString()
    cases.push({ id: fixture.path, path: `${url.pathname}${query ? '?' + query : ''}`, contract, values, args, response,
      verified: fixture.path.includes('VERIFIED'), expected: response.body.data })
  }
  return cases
}

import type { AddressInfo } from 'node:net'
import type { IncomingMessage } from 'node:http'
import assert from 'node:assert/strict'
import { createServer, get } from 'node:http'
import test from 'node:test'
import { responseFailure } from '../dist/errors.js'
import { PrivateResults } from '../dist/private-results.js'

const permission = 'Permission check failed (/, Pool.Allocate)'
for (const operation of ['Request', 'Transfer'] as const) {
  for (const { name, status, statusMessage, body, expected } of [
    { name: 'legacy permission status', status: 403, statusMessage: permission, body: { data: null }, expected: permission },
    { name: 'modern permission body', status: 403, statusMessage: 'Forbidden', body: { data: null, message: permission }, expected: permission },
    { name: 'body message precedence', status: 403, statusMessage: 'Permission check failed (/, VM.Audit)', body: { data: null, message: permission }, expected: permission },
    { name: 'parameter detail', status: 400, statusMessage: 'Parameter verification failed.', body: { data: null, errors: { poolid: 'invalid format' } }, expected: 'poolid: invalid format' },
    { name: 'private permission path', status: 403, statusMessage: 'Permission check failed (/nodes/private-host, Pool.Allocate)', body: { data: null }, expected: 'Permission check failed ([REDACTED], Pool.Allocate)' },
    { name: 'protected permission value', status: 403, statusMessage: permission, body: { data: null }, expected: 'Permission check failed (/, [REDACTED])' },
    { name: 'unrecognized status text', status: 403, statusMessage: 'private-host synthetic-secret', body: { data: null }, expected: '' },
    { name: 'oversized status hint', status: 403, statusMessage: `Permission check failed (/${'x'.repeat(1100)}, Pool.Allocate)`, body: { data: null }, expected: '' },
  ]) {
    test(`${operation} preserves sanitized ${name}`, async () => {
      const results = new PrivateResults()
      results.register(name === 'protected permission value' ? 'Pool.Allocate' : 'synthetic-secret')
      const server = createServer((_request, response) => response.writeHead(status, statusMessage).end(JSON.stringify(body)))
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      try {
        const response = await new Promise<IncomingMessage>((resolve, reject) => get(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, resolve).once('error', reject))
        const failure = await responseFailure(response, operation, results)
        assert.equal(failure.message, `${operation} returned HTTP ${status}.${expected ? ` ${expected}` : ''}`)
        assert.equal(failure.httpStatus, status)
        assert.equal(failure.code, status === 403 ? 'PERMISSION_DENIED' : 'HTTP_ERROR')
        assert.doesNotMatch(failure.message, /private-host|synthetic-secret/)
      } finally { await new Promise(resolve => server.close(resolve)) }
    })
  }
}

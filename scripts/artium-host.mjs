import { readFileSync, readdirSync, readlinkSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { verifyHostRuntime } from './host-identity.mjs'

const [fixture, directory, origin, caFile] = process.argv.slice(2)
await verifyHostRuntime(fixture)
const load = path => import(pathToFileURL(join(fixture, 'dist', path)))
const { createApp } = await load('src/server/app.js')
const { createProxmoxAdapter } = await load('src/server/adapters/proxmox.js')
const { Audit } = await load('src/server/audit/audit.js')
const { SharedIdentityResolver } = await load('src/server/policy/identity-resolver.js')
const { Runner } = await load('src/server/runner/runner.js')
const { createCredentialStore, openStore } = await load('src/server/store/db.js')
const { EnvironmentKeyProvider } = await load('src/server/store/key-provider.js')
const { EmbeddedSecretSource } = await load('src/server/store/secret-source.js')
const { loadTrustedCa } = await load('src/server/trusted-ca.js')
const { seedToolUser } = await load('test/fixtures/tokens.js')
const { toolPaths, healthDefaults } = await load('src/server/config.js')

// Scheduled health reads must not enter the requested-operation ledger during this bounded replay.
healthDefaults.tickMs = 1_800_001

// Seed real stores using the host's existing synthetic-user builder. HTTP,
// authentication, profile writing, adapter execution and runner are unchanged.
const provider = new EnvironmentKeyProvider({ ARTIUM_AXI_MASTER_KEY: Buffer.alloc(32, 9).toString('base64') })
const db = openStore(join(directory, 'artium.db'), provider)
await seedToolUser(db)
db.exec(`INSERT INTO users (id, username, display_name, password_hash, must_change)
  SELECT 'synthetic-secondary-user', 'synthetic-secondary', 'Secondary Synthetic User', password_hash, 0
  FROM users WHERE id = 'synthetic-development-user';
  INSERT INTO user_roles (user_id, role_id) VALUES ('synthetic-secondary-user', 'synthetic-role')`)
const store = createCredentialStore(db, provider)
store.replaceCredential('proxmox-axi', { auth: 'api-token', origin, tokenId: 'synthetic@pve!acceptance',
  token: process.env.PROXMOX_AXI_ACCEPTANCE_HOST_TOKEN, caBundle: readFileSync(caFile, 'utf8') },
0, 'synthetic-development-user', Date.now())
db.prepare("UPDATE tools SET enabled = 1 WHERE name = 'proxmox-axi'").run()
const source = new EmbeddedSecretSource(store)
const runner = await Runner.create(join(directory, 'calls'), loadTrustedCa({ ARTIUM_AXI_EXTRA_CA_FILE: caFile }))
const app = createApp({ db, audit: new Audit(db, Date.now, () => {}), runner, credentialStore: store,
  resolver: new SharedIdentityResolver(store), environment: {},
  adapters: [createProxmoxAdapter(source, join(directory, 'writes.log'))] })
const url = await app.listen({ host: '127.0.0.1', port: 0 })
process.send({ event: 'ready', url, pid: process.pid, executable: toolPaths['proxmox-axi'], namespace: readlinkSync('/proc/self/ns/net') })
process.on('message', async message => {
  if (message && typeof message === 'object' && message.event === 'configure-writes') {
    const current = store.findCredential('proxmox-axi')
    store.replaceCredential('proxmox-axi', { auth: 'api-token', origin: message.origin, tokenId: 'synthetic@pve!acceptance',
      token: process.env.PROXMOX_AXI_ACCEPTANCE_HOST_TOKEN, caBundle: readFileSync(caFile, 'utf8'), writes: { operations: message.toolOperations } },
    current?.revision ?? 0, 'synthetic-development-user', Date.now())
    db.prepare("UPDATE tools SET native_settings = ? WHERE name = 'proxmox-axi'")
      .run(JSON.stringify({ hostWrites: { allowWrites: message.enabled, operations: message.hostOperations } }))
    process.send({ event: 'configured-writes' })
  }
  if (message === 'snapshot') process.send({ event: 'snapshot', callsRemaining: readdirSync(join(directory, 'calls')),
    audit: db.prepare("SELECT event, tool, arguments, exit_code, error_code, action FROM audit WHERE tool = 'proxmox-axi' ORDER BY id").all() })
  if (message === 'stop') {
    await app.close()
    await runner.shutdown()
    db.close()
    process.disconnect()
  }
})

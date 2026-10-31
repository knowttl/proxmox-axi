import { lstat, open } from 'node:fs/promises'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { Ajv } from 'ajv'
import schema from './profile-schema.json' with { type: 'json' }
import { Failure } from './errors.js'

type SecretRef = { env: string } | { file: string }
interface Profile { auth: 'api-token', origin: string, tokenId: string, token?: SecretRef, caBundle?: string }
export interface Credentials {
  origin: string
  tokenId: string
  token: string
  ca?: string
  diagnostics: { profile: string, source: string, tokenSource: string }
}

const validateProfile = new Ajv({ strict: false }).compile<Profile>(schema)
const invalid = () => new Failure('CONFIG_INVALID', 'Invalid API token profile or configuration.', 'Use a strict API token profile with SecretRefs; see proxmox-axi get --help.')

async function privateFile(path: string, secret: boolean): Promise<string> {
  if (!isAbsolute(path) || (process.platform === 'win32' && /^(\\\\|\/\/)/.test(path))) throw invalid()
  const info = await lstat(path)
  if (!info.isFile() || info.isSymbolicLink() || (process.platform !== 'win32' &&
    (info.uid !== process.getuid?.() || (info.mode & (secret ? 0o077 : 0o022)) !== 0))) {
    throw new Failure('CONFIG_INSECURE', 'Credential file is not a protected regular file.', 'Use an owned regular file with chmod 600 on Linux.')
  }
  const file = await open(path, 'r')
  try {
    const opened = await file.stat()
    if (opened.ino !== info.ino || opened.dev !== info.dev || opened.size > 1_048_576) throw invalid()
    return await file.readFile('utf8')
  } finally { await file.close() }
}

export async function resolveCredentials(selection: { config?: string, profile?: string }): Promise<Credentials> {
  const env = process.env
  const selected = selection.profile ?? env.PROXMOX_AXI_PROFILE
  let profile: unknown
  let name: string
  let source: string
  const environmentFields = ['ORIGIN', 'AUTH', 'TOKEN_ID', 'TOKEN', 'CA_BUNDLE']
  if (!selected && environmentFields.some(field => env[`PROXMOX_AXI_${field}`] !== undefined)) {
    if (!env.PROXMOX_AXI_ORIGIN || !env.PROXMOX_AXI_TOKEN_ID || !env.PROXMOX_AXI_TOKEN) throw invalid()
    profile = { auth: env.PROXMOX_AXI_AUTH ?? 'api-token', origin: env.PROXMOX_AXI_ORIGIN,
      tokenId: env.PROXMOX_AXI_TOKEN_ID, token: { env: 'PROXMOX_AXI_TOKEN' },
      ...(env.PROXMOX_AXI_CA_BUNDLE ? { caBundle: env.PROXMOX_AXI_CA_BUNDLE } : {}) }
    name = 'environment'
    source = 'environment'
  } else {
    const configHome = process.platform === 'win32' ? env.APPDATA ?? join(homedir(), 'AppData', 'Roaming') :
      env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(homedir(), '.config')
    const path = selection.config ?? env.PROXMOX_AXI_CONFIG ?? join(configHome, 'proxmox-axi', 'config.json')
    let document: unknown
    try { document = JSON.parse(await privateFile(path, false)) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new Failure('AUTH_REQUIRED', 'No API token profile is configured.', 'Configure PROXMOX_AXI_ORIGIN, PROXMOX_AXI_TOKEN_ID and PROXMOX_AXI_TOKEN.')
      }
      if (error instanceof SyntaxError) throw invalid()
      throw error
    }
    if (!document || typeof document !== 'object' || Array.isArray(document)) throw invalid()
    const config = document as Record<string, unknown>
    if (config.version !== 1 || Object.keys(config).some(key => !['version', 'defaultProfile', 'profiles'].includes(key)) ||
      !config.profiles || typeof config.profiles !== 'object' || Array.isArray(config.profiles) ||
      (config.defaultProfile !== undefined && typeof config.defaultProfile !== 'string')) throw invalid()
    const profiles = config.profiles as Record<string, unknown>
    const names = Object.keys(profiles)
    if (names.some(key => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(key))) throw invalid()
    const chosen = selected ?? config.defaultProfile ?? (names.length === 1 ? names[0] : undefined)
    if (typeof chosen !== 'string') throw new Failure(names.length ? 'PROFILE_AMBIGUOUS' : 'PROFILE_REQUIRED',
      'Select one configured profile.', 'Use proxmox-axi get /version --profile <name>.')
    if (!Object.hasOwn(profiles, chosen)) throw new Failure('PROFILE_NOT_FOUND', 'Selected profile was not found.', 'Select a configured profile.')
    profile = profiles[chosen]
    name = chosen
    source = 'file'
  }
  if (!validateProfile(profile)) throw invalid()
  let origin: URL
  try { origin = new URL(profile.origin) } catch { throw invalid() }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash ||
    origin.pathname !== '/' || origin.origin !== profile.origin) throw invalid()
  const reference = profile.token ?? { env: 'PROXMOX_AXI_TOKEN' }
  const tokenSource = 'env' in reference ? `env:${reference.env}` : `file:${reference.file}`
  const token = 'env' in reference ? env[reference.env] : (await privateFile(reference.file, true)).replace(/^\uFEFF/, '').trimEnd()
  if (!token) throw new Failure('AUTH_REQUIRED', 'The selected token reference has no value.', 'Supply the secret through the selected environment or protected-file reference.')
  if (/[\s\x00-\x1f\x7f]/.test(token)) throw invalid()
  const ca = profile.caBundle ? await privateFile(profile.caBundle, false) : undefined
  return { origin: origin.origin, tokenId: profile.tokenId, token, ...(ca ? { ca } : {}),
    diagnostics: { profile: name, source, tokenSource } }
}

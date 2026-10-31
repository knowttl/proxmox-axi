import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { Ajv } from 'ajv'
import schema from './profile-schema.json' with { type: 'json' }
import { Failure } from './errors.js'
import { readPrivateFile } from './private-file.js'

type SecretRef = { env: string } | { file: string }
interface Profile { auth: 'api-token', origin: string, tokenId: string, token?: SecretRef, caBundle?: string,
  certificatePin?: { sha256: string, origin: string, replaceHostname?: boolean } }
export interface Credentials {
  origin: string
  tokenId: string
  token: string
  ca?: string
  certificatePin?: Profile['certificatePin']
  diagnostics: { profile: string, source: string, tokenSource: string }
}

const validateProfile = new Ajv({ strict: false }).compile<Profile>(schema)
const invalid = () => new Failure('CONFIG_INVALID', 'Invalid API token profile or configuration.', 'Use a strict API token profile with SecretRefs; see proxmox-axi get --help.')

export function configurationPath(config?: string): string {
  const env = process.env
  const home = process.platform === 'win32' ? env.APPDATA ?? join(homedir(), 'AppData', 'Roaming') :
    env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(homedir(), '.config')
  const path = config ?? env.PROXMOX_AXI_CONFIG ?? join(home, 'proxmox-axi', 'config.json')
  if (!isAbsolute(path)) throw invalid()
  return path
}

async function readConfiguration(path: string, verifyAcl = false): Promise<{ profiles: Record<string, unknown>, defaultProfile?: string }> {
  let document: unknown
  try { document = JSON.parse(await readPrivateFile(path, false, verifyAcl)) }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Failure('AUTH_REQUIRED', 'No API token profile is configured.', 'Configure PROXMOX_AXI_ORIGIN, PROXMOX_AXI_TOKEN_ID and PROXMOX_AXI_TOKEN.')
    if (error instanceof SyntaxError) throw invalid()
    throw error
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw invalid()
  const config = document as Record<string, unknown>
  if (config.version !== 1 || Object.keys(config).some(key => !['version', 'defaultProfile', 'profiles'].includes(key)) ||
    !config.profiles || typeof config.profiles !== 'object' || Array.isArray(config.profiles) ||
    (config.defaultProfile !== undefined && typeof config.defaultProfile !== 'string')) throw invalid()
  const profiles = config.profiles as Record<string, unknown>
  if (Object.keys(profiles).some(key => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(key))) throw invalid()
  return { profiles, ...(typeof config.defaultProfile === 'string' ? { defaultProfile: config.defaultProfile } : {}) }
}

export async function listProfiles(config?: string): Promise<{ name: string, default: boolean }[]> {
  const document = await readConfiguration(configurationPath(config))
  return Object.entries(document.profiles).map(([name, profile]) => {
    if (!validateProfile(profile)) throw invalid()
    return { name, default: name === document.defaultProfile }
  })
}

export async function resolveCredentials(selection: { config?: string, profile?: string, verifyAcl?: boolean }): Promise<Credentials> {
  const env = process.env
  if (env.PROXMOX_AXI_READ_ONLY !== undefined && !/^(1|0|true|false)$/i.test(env.PROXMOX_AXI_READ_ONLY)) throw invalid()
  const selected = selection.profile ?? env.PROXMOX_AXI_PROFILE
  if (selected !== undefined && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(selected)) throw invalid()
  let profile: unknown
  let name: string
  let source: string
  const environmentFields = ['ORIGIN', 'AUTH', 'TOKEN_ID', 'TOKEN', 'CA_BUNDLE', 'USER_ID', 'TICKET', 'CSRF_PREVENTION_TOKEN', 'PASSWORD', 'OTP']
  if (!selected && environmentFields.some(field => env[`PROXMOX_AXI_${field}`] !== undefined)) {
    if (['USER_ID', 'TICKET', 'CSRF_PREVENTION_TOKEN', 'PASSWORD', 'OTP'].some(field => env[`PROXMOX_AXI_${field}`] !== undefined)) throw invalid()
    if (!env.PROXMOX_AXI_ORIGIN || !env.PROXMOX_AXI_TOKEN_ID || !env.PROXMOX_AXI_TOKEN) throw invalid()
    profile = { auth: env.PROXMOX_AXI_AUTH ?? 'api-token', origin: env.PROXMOX_AXI_ORIGIN,
      tokenId: env.PROXMOX_AXI_TOKEN_ID, token: { env: 'PROXMOX_AXI_TOKEN' },
      ...(env.PROXMOX_AXI_CA_BUNDLE ? { caBundle: env.PROXMOX_AXI_CA_BUNDLE } : {}) }
    name = 'environment'
    source = 'environment'
  } else {
    const config = await readConfiguration(configurationPath(selection.config), selection.verifyAcl)
    const profiles = config.profiles
    const names = Object.keys(profiles)
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
  if (profile.certificatePin && (profile.certificatePin.origin !== origin.origin || profile.caBundle)) throw invalid()
  const reference = profile.token ?? { env: 'PROXMOX_AXI_TOKEN' }
  const tokenSource = 'env' in reference ? `env:${reference.env}` : `file:${reference.file}`
  const token = 'env' in reference ? env[reference.env] : (await readPrivateFile(reference.file, true, selection.verifyAcl)).replace(/^\uFEFF/, '').trimEnd()
  if (!token) throw new Failure('AUTH_REQUIRED', 'The selected token reference has no value.', 'Supply the secret through the selected environment or protected-file reference.')
  if (/[^\x21-\x7e]/.test(token)) throw invalid()
  const ca = profile.caBundle ? await readPrivateFile(profile.caBundle, false, selection.verifyAcl) : undefined
  return { origin: origin.origin, tokenId: profile.tokenId, token, ...(ca ? { ca } : {}),
    ...(profile.certificatePin ? { certificatePin: profile.certificatePin } : {}),
    diagnostics: { profile: name, source, tokenSource } }
}

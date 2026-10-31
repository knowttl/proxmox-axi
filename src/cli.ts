import { encode } from '@toon-format/toon'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'
import { lstat, open } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { configurationPath, listProfiles, resolveCredentials, type Credentials } from './credentials.js'
import { buildPath, contracts, parseParameter, selectContract } from './contract.js'
import { Failure } from './errors.js'
import { redact } from './redact.js'
import { readOperation, doctor } from './reads.js'
import { presentRead } from './presentation.js'
import operations from './operations.json' with { type: 'json' }

const flags = ['--config', '--profile', '--format', '--catalogue', '--body-file', '--limit', '--fields', '--full', '--help']
const help = {
  purpose: operations[0]!.help,
  usage: 'proxmox-axi get /version [--config <absolute-path>] [--profile <name>] [--format toon|json]',
  flags: ['--config <absolute-path> (default PROXMOX_AXI_CONFIG or OS config path)',
    '--profile <name> (default canonical profile selection)', '--format toon|json (default toon)',
    '--catalogue legacy-8.2.7|published-current (default detect target version; explicit selection is unverified)',
    '--limit <1-1000> (default 100 display rows)', '--fields <comma-separated names>', '--full (all received rows and fields; 65536-byte cap)',
    '--api-<parameter> <value> (vendor parameter)', '--body-file <absolute-path|-> (JSON, 64 KiB, five seconds)', '--help'],
  examples: ['proxmox-axi get /version', 'proxmox-axi get /version --profile lab --format json'],
}

export async function main(args: string[]): Promise<void> {
  let format = 'toon'
  let credentials: Credentials | undefined
  const output = (value: Record<string, unknown>) => {
    let text = format === 'json' ? JSON.stringify(value) : encode(value)
    if (credentials) {
      for (const secret of [credentials.token, encodeURIComponent(credentials.token), JSON.stringify(credentials.token).slice(1, -1)]) {
        text = text.replaceAll(secret, '[REDACTED]')
      }
    }
    if (Buffer.byteLength(text) > 65536) {
      process.exitCode = 1
      const error = { error: { code: 'OUTPUT_LIMIT', message: 'Rendered output exceeds 65536 bytes.' }, help: ['Request fewer rows or fields.'] }
      text = format === 'json' ? JSON.stringify(error) : encode(error)
    }
    console.log(text)
  }
  try {
    const positional: string[] = []
    const options: Record<string, string> = {}
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!
      if (!argument.startsWith('-')) { positional.push(argument); continue }
      if (!flags.includes(argument) && !argument.startsWith('--api-')) throw usage('Unknown flag; valid flags: --config, --profile, --format, --catalogue, --body-file, --api-<parameter>, --help.')
      if (/^--api-(?:password|token|ticket|otp|secret|api-key|private-key|vncticket|csrf-prevention-token)$/.test(argument)) throw usage('Secret arguments are not accepted; use a protected credential reference or the operation-specific private input contract.')
      if (argument === '--help' || argument === '--full') { options[argument === '--help' ? 'help' : '--full'] = 'true'; continue }
      const value = args[++index]
      if (!value || value.startsWith('--') || (value.startsWith('-') && value !== '-' && !argument.startsWith('--api-'))) throw usage('A flag value is required.')
      if (options[argument]) throw usage('Duplicate flags are not allowed.')
      options[argument] = value
    }
    format = options['--format'] ?? 'toon'
    if (!['toon', 'json'].includes(format)) { format = 'toon'; throw usage('Format must be toon or json.') }
    if (positional[0] === 'help') { positional.shift(); options.help = 'true' }
    if (positional[0] === 'ls') {
      if (positional.length === 1) positional.push('/nodes')
      positional[0] = 'get'
    }
    const command = positional.join(' ')
    const limit = Number(options['--limit'] ?? 100)
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw usage('Display limit must be an integer from 1 to 1000.')
    const fields = options['--fields']?.split(',')
    if (fields?.some(field => !/^[a-zA-Z0-9_-]+$/.test(field))) throw usage('Fields must be comma-separated field names.')
    if (options.help && (['inventory', 'schema', 'config path', 'profile list', 'doctor', 'auth status'].includes(command) || positional[0] === 'schema')) {
      const usages: Record<string, string> = {
        inventory: 'inventory [--catalogue <release>] [--format toon|json]',
        schema: 'schema <method> <template> [--catalogue <release>] [--format toon|json]',
        'config path': 'config path [--config <absolute-path>] [--format toon|json]',
        'profile list': 'profile list [--config <absolute-path>] [--format toon|json]',
        doctor: 'doctor [--config <absolute-path>] [--profile <name>] [--format toon|json]',
        'auth status': 'auth status [--config <absolute-path>] [--profile <name>] [--format toon|json]',
      }
      const key = positional[0] === 'schema' ? 'schema' : command
      const names = ['--format', '--help', ...(['inventory', 'schema'].includes(key) ? ['--catalogue'] :
        ['doctor', 'auth status'].includes(key) ? ['--config', '--profile'] : ['--config'])]
      if (Object.keys(options).some(option => option !== 'help' && !names.includes(option))) throw usage(`Valid flags: ${names.join(', ')}.`)
      output({ purpose: key === 'doctor' ? 'Check private-file protection and perform one bounded version read.' : `Inspect ${key}.`,
        usage: `proxmox-axi ${usages[key]}`, examples: key === 'schema' ? ['proxmox-axi schema get /version', 'proxmox-axi schema get /nodes --catalogue published-current'] :
          [`proxmox-axi ${key}`, `proxmox-axi ${key} --format json`], flags: help.flags.filter(flag => names.some(name => flag.startsWith(name))) })
      return
    }
    if (command === 'config path' || command === 'profile list') {
      if (Object.keys(options).some(key => !['--config', '--format'].includes(key))) throw usage('Invalid local configuration option.')
      if (command === 'config path') output({ path: configurationPath(options['--config']) })
      else {
        const profiles = await listProfiles(options['--config'])
        output({ count: profiles.length, profiles })
      }
      return
    }
    const release = options['--catalogue'] ?? 'legacy-8.2.7'
    if (command === 'inventory') {
      if (Object.keys(options).some(key => !['--format', '--catalogue', '--full', '--limit'].includes(key))) throw usage('Invalid inventory option.')
      const selected = contracts.filter(contract => contract.release === release)
      if (!selected.length) throw usage('Unknown catalogue.')
      output({ release, count: selected.length, operations: selected.slice(0, options['--full'] ? selected.length : limit).map(({ method, path, callable }) => ({ method, path, callable })),
        help: ['proxmox-axi inventory --full', 'proxmox-axi schema get /nodes'] })
      return
    }
    if (positional[0] === 'schema' && positional.length === 3) {
      if (Object.keys(options).some(key => !['--format', '--catalogue'].includes(key))) throw usage('Invalid schema option.')
      const contract = selectContract(positional[1]!, positional[2]!, release)
      output({ release, method: contract.method, path: contract.path, callable: contract.callable,
        policy: contract.policy, invocation: contract.invocation, parameters: contract.parameters, returns: contract.returns })
      return
    }
    if (options.help) {
      if (positional.length === 2 && !['auth status'].includes(command)) {
        const contract = selectContract(positional[0]!, positional[1]!, release)
        output({ purpose: contract.path === '/version' ? help.purpose : contract.description,
          usage: contract.path === '/version' ? help.usage : `proxmox-axi ${command} [--api-<parameter> <value>] [--catalogue ${release}]`,
          parameters: contract.parameters, policy: contract.policy, flags: help.flags, examples: help.examples })
      } else {
        if (!['', 'get', 'auth', 'auth status', 'home', 'doctor', 'inventory', 'schema'].includes(command)) throw usage('Unknown command.')
        output(help)
      }
      return
    }
    const isLocal = ['', 'home', 'auth status', 'doctor'].includes(command)
    if (isLocal && Object.keys(options).some(key => !['--config', '--profile', '--format'].includes(key))) throw usage('Valid local flags: --config, --profile, --format, --help.')
    const contract = ['', 'home', 'doctor'].includes(command) ? selectContract('GET', '/version', release) :
      isLocal ? undefined : positional.length === 2 ? selectContract(positional[0]!, positional[1]!, release) : undefined
    if (!isLocal && !contract) throw usage('Select a command from inventory.')
    const values: Record<string, unknown> = Object.create(null)
    if (options['--body-file']) {
      const path = options['--body-file']
      if (path !== '-' && !isAbsolute(path)) throw usage('Body file must be an absolute path or - for bounded stdin.')
      if (path !== '-') {
        const info = await lstat(path)
        if (!info.isFile() || info.isSymbolicLink() || info.size > 65536) throw usage('Body file must be a regular file of at most 65536 bytes.')
      }
      const file = path === '-' ? undefined : await open(path, 'r')
      const stream = file ? file.createReadStream({ autoClose: false }) : process.stdin
      const deadline = setTimeout(() => stream.destroy(usage('Body input exceeded 5000 ms.')), 5000)
      try {
        const chunks: Buffer[] = []
        let bytes = 0
        for await (const chunk of stream) {
          const buffer = Buffer.from(chunk)
          bytes += buffer.length
          if (bytes > 65536) throw usage('Body exceeds 65536 bytes.')
          chunks.push(buffer)
        }
        let body: unknown
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw usage('Body must be valid JSON.') }
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw usage('Body must be a JSON parameter object.')
        Object.assign(values, body)
      } finally { clearTimeout(deadline); await file?.close() }
    }
    for (const [flag, value] of Object.entries(options)) if (flag.startsWith('--api-')) {
      const name = flag.slice(6)
      const properties = contract?.parameters.properties ?? {}
      const schema = Object.hasOwn(properties, name) ? properties[name] : undefined
      if (!schema || Object.hasOwn(values, name)) throw usage('Unknown or duplicate API parameter.')
      values[name] = parseParameter(value, schema)
    }
    if (isLocal && (Object.keys(values).length || options['--body-file'] || options['--catalogue'])) throw usage('Invalid local command option.')
    if (contract && !contract.callable) {
      if (!options['--catalogue'] && contract.method === 'GET' && !contracts.some(candidate => candidate.release === 'published-current' && candidate.path === contract.path && candidate.method === contract.method)) {
        throw new Failure('CAPABILITY_UNSUPPORTED', 'Legacy route is absent from the current catalogue.', 'Use proxmox-axi inventory --catalogue published-current to inspect available routes.')
      }
      throw new Failure('CONTRACT_UNRESOLVED', 'Operation is not admitted by the reviewed policy.', 'Inspect the operation schema and policy before requesting admission.')
    }
    const wirePath = contract ? buildPath(contract, values) : undefined
    credentials = await resolveCredentials({ ...(options['--config'] ? { config: options['--config'] } : {}),
      verifyAcl: command === 'auth status' || command === 'doctor',
      ...(options['--profile'] ? { profile: options['--profile'] } : {}) })
    if (command === 'auth status') {
      output({ credential: { ...credentials.diagnostics, origin: credentials.origin, tokenId: credentials.tokenId } })
    } else if (command === 'doctor') {
      output(redact(await doctor(credentials), [credentials.token]) as Record<string, unknown>)
    } else {
      const selected = contract ?? selectContract('GET', '/version', release)
      const result = await readOperation(credentials, selected, values, options['--catalogue'])
      const nextOptions = ['--config', '--profile', '--catalogue'].filter(key => options[key]).map(key => `${key} ${JSON.stringify(options[key])}`).join(' ')
      const next = `proxmox-axi schema get ${selected.path} ${nextOptions}`.trim()
      const safeData = redact(presentRead(result, selected.path, { limit, full: !!options['--full'], ...(fields ? { fields } : {}), next }), [credentials.token]) as Record<string, unknown>
      output({ ...(['', 'home'].includes(command) ? { bin: fileURLToPath(new URL('../bin/proxmox-axi.mjs', import.meta.url)).replace(homedir(), '~'),
        description: 'Read Proxmox VE inventory and task information.', help: ['proxmox-axi ls', 'proxmox-axi doctor', 'proxmox-axi inventory'] } : {}),
        ...(selected.path === '/version' ? { version: safeData.data, compatibility: safeData.compatibility } : safeData), credential: credentials.diagnostics })
    }
  } catch (error) {
    const failure = error instanceof Failure ? error : new Failure('CONFIG_INVALID', 'Unable to read the selected configuration.', 'Check the selected configuration and protected file paths.')
    output({ error: { code: failure.code, message: failure.message }, help: [failure.next] })
    process.exitCode = failure.exitCode
  }
}

function usage(message: string): Failure {
  return new Failure('INVALID_INPUT', message, help.usage, 2)
}

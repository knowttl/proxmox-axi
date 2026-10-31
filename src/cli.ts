import { encode } from '@toon-format/toon'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'
import { resolveCredentials, type Credentials } from './credentials.js'
import { readVersion } from './transport.js'
import { Failure } from './errors.js'
import operations from './operations.json' with { type: 'json' }

const flags = ['--config', '--profile', '--format', '--help']
const help = {
  purpose: operations[0]!.help,
  usage: 'proxmox-axi get /version [--config <absolute-path>] [--profile <name>] [--format toon|json]',
  flags: ['--config <absolute-path> (default PROXMOX_AXI_CONFIG or OS config path)',
    '--profile <name> (default canonical profile selection)', '--format toon|json (default toon)', '--help'],
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
    console.log(text)
  }
  try {
    const positional: string[] = []
    const options: Record<string, string> = {}
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!
      if (!argument.startsWith('-')) { positional.push(argument); continue }
      if (!flags.includes(argument)) throw usage('Unknown flag; valid flags: --config, --profile, --format, --help.')
      if (argument === '--help') { options.help = 'true'; continue }
      const value = args[++index]
      if (!value || value.startsWith('-')) throw usage('A flag value is required.')
      if (options[argument]) throw usage('Duplicate flags are not allowed.')
      options[argument] = value
    }
    format = options['--format'] ?? 'toon'
    if (!['toon', 'json'].includes(format)) { format = 'toon'; throw usage('Format must be toon or json.') }
    const command = positional.join(' ')
    if (options.help) {
      if (!['', 'get', 'get /version', 'auth', 'auth status', 'home'].includes(command)) throw usage('Unknown command.')
      output(help)
      return
    }
    if (!['', 'home', 'get /version', 'auth status'].includes(command)) throw usage('Only get /version and auth status are available in this build.')
    credentials = await resolveCredentials({ ...(options['--config'] ? { config: options['--config'] } : {}),
      ...(options['--profile'] ? { profile: options['--profile'] } : {}) })
    if (command === 'auth status') {
      output({ credential: { ...credentials.diagnostics, origin: credentials.origin, tokenId: credentials.tokenId } })
    } else {
      const version = await readVersion(credentials)
      output({ ...(['', 'home'].includes(command) ? { bin: fileURLToPath(new URL('../bin/proxmox-axi.mjs', import.meta.url)).replace(homedir(), '~'),
        description: 'Read Proxmox VE server information.' } : {}), version, credential: credentials.diagnostics })
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

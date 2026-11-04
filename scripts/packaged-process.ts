import type { ChildProcess } from 'node:child_process'
import type { Readable } from 'node:stream'

// Diagnostics deliberately exclude argv, environment, output and private payloads.
export function observePackaged<Frame>(child: ChildProcess, options: {
  caseId: string, session?: boolean, privateFrames?: boolean,
}) {
  let caseId = options.caseId, state = 'running', stdout = '', stderr = '', pending = ''
  let privateBytes = Buffer.alloc(0)
  const diagnostic = (channel: string, reason: string) => new Error(`${caseId}: ${channel}: ${reason}; child=${state}`)
  function queue<T>(channel: string) {
    const values: T[] = []
    const readers: { resolve: (value: T) => void, reject: (error: Error) => void, timer: NodeJS.Timeout }[] = []
    let ended: Error | undefined
    return {
      push(value: T) {
        const reader = readers.shift()
        if (reader) { clearTimeout(reader.timer); reader.resolve(value) } else values.push(value)
      },
      end(reason: string) {
        ended = diagnostic(channel, reason)
        for (const reader of readers.splice(0)) { clearTimeout(reader.timer); reader.reject(ended) }
      },
      next(): Promise<T> {
        if (values.length) return Promise.resolve(values.shift()!)
        if (ended) return Promise.reject(ended)
        return new Promise((resolve, reject) => {
          const reader = { resolve, reject, timer: setTimeout(() => {
            readers.splice(readers.indexOf(reader), 1)
            reject(diagnostic(channel, 'response deadline exceeded'))
          }, 10_000) }
          readers.push(reader)
        })
      },
    }
  }
  const lines = queue<Record<string, unknown>>('public response'), frames = queue<Frame>('private frame')
  const fail = (reason: string) => { lines.end(reason); frames.end(reason) }
  const watchdog = () => {
    state = 'watchdog expired'
    fail('command watchdog exceeded')
    child.kill('SIGKILL')
  }
  let timer = setTimeout(watchdog, 60_000)
  child.stdout!.on('data', (chunk: Buffer) => {
    stdout += chunk.toString()
    if (!options.session) return
    pending += chunk.toString()
    let end: number
    while ((end = pending.indexOf('\n')) >= 0) {
      try {
        const value: unknown = JSON.parse(pending.slice(0, end))
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error()
        lines.push(value as Record<string, unknown>)
      }
      catch { fail('malformed public response'); child.kill('SIGKILL'); return }
      pending = pending.slice(end + 1)
    }
  })
  child.stderr!.on('data', (chunk: Buffer) => { stderr += chunk.toString() })
  if (options.privateFrames) (child.stdio[3] as Readable).on('data', (chunk: Buffer) => {
    privateBytes = Buffer.concat([privateBytes, chunk])
    while (privateBytes.length >= 4) {
      const length = privateBytes.readUInt32BE(0)
      if (length > 65536) { fail('oversized private frame'); child.kill('SIGKILL'); return }
      if (privateBytes.length < 4 + length) return
      try { frames.push(JSON.parse(privateBytes.subarray(4, 4 + length).toString()) as Frame) }
      catch { fail('malformed private frame'); child.kill('SIGKILL'); return }
      privateBytes = privateBytes.subarray(4 + length)
    }
  })
  const closed = new Promise<{ code: number, stdout: string, stderr: string }>((resolve, reject) => {
    child.once('error', () => {
      clearTimeout(timer); state = 'spawn failed'; fail('child unavailable')
      reject(diagnostic('process', 'child unavailable'))
    })
    child.once('close', (code, signal) => {
      clearTimeout(timer)
      const watchdogExpired = state === 'watchdog expired'
      state = `closed exit=${code ?? 'none'} signal=${signal ?? 'none'}`
      fail(watchdogExpired ? 'command watchdog exceeded' : 'child closed before response')
      if (signal) reject(diagnostic('process', watchdogExpired ? 'command watchdog exceeded' : 'child terminated'))
      else resolve({ code: code!, stdout, stderr })
    })
  })
  // Session callers await responses before awaiting close; preserve early errors
  // without producing an unhandled rejection while a response is outstanding.
  void closed.catch(() => {})
  return { child, lines, frames, closed, begin(id: string) {
    caseId = id
    clearTimeout(timer)
    timer = setTimeout(watchdog, 60_000)
  } }
}

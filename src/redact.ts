const sensitiveKey = /^(?:password|passwd|secret|token|ticket|csrfpreventiontoken|private[-_]?key|access[-_]?token|refresh[-_]?token|authorization|cookie)$/i

export function redact(value: unknown, secrets: string[]): unknown {
  if (typeof value === 'string') {
    let text = value
    for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1)]) {
      text = text.replaceAll(form, '[REDACTED]')
    }
    return text.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, '[REDACTED]')
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
      .replace(/(?:AccountKey|SharedAccessSignature)=[^\s;]+/gi, '[REDACTED]')
  }
  if (Array.isArray(value)) return value.map(item => redact(item, secrets))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
    sensitiveKey.test(key) ? '[REDACTED]' : redact(item, secrets)]))
  return value
}

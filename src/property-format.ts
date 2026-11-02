// Both invocation discovery and runtime validation must recognize the same reviewed inline format.
export function propertyFormatPattern(format: Record<string, Record<string, unknown>>): string | undefined {
  const current = format.current
  if (Object.keys(format).length !== 1 || !current || current.type !== 'integer' || current.minimum !== 16 || current.default_key !== 1 ||
    Object.keys(current).some(key => !['type', 'minimum', 'default_key', 'default', 'description'].includes(key))) return undefined
  return '^(?:current=)?(?:1[6-9]|[2-9][0-9]|[1-9][0-9]{2,})$'
}

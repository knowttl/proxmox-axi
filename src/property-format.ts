// Both invocation discovery and runtime validation must recognize the same reviewed inline format.
export function propertyFormatPattern(format: Record<string, Record<string, unknown>>): string | undefined {
  const positive = '(?:[1-9][0-9]*(?:\\.[0-9]+)?|0\\.[0-9]*[1-9][0-9]*)'
  const storage = '[A-Za-z][A-Za-z0-9._-]*:'
  const identifier = '[A-Za-z][A-Za-z0-9_.-]{0,14}'
  const mac = '[0-9A-Fa-f][02468AaCcEe](?::[0-9A-Fa-f]{2}){5}'
  const tag = '(?:[1-9]|[1-9][0-9]{1,2}|[1-3][0-9]{3}|40[0-8][0-9]|409[0-4])'
  const rate = '[0-9]+(?:\\.[0-9]+)?'
  if (format.model?.default_key === 1 && format.macaddr?.format === 'mac-addr' && Array.isArray(format.model.enum)) {
    const availableModels = format.model.enum
    const models = ['virtio', 'e1000', 'e1000e', 'vmxnet3'].filter(model => availableModels.includes(model))
    const model = `(?:${models.join('|')})`
    return `^(?:(?:model=)?${model}|${model}=${mac})(?:,bridge=${identifier})?(?:,firewall=[01])?(?:,link_down=[01])?(?:,rate=${rate})?(?:,tag=${tag})?$`
  }
  if (format.name?.type === 'string' && format.ip?.format === 'pve-ipv4-config') {
    const octet = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    const ipv4 = `${octet}(?:\\.${octet}){3}`
    return `^name=${identifier}(?:,bridge=${identifier})?(?:,firewall=[01])?(?:,gw=${ipv4})?(?:,hwaddr=${mac})?(?:,ip=(?:dhcp|manual|${ipv4}/(?:[0-9]|[12][0-9]|3[0-2])))?(?:,ip6=(?:auto|dhcp|manual))?(?:,link_down=[01])?(?:,rate=${rate})?(?:,tag=${tag})?(?:,type=veth)?$`
  }
  if (format.enabled?.type === 'boolean' && format.enabled.default_key === 1 && format.type?.default === 'virtio') return '^(?:enabled=)?[01]$'
  if (format.file?.format === 'pve-volume-id-or-qm-path') {
    const volume = `${storage}(?:${positive}|(?:[1-9][0-9]*/)?vm-[1-9][0-9]*-disk-[0-9]+(?:\\.(?:raw|qcow2|vmdk))?)`
    const options: Record<string, string> = { backup: '[01]', cache: '(?:none|writethrough|writeback|directsync)', discard: '(?:ignore|on)',
      format: '(?:raw|qcow2|vmdk)', iothread: '[01]', ssd: '[01]', ro: '[01]' }
    const disk = `(?:file=)?${volume}${Object.entries(options).filter(([key]) => Object.hasOwn(format, key)).map(([key, value]) => `(?:,${key}=${value})?`).join('')}`
    const media = Array.isArray(format.media?.enum) && format.media.enum.includes('cdrom') ? `|(?:file=)?(?:${storage}iso/[A-Za-z0-9][A-Za-z0-9._-]*\\.iso|none),media=cdrom` : ''
    return `^(?:${disk}${media})$`
  }
  if (format.volume?.format === 'pve-lxc-mp-string') {
    const volume = `${storage}(?:${positive}|(?:vm|subvol)-[1-9][0-9]*-disk-[0-9]+(?:\\.raw)?)`
    const path = '(?:/(?!\\.{1,2}(?:/|,|$))[A-Za-z0-9._-]+)+'
    const options = ['acl', 'backup', 'quota', 'ro'].filter(key => Object.hasOwn(format, key)).map(key => `(?:,${key}=[01])?`).join('')
    return `^(?:volume=)?${volume}${format.mp ? `,mp=${path}` : ''}${options}$`
  }
  const current = format.current
  if (Object.keys(format).length !== 1 || !current || current.type !== 'integer' || current.minimum !== 16 || current.default_key !== 1 ||
    Object.keys(current).some(key => !['type', 'minimum', 'default_key', 'default', 'description'].includes(key))) return undefined
  return '^(?:current=)?(?:1[6-9]|[2-9][0-9]|[1-9][0-9]{2,})$'
}

// Only explicitly admitted concrete names expand a vendor's numbered template.
export function parameterProperties<T>(schema: { properties?: Record<string, T> }, allowedInputs?: string[]): Record<string, T> {
  const properties = { ...schema.properties }
  for (const name of allowedInputs ?? []) {
    const prefix = /^([a-z]+)[0-9]+$/.exec(name)?.[1]
    const template = prefix ? properties[`${prefix}[n]`] : undefined
    if (template !== undefined && !Object.hasOwn(properties, name)) properties[name] = template
  }
  return properties
}

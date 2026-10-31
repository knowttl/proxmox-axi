import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { Failure } from './errors.js'

const execute = promisify(execFile)

export async function windowsProtection(path: string, mode: 'read' | 'verify' | 'write', directory = false): Promise<void> {
  const script = `
$ErrorActionPreference = 'Stop'
$path = $env:PROXMOX_AXI_PRIVATE_PATH
$item = Get-Item -LiteralPath $path -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point' }
if ($env:PROXMOX_AXI_PRIVATE_MODE -eq 'read') { exit 0 }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed = @($user.Value, 'S-1-5-18', 'S-1-5-32-544')
$acl = Get-Acl -LiteralPath $path
if ($env:PROXMOX_AXI_PRIVATE_MODE -eq 'write') {
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
  foreach ($sid in $allowed) {
    $identity = [Security.Principal.SecurityIdentifier]::new($sid)
    $inherit = if ($env:PROXMOX_AXI_PRIVATE_DIRECTORY -eq '1') { 'ContainerInherit,ObjectInherit' } else { 'None' }
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', $inherit, 'None', 'Allow')
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $path -AclObject $acl
} else {
  if (!$acl.AreAccessRulesProtected) { throw 'Inherited ACL' }
  foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($rule.AccessControlType -ne 'Allow' -or $allowed -notcontains $sid) { throw 'Unexpected ACL principal' }
  }
}
`
  try {
    await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      env: { ...process.env, PROXMOX_AXI_PRIVATE_PATH: path, PROXMOX_AXI_PRIVATE_MODE: mode,
        PROXMOX_AXI_PRIVATE_DIRECTORY: directory ? '1' : '0' }, timeout: 5000, maxBuffer: 65536, windowsHide: true,
    })
  } catch {
    throw new Failure('CONFIG_INSECURE', 'Windows file protection could not be established or verified.', 'Re-create the selected file with a protected Windows DACL.')
  }
}

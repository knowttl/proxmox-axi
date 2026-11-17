import fileSystem from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { sep } from 'node:path'

const rename = fileSystem.rename
const open = fileSystem.open
const role = process.env.JOURNAL_RACE_ROLE
let signalled = false
const journal = path => String(path).startsWith(`${process.env.PROXMOX_AXI_WRITE_LOG}.d${sep}`)

fileSystem.rename = async (from, to) => {
  if (role === 'winner' && !signalled && journal(to) && String(to).endsWith('.json')) {
    signalled = true
    process.send('replacing')
    await new Promise(resolve => process.once('message', resolve))
  }
  try { return await rename(from, to) }
  catch (error) {
    if (role === 'loser' && !signalled && journal(to) && String(to).endsWith('.json.lock') && ['EEXIST', 'ENOTEMPTY', 'EPERM'].includes(error.code)) {
      signalled = true
      process.send('contended')
    }
    throw error
  }
}

fileSystem.open = async (...args) => {
  if (role === 'loser' && !signalled && journal(args[0]) && String(args[0]).endsWith('.json') && typeof args[1] === 'number') {
    signalled = true
    process.send('read')
  }
  return open(...args)
}
syncBuiltinESMExports()

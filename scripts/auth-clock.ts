import { readFileSync } from 'node:fs'

// Acceptance-only clock boundary. This module is never shipped in the package.
const clock = process.env.PROXMOX_AXI_TEST_CLOCK_FILE
if (clock) Date.now = () => Number(readFileSync(clock, 'utf8'))

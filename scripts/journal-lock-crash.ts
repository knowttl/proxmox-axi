const moduleUrl = process.argv[2], id = process.argv[3]
if (!moduleUrl || !id) throw new Error('Journal module URL and intent ID are required')
const { Journal } = await import(moduleUrl) as typeof import('../src/journal.js')
const journal = new Journal()
await journal.initialize()
await journal.update(id, () => { process.kill(process.pid, 'SIGKILL') })

import { readFile, stat } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { replay, sha256, compareCatalogues } from './catalogue.mjs'

try {
  const paths = process.argv.slice(2)
  if (paths.length !== 2 || paths.some(path => !isAbsolute(path))) throw new Error('Supply absolute previous and candidate capture paths.')
  const catalogues = []
  for (const [index, path] of paths.entries()) {
    const info = await stat(path)
    if (!info.isFile() || info.size > 8_388_608) throw new Error('Each capture must be a regular file of at most 8 MiB.')
    const bytes = await readFile(path)
    catalogues.push(replay(bytes, { release: index ? 'candidate' : 'previous', sha256: sha256(bytes) }))
  }
  console.log(JSON.stringify({ previousSha256: catalogues[0].captureSha256, candidateSha256: catalogues[1].captureSha256,
    ...compareCatalogues(...catalogues), admitted: false,
    help: ['Review effects, secret fields, transports and contract changes before updating catalogue hashes or operation admission.'] }))
} catch {
  console.log(JSON.stringify({ error: { code: 'INVALID_CAPTURE', message: 'Supply two absolute, valid API schema captures of at most 8 MiB each.' } }))
  process.exitCode = 2
}

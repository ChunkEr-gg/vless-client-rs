import { attestProvenance } from '@actions/attest';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { basename } from 'node:path';

const [output, ...files] = process.argv.slice(2);
if (!output || !files.length) throw new Error('Expected bundle path and artifact paths');
const subjects = [];
for (const file of files) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  subjects.push({ name: basename(file), digest: { sha256: hash.digest('hex') } });
}
// Keep the private Sigstore bundle with the artifact. Personal private repos
// can sign with Actions OIDC but cannot persist to the attestations REST API.
const { bundle } = await attestProvenance({ subjects, token: process.env.GH_TOKEN, skipWrite: true });
await writeFile(output, JSON.stringify(bundle) + '\n', { flag: 'wx' });

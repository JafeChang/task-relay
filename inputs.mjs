import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export function validateInputs(inputs = []) {
  if (!Array.isArray(inputs) || inputs.length > 8) throw new Error('Invalid inputs');
  const names = new Set();
  let total = 0;
  for (const item of inputs) {
    if (!Number.isSafeInteger(item.id) || item.id < 1 || !Number.isSafeInteger(item.size) || item.size < 0 ||
        item.size >= 2 * 1024**3 || !/^[a-f0-9]{64}$/.test(item.sha256) ||
        !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$/.test(item.name) || names.has(item.name)) {
      throw new Error('Invalid input');
    }
    names.add(item.name);
    total += item.size;
  }
  if (total > 4 * 1024**3) throw new Error('Input size limit exceeded');
  return inputs;
}

export async function downloadInput(repository, token, item, directory) {
  validateInputs([item]);
  let response = await fetch(`https://api.github.com/repos/${repository}/releases/assets/${item.id}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/octet-stream', 'User-Agent': 'task-executor' },
    redirect: 'manual', signal: AbortSignal.timeout(600000),
  });
  if (response.status === 302) {
    const target = new URL(response.headers.get('location'));
    if (target.protocol !== 'https:' || target.username || target.password ||
        !['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(target.hostname)) {
      throw new Error('Unexpected input host');
    }
    // Signed asset URLs do not need, and must not receive, the API credential.
    response = await fetch(target, { redirect: 'error', signal: AbortSignal.timeout(600000) });
  }
  if (!response.ok || !response.body) throw new Error('Input download failed');
  const length = response.headers.get('content-length');
  if (length !== null && Number(length) !== item.size) throw new Error('Input size mismatch');
  const file = path.join(directory, item.name);
  const hash = createHash('sha256');
  let received = 0;
  const verifier = new Transform({ transform(chunk, encoding, callback) {
    received += chunk.length;
    if (received > item.size) { callback(new Error('Input size mismatch')); return; }
    hash.update(chunk);
    callback(null, chunk);
  } });
  let created = false;
  try {
    const output = createWriteStream(file, { mode: 0o600, flags: 'wx' });
    output.once('open', () => { created = true; });
    await pipeline(Readable.fromWeb(response.body), verifier, output);
    if (received !== item.size || hash.digest('hex') !== item.sha256) throw new Error('Input identity mismatch');
    return { ...item, received };
  } catch {
    if (created) await rm(file, { force: true });
    throw new Error('Input transfer failed');
  }
}

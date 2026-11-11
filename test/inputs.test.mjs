import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { validateInputs, downloadInput } from '../inputs.mjs';

const bytes = Buffer.from('fixture input');
const input = () => ({ id: 1, name: 'fixture.bin', size: bytes.length,
  sha256: createHash('sha256').update(bytes).digest('hex') });

test('input bounds reject traversal, duplicates and oversized transfers', () => {
  assert.deepEqual(validateInputs(), []);
  for (const name of ['../outside', '/outside', '..', 'a/b', 'a\\b']) assert.throws(() => validateInputs([{ ...input(), name }]));
  assert.throws(() => validateInputs([input(), input()]));
  assert.throws(() => validateInputs([{ ...input(), size: 2 * 1024**3 }]));
  assert.throws(() => validateInputs([{ ...input(), sha256: 'invalid' }]));
});

test('verified asset transfer never forwards API credentials to signed URL', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'input-test-'));
  const previous = globalThis.fetch;
  try {
    const calls = [];
    globalThis.fetch = async (url, options) => {
      calls.push({ url: String(url), options });
      return calls.length === 1 ? new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/fixture' } }) : new Response(bytes);
    };
    const result = await downloadInput('example/source', 'private-credential', input(), directory);
    assert.equal(result.received, bytes.length);
    assert.deepEqual(await readFile(path.join(directory, 'fixture.bin')), bytes);
    assert.equal(calls[0].options.headers.Authorization, 'Bearer private-credential');
    assert.equal(calls[1].options.headers, undefined);
  } finally { globalThis.fetch = previous; await rm(directory, { recursive: true, force: true }); }
});

test('bad content, truncation, excess bytes and redirects leave no input', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'input-test-'));
  const previous = globalThis.fetch;
  try {
    for (const response of [new Response('wrong bytes'), new Response(bytes.subarray(1)),
      new Response(Buffer.concat([bytes, bytes])), new Response(null, { status: 302, headers: { location: 'https://untrusted.example/asset' } })]) {
      globalThis.fetch = async () => response;
      await assert.rejects(downloadInput('example/source', 'credential', input(), directory));
      assert.deepEqual(await readdir(directory), []);
    }
  } finally { globalThis.fetch = previous; await rm(directory, { recursive: true, force: true }); }
});

test('a repeated transfer preserves an existing input file', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'input-test-'));
  const previous = globalThis.fetch;
  try {
    const file = path.join(directory, 'fixture.bin');
    await writeFile(file, 'existing verified input');
    globalThis.fetch = async () => new Response(bytes);
    await assert.rejects(downloadInput('example/source', 'credential', input(), directory));
    assert.equal(await readFile(file, 'utf8'), 'existing verified input');
  } finally { globalThis.fetch = previous; await rm(directory, { recursive: true, force: true }); }
});

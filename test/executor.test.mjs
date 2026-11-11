import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readdir, rm, symlink } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import { seal, open } from '../envelope.mjs';
import { validate, childEnvironment, outputFiles, run, execute } from '../executor.mjs';

const key = randomBytes(32).toString('hex');
const context = { repository: 'example/relay', runner: 'ubuntu-24.04', run_url: 'https://github.com/example/relay/actions/runs/1' };
const sha = 'a'.repeat(40);
function request() {
  return { version: 1, id: randomBytes(16).toString('hex'), public_repository: context.repository,
    runner: context.runner, repository: 'example/source', ref: 'refs/heads/check', sha,
    issued_at: Date.now(), expires_at: Date.now() + 3600000,
    steps: [{ argv: [process.execPath, '-e', ''], timeout: 10, env: {} }], outputs: [] };
}

test('authenticated, randomized and padded envelopes', () => {
  const value = request();
  const ticket = seal(value, key);
  assert.deepEqual(open(ticket, key), value);
  assert.notEqual(seal(value, key), ticket);
  assert.equal(Buffer.from(ticket, 'base64url').length, 4124);
  assert(!ticket.includes(value.repository));
  const mutated = Buffer.from(ticket, 'base64url');
  mutated[40] ^= 1;
  assert.throws(() => open(mutated.toString('base64url'), key));
  assert.throws(() => open(ticket, randomBytes(32).toString('hex')));
  assert.throws(() => open('bad', key));
  assert.throws(() => seal('x'.repeat(45000), key));
});

for (const [name, change] of [
  ['wrong repository binding', r => { r.public_repository = 'other/relay'; }],
  ['wrong runner binding', r => { r.runner = 'windows-2025'; }],
  ['foreign source account', r => { r.repository = 'other/source'; }],
  ['public relay destination', r => { r.repository = context.repository; }],
  ['expired ticket', r => { r.expires_at = Date.now() - 1000; }],
  ['future ticket', r => { r.issued_at = Date.now() + 120000; }],
  ['excess lifetime', r => { r.expires_at += 25 * 3600000; }],
  ['short SHA', r => { r.sha = 'abcdef'; }],
  ['ref traversal', r => { r.ref = 'refs/heads/../main'; }],
  ['output traversal', r => { r.outputs = ['../private']; }],
  ['absolute output', r => { r.outputs = ['/private']; }],
  ['git metadata output', r => { r.outputs = ['.git/config']; }],
  ['environment command channel', r => { r.steps[0].env.GITHUB_OUTPUT = '/somewhere'; }],
  ['credential environment', r => { r.steps[0].env.SOURCE_TOKEN = 'value'; }],
  ['runtime injection', r => { r.steps[0].env.NODE_OPTIONS = '--require=other'; }],
  ['invalid timeout', r => { r.steps[0].timeout = 0; }],
  ['total time limit', r => { r.steps = Array.from({ length: 3 }, () => ({ argv: ['true'], timeout: 10800, env: {} })); }],
]) test(`rejects ${name}`, () => {
  const value = request(); change(value); assert.throws(() => validate(value, context));
});

test('child environment excludes credentials and workflow channels', () => {
  const env = childEnvironment({ PATH: '/bin', HOME: '/home/example', GITHUB_ENV: 'hidden',
    GITHUB_STEP_SUMMARY: 'hidden', ACTIONS_RUNTIME_TOKEN: 'hidden', EXECUTION_KEY: 'hidden',
    SOURCE_TOKEN: 'hidden', RESULT_TOKEN: 'hidden', TICKET: 'hidden', GIT_CONFIG_VALUE_0: 'hidden',
    NODE_OPTIONS: 'hidden', BASH_ENV: 'hidden', RUNNER_TEMP: 'hidden' }, { BUILD_JOBS: '2' });
  assert.equal(env.PATH, '/bin');
  assert.equal(env.BUILD_JOBS, '2');
  assert.equal(Object.values(env).includes('hidden'), false);
});

test('outputs reject symlinks and escape through symlinked ancestors', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'relay-test-'));
  try {
    const root = path.join(directory, 'root');
    await mkdir(root); await mkdir(path.join(directory, 'outside'));
    await writeFile(path.join(directory, 'outside/file'), 'private');
    await writeFile(path.join(root, 'file'), 'result');
    await symlink('../outside', path.join(root, 'link'));
    await assert.rejects(outputFiles(root, ['link']));
    await assert.rejects(outputFiles(root, ['link/file']));
    assert.deepEqual(await outputFiles(root, ['file', 'file']), [path.join(root, 'file')]);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('captures output and kills commands on timeout or overflow', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'relay-test-'));
  const log = createWriteStream(path.join(directory, 'log'));
  try {
    const options = { cwd: directory, env: childEnvironment(process.env), timeout: 1, log };
    const timed = await run([process.execPath, '-e', 'setInterval(()=>{},100)'], options);
    assert.equal(timed.timed_out, true);
    assert.notEqual(timed.code, 0);
    const overflow = await run([process.execPath, '-e', 'process.stdout.write("x".repeat(10000));setInterval(()=>{},100)'], { ...options, limit: 10 });
    assert.equal(overflow.log_limit_exceeded, true);
    assert.notEqual(overflow.code, 0);
  } finally {
    await new Promise(resolve => log.end(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test('private-only result transport, checkout binding and failure receipts', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'relay-test-'));
  const oldPath = process.env.PATH;
  const oldFetch = globalThis.fetch;
  try {
    await mkdir(path.join(directory, 'bin'));
    await writeFile(path.join(directory, 'bin/git'), `#!/usr/bin/env node\nif(process.argv.includes('rev-parse'))console.log('${sha}');\n`, { mode: 0o700 });
    process.env.PATH = path.join(directory, 'bin') + path.delimiter + oldPath;
    for (const scenario of ['success', 'command-failure', 'missing-output', 'changed-source', 'public-destination', 'claim-collision', 'upload-failure']) {
      await t.test(scenario, async () => {
        const calls = [];
        const uploads = new Map();
        let claimed = false;
        globalThis.fetch = async (url, options) => {
          calls.push({ url: String(url), options });
          assert.match(String(url), /^https:\/\/(api|uploads)\.github\.com\/repos\/example\/source(?:\/|$)/);
          if (options.method === 'GET') return Response.json({ private: scenario !== 'public-destination', full_name: 'example/source' });
          if (String(url).endsWith('/git/refs')) {
            if (claimed || scenario === 'claim-collision') return new Response('', { status: 422 });
            claimed = true; return Response.json({ ref: 'claimed' });
          }
          if (String(url).endsWith('/releases')) return Response.json({ id: 7 });
          if (String(url).includes('/assets?name=')) {
            const name = new URL(url).searchParams.get('name');
            if (scenario === 'upload-failure') return new Response('', { status: 500 });
            uploads.set(name, options.body);
            return Response.json({ id: uploads.size });
          }
          return Response.json({ id: 7 });
        };
        const value = request();
        value.steps[0].argv = [process.execPath, '-e', `console.log('sensitive-unit-name');console.error('sensitive-error-name');require('fs').writeFileSync('result.txt','private-result');process.exit(${scenario === 'command-failure' ? 2 : 0})`];
        value.outputs = [scenario === 'missing-output' ? 'missing.txt' : 'result.txt'];
        if (scenario === 'changed-source') value.sha = 'b'.repeat(40);
        const credentials = { source: 'read-value', result: 'write-value' };
        const scopedContext = { ...context, scratch: directory };
        if (['public-destination', 'claim-collision', 'upload-failure'].includes(scenario)) {
          await assert.rejects(execute(value, scopedContext, credentials));
          assert.equal(uploads.has('receipt.json'), false);
        } else {
          assert.equal(await execute(value, scopedContext, credentials), scenario === 'success');
          const receipt = JSON.parse(uploads.get('receipt.json').toString());
          assert.equal(receipt.source_sha, value.sha);
          assert.equal(receipt.result, scenario === 'success' ? 'SUCCESS' : 'FAILURE');
          assert.equal(receipt.production_ready, false);
          if (scenario !== 'changed-source') {
            const log = gunzipSync(uploads.get('execution.log.gz')).toString();
            assert(log.includes('sensitive-unit-name'));
            assert(log.includes('sensitive-error-name'));
          } else assert.equal(receipt.steps.length, 0);
          if (scenario === 'success') {
            assert.equal(uploads.get('output-1.bin').toString(), 'private-result');
            assert.match(receipt.assets[0].sha256, /^[a-f0-9]{64}$/);
            await assert.rejects(execute(value, scopedContext, credentials));
          }
          if (scenario === 'command-failure') assert.equal(uploads.get('output-1.bin').toString(), 'private-result');
          const update = calls.find(c => c.options.method === 'PATCH');
          assert.equal(JSON.parse(update.options.body).tag_name, `ci-request-${value.id}`);
        }
        // One claim POST, no automatic retry, no public result writes.
        if (scenario !== 'success') assert(calls.filter(c => c.url.endsWith('/git/refs')).length <= 1);
        assert.equal((await readdir(directory)).filter(n => n.startsWith('task-')).length, 0);
      });
    }
  } finally {
    globalThis.fetch = oldFetch;
    process.env.PATH = oldPath;
    await rm(directory, { recursive: true, force: true });
  }
});

test('entry point emits only a generic failure for invalid private input', () => {
  const result = spawnSync(process.execPath, ['executor.mjs'], { cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_RUN_ATTEMPT: '1',
      EXECUTION_KEY: key, TICKET: 'sensitive-invalid-ticket', SOURCE_TOKEN: 'sensitive-token' }, encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'Task failed.\n');
});

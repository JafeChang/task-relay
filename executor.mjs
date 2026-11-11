import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, lstat, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { createGzip } from 'node:zlib';
import { open } from './envelope.mjs';

export const RUNNERS = ['ubuntu-24.04', 'ubuntu-24.04-arm', 'windows-2025',
  'windows-11-arm', 'macos-26-intel', 'macos-26'];
const repoPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const reserved = /^(?:GITHUB_|ACTIONS_|RUNNER_|INPUT_|GIT_|NODE_|EXECUTOR_|LD_|DYLD_|SOURCE_TOKEN$|RESULT_TOKEN$|EXECUTION_KEY$|TICKET$|BASH_ENV$|ENV$|SHELLOPTS$|PYTHONPATH$|PYTHONSTARTUP$)/i;
const maxLog = 64 * 1024 * 1024;

export function validate(request, context, now = Date.now()) {
  if (request?.version !== 1 || request.public_repository !== context.repository ||
      request.runner !== context.runner || !RUNNERS.includes(request.runner) ||
      !/^[a-f0-9]{32}$/.test(request.id) || !/^[a-f0-9]{40}$/.test(request.sha) ||
      !repoPattern.test(request.repository) ||
      request.repository.split('/')[0].toLowerCase() !== context.repository.split('/')[0].toLowerCase() ||
      request.repository.toLowerCase() === context.repository.toLowerCase() ||
      !/^refs\/heads\/[A-Za-z0-9][A-Za-z0-9/_.-]*$/.test(request.ref) ||
      request.ref.includes('..') || request.ref.endsWith('/') ||
      !Number.isSafeInteger(request.issued_at) || !Number.isSafeInteger(request.expires_at) ||
      request.issued_at > now + 60000 || request.expires_at <= now ||
      request.expires_at - request.issued_at > 24 * 3600 * 1000) throw new Error('Invalid request');
  if (!Array.isArray(request.steps) || !request.steps.length || request.steps.length > 40) {
    throw new Error('Invalid steps');
  }
  let seconds = 0;
  for (const step of request.steps) {
    if (!Array.isArray(step.argv) || !step.argv.length || step.argv.some(x => typeof x !== 'string' || x.includes('\0')) ||
        !Number.isInteger(step.timeout) || step.timeout < 1 || step.timeout > 10800 ||
        !step.env || typeof step.env !== 'object' || Array.isArray(step.env) ||
        Object.entries(step.env).some(([k, v]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || reserved.test(k) || typeof v !== 'string')) {
      throw new Error('Invalid step');
    }
    seconds += step.timeout;
  }
  if (seconds > 19800 || !Array.isArray(request.outputs) || request.outputs.length > 20 ||
      request.outputs.some(x => typeof x !== 'string' || !x || x.includes('\\') || x.includes('\0') ||
        path.posix.isAbsolute(x) || x.split('/').some(part => !part || part === '.' || part === '..' || part === '.git'))) {
    throw new Error('Invalid bounds');
  }
  return request;
}

export function childEnvironment(base, extra = {}) {
  const safe = Object.fromEntries(Object.entries(base).filter(([key]) => !reserved.test(key)));
  for (const key of Object.keys(extra)) if (reserved.test(key)) throw new Error('Reserved environment');
  return { ...safe, ...extra, CI: 'true', GIT_TERMINAL_PROMPT: '0' };
}

function killTree(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
    killer.on('error', () => {});
  } else {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Already exited. */ }
  }
}

export async function run(argv, { cwd, env, timeout, log, limit = maxLog }) {
  return await new Promise(resolve => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env, detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let bytes = 0;
    let timedOut = false;
    let overflow = false;
    let stdout = '';
    const capture = (data, out) => {
      bytes += data.length;
      if (bytes <= limit) {
        log.write(data);
        if (out && stdout.length < 4096) stdout += data.toString('utf8').slice(0, 4096 - stdout.length);
      } else {
        overflow = true;
        killTree(child);
      }
    };
    child.stdout.on('data', data => capture(data, true));
    child.stderr.on('data', data => capture(data, false));
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, timeout * 1000);
    const cancel = () => killTree(child);
    process.once('SIGTERM', cancel);
    process.once('SIGINT', cancel);
    child.on('error', () => {});
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      process.removeListener('SIGTERM', cancel);
      process.removeListener('SIGINT', cancel);
      // A normally exited parent can leave detached descendants holding files or credentials.
      killTree(child);
      resolve({ code, signal, timed_out: timedOut, log_limit_exceeded: overflow, stdout });
    });
  });
}

async function api(repository, token, suffix, { method = 'GET', body } = {}) {
  const response = await fetch(`https://api.github.com/repos/${repository}${suffix}`, {
    method, headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
      'User-Agent': 'task-executor', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(120000), redirect: 'error',
  });
  if (!response.ok) throw new Error('API request failed');
  return response.status === 204 ? null : await response.json();
}

async function upload(repository, token, release, name, file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 256 * 1024 * 1024) throw new Error('Invalid asset');
  const bytes = await readFile(file);
  const response = await fetch(`https://uploads.github.com/repos/${repository}/releases/${release}/assets?name=${encodeURIComponent(name)}`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream',
      'Content-Length': String(bytes.length), 'User-Agent': 'task-executor' },
    body: bytes, signal: AbortSignal.timeout(600000), redirect: 'error',
  });
  if (!response.ok) throw new Error('Asset upload failed');
  const asset = await response.json();
  return { name, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), asset_id: asset.id };
}

export async function outputFiles(root, requested) {
  const files = [];
  const seen = new Set();
  let bytes = 0;
  const visit = async file => {
    const stat = await lstat(file);
    const actual = await realpath(file);
    if (stat.isSymbolicLink() || !actual.startsWith(root + path.sep)) throw new Error('Unsafe output');
    if (stat.isDirectory()) {
      for (const name of (await readdir(file)).sort()) await visit(path.join(file, name));
    } else if (stat.isFile()) {
      if (seen.has(actual)) return;
      seen.add(actual);
      bytes += stat.size;
      if (stat.size > 256 * 1024 * 1024 || bytes > 1024 * 1024 * 1024 || files.length >= 100) {
        throw new Error('Output limit exceeded');
      }
      files.push(file);
    } else throw new Error('Invalid output');
  };
  for (const name of requested) await visit(path.resolve(root, name));
  return files;
}

export async function execute(request, context, credentials) {
  validate(request, context);
  if (!credentials.source || !credentials.result) throw new Error('Missing credentials');
  for (const token of [credentials.source, credentials.result]) {
    const info = await api(request.repository, token, '');
    if (info.private !== true || info.full_name.toLowerCase() !== request.repository.toLowerCase()) {
      throw new Error('Destination must be private');
    }
  }
  // Creating this private ref claims the request exactly once, before any build.
  // Ambiguous POST responses are never retried. A rerun must use a new request.
  const tag = `ci-request-${request.id}`;
  await api(request.repository, credentials.result, '/git/refs', {
    method: 'POST', body: { ref: `refs/tags/${tag}`, sha: request.sha },
  });
  const release = await api(request.repository, credentials.result, '/releases', {
    method: 'POST', body: { tag_name: tag, name: `CI ${request.id}`, draft: true,
      body: 'Pending. Missing or incomplete receipts do not indicate success.' },
  });
  const directory = await mkdtemp(path.join(context.scratch || tmpdir(), 'task-'));
  const source = path.join(directory, 'source');
  const logPath = path.join(directory, 'execution.log');
  const log = createWriteStream(logPath, { mode: 0o600 });
  // Prevent stream errors from printing path-bearing exception details.
  let logError = false;
  log.on('error', () => { logError = true; });
  const receipt = { version: 1, request_id: request.id, repository: request.repository,
    source_sha: request.sha, ref: request.ref, runner: request.runner,
    started_at: new Date().toISOString(), result: 'FAILURE', steps: [], assets: [],
    public_run: context.run_url, production_ready: false };
  try {
    await mkdir(source);
    const environment = childEnvironment(process.env);
    const git = async (args, auth = false) => {
      const env = { ...environment };
      if (auth) {
        env.GIT_CONFIG_COUNT = '1';
        env.GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraheader';
        env.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${Buffer.from('x-access-token:' + credentials.source).toString('base64')}`;
      }
      const result = await run(['git', '-c', 'core.fsmonitor=false', ...args], {
        cwd: source, env, timeout: 900, log,
      });
      if (result.code !== 0 || result.timed_out || result.log_limit_exceeded) throw new Error('Checkout failed');
      return result.stdout.trim();
    };
    await git(['init', '--quiet']);
    await git(['remote', 'add', 'origin', `https://github.com/${request.repository}.git`]);
    await git(['fetch', '--quiet', '--no-tags', '--depth=1', 'origin', `${request.ref}:refs/remotes/origin/input`], true);
    const fetched = await git(['rev-parse', 'refs/remotes/origin/input']);
    if (fetched !== request.sha) throw new Error('Source changed');
    await git(['checkout', '--quiet', '--detach', request.sha]);
    receipt.checkout_sha = await git(['rev-parse', 'HEAD']);
    for (const step of request.steps) {
      const result = await run(step.argv, { cwd: source,
        env: childEnvironment(process.env, step.env), timeout: step.timeout, log });
      delete result.stdout;
      receipt.steps.push(result);
      if (result.code !== 0 || result.timed_out || result.log_limit_exceeded || logError) throw new Error('Step failed');
    }
    const files = await outputFiles(source, request.outputs);
    for (const [index, file] of files.entries()) {
      receipt.assets.push({ path: path.relative(source, file),
        ...await upload(request.repository, credentials.result, release.id, `output-${index + 1}.bin`, file) });
    }
    receipt.result = 'SUCCESS';
  } catch {
    receipt.result = 'FAILURE';
  } finally {
    try {
      await new Promise((resolve, reject) => {
        if (log.destroyed) { logError ? reject(new Error('Log failed')) : resolve(); return; }
        log.once('error', reject);
        log.end(resolve);
      });
      if (logError) throw new Error('Log failed');
      const compressed = path.join(directory, 'execution.log.gz');
      await pipeline(createReadStream(logPath), createGzip(), createWriteStream(compressed, { mode: 0o600 }));
      receipt.assets.push(await upload(request.repository, credentials.result, release.id, 'execution.log.gz', compressed));
      receipt.finished_at = new Date().toISOString();
      const receiptPath = path.join(directory, 'receipt.json');
      await writeFile(receiptPath, JSON.stringify(receipt, null, 2) + '\n', { mode: 0o600 });
      await upload(request.repository, credentials.result, release.id, 'receipt.json', receiptPath);
      await api(request.repository, credentials.result, `/releases/${release.id}`, {
        method: 'PATCH', body: { body: `${receipt.result}; source ${request.sha}; request ${request.id}. See receipt.json.` },
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
  return receipt.result === 'SUCCESS';
}

export async function main() {
  if (process.env.RUNNER_DEBUG === '1' || process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
      process.env.GITHUB_RUN_ATTEMPT !== '1') throw new Error('Invalid execution context');
  const context = { repository: process.env.GITHUB_REPOSITORY, runner: process.env.EXECUTOR_RUNNER,
    run_url: `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` };
  const request = open(process.env.TICKET, process.env.EXECUTION_KEY);
  const credentials = { source: process.env.SOURCE_TOKEN, result: process.env.RESULT_TOKEN };
  for (const key of ['TICKET', 'EXECUTION_KEY', 'SOURCE_TOKEN', 'RESULT_TOKEN']) delete process.env[key];
  return await execute(request, context, credentials);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.on('uncaughtException', () => { process.stderr.write('Task failed.\n'); process.exit(1); });
  process.on('unhandledRejection', () => { process.stderr.write('Task failed.\n'); process.exit(1); });
  try {
    const success = await main();
    process.stdout.write(success ? 'Task completed.\n' : 'Task failed.\n');
    process.exitCode = success ? 0 : 1;
  } catch {
    process.stderr.write('Task failed.\n');
    process.exitCode = 1;
  }
}

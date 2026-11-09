#!/usr/bin/env node
// Startup checks: the remote device names folder limits left in the config
// file, and ripgrep is only used when the binary actually runs.
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const { readAllowedDirectories } = await import('../dist/remote-device/device.js');
const { ripgrepRuns, getRipgrepPath, clearRipgrepCache } = await import('../dist/utils/ripgrep-resolver.js');

const tmp = await mkdtemp(path.join(os.tmpdir(), 'dc-startup-'));
try {
  const cfg = path.join(tmp, 'config.json');
  assert.deepEqual(await readAllowedDirectories(path.join(tmp, 'missing.json')), []);
  await writeFile(cfg, '{not json');
  assert.deepEqual(await readAllowedDirectories(cfg), []);
  await writeFile(cfg, JSON.stringify({ allowedDirectories: [] }));
  assert.deepEqual(await readAllowedDirectories(cfg), []);
  await writeFile(cfg, JSON.stringify({ allowedDirectories: ['/'] }));
  assert.deepEqual(await readAllowedDirectories(cfg), [], '"/" means every path');
  await writeFile(cfg, JSON.stringify({ allowedDirectories: ['C:\\a', '', 5, 'D:\\b'] }));
  assert.deepEqual(await readAllowedDirectories(cfg), ['C:\\a', 'D:\\b']);

  // A file that exists but is not a runnable ripgrep is rejected.
  const fake = path.join(tmp, process.platform === 'win32' ? 'rg.exe' : 'rg');
  await writeFile(fake, 'not a program', { mode: 0o755 });
  assert.equal(ripgrepRuns(fake), false);
  assert.equal(ripgrepRuns(path.join(tmp, 'nope')), false);

  // Whatever ripgrep the resolver picks, it runs.
  clearRipgrepCache();
  let rg;
  try { rg = await getRipgrepPath(); } catch { rg = undefined; }
  if (rg) assert.equal(ripgrepRuns(rg), true, `${rg} should run`);
  console.log('test-startup-checks: all passed');
} finally {
  await rm(tmp, { recursive: true, force: true });
}

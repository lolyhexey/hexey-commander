#!/usr/bin/env node
// jadx tools offered by a remote device. The pure parts always run; the
// end-to-end part runs only when JADX_HOME points at a real jadx and
// JADX_TEST_APK at an APK to decompile.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const j = await import('../dist/remote-device/jadx-tools.js');
const { selectPublishedTools } = await import('../dist/remote-device/tool-allowlist.js');

const tmp = await mkdtemp(path.join(os.tmpdir(), 'dc-jadx-'));
try {
  // Not offered without the opt-in, or when the folder has no jadx jar.
  assert.equal(j.resolveJadxSetup({}), undefined);
  assert.equal(j.resolveJadxSetup({ JADX_HOME: tmp }), undefined);
  await mkdir(path.join(tmp, 'lib'));
  assert.equal(j.resolveJadxSetup({ JADX_HOME: tmp }), undefined);

  const fake = path.join(tmp, 'jadx');
  await mkdir(path.join(fake, 'lib'), { recursive: true });
  await writeFile(path.join(fake, 'lib', 'jadx-1.5.6-all.jar'), '');
  const setup = j.resolveJadxSetup({ JADX_HOME: fake, JADX_OUTPUT_DIR: path.join(tmp, 'out') });
  assert.ok(setup);
  assert.equal(setup.jar, path.join(fake, 'lib', 'jadx-1.5.6-all.jar'));
  assert.equal(setup.outputDir, path.join(tmp, 'out'));

  // Every tool is jadx_-prefixed, published whole and requires a file.
  assert.ok(j.JADX_TOOLS.every((t) => t.name.startsWith(j.JADX_TOOL_PREFIX) && j.isJadxTool(t.name)));
  assert.equal(j.isJadxTool('ghidra_decompile'), false);
  assert.equal(selectPublishedTools([...j.JADX_TOOLS]).length, j.JADX_TOOLS.length);
  for (const t of j.JADX_TOOLS) assert.ok(t.inputSchema.required.includes('file'), t.name);

  // Errors are tool errors, not throws: a missing file, and reading before decompiling.
  const missing = await j.callJadxTool(setup, 'jadx_list_classes', { file: path.join(tmp, 'nope.apk') });
  assert.equal(missing.isError, true);
  assert.match(missing.content[0].text, /no such file/);
  const apk = path.join(tmp, 'a.apk');
  await writeFile(apk, 'x');
  const early = await j.callJadxTool(setup, 'jadx_get_manifest', { file: apk });
  assert.equal(early.isError, true);
  assert.match(early.content[0].text, /jadx_decompile/);

  const home = process.env.JADX_HOME;
  const testApk = process.env.JADX_TEST_APK;
  if (home && testApk && j.resolveJadxSetup(process.env)) {
    const real = j.resolveJadxSetup({ ...process.env, JADX_OUTPUT_DIR: path.join(tmp, 'real') });
    const call = (name, args) => j.callJadxTool(real, name, { file: testApk, ...args });
    const d = await call('jadx_decompile', {});
    assert.equal(d.isError, undefined, d.content[0].text);
    assert.match(d.content[0].text, /classes: [1-9]/);
    assert.match((await call('jadx_decompile', {})).content[0].text, /Already decompiled/);
    const classes = (await call('jadx_list_classes', {})).content[0].text.split('\n');
    const src = await call('jadx_get_class', { class: classes[1] });
    assert.equal(src.isError, undefined);
    assert.match(src.content[0].text, /class /);
    assert.match((await call('jadx_get_manifest', {})).content[0].text, /<manifest/);
    assert.match((await call('jadx_search_code', { query: 'class', max: 2 })).content[0].text, /^2 matches/);
    // Paths may not climb out of the output folder.
    assert.equal((await call('jadx_get_resource', { path: '../../' + path.basename(testApk) })).isError, true);
    console.log('jadx end-to-end: passed');
  } else {
    console.log('jadx end-to-end: skipped (JADX_HOME or JADX_TEST_APK not set)');
  }
  console.log('test-remote-jadx-tools: all passed');
} finally {
  await rm(tmp, { recursive: true, force: true });
}

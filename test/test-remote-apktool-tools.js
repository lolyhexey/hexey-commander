#!/usr/bin/env node
// apktool tools offered by a remote device. The pure parts always run; the
// end-to-end part (decode, edit, build, zipalign, sign, verify; no install)
// runs only when APKTOOL_JAR points at a real apktool jar and APKTOOL_TEST_APK
// at an APK.
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const t = await import('../dist/remote-device/apktool-tools.js');
const { selectPublishedTools } = await import('../dist/remote-device/tool-allowlist.js');

const tmp = await mkdtemp(path.join(os.tmpdir(), 'dc-apktool-'));
try {
  // Not offered without the opt-in, or when it does not name an existing jar.
  assert.equal(t.resolveApktoolSetup({}), undefined);
  assert.equal(t.resolveApktoolSetup({ APKTOOL_JAR: path.join(tmp, 'missing.jar') }), undefined);
  const notJar = path.join(tmp, 'apktool.txt');
  await writeFile(notJar, '');
  assert.equal(t.resolveApktoolSetup({ APKTOOL_JAR: notJar }), undefined);

  const jar = path.join(tmp, 'apktool_3.0.3.jar');
  await writeFile(jar, '');
  const setup = t.resolveApktoolSetup({ APKTOOL_JAR: jar, APKTOOL_WORK_DIR: path.join(tmp, 'work'), ANDROID_HOME: path.join(tmp, 'no-sdk') });
  assert.ok(setup);
  assert.equal(setup.jar, jar);
  assert.equal(setup.workDir, path.join(tmp, 'work'));

  assert.ok(t.APKTOOL_TOOLS.every((x) => x.name.startsWith(t.APKTOOL_TOOL_PREFIX) && t.isApktoolTool(x.name)));
  assert.equal(t.isApktoolTool('jadx_decompile'), false);
  assert.equal(selectPublishedTools([...t.APKTOOL_TOOLS]).length, t.APKTOOL_TOOLS.length);

  const missing = await t.callApktoolTool(setup, 'apktool_list_files', { file: path.join(tmp, 'nope.apk') });
  assert.equal(missing.isError, true);
  const apk = path.join(tmp, 'a.apk');
  await writeFile(apk, 'x');
  const early = await t.callApktoolTool(setup, 'apktool_build', { file: apk });
  assert.equal(early.isError, true);
  assert.match(early.content[0].text, /apktool_decode/);

  const realJar = process.env.APKTOOL_JAR;
  const testApk = process.env.APKTOOL_TEST_APK;
  if (realJar && testApk && t.resolveApktoolSetup(process.env)) {
    const real = t.resolveApktoolSetup({ ...process.env, APKTOOL_WORK_DIR: path.join(tmp, 'real') });
    const call = (name, args) => t.callApktoolTool(real, name, { file: testApk, ...args });
    const d = await call('apktool_decode', {});
    assert.equal(d.isError, undefined, d.content[0].text);
    assert.match((await call('apktool_decode', {})).content[0].text, /Already decoded/);
    assert.match((await call('apktool_read_file', { path: 'apktool.yml' })).content[0].text, /^1\t/);
    assert.equal((await call('apktool_write_file', { path: '../../x.txt', content: 'x' })).isError, true);
    assert.equal((await call('apktool_read_file', { path: '../../' + path.basename(testApk) })).isError, true);
    assert.match((await call('apktool_write_file', { path: 'assets/hexey-test.txt', content: 'hello' })).content[0].text, /Wrote/);
    assert.match((await call('apktool_edit_file', { path: 'assets/hexey-test.txt', old_text: 'hello', new_text: 'bye' })).content[0].text, /Replaced 1/);
    assert.equal((await call('apktool_edit_file', { path: 'assets/hexey-test.txt', old_text: 'hello', new_text: 'x' })).isError, true);
    if (real.apksigner) {
      const b = await call('apktool_build', {});
      assert.equal(b.isError, undefined, b.content[0].text);
      assert.match(b.content[0].text, /signed \(v/);
      assert.match(b.content[0].text, /sha256: [0-9a-f]{64}/);
    }
    console.log('apktool end-to-end: passed');
  } else {
    console.log('apktool end-to-end: skipped (APKTOOL_JAR or APKTOOL_TEST_APK not set)');
  }
  console.log('test-remote-apktool-tools: all passed');
} finally {
  await rm(tmp, { recursive: true, force: true });
}

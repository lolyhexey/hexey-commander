#!/usr/bin/env node
// adb tools offered by a remote device. The checks here need no device; with
// ADB_TEST_SERIAL set to a connected device, a few read-only calls run too.
import assert from 'node:assert/strict';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const t = await import('../dist/remote-device/adb-tools.js');
const { selectPublishedTools } = await import('../dist/remote-device/tool-allowlist.js');

// Offered only with ADB_ENABLED=1.
assert.equal(t.resolveAdbSetup({}), undefined);
assert.equal(t.resolveAdbSetup({ ADB_ENABLED: 'true' }), undefined);
assert.ok(t.resolveAdbSetup({ ADB_ENABLED: '1' }));

assert.ok(t.ADB_TOOLS.every((x) => x.name.startsWith(t.ADB_TOOL_PREFIX) && t.isAdbTool(x.name)));
assert.equal(t.isAdbTool('apktool_build'), false);
assert.equal(selectPublishedTools([...t.ADB_TOOLS]).length, t.ADB_TOOLS.length);

// Bad input is refused before anything reaches the device or a shell.
const setup = { adb: 'adb-that-does-not-exist' };
for (const [name, args, re] of [
  ['adb_pull_apk', { package: 'x;rm -rf /', local_dir: '/tmp/x' }, /not a package name/],
  ['adb_pull_apk', { package: 'com.example', local_dir: 'relative' }, /absolute/],
  ['adb_logcat', { package: '$(reboot)' }, /not a package name/],
  ['adb_shell', { command: '  ' }, /command is required/],
  ['adb_install', { apk: '/no/such.apk' }, /no such APK/],
  ['adb_pull', { remote: '/sdcard/a', local: 'rel' }, /absolute/],
]) {
  const r = await t.callAdbTool(setup, name, args);
  assert.equal(r.isError, true, name);
  assert.match(r.content[0].text, re, name);
}
// A missing adb is a tool error, not a crash.
assert.equal((await t.callAdbTool(setup, 'adb_devices', {})).isError, true);

const serial = process.env.ADB_TEST_SERIAL;
if (serial) {
  const real = t.resolveAdbSetup({ ...process.env, ADB_ENABLED: '1' });
  assert.match((await t.callAdbTool(real, 'adb_devices', {})).content[0].text, new RegExp(serial));
  const ok = await t.callAdbTool(real, 'adb_shell', { serial, command: 'echo hexey' });
  assert.match(ok.content[0].text, /hexey\n\[exit 0\]/);
  const bad = await t.callAdbTool(real, 'adb_shell', { serial, command: 'exit 3' });
  assert.equal(bad.isError, true);
  assert.match(bad.content[0].text, /\[exit 3\]/);
  console.log('adb device checks: passed');
} else {
  console.log('adb device checks: skipped (ADB_TEST_SERIAL not set)');
}
console.log('test-remote-adb-tools: all passed');

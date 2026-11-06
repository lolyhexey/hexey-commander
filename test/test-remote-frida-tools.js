#!/usr/bin/env node
// Frida tools offered by a remote device. The pure parts always run; the
// end-to-end part runs only with FRIDA_ENABLED=1 and the frida Python module,
// against a ping.exe this test starts and ends itself.
import assert from 'node:assert/strict';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const f = await import('../dist/remote-device/frida-tools.js');
const { selectPublishedTools } = await import('../dist/remote-device/tool-allowlist.js');

// Off unless the person at the device turns it on.
assert.equal(f.resolveFridaSetup({}), undefined);
assert.equal(f.resolveFridaSetup({ FRIDA_ENABLED: '0' }), undefined);
assert.equal(f.resolveFridaSetup({ FRIDA_ENABLED: '1', FRIDA_PYTHON: 'no-such-python-xyz' }), undefined);

// Well-formed and publishable.
const published = selectPublishedTools([...f.FRIDA_TOOLS]);
assert.equal(published.length, f.FRIDA_TOOLS.length);
for (const t of f.FRIDA_TOOLS) {
  assert.equal(t.inputSchema.type, 'object', t.name);
  for (const r of t.inputSchema.required ?? []) assert.ok(t.inputSchema.properties[r], `${t.name}.${r}`);
  assert.ok(f.isFridaTool(t.name));
}
assert.ok(!f.isFridaTool('frida_whatever'));
assert.ok(!f.isFridaTool('read_file'));

assert.equal(f.hexDump('0x1000', '4d5a9000'), '0x1000  4d 5a 90 00                                      MZ..');

const setup = f.resolveFridaSetup({ ...process.env, FRIDA_ENABLED: '1' });
if (setup && process.platform === 'win32') {
  const call = (name, args) => f.callFridaTool(setup, name, args);
  const ok = async (name, args, re) => {
    const r = await call(name, args);
    const t = r.content[0].text;
    assert.ok(!r.isError, `${name}: ${t.slice(0, 600)}`);
    if (re) assert.match(t, re, `${name}: ${t.slice(0, 600)}`);
    return t;
  };
  try {
    const sp = JSON.parse(await ok('frida_spawn', { program: 'C:\\Windows\\System32\\PING.EXE', args: ['-n', '30', '127.0.0.1'] }, /"session"/));
    const s = sp.session;
    await ok('frida_list_processes', { filter: String(sp.pid) }, new RegExp(`^${sp.pid}\\s+`, 'm'));
    await ok('frida_list_sessions', {}, new RegExp(`"pid": ${sp.pid}`));
    const mods = await ok('frida_list_modules', { session: s, filter: 'kernel32' }, /KERNEL32\.DLL/i);
    const base = mods.split(/\s+/)[0];
    await ok('frida_read_memory', { session: s, address: base, length: 16 }, /^0x[0-9a-f]+\s+4d 5a/m);
    await ok('frida_list_exports', { session: s, module: 'kernel32.dll', filter: 'GetTickCount' }, /function\s+GetTickCount/);
    const tr = await ok('frida_trace_function', { session: s, target: 'kernel32.dll!GetTickCount', duration_ms: 1500 }, /"resolved": "0x/);
    assert.ok(tr.startsWith('['), tr.slice(0, 200));
    await ok('frida_run_script', { session: s, source: 'send(Process.arch); send({done:true});', timeout_ms: 3000 }, /"payload": "(x64|ia32|arm64)"/);
    const bad = await call('frida_read_memory', { session: s, address: '0x1', length: 4 });
    assert.equal(bad.isError, true);
    assert.equal((await call('frida_list_modules', { session: '999' })).isError, true);
    await ok('frida_detach', { session: s, kill: true }, /"detached"/);
    assert.equal((await call('frida_list_modules', { session: s })).isError, true);
    console.log('frida end-to-end: passed');
  } finally {
    f.shutdownFrida();
  }
} else {
  console.log('frida end-to-end: skipped (FRIDA_ENABLED or frida Python module missing)');
}
console.log('test-remote-frida-tools: all passed');

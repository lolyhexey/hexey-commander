#!/usr/bin/env node
// Ghidra tools offered by a remote device. The pure parts always run; the
// end-to-end part runs only when GHIDRA_INSTALL_DIR points at a real Ghidra.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
const g = await import('../dist/remote-device/ghidra-tools.js');
const { selectPublishedTools } = await import('../dist/remote-device/tool-allowlist.js');

const tmp = await mkdtemp(path.join(os.tmpdir(), 'dc-ghidra-'));
try {
  // Not offered without the opt-in, or when the folder is not a Ghidra install.
  assert.equal(g.resolveGhidraSetup({}), undefined);
  assert.equal(g.resolveGhidraSetup({ GHIDRA_INSTALL_DIR: tmp }), undefined);
  const fake = path.join(tmp, 'ghidra');
  await mkdir(path.join(fake, 'Ghidra', 'Framework', 'Utility', 'lib'), { recursive: true });
  await writeFile(path.join(fake, 'Ghidra', 'Framework', 'Utility', 'lib', 'Utility.jar'), '');
  const setup = g.resolveGhidraSetup({ GHIDRA_INSTALL_DIR: fake, GHIDRA_PROJECTS_DIR: path.join(tmp, 'p') });
  assert.ok(setup);
  assert.equal(setup.installDir, fake);
  assert.equal(setup.projectsDir, path.join(tmp, 'p'));

  // The default projects folder is one Ghidra accepts: no part starting with ".".
  const def = g.resolveGhidraSetup({ GHIDRA_INSTALL_DIR: fake, LOCALAPPDATA: process.env.LOCALAPPDATA });
  assert.equal(g.dottedPathElement(def.projectsDir), undefined, def.projectsDir);
  assert.equal(g.dottedPathElement(path.join(os.homedir(), '.desktop-commander', 'x')), '.desktop-commander');
  // A configured folder Ghidra would refuse is reported clearly, not as an analysis failure.
  const dotted = { ...setup, projectsDir: path.join(tmp, '.hidden', 'p') };
  await writeFile(path.join(tmp, 'y.bin'), 'y');
  const dr = await g.callGhidraTool(dotted, 'ghidra_analyze', { file: path.join(tmp, 'y.bin') });
  assert.equal(dr.isError, true);
  assert.match(dr.content[0].text, /starts with "\."/);

  // Same file name in two folders gets two projects; same path gets the same one.
  const a = g.projectNameFor('C:\\a\\tool.exe'), b = g.projectNameFor('C:\\b\\tool.exe');
  assert.notEqual(a, b);
  assert.equal(a, g.projectNameFor('C:\\a\\tool.exe'));
  assert.match(a, /^tool\.exe-[0-9a-f]{12}$/);
  assert.match(g.projectNameFor('/x/we ird;&|name'), /^we_ird___name-[0-9a-f]{12}$/);

  // Only the script's block is returned.
  assert.equal(g.extractBlock('noise\n=== HEXEY info  ===\nname: x\n=== END ===\nmore'), '=== HEXEY info  ===\nname: x\n=== END ===');
  assert.equal(g.extractBlock('no block here'), undefined);

  // Tools are well-formed and publishable alongside the usual ones.
  const published = selectPublishedTools([...g.GHIDRA_TOOLS]);
  assert.equal(published.length, g.GHIDRA_TOOLS.length);
  assert.equal(new Set(published.map((t) => t.name)).size, published.length);
  // Names an AI may already use stay as they were.
  for (const n of ['ghidra_analyze', 'ghidra_info', 'ghidra_list_functions', 'ghidra_decompile', 'ghidra_strings', 'ghidra_xrefs']) {
    assert.ok(published.some((t) => t.name === n), n);
  }
  for (const t of g.GHIDRA_TOOLS) {
    assert.equal(t.inputSchema.type, 'object');
    const notPerFile = ['ghidra_list_projects', 'ghidra_analysis_status', 'ghidra_batch_analyze'];
    if (!notPerFile.includes(t.name)) assert.ok(t.inputSchema.required.includes('file'), t.name);
    for (const r of t.inputSchema.required ?? []) assert.ok(t.inputSchema.properties[r], `${t.name}.${r}`);
    assert.equal(typeof t.annotations.readOnlyHint, 'boolean', t.name);
  }
  // Together with Desktop Commander's own tools the list stays under the publish limit.
  assert.ok(g.GHIDRA_TOOLS.length + 40 <= 100);
  assert.ok(g.isGhidraTool('ghidra_decompile'));
  assert.ok(!g.isGhidraTool('ghidra_whatever'));
  assert.ok(!g.isGhidraTool('read_file'));

  // Bad input is refused before anything runs.
  const err = async (name, args, re) => {
    const r = await g.callGhidraTool(setup, name, args);
    assert.equal(r.isError, true, name);
    assert.match(r.content[0].text, re, name);
  };
  await err('ghidra_info', {}, /absolute path/);
  await err('ghidra_info', { file: 'relative.exe' }, /absolute path/);
  await err('ghidra_info', { file: path.join(tmp, 'missing.exe') }, /file not found/);
  await err('ghidra_info', { file: tmp }, /not a file/);
  const bin = path.join(tmp, 'x.bin');
  await writeFile(bin, 'x');
  await err('ghidra_info', { file: bin }, /has not been analyzed yet/);
  await err('ghidra_decompile', { file: bin }, /"target"/);
  await err('ghidra_disassemble', { file: bin, target: 'entry', count: 'lots' }, /whole number/);
  await err('ghidra_read_bytes', { file: bin, address: '140000000', length: -5 }, /whole number/);
  // Ghidra would read a value starting with "-" as its own option.
  await err('ghidra_search_symbols', { file: bin, query: '-deleteProject' }, /cannot start with "-"/);
  await err('ghidra_get_function', { file: bin, target: { x: 1 } }, /must be a string/);

  // End to end against a real Ghidra, when one is configured.
  const real = g.resolveGhidraSetup({ ...process.env, GHIDRA_PROJECTS_DIR: path.join(tmp, 'real') });
  const sample = process.platform === 'win32' ? 'C:\\Windows\\System32\\whoami.exe' : '/bin/ls';
  if (real) {
    const an = await g.callGhidraTool(real, 'ghidra_analyze', { file: sample });
    assert.ok(!an.isError, an.content[0].text);
    assert.match(an.content[0].text, /Import succeeded/);
    const info = await g.callGhidraTool(real, 'ghidra_info', { file: sample });
    assert.match(info.content[0].text, /functions: \d+/);
    const list = await g.callGhidraTool(real, 'ghidra_list_functions', { file: sample, filter: 'entry' });
    assert.match(list.content[0].text, /entry/);
    const dec = await g.callGhidraTool(real, 'ghidra_decompile', { file: sample, target: 'entry' });
    assert.ok(!dec.isError, dec.content[0].text);
    assert.match(dec.content[0].text, /entry\s*\(/);
    assert.doesNotMatch(dec.content[0].text, /^INFO /m);
    const strs = await g.callGhidraTool(real, 'ghidra_strings', { file: sample });
    assert.match(strs.content[0].text, /=== END ===/);
    const xr = await g.callGhidraTool(real, 'ghidra_xrefs', { file: sample, target: 'entry' });
    assert.match(xr.content[0].text, /=== END ===/);
    // Every query tool answers with its block and no error.
    const call = async (name, args, re) => {
      const r = await g.callGhidraTool(real, name, { file: sample, ...args });
      const t = r.content[0].text;
      assert.ok(!r.isError, `${name}: ${t.slice(0, 600)}`);
      assert.match(t, /=== END ===$/, name);
      if (re) assert.match(t, re, `${name}: ${t.slice(0, 600)}`);
      return t;
    };
    if (process.platform === 'win32') {
      await call('ghidra_get_memory_map', {}, /\.text\s+\S+\s+\S+\s+\d+\s+r-x/);
      await call('ghidra_get_imports', {}, /KERNEL32\.DLL!|kernel32\.dll!|api-ms-/i);
      await call('ghidra_get_exports', {}, /entry/);
      await call('ghidra_search_symbols', { query: 'entry' }, /entry/);
      await call('ghidra_get_function', { target: 'entry' }, /signature: .*entry/);
      await call('ghidra_disassemble', { target: 'entry' }, /^140001cb0\s+[0-9a-f]{2}/m);
      await call('ghidra_disassemble', { target: '140001cb0', count: 3 }, /stopped after 3/);
      await call('ghidra_read_bytes', { address: '140000000', length: 32 }, /^140000000\s+4d 5a/m);
      await call('ghidra_read_bytes', { address: '0x140000000', length: 2 }, /4d 5a\s+MZ/);
      await call('ghidra_search_bytes', { pattern: '4d 5a ?? 00' }, /^140000000\s/m);
      await call('ghidra_search_constants', { value: '0x5A4D' });
      await call('ghidra_get_references_from', { target: 'entry' }, /->/);
      await call('ghidra_get_function_calls', { target: 'entry' }, /->/);
      await call('ghidra_get_call_graph', { target: 'entry', depth: 2 }, /callees of entry:\n\s+\S+\s+FUN_/);
      await call('ghidra_get_cfg', { target: 'entry' }, /^140001cb0 - /m);
      await call('ghidra_get_pcode', { target: 'entry' }, /CALL|COPY|INT_/);
      await call('ghidra_get_high_pcode', { target: 'entry' }, /CALL/);
      await call('ghidra_get_variables', { target: 'entry' }, /declared in the function:/);
      await call('ghidra_get_decompiler_tokens', { target: 'entry' }, /entry/);
      await call('ghidra_get_data_types', { filter: 'IMAGE_DOS_HEADER' }, /e_magic/);
    }
    if (process.platform === 'win32') {
      // Edits, backups and undo, on a copy so other runs are not affected.
      const { copyFile, readFile, stat } = await import('node:fs/promises');
      const copy = path.join(tmp, 'edit-me.exe');
      await copyFile(sample, copy);
      const on = (name, args) => g.callGhidraTool(real, name, { file: copy, ...args });
      const ok = async (name, args, re) => {
        const r = await on(name, args);
        assert.ok(!r.isError, `${name}: ${r.content[0].text.slice(0, 800)}`);
        if (re) assert.match(r.content[0].text, re, `${name}: ${r.content[0].text.slice(0, 800)}`);
        return r.content[0].text;
      };
      assert.equal((await on('ghidra_rename_function', { target: 'entry', new_name: 'x' })).isError, true); // not analyzed yet
      await ok('ghidra_analyze', {}, /Import succeeded/);
      assert.equal((await on('ghidra_undo_edit', {})).isError, true); // nothing to undo

      await ok('ghidra_rename_function', { target: 'entry', new_name: 'my_entry' }, /renamed function entry -> my_entry/);
      await ok('ghidra_decompile', { target: 'my_entry' }, /void my_entry\(void\)/);
      await ok('ghidra_undo_edit', {}, /before: rename_function/);
      await ok('ghidra_decompile', { target: 'entry' }, /void entry\(void\)/);
      assert.equal((await on('ghidra_decompile', { target: 'my_entry' })).isError, true);

      await ok('ghidra_set_function_signature', { target: 'FUN_140001af0', signature: 'int run_main(int mode)' }, /int run_main\(int mode\)/);
      await ok('ghidra_get_function', { target: 'run_main' }, /signature: int run_main\(int mode\)/);
      await ok('ghidra_rename_variable', { target: 'run_main', old_name: 'mode', new_name: 'how' }, /mode -> how/);
      await ok('ghidra_get_function', { target: 'run_main' }, /int run_main\(int how\)/);
      await ok('ghidra_set_comment', { address: '140001cb0', kind: 'plate', comment: 'Program start' }, /set plate comment at 140001cb0/);
      await ok('ghidra_decompile', { target: 'entry' }, /Program start/);
      await ok('ghidra_create_structure', { definition: 'struct HexeyHdr { int magic; short count; char name[16]; };' }, /HexeyHdr \(24 bytes\)/);
      await ok('ghidra_get_data_types', { filter: 'HexeyHdr' }, /\+0x6\s+char\[16\]\s+name/);
      await ok('ghidra_apply_data_type', { address: '140000000', type: 'word' }, /applied word at 140000000/);
      assert.match((await on('ghidra_apply_data_type', { address: '140001cb0', type: 'dword' })).content[0].text, /is code/);
      await ok('ghidra_patch_bytes', { address: '140001cb0', bytes: '90 90 90 90' }, /patched 4 bytes at 140001cb0 \(was 48 83 ec 28\)/);
      await ok('ghidra_disassemble', { target: '140001cb0', count: 2 }, /140001cb0\s+90\s+NOP/);
      // A failed edit restores the project and changes nothing.
      assert.equal((await on('ghidra_patch_bytes', { address: '140001cb0', bytes: 'zz' })).isError, true);
      await ok('ghidra_disassemble', { target: '140001cb0', count: 1 }, /NOP/);

      // Exports go to the projects folder; the binary itself is untouched.
      const exp = await ok('ghidra_export_program', { format: 'original' }, /exported Original File to /);
      const outPath = /exported Original File to (.+) \(\d+ bytes\)/.exec(exp)[1];
      const outBytes = await readFile(outPath);
      const src = await readFile(copy);
      assert.equal(outBytes.length, src.length);
      assert.ok(outBytes.indexOf(Buffer.from([0x90, 0x90, 0x90, 0x90])) >= 0);
      assert.equal(src.indexOf(Buffer.from([0x90, 0x90, 0x90, 0x90, 0x48])), -1);
      await ok('ghidra_export_program', { format: 'c' }, /exported C\/C\+\+ to .+\.c /);
      assert.equal((await on('ghidra_export_program', { format: 'exe' })).isError, true);

      const rep = await ok('ghidra_export_report', { max_items: 20 }, /"functionCount": \d+/);
      const repPath = /^Saved to (.+)$/m.exec(rep)[1];
      assert.ok((await stat(repPath)).size > 0);
      await ok('ghidra_export_report', { format: 'markdown' }, /## Imports/);

      // Every edit is in the audit log.
      const log = (await readFile(path.join(tmp, 'real', '_audit.jsonl'), 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
      for (const t of ['ghidra_rename_function', 'ghidra_undo_edit', 'ghidra_patch_bytes', 'ghidra_export_program']) assert.ok(log.some((e) => e.tool === t), t);
      assert.ok(log.some((e) => e.tool === 'ghidra_patch_bytes' && e.ok === false));

      // Projects, batches, status and cancel.
      const listed = (await g.callGhidraTool(real, 'ghidra_list_projects', {})).content[0].text;
      assert.ok(listed.includes(copy) && listed.includes(sample), listed);
      const b1 = path.join(tmp, 'b1.exe'), b2 = path.join(tmp, 'b2.exe');
      await copyFile('C:\\Windows\\System32\\where.exe', b1);
      await copyFile('C:\\Windows\\System32\\findstr.exe', b2);
      const q = await g.callGhidraTool(real, 'ghidra_batch_analyze', { files: [b1, b2] });
      assert.match(q.content[0].text, /Queued 2 file/);
      const c = await g.callGhidraTool(real, 'ghidra_cancel_analysis', { file: b2 });
      assert.match(c.content[0].text, /Cancelled the queued analysis/);
      for (let i = 0; i < 120; i++) {
        const st = (await g.callGhidraTool(real, 'ghidra_analysis_status', {})).content[0].text;
        if (/done .*b1\.exe/.test(st)) break;
        await new Promise((r) => setTimeout(r, 1000));
      }
      const st = (await g.callGhidraTool(real, 'ghidra_analysis_status', {})).content[0].text;
      assert.match(st, /^done .*b1\.exe/m, st);
      assert.match(st, /^cancelled .*b2\.exe/m, st);
      assert.equal((await g.callGhidraTool(real, 'ghidra_info', { file: b2 })).isError, true);
      await ok('ghidra_info', { file: b1 }, /functions: \d+/);
      assert.equal((await g.callGhidraTool(real, 'ghidra_batch_analyze', { files: [] })).isError, true);
      assert.equal((await g.callGhidraTool(real, 'ghidra_batch_analyze', { files: ['relative.exe'] })).isError, true);
    }
    const none = await g.callGhidraTool(real, 'ghidra_decompile', { file: sample, target: 'no_such_fn' });
    assert.equal(none.isError, true);
    assert.match(none.content[0].text, /function not found/);
    console.log('ghidra end-to-end: passed');
  } else {
    console.log('ghidra end-to-end: skipped (GHIDRA_INSTALL_DIR not set)');
  }
  console.log('test-remote-ghidra-tools: all passed');
} finally {
  await rm(tmp, { recursive: true, force: true });
}

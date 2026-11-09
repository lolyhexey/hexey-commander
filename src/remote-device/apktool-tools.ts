import { spawn } from 'child_process';
import { createHash } from 'crypto';
import fs from 'fs/promises';
import { existsSync, readdirSync } from 'fs';
import os from 'os';
import path from 'path';
import { findWindowsJdk, javaExe, projectNameFor } from './ghidra-tools.js';

/**
 * apktool tools a remote AI can call on this device: decode an APK to smali
 * and resources, read and change those files, then build, zipalign, sign with
 * a local debug key and optionally install the result with adb. Offered only
 * when the person at the device opts in by setting APKTOOL_JAR to an apktool
 * jar. Signing needs apksigner from the Android SDK build-tools.
 */

export const APKTOOL_TOOL_PREFIX = 'apktool_';
const RUN_TIMEOUT_MS = 30 * 60_000;
const MAX_OUTPUT_CHARS = 400_000;
const MAX_LIST = 5000;
const STAMP = '.hexey-apktool.json';
const KEY_ALIAS = 'hexey';
const KEY_PASS = 'hexey-debug';

const FILE = { type: 'string', description: 'Absolute path of the original APK. Run apktool_decode on it first.' };
const REL = { type: 'string', description: 'Path inside the decoded folder, e.g. "smali/com/example/Main.smali" or "AndroidManifest.xml".' };
const ro = { readOnlyHint: true, openWorldHint: false };
const rw = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };

export const APKTOOL_TOOLS = [
    {
        name: 'apktool_decode',
        title: 'apktool: decode APK',
        description: 'Decode an APK with apktool on this device into smali code, AndroidManifest.xml and resources, ready to change and rebuild. The original APK is never modified. Decoding again (force) discards earlier changes.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: { type: 'string', description: 'Absolute path of the APK.' },
                no_res: { type: 'boolean', description: 'Keep resources as they are instead of decoding them (faster, avoids resource rebuild problems; the manifest stays binary).' },
                no_src: { type: 'boolean', description: 'Keep classes.dex as it is instead of decoding to smali.' },
                force: { type: 'boolean', description: 'Decode again even if a decoded folder exists, discarding changes in it.' },
            },
            required: ['file'],
        },
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    {
        name: 'apktool_list_files',
        title: 'apktool: list decoded files',
        description: `Paths in the decoded folder (smali*/, res/, AndroidManifest.xml, apktool.yml, ...). Capped at ${MAX_LIST}.`,
        inputSchema: { type: 'object' as const, properties: { file: FILE, filter: { type: 'string', description: 'Optional case-insensitive part of the path, e.g. "MainActivity" or "smali/com/example".' } }, required: ['file'] },
        annotations: ro,
    },
    {
        name: 'apktool_read_file',
        title: 'apktool: read decoded file',
        description: 'Text of one file in the decoded folder, with line numbers. Binary files are reported by size only.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: FILE, path: REL,
                offset: { type: 'integer', description: 'First line to show, from 1 (default 1).' },
                limit: { type: 'integer', description: 'Most lines to show (default 2000).' },
            },
            required: ['file', 'path'],
        },
        annotations: ro,
    },
    {
        name: 'apktool_edit_file',
        title: 'apktool: edit decoded file',
        description: 'Replace text in one file of the decoded folder. old_text must occur exactly once unless replace_all is set. Use apktool_build afterwards.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: FILE, path: REL,
                old_text: { type: 'string', description: 'Exact text to replace.' },
                new_text: { type: 'string', description: 'Text to put in its place.' },
                replace_all: { type: 'boolean', description: 'Replace every occurrence.' },
            },
            required: ['file', 'path', 'old_text', 'new_text'],
        },
        annotations: rw,
    },
    {
        name: 'apktool_write_file',
        title: 'apktool: write decoded file',
        description: 'Create or overwrite one file in the decoded folder (e.g. a new smali class). Use apktool_build afterwards.',
        inputSchema: { type: 'object' as const, properties: { file: FILE, path: REL, content: { type: 'string', description: 'Whole new content of the file.' } }, required: ['file', 'path', 'content'] },
        annotations: rw,
    },
    {
        name: 'apktool_build',
        title: 'apktool: build, sign and install',
        description: 'Build the decoded folder back into an APK, zipalign it, sign it with this device\'s debug key (with the signature schemes apksigner picks for the app\'s minSdk) and verify the signature. With install, also install it with adb (an installed app signed with another key must be uninstalled first; set uninstall_first to do that, which deletes its data).',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: FILE,
                output: { type: 'string', description: 'Optional absolute path for the signed APK. Default: next to the decoded folder.' },
                install: { type: 'boolean', description: 'Install the signed APK with adb install -r.' },
                serial: { type: 'string', description: 'adb device serial, when more than one device is connected.' },
                uninstall_first: { type: 'boolean', description: 'Uninstall the existing app (and its data) before installing. Needed when it was signed with another key.' },
            },
            required: ['file'],
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
];

const NAMES = new Set(APKTOOL_TOOLS.map((t) => t.name));
export function isApktoolTool(name: string): boolean {
    return NAMES.has(name);
}

export interface ApktoolSetup {
    jar: string;
    java: string;
    keytool: string;
    workDir: string;
    /** apksigner.jar and zipalign from the newest Android SDK build-tools, when found. */
    apksigner?: string;
    zipalign?: string;
    adb: string;
}

const exe = (name: string) => process.platform === 'win32' ? `${name}.exe` : name;

/** The newest build-tools folder of the Android SDK that has apksigner.jar. */
function findBuildTools(sdk: string): string | undefined {
    let names: string[] = [];
    try { names = readdirSync(path.join(sdk, 'build-tools')); } catch { return undefined; }
    return names
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
        .map((n) => path.join(sdk, 'build-tools', n))
        .find((d) => existsSync(path.join(d, 'lib', 'apksigner.jar')));
}

/**
 * Where apktool, Java and the Android SDK tools are, or undefined when apktool
 * tools should not be offered. APKTOOL_JAR is the opt-in; Java comes from
 * APKTOOL_JAVA_HOME, JAVA_HOME, a JDK in the usual Windows folders, or `java`
 * on PATH; the SDK from ANDROID_HOME, ANDROID_SDK_ROOT or the default folder.
 */
export function resolveApktoolSetup(env: NodeJS.ProcessEnv = process.env): ApktoolSetup | undefined {
    const jar = env.APKTOOL_JAR;
    if (!jar || !existsSync(jar) || !/\.jar$/i.test(jar)) return undefined;
    const homes = [env.APKTOOL_JAVA_HOME, env.JAVA_HOME].filter((h): h is string => !!h);
    let java = homes.map((h) => path.join(h, 'bin', javaExe)).find((p) => existsSync(p));
    if (!java && process.platform === 'win32') java = findWindowsJdk();
    if (!java) java = 'java';
    const keytool = path.isAbsolute(java) ? path.join(path.dirname(java), exe('keytool')) : 'keytool';
    const sdks = [env.ANDROID_HOME, env.ANDROID_SDK_ROOT,
        process.platform === 'win32' && env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Android', 'Sdk') : path.join(os.homedir(), 'Android', 'Sdk')]
        .filter((s): s is string => !!s && existsSync(s));
    const sdk = sdks[0];
    const bt = sdk ? findBuildTools(sdk) : undefined;
    const adbPath = sdk ? path.join(sdk, 'platform-tools', exe('adb')) : undefined;
    const base = process.platform === 'win32' && env.LOCALAPPDATA ? env.LOCALAPPDATA : os.homedir();
    return {
        jar: path.resolve(jar),
        java,
        keytool,
        workDir: path.resolve(env.APKTOOL_WORK_DIR || path.join(base, 'DesktopCommander', 'apktool')),
        apksigner: bt ? path.join(bt, 'lib', 'apksigner.jar') : undefined,
        zipalign: bt && existsSync(path.join(bt, exe('zipalign'))) ? path.join(bt, exe('zipalign')) : undefined,
        adb: adbPath && existsSync(adbPath) ? adbPath : 'adb',
    };
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const cap = (t: string) => t.length > MAX_OUTPUT_CHARS ? `${t.slice(0, MAX_OUTPUT_CHARS)}\n... (cut at ${MAX_OUTPUT_CHARS} characters)` : t;
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: cap(t) }], ...(isError && { isError: true }) });

/** One job at a time per APK, so decode, edits and build never interleave. */
const queues = new Map<string, Promise<unknown>>();
function serialize<T>(key: string, job: () => Promise<T>): Promise<T> {
    const next = (queues.get(key) ?? Promise.resolve()).catch(() => undefined).then(job);
    queues.set(key, next);
    void next.finally(() => { if (queues.get(key) === next) queues.delete(key); }).catch(() => undefined);
    return next;
}

interface Run { code: number | null; output: string; timedOut: boolean }
function run(cmd: string, args: string[], timeoutMs = RUN_TIMEOUT_MS): Promise<Run> {
    return new Promise((resolve) => {
        const child = spawn(cmd, args, { windowsHide: true, shell: false });
        let output = '';
        const take = (b: Buffer) => { if (output.length < MAX_OUTPUT_CHARS) output += b.toString('utf8'); };
        child.stdout.on('data', take);
        child.stderr.on('data', take);
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
        child.on('error', (e) => { output += `\n${e.message}`; });
        child.on('close', (code) => { clearTimeout(timer); resolve({ code, output: output.trim(), timedOut }); });
    });
}

const tail = (s: string, n = 30) => s.split('\n').slice(-n).join('\n');
const ok = (r: Run) => r.code === 0 && !r.timedOut;

const projectDir = (setup: ApktoolSetup, file: string) => path.join(setup.workDir, projectNameFor(file));
const decodedDir = (setup: ApktoolSetup, file: string) => path.join(projectDir(setup, file), 'decoded');

/** Every file under `dir`, as paths relative to it with forward slashes. */
async function walk(dir: string, rel = ''): Promise<string[]> {
    let entries: import('fs').Dirent[];
    try { entries = await fs.readdir(path.join(dir, rel), { withFileTypes: true }); } catch { return []; }
    const out: string[] = [];
    for (const e of entries) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) { if (r !== 'build') out.push(...await walk(dir, r)); }
        else if (e.isFile() && e.name !== STAMP) out.push(r);
    }
    return out;
}

/** `p` inside `root`, refusing paths that climb out of it. */
function inside(root: string, p: string): string | undefined {
    const full = path.resolve(root, p.replace(/^[\\/]+/, ''));
    const rel = path.relative(root, full);
    return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? full : undefined;
}

async function decoded(setup: ApktoolSetup, file: string): Promise<string> {
    const dir = decodedDir(setup, file);
    if (!existsSync(path.join(dir, STAMP))) throw new Error(`${file} has not been decoded yet. Run apktool_decode on it first.`);
    return dir;
}

/** The debug key this device signs with, created on first use. */
async function ensureKeystore(setup: ApktoolSetup): Promise<string> {
    const ks = path.join(setup.workDir, 'hexey-debug.keystore');
    if (existsSync(ks)) return ks;
    await fs.mkdir(setup.workDir, { recursive: true });
    const r = await run(setup.keytool, ['-genkeypair', '-keystore', ks, '-storetype', 'PKCS12', '-alias', KEY_ALIAS,
        '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000', '-storepass', KEY_PASS, '-keypass', KEY_PASS,
        '-dname', 'CN=Hexey Commander Debug, O=Hexey, C=TH'], 120_000);
    if (!ok(r) || !existsSync(ks)) throw new Error(`could not create the debug keystore with keytool:\n${tail(r.output)}`);
    return ks;
}

async function sha256(file: string): Promise<string> {
    return createHash('sha256').update(await fs.readFile(file)).digest('hex');
}

/** The package name in a decoded AndroidManifest.xml, when it is text. */
async function packageName(dir: string): Promise<string | undefined> {
    try {
        const m = /<manifest[^>]*\spackage="([^"]+)"/.exec(await fs.readFile(path.join(dir, 'AndroidManifest.xml'), 'utf8'));
        if (m) return m[1];
    } catch { /* binary or missing */ }
    try {
        return /renameManifestPackage:\s*(\S+)/.exec(await fs.readFile(path.join(dir, 'apktool.yml'), 'utf8'))?.[1];
    } catch { return undefined; }
}

export async function callApktoolTool(setup: ApktoolSetup, name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
        const file = typeof args.file === 'string' && args.file ? path.resolve(args.file) : '';
        if (!file) return text('ERROR: file is required.', true);
        let info;
        try { info = await fs.stat(file); } catch { return text(`ERROR: no such file: ${file}`, true); }
        if (!info.isFile()) return text(`ERROR: not a file: ${file}`, true);

        if (name === 'apktool_decode') {
            return await serialize(file, async () => {
                const dir = decodedDir(setup, file);
                if (!args.force && existsSync(path.join(dir, STAMP))) {
                    return text(`Already decoded: ${dir}\nEarlier changes are kept. Set force to decode again and discard them.`);
                }
                await fs.rm(dir, { recursive: true, force: true });
                await fs.mkdir(path.dirname(dir), { recursive: true });
                const started = Date.now();
                const r = await run(setup.java, ['-Dfile.encoding=UTF-8', '-jar', setup.jar, 'd', '-f', '-o', dir,
                    ...(args.no_res === true ? ['-r'] : []), ...(args.no_src === true ? ['-s'] : []), file]);
                if (!ok(r) || !existsSync(path.join(dir, 'apktool.yml'))) {
                    return text(`ERROR: apktool decode failed (exit ${r.code}${r.timedOut ? ', timed out' : ''}).\n${tail(r.output)}`, true);
                }
                await fs.writeFile(path.join(dir, STAMP), JSON.stringify({ file, size: info.size, mtimeMs: info.mtimeMs }));
                const files = await walk(dir);
                const smali = files.filter((f) => f.endsWith('.smali')).length;
                return text([
                    `Decoded ${file} in ${Math.round((Date.now() - started) / 1000)} s`,
                    `package: ${await packageName(dir) ?? 'unknown'}`,
                    `smali files: ${smali}`,
                    `files: ${files.length}`,
                    `folder: ${dir}`,
                ].join('\n'));
            });
        }

        if (name === 'apktool_list_files') {
            const dir = await decoded(setup, file);
            const filter = typeof args.filter === 'string' ? args.filter.toLowerCase() : '';
            const all = (await walk(dir)).sort();
            const hits = filter ? all.filter((f) => f.toLowerCase().includes(filter)) : all;
            return text(`${hits.length} files${hits.length > MAX_LIST ? ` (first ${MAX_LIST})` : ''}\n${hits.slice(0, MAX_LIST).join('\n')}`);
        }

        const rel = typeof args.path === 'string' ? args.path : '';

        if (name === 'apktool_read_file') {
            const dir = await decoded(setup, file);
            const p = rel ? inside(dir, rel) : undefined;
            if (!p || !existsSync(p)) return text(`ERROR: no such file in the decoded folder: ${rel}. Use apktool_list_files.`, true);
            const buf = await fs.readFile(p);
            if (buf.subarray(0, 8000).includes(0)) return text(`${rel}: binary file, ${buf.length} bytes (not shown).`);
            const lines = buf.toString('utf8').split(/\r?\n/);
            const offset = Math.max(Number(args.offset) || 1, 1);
            const limit = Math.min(Math.max(Number(args.limit) || 2000, 1), 20000);
            const shown = lines.slice(offset - 1, offset - 1 + limit).map((l, i) => `${offset + i}\t${l}`);
            const more = offset - 1 + limit < lines.length ? `\n... ${lines.length} lines in all; use offset to read on.` : '';
            return text(shown.join('\n') + more);
        }

        if (name === 'apktool_edit_file' || name === 'apktool_write_file') {
            return await serialize(file, async () => {
                const dir = await decoded(setup, file);
                const p = rel ? inside(dir, rel) : undefined;
                if (!p) return text(`ERROR: bad path: ${rel}`, true);
                if (name === 'apktool_write_file') {
                    if (typeof args.content !== 'string') return text('ERROR: content is required.', true);
                    await fs.mkdir(path.dirname(p), { recursive: true });
                    await fs.writeFile(p, args.content, 'utf8');
                    return text(`Wrote ${rel} (${Buffer.byteLength(args.content)} bytes).`);
                }
                if (!existsSync(p)) return text(`ERROR: no such file in the decoded folder: ${rel}`, true);
                const oldText = typeof args.old_text === 'string' ? args.old_text : '';
                const newText = typeof args.new_text === 'string' ? args.new_text : undefined;
                if (!oldText || newText === undefined) return text('ERROR: old_text and new_text are required.', true);
                const raw = await fs.readFile(p, 'utf8');
                // Match regardless of the file's line endings, and keep them.
                const crlf = raw.includes('\r\n');
                const norm = (s: string) => s.replace(/\r\n/g, '\n');
                const body = norm(raw);
                const find = norm(oldText);
                const count = body.split(find).length - 1;
                if (count === 0) return text(`ERROR: old_text not found in ${rel}.`, true);
                if (count > 1 && args.replace_all !== true) return text(`ERROR: old_text occurs ${count} times in ${rel}; add context to make it unique or set replace_all.`, true);
                let out = args.replace_all === true ? body.split(find).join(norm(newText)) : body.replace(find, () => norm(newText));
                if (crlf) out = out.replace(/\n/g, '\r\n');
                await fs.writeFile(p, out, 'utf8');
                return text(`Replaced ${args.replace_all === true ? count : 1} occurrence(s) in ${rel}.`);
            });
        }

        if (name === 'apktool_build') {
            return await serialize(file, async () => {
                const dir = await decoded(setup, file);
                const proj = projectDir(setup, file);
                const base = path.basename(file).replace(/\.apk$/i, '');
                const unsigned = path.join(proj, `${base}-unsigned.apk`);
                const aligned = path.join(proj, `${base}-aligned.apk`);
                const out = typeof args.output === 'string' && args.output ? path.resolve(args.output) : path.join(proj, `${base}-signed.apk`);
                const steps: string[] = [];
                await fs.rm(unsigned, { force: true });

                const b = await run(setup.java, ['-Dfile.encoding=UTF-8', '-jar', setup.jar, 'b', '-f', '-o', unsigned, dir]);
                if (!ok(b) || !existsSync(unsigned)) return text(`ERROR: apktool build failed (exit ${b.code}${b.timedOut ? ', timed out' : ''}).\n${tail(b.output, 40)}`, true);
                steps.push('built');

                if (!setup.apksigner) {
                    return text(`Built ${unsigned}\nNOT SIGNED: apksigner was not found (install Android SDK build-tools and set ANDROID_HOME). Android will not install an unsigned APK.`, true);
                }
                let toSign = unsigned;
                if (setup.zipalign) {
                    // -P 16 aligns native libraries for 16 KB pages; older zipalign lacks it.
                    let z = await run(setup.zipalign, ['-P', '16', '-f', '4', unsigned, aligned], 300_000);
                    if (!ok(z)) z = await run(setup.zipalign, ['-p', '-f', '4', unsigned, aligned], 300_000);
                    if (!ok(z)) return text(`ERROR: zipalign failed.\n${tail(z.output)}`, true);
                    toSign = aligned;
                    steps.push('zipaligned');
                } else {
                    steps.push('not zipaligned (zipalign not found)');
                }

                const ks = await ensureKeystore(setup);
                await fs.mkdir(path.dirname(out), { recursive: true });
                const s = await run(setup.java, ['-jar', setup.apksigner, 'sign', '--ks', ks, '--ks-key-alias', KEY_ALIAS,
                    '--ks-pass', `pass:${KEY_PASS}`, '--key-pass', `pass:${KEY_PASS}`, '--v4-signing-enabled', 'false', '--out', out, toSign], 300_000);
                if (!ok(s) || !existsSync(out)) return text(`ERROR: signing failed.\n${tail(s.output)}`, true);
                const v = await run(setup.java, ['-jar', setup.apksigner, 'verify', '--verbose', out], 300_000);
                if (!ok(v)) return text(`ERROR: the signed APK does not verify.\n${tail(v.output)}`, true);
                const schemes = v.output.split('\n').filter((l) => /using v\d.* scheme.*: true/i.test(l)).map((l) => l.replace(/.*using (v[\d.]+).*/i, '$1'));
                steps.push(`signed (${schemes.join(', ') || 'verified'})`);
                await fs.rm(unsigned, { force: true });
                await fs.rm(aligned, { force: true });

                const lines = [
                    `APK: ${out}`,
                    `size: ${(await fs.stat(out)).size} bytes`,
                    `sha256: ${await sha256(out)}`,
                    `steps: ${steps.join(' -> ')}`,
                    'Signed with this device\'s debug key, not the original developer\'s key.',
                ];

                if (args.install === true) {
                    const serial = typeof args.serial === 'string' && args.serial ? ['-s', args.serial] : [];
                    if (args.uninstall_first === true) {
                        const pkg = await packageName(dir);
                        if (!pkg) return text(`${lines.join('\n')}\nERROR: could not read the package name to uninstall.`, true);
                        const u = await run(setup.adb, [...serial, 'uninstall', pkg], 120_000);
                        lines.push(`uninstall ${pkg}: ${u.output.split('\n').pop() || `exit ${u.code}`}`);
                    }
                    const i = await run(setup.adb, [...serial, 'install', '-r', out], 600_000);
                    const success = ok(i) && /Success/.test(i.output);
                    lines.push(success ? 'install: Success' : `install FAILED:\n${tail(i.output, 15)}`);
                    if (!success && /INSTALL_FAILED_UPDATE_INCOMPATIBLE|signatures do not match/i.test(i.output)) {
                        lines.push('The installed app is signed with another key. Call again with uninstall_first (this deletes the app\'s data).');
                    }
                    return text(lines.join('\n'), !success);
                }
                return text(lines.join('\n'));
            });
        }

        return text(`ERROR: unknown apktool tool: ${name}`, true);
    } catch (e: any) {
        return text(`ERROR: ${e?.message ?? e}`, true);
    }
}

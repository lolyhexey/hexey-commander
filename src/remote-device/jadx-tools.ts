import { spawn } from 'child_process';
import fs from 'fs/promises';
import { existsSync, readdirSync } from 'fs';
import os from 'os';
import path from 'path';
import { findWindowsJdk, javaExe, projectNameFor } from './ghidra-tools.js';

/**
 * jadx tools a remote AI can call on this device: decompile an APK, DEX, AAR
 * or JAR to Java once, then list classes, read a class, search the code and
 * read the manifest and resources. Offered only when the person at the device
 * opts in by setting JADX_HOME to a jadx install (the folder holding
 * lib/jadx-*-all.jar).
 */

export const JADX_TOOL_PREFIX = 'jadx_';
const DECOMPILE_TIMEOUT_MS = 30 * 60_000;
const MAX_OUTPUT_CHARS = 400_000;
const MAX_LIST = 5000;
const STAMP = '.hexey-jadx.json';

const FILE = { type: 'string', description: 'Absolute path of the APK, DEX, AAR, AAB or JAR. Run jadx_decompile on it first.' };
const ro = { readOnlyHint: true, openWorldHint: false };

export const JADX_TOOLS = [
    {
        name: 'jadx_decompile',
        title: 'jadx: decompile',
        description: 'Decompile an APK, DEX, AAR, AAB or JAR to Java sources and decoded resources with jadx on this device, so the other jadx_* tools can read them. Needed once per file (again only when the file changes or force is set). Large apps can take minutes.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: FILE,
                deobf: { type: 'boolean', description: 'Rename short or obfuscated names to unique readable ones (jadx --deobf). Default false.' },
                force: { type: 'boolean', description: 'Decompile again even if an up-to-date result exists.' },
            },
            required: ['file'],
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    {
        name: 'jadx_list_classes',
        title: 'jadx: list classes',
        description: `Fully qualified names of the decompiled classes (one per source file). Capped at ${MAX_LIST}.`,
        inputSchema: { type: 'object' as const, properties: { file: FILE, filter: { type: 'string', description: 'Optional case-insensitive part of the class name, e.g. "com.example" or "Login".' } }, required: ['file'] },
        annotations: ro,
    },
    {
        name: 'jadx_get_class',
        title: 'jadx: class source',
        description: 'Java source of one decompiled class. An inner class (a.b.Outer$Inner) returns its outer class\'s file.',
        inputSchema: { type: 'object' as const, properties: { file: FILE, class: { type: 'string', description: 'Fully qualified class name, e.g. "com.example.MainActivity".' } }, required: ['file', 'class'] },
        annotations: ro,
    },
    {
        name: 'jadx_search_code',
        title: 'jadx: search code',
        description: 'Lines of the decompiled Java that contain the query (case-insensitive) or match it as a regular expression: class, line number and the line.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: FILE,
                query: { type: 'string', description: 'Text to find, or a regular expression when regex is true.' },
                regex: { type: 'boolean', description: 'Treat query as a JavaScript regular expression (case-insensitive).' },
                package: { type: 'string', description: 'Optional package prefix to search in, e.g. "com.example".' },
                max: { type: 'integer', description: 'Most matches (default 200, max 2000).' },
            },
            required: ['file', 'query'],
        },
        annotations: ro,
    },
    {
        name: 'jadx_find_usages',
        title: 'jadx: find usages',
        description: 'Where a class, or one of its methods or fields, is used in the decompiled Java: class, line number and the line. Found by reading the source (classes that import the class, name it in full or share its package), not by a bytecode index, so a call through a subclass or an interface can be missed.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                file: FILE,
                class: { type: 'string', description: 'Fully qualified class name, e.g. "com.example.net.Api".' },
                member: { type: 'string', description: 'Optional method or field name, e.g. "login". Without it, every mention of the class.' },
                max: { type: 'integer', description: 'Most matches (default 300, max 2000).' },
            },
            required: ['file', 'class'],
        },
        annotations: ro,
    },
    {
        name: 'jadx_get_manifest',
        title: 'jadx: AndroidManifest.xml',
        description: 'The decoded AndroidManifest.xml of a decompiled APK.',
        inputSchema: { type: 'object' as const, properties: { file: FILE }, required: ['file'] },
        annotations: ro,
    },
    {
        name: 'jadx_list_resources',
        title: 'jadx: list resources',
        description: `Paths of the decoded resource files (res/, assets/, lib/, ...). Capped at ${MAX_LIST}.`,
        inputSchema: { type: 'object' as const, properties: { file: FILE, filter: { type: 'string', description: 'Optional case-insensitive part of the path, e.g. "strings.xml".' } }, required: ['file'] },
        annotations: ro,
    },
    {
        name: 'jadx_get_resource',
        title: 'jadx: read resource',
        description: 'Text of one decoded resource file, by a path from jadx_list_resources (e.g. "res/values/strings.xml"). Binary files are reported by size only.',
        inputSchema: { type: 'object' as const, properties: { file: FILE, path: { type: 'string', description: 'Path relative to the resources folder.' } }, required: ['file', 'path'] },
        annotations: ro,
    },
];

const NAMES = new Set(JADX_TOOLS.map((t) => t.name));
export function isJadxTool(name: string): boolean {
    return NAMES.has(name);
}

export interface JadxSetup {
    jar: string;
    java: string;
    outputDir: string;
}

/**
 * Where jadx and Java are, or undefined when jadx tools should not be offered.
 * JADX_HOME is the opt-in; Java comes from JADX_JAVA_HOME, JAVA_HOME, a JDK in
 * the usual Windows folders, or `java` on PATH.
 */
export function resolveJadxSetup(env: NodeJS.ProcessEnv = process.env): JadxSetup | undefined {
    const home = env.JADX_HOME;
    if (!home) return undefined;
    let names: string[] = [];
    try { names = readdirSync(path.join(home, 'lib')); } catch { return undefined; }
    const jarName = names.filter((n) => /^jadx-.*-all\.jar$/.test(n)).sort().pop();
    if (!jarName) return undefined;
    const homes = [env.JADX_JAVA_HOME, env.JAVA_HOME].filter((h): h is string => !!h);
    let java = homes.map((h) => path.join(h, 'bin', javaExe)).find((p) => existsSync(p));
    if (!java && process.platform === 'win32') java = findWindowsJdk();
    if (!java) java = 'java';
    const base = process.platform === 'win32' && env.LOCALAPPDATA ? env.LOCALAPPDATA : os.homedir();
    const outputDir = path.resolve(env.JADX_OUTPUT_DIR || path.join(base, 'DesktopCommander', 'jadx-output'));
    return { jar: path.join(home, 'lib', jarName), java, outputDir };
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: cap(t) }], ...(isError && { isError: true }) });
const cap = (t: string) => t.length > MAX_OUTPUT_CHARS ? `${t.slice(0, MAX_OUTPUT_CHARS)}\n... (cut at ${MAX_OUTPUT_CHARS} characters)` : t;

/** One decompile at a time per file, so two calls never write the same folder. */
const queues = new Map<string, Promise<unknown>>();
function serialize<T>(key: string, job: () => Promise<T>): Promise<T> {
    const next = (queues.get(key) ?? Promise.resolve()).catch(() => undefined).then(job);
    queues.set(key, next);
    void next.finally(() => { if (queues.get(key) === next) queues.delete(key); }).catch(() => undefined);
    return next;
}

const outFor = (setup: JadxSetup, file: string) => path.join(setup.outputDir, projectNameFor(file));

interface Stamp { size: number; mtimeMs: number; deobf: boolean }

async function readStamp(dir: string): Promise<Stamp | undefined> {
    try { return JSON.parse(await fs.readFile(path.join(dir, STAMP), 'utf8')); } catch { return undefined; }
}

function runJadx(setup: JadxSetup, args: string[]): Promise<{ code: number | null; output: string; timedOut: boolean }> {
    return new Promise((resolve) => {
        const child = spawn(setup.java, [
            '-XX:+IgnoreUnrecognizedVMOptions', '-Xms256M', '-XX:MaxRAMPercentage=70.0',
            '-Djdk.util.zip.disableZip64ExtraFieldValidation=true', '--enable-native-access=ALL-UNNAMED',
            '-Dfile.encoding=UTF-8',
            '-cp', setup.jar, 'jadx.cli.JadxCLI', ...args,
        ], { windowsHide: true, shell: false });
        let output = '';
        const take = (b: Buffer) => { if (output.length < MAX_OUTPUT_CHARS) output += b.toString('utf8'); };
        child.stdout.on('data', take);
        child.stderr.on('data', take);
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; child.kill(); }, DECOMPILE_TIMEOUT_MS);
        child.on('error', (e) => { output += `\n${e.message}`; });
        child.on('close', (code) => { clearTimeout(timer); resolve({ code, output, timedOut }); });
    });
}

/** Every file under `dir`, as paths relative to it with forward slashes. */
async function walk(dir: string, rel = ''): Promise<string[]> {
    let entries: import('fs').Dirent[];
    try { entries = await fs.readdir(path.join(dir, rel), { withFileTypes: true }); } catch { return []; }
    const out: string[] = [];
    for (const e of entries) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) out.push(...await walk(dir, r));
        else if (e.isFile()) out.push(r);
    }
    return out;
}

/** `p` inside `root`, refusing paths that climb out of it. */
function inside(root: string, p: string): string | undefined {
    const full = path.resolve(root, p);
    const rel = path.relative(root, full);
    return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? full : undefined;
}

async function decompiled(setup: JadxSetup, file: string): Promise<string> {
    const dir = outFor(setup, file);
    if (!await readStamp(dir)) throw new Error(`${file} has not been decompiled yet. Run jadx_decompile on it first.`);
    return dir;
}

const classOf = (rel: string) => rel.replace(/\.java$/, '').split('/').join('.');

export async function callJadxTool(setup: JadxSetup, name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
        const file = typeof args.file === 'string' ? path.resolve(args.file) : '';
        if (!file) return text('ERROR: file is required.', true);
        let info;
        try { info = await fs.stat(file); } catch { return text(`ERROR: no such file: ${file}`, true); }
        if (!info.isFile()) return text(`ERROR: not a file: ${file}`, true);

        if (name === 'jadx_decompile') {
            const deobf = args.deobf === true;
            return await serialize(file, async () => {
                const dir = outFor(setup, file);
                const stamp = await readStamp(dir);
                if (!args.force && stamp && stamp.size === info.size && stamp.mtimeMs === info.mtimeMs && stamp.deobf === deobf) {
                    const classes = (await walk(path.join(dir, 'sources'))).filter((f) => f.endsWith('.java')).length;
                    return text(`Already decompiled (file unchanged): ${classes} classes in ${dir}`);
                }
                await fs.rm(dir, { recursive: true, force: true });
                await fs.mkdir(dir, { recursive: true });
                const started = Date.now();
                const r = await runJadx(setup, ['-d', dir, '--show-bad-code', ...(deobf ? ['--deobf'] : []), file]);
                const sources = (await walk(path.join(dir, 'sources'))).filter((f) => f.endsWith('.java'));
                const resources = await walk(path.join(dir, 'resources'));
                if (r.timedOut) return text(`ERROR: jadx did not finish within ${DECOMPILE_TIMEOUT_MS / 60_000} minutes.`, true);
                if (sources.length === 0 && resources.length === 0) {
                    return text(`ERROR: jadx produced nothing (exit ${r.code}).\n${r.output.split('\n').slice(-40).join('\n')}`, true);
                }
                await fs.writeFile(path.join(dir, STAMP), JSON.stringify({ size: info.size, mtimeMs: info.mtimeMs, deobf } satisfies Stamp));
                const errors = /ERROR - finished with errors, count: (\d+)/.exec(r.output)?.[1];
                return text([
                    `Decompiled ${file} in ${Math.round((Date.now() - started) / 1000)} s`,
                    `classes: ${sources.length}`,
                    `resource files: ${resources.length}`,
                    `output: ${dir}`,
                    errors ? `jadx reported ${errors} errors (methods it could not fully decompile are shown as bad code)` : `exit code: ${r.code}`,
                ].join('\n'));
            });
        }

        const dir = await decompiled(setup, file);
        const sourcesDir = path.join(dir, 'sources');
        const resourcesDir = path.join(dir, 'resources');

        if (name === 'jadx_list_classes') {
            const filter = typeof args.filter === 'string' ? args.filter.toLowerCase() : '';
            const all = (await walk(sourcesDir)).filter((f) => f.endsWith('.java')).map(classOf).sort();
            const hits = filter ? all.filter((c) => c.toLowerCase().includes(filter)) : all;
            return text(`${hits.length} classes${hits.length > MAX_LIST ? ` (first ${MAX_LIST})` : ''}\n${hits.slice(0, MAX_LIST).join('\n')}`);
        }

        if (name === 'jadx_get_class') {
            const cls = typeof args.class === 'string' ? args.class.trim().replace(/\$.*$/, '') : '';
            if (!cls) return text('ERROR: class is required.', true);
            const p = inside(sourcesDir, `${cls.split('.').join('/')}.java`);
            if (!p || !existsSync(p)) return text(`ERROR: class not found: ${cls}. Use jadx_list_classes to find its name.`, true);
            return text(await fs.readFile(p, 'utf8'));
        }

        if (name === 'jadx_search_code') {
            const query = typeof args.query === 'string' ? args.query : '';
            if (!query) return text('ERROR: query is required.', true);
            const max = Math.min(Math.max(Number(args.max) || 200, 1), 2000);
            let test: (line: string) => boolean;
            if (args.regex === true) {
                let re: RegExp;
                try { re = new RegExp(query, 'i'); } catch (e: any) { return text(`ERROR: bad regular expression: ${e.message}`, true); }
                test = (l) => re.test(l);
            } else {
                const q = query.toLowerCase();
                test = (l) => l.toLowerCase().includes(q);
            }
            const pkg = typeof args.package === 'string' ? args.package.trim().replace(/\.$/, '') : '';
            const root = pkg ? inside(sourcesDir, pkg.split('.').join('/')) : sourcesDir;
            if (!root) return text(`ERROR: bad package: ${pkg}`, true);
            const prefix = pkg ? `${pkg.split('.').join('/')}/` : '';
            const out: string[] = [];
            let files = 0;
            for (const rel of (await walk(root)).filter((f) => f.endsWith('.java')).sort()) {
                files++;
                const lines = (await fs.readFile(path.join(root, rel), 'utf8')).split(/\r?\n/);
                for (let i = 0; i < lines.length && out.length < max; i++) {
                    if (test(lines[i])) out.push(`${classOf(prefix + rel)}:${i + 1}: ${lines[i].trim().slice(0, 300)}`);
                }
                if (out.length >= max) break;
            }
            const head = out.length >= max ? `${out.length} matches (stopped at max ${max})` : `${out.length} matches in ${files} classes`;
            return text(`${head}\n${out.join('\n')}`);
        }

        if (name === 'jadx_find_usages') {
            const fqn = typeof args.class === 'string' ? args.class.trim().replace(/\$/g, '.') : '';
            if (!/^[\w$.]+$/.test(fqn) || !fqn.includes('.')) return text('ERROR: class must be a fully qualified name, e.g. com.example.Api.', true);
            const member = typeof args.member === 'string' ? args.member.trim() : '';
            if (member && !/^[\w$]+$/.test(member)) return text('ERROR: member must be a plain method or field name.', true);
            const max = Math.min(Math.max(Number(args.max) || 300, 1), 2000);
            const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const parts = fqn.split('.');
            // An inner class (a.b.Outer.Inner) is written Outer.Inner by code that imports Outer.
            const outerIdx = parts.findIndex((p, i) => i > 0 && /^[A-Z]/.test(p));
            const pkg = parts.slice(0, outerIdx > 0 ? outerIdx : parts.length - 1).join('.');
            const simple = parts.slice(outerIdx > 0 ? outerIdx : parts.length - 1).join('.');
            const topLevel = `${pkg}.${simple.split('.')[0]}`;
            const ownFile = `${topLevel.split('.').join('/')}.java`;
            const nameRe = new RegExp(`(?<![\\w.])(?:${esc(fqn)}|${esc(simple)})\\b`);
            const memberRe = member ? new RegExp(`(?:\\b${esc(simple)}|\\b${esc(fqn)}|\\bthis|\\bsuper|\\w|\\))\\s*\\.\\s*${esc(member)}\\b|(?<![\\w.])${esc(member)}\\s*\\(`) : undefined;
            const out: string[] = [];
            let scanned = 0;
            for (const rel of (await walk(sourcesDir)).filter((f) => f.endsWith('.java')).sort()) {
                const src = await fs.readFile(path.join(sourcesDir, rel), 'utf8');
                const relPkg = path.posix.dirname(rel).split('/').join('.');
                const isOwn = rel === ownFile;
                const sees = isOwn || relPkg === pkg || src.includes(`import ${topLevel};`) || src.includes(`import ${pkg}.*;`) || src.includes(fqn);
                if (!sees) continue;
                scanned++;
                const lines = src.split(/\r?\n/);
                for (let i = 0; i < lines.length && out.length < max; i++) {
                    const l = lines[i];
                    if (/^\s*(import|package)\s/.test(l)) continue;
                    if (memberRe) {
                        // In the class's own file a bare call counts; elsewhere it must go through the class name or an instance.
                        const hit = isOwn ? memberRe.test(l) : (memberRe.test(l) && (nameRe.test(src) || src.includes(fqn)));
                        if (!hit) continue;
                    } else if (isOwn || !nameRe.test(l)) {
                        continue;
                    }
                    out.push(`${classOf(rel)}:${i + 1}: ${l.trim().slice(0, 300)}`);
                }
                if (out.length >= max) break;
            }
            const what = member ? `${fqn}.${member}` : fqn;
            const head = out.length >= max ? `${out.length} usages of ${what} (stopped at max ${max})` : `${out.length} usages of ${what} in ${scanned} classes that can see it`;
            return text(`${head}\n${out.join('\n')}`);
        }

        if (name === 'jadx_get_manifest') {
            const p = path.join(resourcesDir, 'AndroidManifest.xml');
            if (!existsSync(p)) return text('ERROR: no AndroidManifest.xml in this file (only APKs and AARs have one).', true);
            return text(await fs.readFile(p, 'utf8'));
        }

        if (name === 'jadx_list_resources') {
            const filter = typeof args.filter === 'string' ? args.filter.toLowerCase() : '';
            const all = (await walk(resourcesDir)).sort();
            const hits = filter ? all.filter((f) => f.toLowerCase().includes(filter)) : all;
            return text(`${hits.length} files${hits.length > MAX_LIST ? ` (first ${MAX_LIST})` : ''}\n${hits.slice(0, MAX_LIST).join('\n')}`);
        }

        if (name === 'jadx_get_resource') {
            const rel = typeof args.path === 'string' ? args.path.replace(/^[\\/]+/, '') : '';
            const p = rel ? inside(resourcesDir, rel) : undefined;
            if (!p || !existsSync(p)) return text(`ERROR: no such resource: ${rel}. Use jadx_list_resources to find it.`, true);
            const buf = await fs.readFile(p);
            if (buf.subarray(0, 8000).includes(0)) return text(`${rel}: binary file, ${buf.length} bytes (not shown).`);
            return text(buf.toString('utf8'));
        }

        return text(`ERROR: unknown jadx tool: ${name}`, true);
    } catch (e: any) {
        return text(`ERROR: ${e?.message ?? e}`, true);
    }
}

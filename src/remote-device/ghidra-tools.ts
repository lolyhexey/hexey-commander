import { spawn, type ChildProcess } from 'child_process';
import { createHash } from 'crypto';
import fs from 'fs/promises';
import { existsSync, readdirSync } from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Ghidra tools a remote AI can call on this device: analyze a binary once,
 * then list functions, decompile, list strings and find references, all
 * through Ghidra's headless analyzer. Offered only when the person at the
 * device opts in by setting GHIDRA_INSTALL_DIR to a Ghidra install, and a
 * Java runtime can be found.
 */

export const GHIDRA_TOOL_PREFIX = 'ghidra_';
const ANALYZE_TIMEOUT_MS = 30 * 60_000;
const QUERY_TIMEOUT_MS = 10 * 60_000;
const MAX_OUTPUT_CHARS = 400_000;
const START = '=== HEXEY ';
const END = '=== END ===';

/** The Ghidra scripts (HexeyTool.java for queries, HexeyEdit.java for edits), shipped next to this module. */
const SCRIPTS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'scripts');

type Prop = { type: 'string' | 'integer'; description: string };
const P = {
    file: { type: 'string', description: 'Absolute path of the binary (exe, dll, so, elf, ...). Run ghidra_analyze on it first.' },
    target: { type: 'string', description: 'Function name (e.g. "entry", "FUN_140001af0") or address in hex (e.g. "140001cb0").' },
    address: { type: 'string', description: 'Address in hex, e.g. "140001cb0".' },
    filter: { type: 'string', description: 'Optional case-insensitive substring to filter by.' },
} satisfies Record<string, Prop>;

/**
 * One query tool: the script mode it runs and the arguments it passes, in
 * order. `required` lists the arguments that must be given.
 */
interface QuerySpec {
    name: string;
    title: string;
    description: string;
    mode: string;
    args: [string, Prop][];
    required?: string[];
}

const NOTE = ' Read-only. Output is capped at 2000 lines.';
const QUERIES: QuerySpec[] = [
    { name: 'ghidra_info', title: 'Ghidra: program info', mode: 'info', args: [], description: 'Summary of an analyzed binary: format, architecture, compiler, image base, function count and MD5.' },
    { name: 'ghidra_get_memory_map', title: 'Ghidra: memory map', mode: 'memmap', args: [], description: 'Memory blocks / sections with start, end, size, r/w/x permissions and whether initialized.' },
    { name: 'ghidra_get_imports', title: 'Ghidra: imports', mode: 'imports', args: [['filter', P.filter]], description: 'Imported functions as library!name, with a referencing address when known.' },
    { name: 'ghidra_get_exports', title: 'Ghidra: exports', mode: 'exports', args: [['filter', P.filter]], description: 'Exported functions and entry points with their addresses.' },
    { name: 'ghidra_list_functions', title: 'Ghidra: list functions', mode: 'list', args: [['filter', P.filter]], description: 'Functions: entry address, size in bytes and name.' },
    { name: 'ghidra_search_symbols', title: 'Ghidra: search symbols', mode: 'symbols', args: [['query', { type: 'string', description: 'Part of a symbol name, or an address in hex.' }]], required: ['query'], description: 'Symbols whose name contains the query, or that sit at the given address: address, type, full name.' },
    { name: 'ghidra_get_function', title: 'Ghidra: function details', mode: 'function', args: [['target', P.target]], required: ['target'], description: 'Signature, calling convention, return type, parameters with storage, frame size and caller/callee counts of one function.' },
    { name: 'ghidra_decompile', title: 'Ghidra: decompile function', mode: 'decompile', args: [['target', P.target]], required: ['target'], description: 'C pseudocode of one function from Ghidra\'s decompiler.' },
    { name: 'ghidra_disassemble', title: 'Ghidra: disassemble', mode: 'disasm', args: [['target', P.target], ['count', { type: 'integer', description: 'Most instructions to show (default 200, max 2000). For a function, its whole body up to this count.' }]], required: ['target'], description: 'Assembly with address, opcode bytes and instruction, for a function or starting at an address.' },
    { name: 'ghidra_read_bytes', title: 'Ghidra: read bytes', mode: 'bytes', args: [['address', P.address], ['length', { type: 'integer', description: 'Bytes to read (default 256, max 4096).' }]], required: ['address'], description: 'Raw bytes at a virtual address as a hex dump with ASCII.' },
    { name: 'ghidra_search_bytes', title: 'Ghidra: search bytes', mode: 'search_bytes', args: [['pattern', { type: 'string', description: 'Hex bytes separated by spaces; ?? is a wildcard. E.g. "48 8b ?? 05".' }], ['max', { type: 'integer', description: 'Most matches (default 100, max 1000).' }]], required: ['pattern'], description: 'Addresses where a byte pattern occurs, with the memory block and containing function.' },
    { name: 'ghidra_search_constants', title: 'Ghidra: search constants', mode: 'constants', args: [['value', { type: 'string', description: 'Number, decimal or 0x hex, e.g. "0x5A4D".' }]], required: ['value'], description: 'Instructions that use a constant value as an operand, with the containing function.' },
    { name: 'ghidra_xrefs', title: 'Ghidra: references to', mode: 'xrefs', args: [['target', P.target]], required: ['target'], description: 'Every reference to a function or address: from address, reference type and the function it is in.' },
    { name: 'ghidra_get_references_from', title: 'Ghidra: references from', mode: 'refs_from', args: [['target', P.target]], required: ['target'], description: 'References leaving an address, or every instruction of a function: to address, type and target name.' },
    { name: 'ghidra_get_function_calls', title: 'Ghidra: calls in function', mode: 'calls', args: [['target', P.target]], required: ['target'], description: 'Each call made inside a function: call-site address, target address and callee name.' },
    { name: 'ghidra_get_call_graph', title: 'Ghidra: call graph', mode: 'callgraph', args: [['target', P.target], ['depth', { type: 'integer', description: 'Levels to follow each way (default 2, max 4).' }]], required: ['target'], description: 'Callers and callees of a function as indented trees.' },
    { name: 'ghidra_get_cfg', title: 'Ghidra: control flow graph', mode: 'cfg', args: [['target', P.target]], required: ['target'], description: 'Basic blocks of a function with address ranges and successor edges (flow type).' },
    { name: 'ghidra_get_pcode', title: 'Ghidra: P-code', mode: 'pcode', args: [['target', P.target]], required: ['target'], description: 'Raw P-code of each instruction in a function.' },
    { name: 'ghidra_get_high_pcode', title: 'Ghidra: high P-code', mode: 'high_pcode', args: [['target', P.target]], required: ['target'], description: 'High P-code of a function after decompilation (SSA form).' },
    { name: 'ghidra_get_variables', title: 'Ghidra: variables', mode: 'variables', args: [['target', P.target]], required: ['target'], description: 'Parameters, locals and stack variables of a function, as declared and as the decompiler sees them.' },
    { name: 'ghidra_get_decompiler_tokens', title: 'Ghidra: decompiler tokens', mode: 'tokens', args: [['target', P.target]], required: ['target'], description: 'Tokens of a function\'s decompiled C with the program address each comes from.' },
    { name: 'ghidra_get_data_types', title: 'Ghidra: data types', mode: 'datatypes', args: [['filter', { type: 'string', description: 'Optional part of a type name; an exact or single match shows its members.' }]], description: 'Structures, unions and enums in the program; members for a single match.' },
    { name: 'ghidra_strings', title: 'Ghidra: strings', mode: 'strings', args: [['filter', P.filter]], description: 'Defined strings with their addresses.' },
];

const toolFor = (q: QuerySpec) => ({
    name: q.name,
    title: q.title,
    description: q.description + NOTE,
    inputSchema: {
        type: 'object' as const,
        properties: { file: P.file, ...Object.fromEntries(q.args) },
        required: ['file', ...(q.required ?? [])],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
});

const ANALYZE_TOOL = {
    name: 'ghidra_analyze',
    title: 'Ghidra: analyze binary',
    description: 'Import and auto-analyze a binary with Ghidra on this device, saving the result so the other ghidra_* tools can query it. Needed once per file (again only if the file changes). Large binaries can take minutes; for several files use ghidra_batch_analyze.',
    inputSchema: { type: 'object' as const, properties: { file: P.file }, required: ['file'] },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
};

const QUERY_BY_NAME = new Map(QUERIES.map((q) => [q.name, q]));

export interface GhidraSetup {
    installDir: string;
    java: string;
    projectsDir: string;
}

const javaExe = process.platform === 'win32' ? 'java.exe' : 'java';

/** The newest JDK under the usual Windows install folders, if any. */
function findWindowsJdk(): string | undefined {
    for (const root of ['C:\\Program Files\\Eclipse Adoptium', 'C:\\Program Files\\Java', 'C:\\Program Files\\Microsoft']) {
        let names: string[] = [];
        try { names = readdirSync(root); } catch { continue; }
        const found = names
            .filter((n) => /^jdk-?\d/i.test(n))
            .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
            .map((n) => path.join(root, n, 'bin', javaExe))
            .find((p) => existsSync(p));
        if (found) return found;
    }
    return undefined;
}

/**
 * Where Ghidra and Java are, or undefined when Ghidra tools should not be
 * offered. GHIDRA_INSTALL_DIR is the opt-in; Java comes from GHIDRA_JAVA_HOME,
 * JAVA_HOME, a JDK in the usual Windows folders, or `java` on PATH.
 */
export function resolveGhidraSetup(env: NodeJS.ProcessEnv = process.env): GhidraSetup | undefined {
    const installDir = env.GHIDRA_INSTALL_DIR;
    if (!installDir || !existsSync(path.join(installDir, 'Ghidra', 'Framework', 'Utility', 'lib', 'Utility.jar'))) return undefined;
    const homes = [env.GHIDRA_JAVA_HOME, env.JAVA_HOME].filter((h): h is string => !!h);
    let java = homes.map((h) => path.join(h, 'bin', javaExe)).find((p) => existsSync(p));
    if (!java && process.platform === 'win32') java = findWindowsJdk();
    if (!java) java = 'java';
    const projectsDir = path.resolve(env.GHIDRA_PROJECTS_DIR || defaultProjectsDir(env));
    return { installDir, java, projectsDir };
}

/**
 * Ghidra refuses project paths with any folder starting with "." (such as
 * ~/.desktop-commander), so the default avoids them.
 */
export function defaultProjectsDir(env: NodeJS.ProcessEnv = process.env): string {
    if (process.platform === 'win32' && env.LOCALAPPDATA) return path.join(env.LOCALAPPDATA, 'DesktopCommander', 'ghidra-projects');
    return path.join(os.homedir(), 'DesktopCommander', 'ghidra-projects');
}

/** The folder in `dir` that Ghidra would refuse because it starts with ".", if any. */
export function dottedPathElement(dir: string): string | undefined {
    return path.resolve(dir).split(/[\\/]+/).find((part) => part.startsWith('.'));
}

/** One project per binary path, so files with the same name never share one. */
export function projectNameFor(file: string): string {
    const base = path.basename(file).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 60) || 'binary';
    const digest = createHash('sha256').update(path.resolve(file).toLowerCase()).digest('hex').slice(0, 12);
    return `${base}-${digest}`;
}

/** The script's own block from Ghidra's output, or undefined when it never ran. */
export function extractBlock(raw: string): string | undefined {
    const output = raw.replace(/\r\n/g, '\n');
    const s = output.indexOf(START);
    const e = output.lastIndexOf(END);
    if (s < 0 || e < s) return undefined;
    return output.slice(s, e + END.length);
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t }], ...(isError && { isError: true }) });

/** Ghidra locks a project while it is open, so calls on one project run one at a time. */
const queues = new Map<string, Promise<unknown>>();
function serialize<T>(key: string, job: () => Promise<T>): Promise<T> {
    const prev = queues.get(key) ?? Promise.resolve();
    const next = prev.catch(() => undefined).then(job);
    queues.set(key, next);
    void next.finally(() => { if (queues.get(key) === next) queues.delete(key); }).catch(() => undefined);
    return next;
}

interface HeadlessRun { code: number | null; output: string; timedOut: boolean; cancelled: boolean }

function runHeadless(setup: GhidraSetup, args: string[], timeoutMs: number, job?: Job): Promise<HeadlessRun> {
    return new Promise((resolve) => {
        const child = spawn(setup.java, [
            '-Xmx4G',
            '-Djava.system.class.loader=ghidra.GhidraClassLoader',
            '-Dfile.encoding=UTF8',
            '-Djava.awt.headless=true',
            '-cp', path.join(setup.installDir, 'Ghidra', 'Framework', 'Utility', 'lib', 'Utility.jar'),
            'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless',
            ...args,
        ], { windowsHide: true, shell: false });
        if (job) job.child = child;
        let output = '';
        const take = (b: Buffer) => {
            if (output.length < MAX_OUTPUT_CHARS * 2) output += b.toString('utf8');
            if (job) {
                const m = /ANALYZING|REPORT: .*|Total Time.*/.exec(b.toString('utf8'));
                if (m) job.lastLine = m[0].trim();
            }
        };
        child.stdout.on('data', take);
        child.stderr.on('data', take);
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
        const done = (code: number | null, extra = '') => {
            clearTimeout(timer);
            if (job) job.child = undefined;
            resolve({ code, output: output + extra, timedOut, cancelled: job?.state === 'cancelled' });
        };
        child.on('error', (err) => done(-1, `\n${err.message}`));
        child.on('close', (code) => done(code));
    });
}

const errorLines = (output: string) =>
    output.split(/\r?\n/).filter((l) => /ERROR|Exception/.test(l)).slice(0, 20).join('\n') || output.slice(-2000);

// ---------------------------------------------------------------------------
// Edits, backups and the audit log

const EDIT_NOTE = ' Changes the Ghidra project only, never the binary on disk. The project is backed up first; ghidra_undo_edit restores it.';

interface EditSpec { name: string; title: string; description: string; mode: string; args: [string, Prop][]; required: string[] }
const EDITS: EditSpec[] = [
    { name: 'ghidra_rename_function', title: 'Ghidra: rename function', mode: 'rename_function', args: [['target', P.target], ['new_name', { type: 'string', description: 'New function name.' }]], required: ['target', 'new_name'], description: 'Rename a function.' },
    { name: 'ghidra_rename_variable', title: 'Ghidra: rename variable', mode: 'rename_variable', args: [['target', P.target], ['old_name', { type: 'string', description: 'Current name, as shown by ghidra_get_variables or the decompiler (e.g. "local_10", "param_1").' }], ['new_name', { type: 'string', description: 'New variable name.' }]], required: ['target', 'old_name', 'new_name'], description: 'Rename a parameter or local variable of a function.' },
    { name: 'ghidra_set_comment', title: 'Ghidra: set comment', mode: 'set_comment', args: [['address', P.address], ['kind', { type: 'string', description: 'eol (default), pre, post, plate or repeatable.' }], ['comment', { type: 'string', description: 'Comment text; empty clears it.' }]], required: ['address'], description: 'Set or clear a comment at an address.' },
    { name: 'ghidra_set_function_signature', title: 'Ghidra: set function signature', mode: 'set_signature', args: [['target', P.target], ['signature', { type: 'string', description: 'C prototype, e.g. "int parse(char *buf, int len)".' }]], required: ['target', 'signature'], description: 'Set a function\'s return type, name and parameters from a C prototype.' },
    { name: 'ghidra_create_structure', title: 'Ghidra: create structure', mode: 'create_structure', args: [['definition', { type: 'string', description: 'C definition, e.g. "struct Header { int magic; short count; char name[16]; };" (also union/enum/typedef).' }]], required: ['definition'], description: 'Define a structure, union, enum or typedef from C; replaces one with the same name.' },
    { name: 'ghidra_apply_data_type', title: 'Ghidra: apply data type', mode: 'apply_data_type', args: [['address', P.address], ['type', { type: 'string', description: 'Data type, e.g. "dword", "char[16]", "IMAGE_DOS_HEADER", "Header *".' }]], required: ['address', 'type'], description: 'Mark the data at an address as a data type. Refuses to overwrite code.' },
    { name: 'ghidra_patch_bytes', title: 'Ghidra: patch bytes', mode: 'patch_bytes', args: [['address', P.address], ['bytes', { type: 'string', description: 'Hex bytes separated by spaces, e.g. "90 90" (max 4096).' }]], required: ['address', 'bytes'], description: 'Overwrite bytes in the project\'s copy of the program and re-disassemble if it was code. Reports the old bytes.' },
];
const EDIT_BY_NAME = new Map(EDITS.map((e) => [e.name, e]));

const BACKUPS_KEPT = 10;
const auditFile = (setup: GhidraSetup) => path.join(setup.projectsDir, '_audit.jsonl');
const backupsDir = (setup: GhidraSetup, project: string) => path.join(setup.projectsDir, '_backups', project);
const exportsDir = (setup: GhidraSetup, project: string) => path.join(setup.projectsDir, '_exports', project);
const stamp = () => new Date().toISOString().replace(/[:.]/g, '-');

async function audit(setup: GhidraSetup, entry: Record<string, unknown>): Promise<void> {
    try {
        await fs.appendFile(auditFile(setup), JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n', 'utf8');
    } catch {
        // The edit itself already happened; a missing log line must not report it as failed.
    }
}

/** Copies the project's files aside and keeps the newest BACKUPS_KEPT copies. */
async function backupProject(setup: GhidraSetup, project: string, reason: string): Promise<string> {
    const dir = path.join(backupsDir(setup, project), `${stamp()}__${reason}`);
    await fs.mkdir(dir, { recursive: true });
    await fs.cp(path.join(setup.projectsDir, `${project}.gpr`), path.join(dir, `${project}.gpr`));
    await fs.cp(path.join(setup.projectsDir, `${project}.rep`), path.join(dir, `${project}.rep`), { recursive: true });
    const all = (await fs.readdir(backupsDir(setup, project))).sort();
    for (const old of all.slice(0, Math.max(0, all.length - BACKUPS_KEPT))) {
        await fs.rm(path.join(backupsDir(setup, project), old), { recursive: true, force: true });
    }
    return dir;
}

async function restoreLatest(setup: GhidraSetup, project: string): Promise<string | undefined> {
    let all: string[] = [];
    try { all = (await fs.readdir(backupsDir(setup, project))).sort(); } catch { return undefined; }
    const latest = all.at(-1);
    if (!latest) return undefined;
    const from = path.join(backupsDir(setup, project), latest);
    await fs.rm(path.join(setup.projectsDir, `${project}.rep`), { recursive: true, force: true });
    await fs.cp(path.join(from, `${project}.rep`), path.join(setup.projectsDir, `${project}.rep`), { recursive: true });
    await fs.cp(path.join(from, `${project}.gpr`), path.join(setup.projectsDir, `${project}.gpr`));
    await fs.rm(from, { recursive: true, force: true });
    return latest;
}

// ---------------------------------------------------------------------------
// Analysis jobs and the index of analyzed files

type JobState = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
interface Job {
    file: string;
    project: string;
    state: JobState;
    queuedAt: number;
    startedAt?: number;
    finishedAt?: number;
    lastLine?: string;
    message?: string;
    child?: ChildProcess;
}
const jobs = new Map<string, Job>();

interface IndexEntry { file: string; analyzedAt: string; size: number; mtimeMs: number }
const indexFile = (setup: GhidraSetup) => path.join(setup.projectsDir, '_index.json');
async function readIndex(setup: GhidraSetup): Promise<Record<string, IndexEntry>> {
    try { return JSON.parse(await fs.readFile(indexFile(setup), 'utf8')); } catch { return {}; }
}
async function recordAnalyzed(setup: GhidraSetup, project: string, file: string): Promise<void> {
    const index = await readIndex(setup);
    const st = await fs.stat(file);
    index[project] = { file, analyzedAt: new Date().toISOString(), size: st.size, mtimeMs: st.mtimeMs };
    await fs.writeFile(indexFile(setup), JSON.stringify(index, null, 2), 'utf8');
}

function newJob(file: string, project: string): Job {
    const job: Job = { file, project, state: 'queued', queuedAt: Date.now() };
    jobs.set(project, job);
    return job;
}

async function analyze(setup: GhidraSetup, file: string, project: string, job: Job = newJob(file, project)): Promise<ToolResult> {
    return serialize(project, async () => {
        if (job.state === 'cancelled') return text(`Cancelled before it started: ${file}`, true);
        job.state = 'running';
        job.startedAt = Date.now();
        const r = await runHeadless(setup, [setup.projectsDir, project, '-import', file, '-overwrite'], ANALYZE_TIMEOUT_MS, job);
        job.finishedAt = Date.now();
        if (r.cancelled) { job.message = 'cancelled'; return text(`Cancelled: ${file}`, true); }
        if (r.timedOut) { job.state = 'failed'; job.message = 'timed out after 30 minutes'; return text('ERROR: analysis did not finish in 30 minutes.', true); }
        const ok = /Import succeeded/.test(r.output) && /Save succeeded/.test(r.output);
        if (!ok) {
            job.state = 'failed';
            job.message = errorLines(r.output).split('\n')[0];
            return text(`ERROR: Ghidra could not analyze the file.\n${errorLines(r.output)}`, true);
        }
        job.state = 'done';
        await recordAnalyzed(setup, project, file);
        const report = r.output.split(/\r?\n/).filter((l) => /REPORT:|Total Time/.test(l)).map((l) => l.replace(/^INFO\s+/, '').trim());
        return text(`Analyzed ${file}\n${report.join('\n')}\nNow query it with the other ghidra_* tools, e.g. ghidra_info, ghidra_list_functions, ghidra_decompile.`);
    });
}

// ---------------------------------------------------------------------------
// Tool list

const fileOnly = { type: 'object' as const, properties: { file: P.file }, required: ['file'] };
const PROJECT_TOOLS = [
    {
        name: 'ghidra_list_projects',
        title: 'Ghidra: list analyzed files',
        description: 'Every binary analyzed on this device: path, when, and whether the file changed since.',
        inputSchema: { type: 'object' as const, properties: {} },
        annotations: { readOnlyHint: true, openWorldHint: false },
    },
    {
        name: 'ghidra_analysis_status',
        title: 'Ghidra: analysis status',
        description: 'Analyses that are queued, running or recently finished, with elapsed time and Ghidra\'s latest progress line. Give "file" for one, or nothing for all.',
        inputSchema: { type: 'object' as const, properties: { file: { ...P.file, description: 'Optional: one binary\'s path.' } } },
        annotations: { readOnlyHint: true, openWorldHint: false },
    },
    {
        name: 'ghidra_cancel_analysis',
        title: 'Ghidra: cancel analysis',
        description: 'Stop the queued or running analysis of a file.',
        inputSchema: fileOnly,
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    {
        name: 'ghidra_batch_analyze',
        title: 'Ghidra: analyze several files',
        description: 'Queue up to 20 binaries for analysis, one at a time in the background, and return at once. Follow progress with ghidra_analysis_status.',
        inputSchema: { type: 'object' as const, properties: { files: { type: 'array', items: { type: 'string' }, description: 'Absolute paths of the binaries (1 to 20).' } }, required: ['files'] },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    {
        name: 'ghidra_export_report',
        title: 'Ghidra: export report',
        description: 'A summary of an analyzed binary (info, memory map, imports, exports, functions, strings) as JSON or Markdown, saved under the projects folder and returned.',
        inputSchema: { type: 'object' as const, properties: { file: P.file, format: { type: 'string', description: '"json" (default) or "markdown".' }, max_items: { type: 'integer', description: 'Most entries per list (default 300, max 2000).' } }, required: ['file'] },
        annotations: { readOnlyHint: true, openWorldHint: false },
    },
    {
        name: 'ghidra_export_program',
        title: 'Ghidra: export program',
        description: 'Export the analyzed program, with any edits, to a new file under the projects folder: "c" (decompiled C), "xml", "ascii" (listing), "original" (the original file format with patches applied) or "raw" (raw bytes). The source binary is never touched.',
        inputSchema: { type: 'object' as const, properties: { file: P.file, format: { type: 'string', description: 'c, xml, ascii, original or raw.' } }, required: ['file', 'format'] },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    {
        name: 'ghidra_undo_edit',
        title: 'Ghidra: undo last edit',
        description: 'Restore the project of a binary to how it was before its latest edit (rename, comment, signature, structure, data type or patch). Can be repeated for earlier edits; the last 10 are kept.',
        inputSchema: fileOnly,
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
];

const editTool = (e: EditSpec) => ({
    name: e.name,
    title: e.title,
    description: e.description + EDIT_NOTE,
    inputSchema: { type: 'object' as const, properties: { file: P.file, ...Object.fromEntries(e.args) }, required: ['file', ...e.required] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
});

export const GHIDRA_TOOLS = [ANALYZE_TOOL, ...QUERIES.map(toolFor), ...EDITS.map(editTool), ...PROJECT_TOOLS];

export function isGhidraTool(name: string): boolean {
    return name.startsWith(GHIDRA_TOOL_PREFIX) && GHIDRA_TOOLS.some((t) => t.name === name);
}

// ---------------------------------------------------------------------------
// Calls

/** Validated script arguments in order, or an error result. */
function scriptArgsFor(spec: { args: [string, Prop][]; required?: string[] }, args: Record<string, unknown>): string[] | ToolResult {
    const out: string[] = [];
    for (const [key, prop] of spec.args) {
        const raw = args[key];
        let value = '';
        if (prop.type === 'integer') {
            if (raw !== undefined && raw !== null && raw !== '') {
                const n = Number(raw);
                if (!Number.isInteger(n) || n < 1) return text(`ERROR: "${key}" must be a positive whole number.`, true);
                value = String(n);
            }
        } else if (raw !== undefined && raw !== null) {
            if (typeof raw !== 'string') return text(`ERROR: "${key}" must be a string.`, true);
            value = key === 'comment' ? raw : raw.trim();
        }
        if (spec.required?.includes(key) && !value) return text(`ERROR: "${key}" is required.`, true);
        // Ghidra reads anything starting with "-" as one of its own options.
        if (value.startsWith('-')) return text(`ERROR: "${key}" cannot start with "-".`, true);
        if (value.length > 8000) return text(`ERROR: "${key}" is too long.`, true);
        out.push(value);
    }
    return out;
}

/** An absolute path to an existing file, or an error result. */
async function checkFile(file: unknown): Promise<string | ToolResult> {
    if (typeof file !== 'string' || !file || !path.isAbsolute(file)) return text('ERROR: "file" must be an absolute path to a binary.', true);
    try {
        const st = await fs.stat(file);
        if (!st.isFile()) return text(`ERROR: not a file: ${file}`, true);
    } catch {
        return text(`ERROR: file not found: ${file}`, true);
    }
    return file;
}

const isResult = (v: unknown): v is ToolResult => typeof v === 'object' && v !== null && 'content' in v;

/** Copies a shipped script next to the projects, where Ghidra will compile it. */
async function stageScript(setup: GhidraSetup, name: string): Promise<string> {
    const scriptDir = path.join(setup.projectsDir, '_scripts');
    await fs.mkdir(scriptDir, { recursive: true });
    const source = await fs.readFile(path.join(SCRIPTS_DIR, name), 'utf8');
    const target = path.join(scriptDir, name);
    let current = '';
    try { current = await fs.readFile(target, 'utf8'); } catch { /* first use */ }
    if (current !== source) await fs.writeFile(target, source, 'utf8');
    return scriptDir;
}

/** Runs one script mode on a project; `write` opens it for changes and saves them. */
async function runScript(setup: GhidraSetup, project: string, program: string, script: string, mode: string, scriptArgs: string[], write: boolean): Promise<{ block?: string; output: string; timedOut: boolean }> {
    const scriptDir = await stageScript(setup, script);
    const r = await runHeadless(setup, [
        setup.projectsDir, project, '-process', program, '-noanalysis', ...(write ? [] : ['-readOnly']),
        '-scriptPath', scriptDir, '-postScript', script, mode, ...scriptArgs,
    ], QUERY_TIMEOUT_MS);
    return { block: extractBlock(r.output), output: r.output, timedOut: r.timedOut };
}

const capped = (block: string) => block.length > MAX_OUTPUT_CHARS ? `${block.slice(0, MAX_OUTPUT_CHARS)}\n... (output truncated)` : block;
const fmtTime = (ms: number) => `${Math.round(ms / 1000)}s`;

export async function callGhidraTool(setup: GhidraSetup, name: string, args: Record<string, unknown>): Promise<ToolResult> {
    args = args ?? {};
    const dotted = dottedPathElement(setup.projectsDir);
    if (dotted) {
        return text(`ERROR: Ghidra cannot use the projects folder ${setup.projectsDir} because "${dotted}" starts with ".". Set GHIDRA_PROJECTS_DIR to a folder without such a part.`, true);
    }
    await fs.mkdir(setup.projectsDir, { recursive: true });

    // Tools that are not about one file.
    if (name === 'ghidra_list_projects') {
        const index = await readIndex(setup);
        const lines: string[] = [];
        for (const [project, e] of Object.entries(index)) {
            if (!existsSync(path.join(setup.projectsDir, `${project}.gpr`))) continue;
            let note = '';
            try {
                const st = await fs.stat(e.file);
                if (st.size !== e.size || Math.abs(st.mtimeMs - e.mtimeMs) > 1) note = '  (file changed since; analyze again)';
            } catch { note = '  (file no longer exists)'; }
            lines.push(`${e.file}  analyzed ${e.analyzedAt}${note}`);
        }
        return text(lines.length ? lines.join('\n') : 'No files analyzed yet. Use ghidra_analyze.');
    }
    if (name === 'ghidra_analysis_status') {
        const want = typeof args.file === 'string' && args.file ? projectNameFor(args.file) : undefined;
        const now = Date.now();
        const lines = [...jobs.values()].filter((j) => !want || j.project === want).map((j) => {
            const elapsed = j.startedAt ? fmtTime((j.finishedAt ?? now) - j.startedAt) : `waiting ${fmtTime(now - j.queuedAt)}`;
            return `${j.state.padEnd(9)} ${elapsed.padEnd(12)} ${j.file}${j.lastLine && j.state === 'running' ? `  [${j.lastLine}]` : ''}${j.message ? `  (${j.message})` : ''}`;
        });
        return text(lines.length ? lines.join('\n') : want ? 'No analysis of that file since the device started.' : 'No analyses since the device started.');
    }
    if (name === 'ghidra_batch_analyze') {
        const files = args.files;
        if (!Array.isArray(files) || files.length < 1 || files.length > 20) return text('ERROR: "files" must list 1 to 20 absolute paths.', true);
        const checked: string[] = [];
        for (const f of files) {
            const c = await checkFile(f);
            if (isResult(c)) return c;
            checked.push(c);
        }
        for (const f of checked) {
            // Listed as queued now, so status and cancel see it; run one at a
            // time across batches, so a batch does not start 20 JVMs.
            const job = newJob(f, projectNameFor(f));
            void serialize('batch', () => analyze(setup, f, job.project, job)).catch(() => undefined);
        }
        return text(`Queued ${checked.length} file(s) for analysis, one at a time:\n${checked.join('\n')}\nFollow progress with ghidra_analysis_status.`);
    }

    const file = await checkFile(args.file);
    if (isResult(file)) return file;
    const project = projectNameFor(file);
    const program = path.basename(file);

    if (name === 'ghidra_analyze') return analyze(setup, file, project);

    if (name === 'ghidra_cancel_analysis') {
        const job = jobs.get(project);
        if (!job || (job.state !== 'queued' && job.state !== 'running')) return text(`No queued or running analysis of ${file}.`, true);
        const was = job.state;
        job.state = 'cancelled';
        job.finishedAt = Date.now();
        job.child?.kill();
        return text(`Cancelled the ${was} analysis of ${file}.`);
    }

    const analyzed = existsSync(path.join(setup.projectsDir, `${project}.gpr`));
    const notAnalyzed = () => text(`ERROR: ${file} has not been analyzed yet. Call ghidra_analyze with this file first.`, true);

    if (name === 'ghidra_undo_edit') {
        if (!analyzed) return notAnalyzed();
        return serialize(project, async () => {
            const restored = await restoreLatest(setup, project);
            if (!restored) return text(`Nothing to undo for ${file}.`, true);
            await audit(setup, { tool: name, file, project, restored });
            return text(`Restored ${file} to before: ${restored.split('__')[1] ?? 'edit'} (backup ${restored.split('__')[0]}).`);
        });
    }

    const query = QUERY_BY_NAME.get(name);
    if (query) {
        const sa = scriptArgsFor(query, args);
        if (isResult(sa)) return sa;
        if (!analyzed) return notAnalyzed();
        return serialize(project, async () => {
            const r = await runScript(setup, project, program, 'HexeyTool.java', query.mode, sa, false);
            if (r.timedOut) return text('ERROR: Ghidra did not answer in 10 minutes.', true);
            if (!r.block) return text(`ERROR: Ghidra query failed.\n${errorLines(r.output)}`, true);
            return text(capped(r.block), /\nERROR: /.test(r.block));
        });
    }

    const edit = EDIT_BY_NAME.get(name);
    if (edit) {
        const sa = scriptArgsFor(edit, args);
        if (isResult(sa)) return sa;
        if (!analyzed) return notAnalyzed();
        return serialize(project, async () => {
            const backup = await backupProject(setup, project, edit.mode);
            const r = await runScript(setup, project, program, 'HexeyEdit.java', edit.mode, sa, true);
            const failed = r.timedOut || !r.block || /\nERROR: /.test(r.block);
            if (failed) {
                // Nothing should have been saved, but put the project back to be sure.
                await restoreLatest(setup, project);
                await audit(setup, { tool: name, file, project, args: Object.fromEntries(edit.args.map(([k], i) => [k, sa[i]])), ok: false });
                if (r.timedOut) return text('ERROR: Ghidra did not answer in 10 minutes; the project was restored.', true);
                return text(r.block ? `${r.block}\n(the project was restored)` : `ERROR: the edit failed; the project was restored.\n${errorLines(r.output)}`, true);
            }
            await audit(setup, { tool: name, file, project, args: Object.fromEntries(edit.args.map(([k], i) => [k, sa[i]])), ok: true, backup: path.basename(backup) });
            return text(`${r.block}\nUndo with ghidra_undo_edit.`);
        });
    }

    if (name === 'ghidra_export_program') {
        const format = typeof args.format === 'string' ? args.format.trim().toLowerCase() : '';
        const ext: Record<string, string> = { c: 'c', xml: 'xml', ascii: 'txt', original: path.extname(program).slice(1) || 'bin', raw: 'bin' };
        if (!ext[format]) return text('ERROR: "format" must be c, xml, ascii, original or raw.', true);
        if (!analyzed) return notAnalyzed();
        const dir = exportsDir(setup, project);
        await fs.mkdir(dir, { recursive: true });
        const out = path.join(dir, `${path.parse(program).name}-${stamp()}.${ext[format]}`);
        return serialize(project, async () => {
            const r = await runScript(setup, project, program, 'HexeyEdit.java', 'export', [format, out], false);
            if (r.timedOut) return text('ERROR: Ghidra did not answer in 10 minutes.', true);
            if (!r.block) return text(`ERROR: export failed.\n${errorLines(r.output)}`, true);
            await audit(setup, { tool: name, file, project, format, out, ok: !/\nERROR: /.test(r.block) });
            return text(r.block, /\nERROR: /.test(r.block));
        });
    }

    if (name === 'ghidra_export_report') {
        const format = typeof args.format === 'string' && args.format.trim() ? args.format.trim().toLowerCase() : 'json';
        if (format !== 'json' && format !== 'markdown') return text('ERROR: "format" must be json or markdown.', true);
        const max = args.max_items === undefined ? 300 : Number(args.max_items);
        if (!Number.isInteger(max) || max < 1) return text('ERROR: "max_items" must be a positive whole number.', true);
        if (!analyzed) return notAnalyzed();
        return serialize(project, async () => {
            const r = await runScript(setup, project, program, 'HexeyTool.java', 'report', [String(Math.min(max, 2000))], false);
            if (r.timedOut) return text('ERROR: Ghidra did not answer in 10 minutes.', true);
            const json = r.block?.split('\n').find((l) => l.startsWith('{'));
            if (!json) return text(`ERROR: report failed.\n${r.block ?? errorLines(r.output)}`, true);
            let data: Record<string, any>;
            try { data = JSON.parse(json); } catch { return text('ERROR: Ghidra produced an unreadable report.', true); }
            const body = format === 'json' ? JSON.stringify({ file, ...data }, null, 2) : reportMarkdown(file, data);
            const dir = exportsDir(setup, project);
            await fs.mkdir(dir, { recursive: true });
            const out = path.join(dir, `${path.parse(program).name}-report-${stamp()}.${format === 'json' ? 'json' : 'md'}`);
            await fs.writeFile(out, body, 'utf8');
            return text(`Saved to ${out}\n\n${capped(body)}`);
        });
    }

    return text(`ERROR: unknown Ghidra tool: ${name}`, true);
}

export function reportMarkdown(file: string, d: Record<string, any>): string {
    const rows = (items: unknown[] | undefined, f: (x: any) => string) => (items ?? []).map(f).join('\n') || '_none_';
    return [
        `# ${d.name}`,
        '',
        `- File: \`${file}\``,
        `- Format: ${d.format}`,
        `- Language: ${d.language} (${d.compiler})`,
        `- Image base: \`${d.imageBase}\``,
        `- MD5: \`${d.md5}\``,
        `- Functions: ${d.functionCount}`,
        '',
        '## Memory',
        '| name | start | size | perms |',
        '|---|---|---|---|',
        rows(d.memory, (m) => `| ${m.name} | \`${m.start}\` | ${m.size} | ${m.perms} |`),
        '',
        '## Imports',
        rows(d.imports, (i) => `- \`${i}\``),
        '',
        '## Exports',
        rows(d.exports, (e) => `- \`${e.address}\` ${e.name}`),
        '',
        '## Functions',
        rows(d.functions, (f) => `- \`${f.address}\` ${f.name} (${f.size} bytes)`),
        '',
        '## Strings',
        rows(d.strings, (s) => `- \`${s.address}\` ${String(s.value).replace(/\n/g, '\\n').slice(0, 200)}`),
        '',
    ].join('\n');
}

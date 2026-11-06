import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Frida tools a remote AI can call on this device: list processes, attach to
 * or spawn one, list its modules and exports, read its memory, trace a
 * function, run a Frida script, detach. They run through one long-lived
 * Python helper (scripts/hexey_frida.py) that keeps sessions open between
 * calls.
 *
 * Offered only when the person at the device sets FRIDA_ENABLED=1 and the
 * Frida Python module can be imported. There are no other limits: the AI can
 * attach to any process this user can.
 */

const HELPER = path.join(path.dirname(fileURLToPath(import.meta.url)), 'scripts', 'hexey_frida.py');
const CALL_TIMEOUT_MS = 10 * 60_000;
const MAX_TEXT = 400_000;

export interface FridaSetup { python: string; version: string }

let cachedSetup: { key: string; value: FridaSetup | undefined } | undefined;

/** Python with Frida importable, or undefined when Frida tools should not be offered. */
export function resolveFridaSetup(env: NodeJS.ProcessEnv = process.env): FridaSetup | undefined {
    if (env.FRIDA_ENABLED !== '1') return undefined;
    const candidates = env.FRIDA_PYTHON ? [env.FRIDA_PYTHON] : process.platform === 'win32' ? ['python', 'py'] : ['python3', 'python'];
    const key = candidates.join('|');
    if (cachedSetup?.key === key) return cachedSetup.value;
    let value: FridaSetup | undefined;
    for (const python of candidates) {
        const r = spawnSync(python, ['-c', 'import frida; print(frida.__version__)'], { encoding: 'utf8', timeout: 15_000, windowsHide: true });
        if (r.status === 0 && r.stdout.trim()) { value = { python, version: r.stdout.trim() }; break; }
    }
    cachedSetup = { key, value };
    return value;
}

// ---------------------------------------------------------------------------
// Helper process

let helper: ChildProcessWithoutNullStreams | undefined;
let nextId = 1;
const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();

function startHelper(setup: FridaSetup): ChildProcessWithoutNullStreams {
    if (helper && helper.exitCode === null && !helper.killed) return helper;
    const child = spawn(setup.python, ['-u', HELPER], { windowsHide: true, shell: false });
    let buf = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
        buf += chunk;
        let nl: number;
        while ((nl = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            let msg: any;
            try { msg = JSON.parse(line); } catch { continue; }
            const p = pending.get(msg.id);
            if (!p) continue;
            pending.delete(msg.id);
            clearTimeout(p.timer);
            if (msg.ok) p.resolve(msg.result);
            else p.reject(new Error(msg.error));
        }
    });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c: string) => { stderr = (stderr + c).slice(-4000); });
    child.on('exit', (code) => {
        for (const [id, p] of pending) {
            clearTimeout(p.timer);
            p.reject(new Error(`the Frida helper stopped (exit ${code})${stderr ? `: ${stderr.trim().split('\n').slice(-3).join(' ')}` : ''}`));
            pending.delete(id);
        }
        if (helper === child) helper = undefined;
    });
    helper = child;
    return child;
}

function request(setup: FridaSetup, op: string, args: Record<string, unknown>, timeoutMs = CALL_TIMEOUT_MS): Promise<any> {
    const child = startHelper(setup);
    const id = nextId++;
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Frida did not answer in ${Math.round(timeoutMs / 1000)}s`)); }, timeoutMs);
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(JSON.stringify({ ...args, id, op }) + '\n');
    });
}

/** Stops the helper, which detaches every session. */
export function shutdownFrida(): void {
    helper?.stdin.end();
    helper = undefined;
}

// ---------------------------------------------------------------------------
// Tools

const S = (description: string) => ({ type: 'string', description });
const I = (description: string) => ({ type: 'integer', description });
const session = S('Session id from frida_attach or frida_spawn.');
const ro = { readOnlyHint: true, openWorldHint: false };
const rw = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };

export const FRIDA_TOOLS = [
    { name: 'frida_list_processes', title: 'Frida: list processes', description: 'Running processes on this device (pid and name).', inputSchema: { type: 'object' as const, properties: { filter: S('Optional part of a process name, or a pid.') } }, annotations: ro },
    { name: 'frida_attach', title: 'Frida: attach', description: 'Attach Frida to a running process by pid or exact name. Returns a session id for the other frida_* tools.', inputSchema: { type: 'object' as const, properties: { target: S('Process id, or exact process name such as "notepad.exe".') }, required: ['target'] }, annotations: rw },
    { name: 'frida_spawn', title: 'Frida: spawn', description: 'Start a program under Frida and attach. With suspended=true it stays paused so hooks can be set before it runs; then call frida_resume.', inputSchema: { type: 'object' as const, properties: { program: S('Absolute path of the program.'), args: { type: 'array', items: { type: 'string' }, description: 'Command-line arguments.' }, suspended: { type: 'boolean', description: 'Keep it paused after starting (default false).' } }, required: ['program'] }, annotations: rw },
    { name: 'frida_resume', title: 'Frida: resume', description: 'Let a process started suspended by frida_spawn run.', inputSchema: { type: 'object' as const, properties: { session }, required: ['session'] }, annotations: rw },
    { name: 'frida_list_sessions', title: 'Frida: list sessions', description: 'Open Frida sessions: id, pid, name, whether spawned, whether still attached.', inputSchema: { type: 'object' as const, properties: {} }, annotations: ro },
    { name: 'frida_list_modules', title: 'Frida: list modules', description: 'Loaded modules (DLL/SO/dylib) of the attached process: name, base, size, path.', inputSchema: { type: 'object' as const, properties: { session, filter: S('Optional part of a module name or path.') }, required: ['session'] }, annotations: ro },
    { name: 'frida_list_exports', title: 'Frida: list exports', description: 'Exports of one loaded module: type, name, address.', inputSchema: { type: 'object' as const, properties: { session, module: S('Module name, e.g. "kernel32.dll".'), filter: S('Optional part of an export name.') }, required: ['session', 'module'] }, annotations: ro },
    { name: 'frida_read_memory', title: 'Frida: read memory', description: 'Read bytes from the attached process\'s memory as a hex dump with ASCII.', inputSchema: { type: 'object' as const, properties: { session, address: S('Address, e.g. "0x7ff6a1b20000".'), length: I('Bytes to read (default 256).') }, required: ['session', 'address'] }, annotations: ro },
    { name: 'frida_trace_function', title: 'Frida: trace function', description: 'Hook a function for a while and report each call: thread, arguments (as pointers), caller, return value. Target "module!export", a global export name, or an address.', inputSchema: { type: 'object' as const, properties: { session, target: S('e.g. "kernel32.dll!CreateFileW", "CreateFileW" or "0x7ff6a1b21234".'), duration_ms: I('How long to watch (default 5000).'), args: I('Arguments to show per call (default 4).'), max_events: I('Stop recording after this many calls (default 200).') }, required: ['session', 'target'] }, annotations: rw },
    { name: 'frida_run_script', title: 'Frida: run script', description: 'Run Frida JavaScript in the attached process and return everything it send()s within the timeout. send({done:true}) ends early. keep=true leaves the script loaded (hooks stay) until detach.', inputSchema: { type: 'object' as const, properties: { session, source: S('Frida JavaScript.'), timeout_ms: I('How long to collect messages (default 5000).'), keep: { type: 'boolean', description: 'Keep the script loaded after returning.' } }, required: ['session', 'source'] }, annotations: rw },
    { name: 'frida_detach', title: 'Frida: detach', description: 'Close a session and unload its scripts. kill=true also ends a process that frida_spawn started.', inputSchema: { type: 'object' as const, properties: { session, kill: { type: 'boolean', description: 'End the spawned process too.' } }, required: ['session'] }, annotations: rw },
];

const OP: Record<string, string> = {
    frida_list_processes: 'processes', frida_attach: 'attach', frida_spawn: 'spawn', frida_resume: 'resume',
    frida_list_sessions: 'sessions', frida_list_modules: 'modules', frida_list_exports: 'exports',
    frida_read_memory: 'read', frida_trace_function: 'trace', frida_run_script: 'script', frida_detach: 'detach',
};

export function isFridaTool(name: string): boolean {
    return Object.prototype.hasOwnProperty.call(OP, name);
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t.length > MAX_TEXT ? `${t.slice(0, MAX_TEXT)}\n... (output truncated)` : t }], ...(isError && { isError: true }) });

/** A hex dump with addresses and ASCII, 16 bytes a line. */
export function hexDump(address: string, hex: string): string {
    let base: bigint;
    try { base = BigInt(address); } catch { base = 0n; }
    const lines: string[] = [];
    for (let off = 0; off < hex.length / 2; off += 16) {
        const row = hex.slice(off * 2, (off + 16) * 2);
        const bytes = row.match(/../g) ?? [];
        const ascii = bytes.map((b) => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; }).join('');
        lines.push(`0x${(base + BigInt(off)).toString(16)}  ${bytes.join(' ').padEnd(47)}  ${ascii}`);
    }
    return lines.join('\n');
}

export async function callFridaTool(setup: FridaSetup, name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const op = OP[name];
    if (!op) return text(`ERROR: unknown Frida tool: ${name}`, true);
    try {
        const result = await request(setup, op, args ?? {});
        if (op === 'read') return text(hexDump(result.address, result.hex));
        if (op === 'processes') return text(result.map((p: any) => `${p.pid}  ${p.name}`).join('\n') || '(no matching processes)');
        if (op === 'modules') return text(result.map((m: any) => `${m.base}  ${String(m.size).padStart(10)}  ${m.name}  ${m.path}`).join('\n') || '(no matching modules)');
        if (op === 'exports') return text(result.map((e: any) => `${e.address}  ${e.type}  ${e.name}`).join('\n') || '(no matching exports)');
        return text(JSON.stringify(result, null, 2));
    } catch (error) {
        return text(`ERROR: ${error instanceof Error ? error.message : String(error)}`, true);
    }
}

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
const B = (description: string) => ({ type: 'boolean', description });
const session = S('Session id from frida_attach or frida_spawn.');
const device = S('Device id or alias (default: local device).');
const ro = { readOnlyHint: true, openWorldHint: false };
const rw = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };

export const FRIDA_TOOLS = [
    // ── Device & Process Management ──────────────────────────────────────
    { name: 'frida_list_devices', title: 'Frida: list devices', description: 'Enumerate available Frida devices: local, USB and remote.', inputSchema: { type: 'object' as const, properties: {} }, annotations: ro },
    { name: 'frida_device_info', title: 'Frida: device info', description: 'Detailed information about a device: OS, architecture, platform, device id and name.', inputSchema: { type: 'object' as const, properties: { device } }, annotations: ro },
    { name: 'frida_connect_device', title: 'Frida: connect remote device', description: 'Connect to a remote Frida server by address (host:port). Returns the device id for use in other tools.', inputSchema: { type: 'object' as const, properties: { address: S('Remote Frida server address, e.g. "192.168.1.100:27042".'), alias: S('Optional friendly name for this device.') }, required: ['address'] }, annotations: rw },
    { name: 'frida_server_status', title: 'Frida: server status', description: 'Check Frida server connectivity and version on a device.', inputSchema: { type: 'object' as const, properties: { device } }, annotations: ro },
    { name: 'frida_list_processes', title: 'Frida: list processes', description: 'Running processes on this device (pid and name).', inputSchema: { type: 'object' as const, properties: { device, filter: S('Optional part of a process name, or a pid.') } }, annotations: ro },
    { name: 'frida_list_applications', title: 'Frida: list applications', description: 'Installed applications on the device (identifier, name, pid if running). Useful for Android/iOS targets.', inputSchema: { type: 'object' as const, properties: { device, filter: S('Optional part of an application name or identifier.') } }, annotations: ro },

    // ── Session & Process Control ─────────────────────────────────────────
    { name: 'frida_attach', title: 'Frida: attach', description: 'Attach Frida to a running process by pid or exact name. Returns a session id for the other frida_* tools.', inputSchema: { type: 'object' as const, properties: { target: S('Process id, or exact process name such as "notepad.exe".'), device }, required: ['target'] }, annotations: rw },
    { name: 'frida_spawn', title: 'Frida: spawn', description: 'Start a program under Frida and attach. With suspended=true it stays paused so hooks can be set before it runs; then call frida_resume.', inputSchema: { type: 'object' as const, properties: { program: S('Absolute path of the program or package identifier (Android/iOS).'), args: { type: 'array', items: { type: 'string' }, description: 'Command-line arguments.' }, suspended: B('Keep it paused after starting (default false).'), device }, required: ['program'] }, annotations: rw },
    { name: 'frida_resume', title: 'Frida: resume', description: 'Let a process started suspended by frida_spawn run.', inputSchema: { type: 'object' as const, properties: { session }, required: ['session'] }, annotations: rw },
    { name: 'frida_kill', title: 'Frida: kill process', description: 'Kill a process by session id or pid. Only kills processes the current user owns.', inputSchema: { type: 'object' as const, properties: { session: S('Session id (optional if pid given).'), pid: I('Process id (optional if session given).'), device } }, annotations: rw },
    { name: 'frida_list_sessions', title: 'Frida: list sessions', description: 'Open Frida sessions: id, pid, name, whether spawned, whether still attached.', inputSchema: { type: 'object' as const, properties: {} }, annotations: ro },
    { name: 'frida_session_status', title: 'Frida: session status', description: 'Detailed status of a single session: pid, name, spawned, attached, loaded scripts and active hooks.', inputSchema: { type: 'object' as const, properties: { session }, required: ['session'] }, annotations: ro },
    { name: 'frida_detach', title: 'Frida: detach', description: 'Close a session and unload its scripts. kill=true also ends a process that frida_spawn started.', inputSchema: { type: 'object' as const, properties: { session, kill: B('End the spawned process too.') }, required: ['session'] }, annotations: rw },

    // ── Script Management ─────────────────────────────────────────────────
    { name: 'frida_run_script', title: 'Frida: run script', description: 'Run Frida JavaScript in the attached process and return everything it send()s within the timeout. send({done:true}) ends early. keep=true leaves the script loaded (hooks stay) until detach.', inputSchema: { type: 'object' as const, properties: { session, source: S('Frida JavaScript.'), timeout_ms: I('How long to collect messages (default 5000).'), keep: B('Keep the script loaded after returning.') }, required: ['session', 'source'] }, annotations: rw },
    { name: 'frida_load_script', title: 'Frida: load script', description: 'Load a persistent Frida JavaScript agent into the session. Returns a script_id for unload/reload/rpc. The script stays active until explicitly unloaded or the session ends.', inputSchema: { type: 'object' as const, properties: { session, source: S('Frida JavaScript agent source code.'), name: S('Optional name to identify this script.') }, required: ['session', 'source'] }, annotations: rw },
    { name: 'frida_unload_script', title: 'Frida: unload script', description: 'Unload a previously loaded script by its id. Removes all hooks and RPC exports from that script.', inputSchema: { type: 'object' as const, properties: { session, script_id: S('Script id from frida_load_script.') }, required: ['session', 'script_id'] }, annotations: rw },
    { name: 'frida_reload_script', title: 'Frida: reload script', description: 'Unload and re-load a script, optionally with new source. Useful for iterating on an agent without losing the session.', inputSchema: { type: 'object' as const, properties: { session, script_id: S('Script id from frida_load_script.'), source: S('New source code (omit to reload the same source).') }, required: ['session', 'script_id'] }, annotations: rw },

    // ── Hook & Instrumentation ────────────────────────────────────────────
    { name: 'frida_hook_function', title: 'Frida: hook function', description: 'Set a persistent hook on a native function. Logs every call with arguments and return value. Returns a hook_id for unhooking. Target "module!export", a global name, or an address.', inputSchema: { type: 'object' as const, properties: { session, target: S('e.g. "kernel32.dll!CreateFileW", "open" or "0x7ff6a1b21234".'), args: I('Number of arguments to capture per call (default 4).') }, required: ['session', 'target'] }, annotations: rw },
    { name: 'frida_unhook_function', title: 'Frida: unhook function', description: 'Remove a persistent hook by its hook_id. The original function behavior is restored.', inputSchema: { type: 'object' as const, properties: { session, hook_id: S('Hook id from frida_hook_function.') }, required: ['session', 'hook_id'] }, annotations: rw },
    { name: 'frida_replace_function', title: 'Frida: replace function', description: 'Replace a native function\'s implementation. The original is saved and restored on unhook or detach. Requires confirmation before execution.', inputSchema: { type: 'object' as const, properties: { session, target: S('Function to replace: "module!export", global name, or address.'), return_value: S('Fixed return value as a string (e.g. "0", "1", "0x0"). Mutually exclusive with source.'), return_type: S('Return type hint: "int", "pointer", "void" (default "int").'), param_types: { type: 'array', items: { type: 'string' }, description: 'Parameter type hints for the NativeCallback.' }, source: S('Custom Frida JS for NativeCallback body. Has access to args array. Mutually exclusive with return_value.') }, required: ['session', 'target'] }, annotations: rw },
    { name: 'frida_call_rpc', title: 'Frida: call RPC', description: 'Call an RPC method exported by a loaded script (via rpc.exports). The script must have been loaded with frida_load_script.', inputSchema: { type: 'object' as const, properties: { session, script_id: S('Script id that exports the RPC method.'), method: S('RPC method name as exported.'), args: { type: 'array', description: 'Arguments to pass to the RPC method.' } }, required: ['session', 'script_id', 'method'] }, annotations: rw },
    { name: 'frida_trace_function', title: 'Frida: trace function', description: 'Hook a function for a while and report each call: thread, arguments (as pointers), caller, return value. Target "module!export", a global export name, or an address.', inputSchema: { type: 'object' as const, properties: { session, target: S('e.g. "kernel32.dll!CreateFileW", "CreateFileW" or "0x7ff6a1b21234".'), duration_ms: I('How long to watch (default 5000).'), args: I('Arguments to show per call (default 4).'), max_events: I('Stop recording after this many calls (default 200).') }, required: ['session', 'target'] }, annotations: rw },

    // ── Memory Analysis ───────────────────────────────────────────────────
    { name: 'frida_list_modules', title: 'Frida: list modules', description: 'Loaded modules (DLL/SO/dylib) of the attached process: name, base, size, path.', inputSchema: { type: 'object' as const, properties: { session, filter: S('Optional part of a module name or path.') }, required: ['session'] }, annotations: ro },
    { name: 'frida_list_exports', title: 'Frida: list exports', description: 'Exports of one loaded module: type, name, address.', inputSchema: { type: 'object' as const, properties: { session, module: S('Module name, e.g. "kernel32.dll".'), filter: S('Optional part of an export name.') }, required: ['session', 'module'] }, annotations: ro },
    { name: 'frida_list_imports', title: 'Frida: list imports', description: 'Imports of one loaded module: type, name, module, address.', inputSchema: { type: 'object' as const, properties: { session, module: S('Module name, e.g. "kernel32.dll".'), filter: S('Optional part of an import name.') }, required: ['session', 'module'] }, annotations: ro },
    { name: 'frida_read_memory', title: 'Frida: read memory', description: 'Read bytes from the attached process\'s memory as a hex dump with ASCII.', inputSchema: { type: 'object' as const, properties: { session, address: S('Address, e.g. "0x7ff6a1b20000".'), length: I('Bytes to read (default 256).') }, required: ['session', 'address'] }, annotations: ro },
    { name: 'frida_scan_memory', title: 'Frida: scan memory', description: 'Search process memory for a byte pattern. Returns matching addresses with context.', inputSchema: { type: 'object' as const, properties: { session, pattern: S('Hex pattern with wildcards, e.g. "48 8b ?? 05" or "41 42 43".'), protection: S('Memory protection filter, e.g. "r--", "rw-", "r-x" (default: search all readable).'), max: I('Maximum matches to return (default 100).') }, required: ['session', 'pattern'] }, annotations: ro },
    { name: 'frida_write_memory', title: 'Frida: write memory', description: 'Write bytes to process memory. The original bytes are saved and can be restored with frida_cleanup. Requires confirmation.', inputSchema: { type: 'object' as const, properties: { session, address: S('Target address, e.g. "0x7ff6a1b20000".'), hex: S('Hex bytes to write, e.g. "90 90 90 90".') }, required: ['session', 'address', 'hex'] }, annotations: rw },
    { name: 'frida_protect_memory', title: 'Frida: change memory protection', description: 'Change memory page protection flags. Requires confirmation.', inputSchema: { type: 'object' as const, properties: { session, address: S('Page-aligned address.'), size: I('Size in bytes of the region.'), protection: S('New protection, e.g. "rwx", "r--", "rw-".') }, required: ['session', 'address', 'size', 'protection'] }, annotations: rw },

    // ── Advanced Dynamic Analysis ─────────────────────────────────────────
    { name: 'frida_list_threads', title: 'Frida: list threads', description: 'Threads in the attached process: id, state, program counter and stack pointer.', inputSchema: { type: 'object' as const, properties: { session }, required: ['session'] }, annotations: ro },
    { name: 'frida_get_registers', title: 'Frida: read registers', description: 'CPU registers of a thread captured during a hook or breakpoint context.', inputSchema: { type: 'object' as const, properties: { session, thread_id: I('Thread id from frida_list_threads.') }, required: ['session', 'thread_id'] }, annotations: ro },
    { name: 'frida_get_backtrace', title: 'Frida: backtrace', description: 'Call stack of a thread: return addresses with symbol names when available.', inputSchema: { type: 'object' as const, properties: { session, thread_id: I('Thread id from frida_list_threads.') }, required: ['session', 'thread_id'] }, annotations: ro },
    { name: 'frida_stalker_start', title: 'Frida: start Stalker tracing', description: 'Start Frida Stalker on a thread for instruction-level or call-level tracing. Stalker follows execution and reports calls, returns, and execution events. Limit events and duration to avoid performance impact.', inputSchema: { type: 'object' as const, properties: { session, thread_id: I('Thread id to trace.'), events: { type: 'array', items: { type: 'string' }, description: 'Event types: "call", "ret", "exec", "block", "compile" (default ["call", "ret"]).' }, max_events: I('Stop after this many events (default 500).'), duration_ms: I('Stop after this many milliseconds (default 5000).') }, required: ['session', 'thread_id'] }, annotations: rw },
    { name: 'frida_stalker_stop', title: 'Frida: stop Stalker tracing', description: 'Stop Stalker tracing on a thread and return collected events.', inputSchema: { type: 'object' as const, properties: { session, thread_id: I('Thread id being traced.') }, required: ['session', 'thread_id'] }, annotations: rw },

    // ── Android Java / JNI ────────────────────────────────────────────────
    { name: 'frida_java_classes', title: 'Frida: Java classes', description: 'Search loaded Java classes in an Android process. Requires Java runtime to be available (Android app with ART).', inputSchema: { type: 'object' as const, properties: { session, filter: S('Optional part of a class name, e.g. "MainActivity" or "com.example".') }, required: ['session'] }, annotations: ro },
    { name: 'frida_java_methods', title: 'Frida: Java methods', description: 'List methods and overloads of a Java class, including parameter types and return type.', inputSchema: { type: 'object' as const, properties: { session, class_name: S('Fully qualified class name, e.g. "com.example.app.MainActivity".') }, required: ['session', 'class_name'] }, annotations: ro },
    { name: 'frida_java_hook', title: 'Frida: hook Java method', description: 'Hook a Java method to log calls with arguments and return values. Returns a hook_id. For overloaded methods, all overloads are hooked.', inputSchema: { type: 'object' as const, properties: { session, class_name: S('Fully qualified class name.'), method: S('Method name to hook.') }, required: ['session', 'class_name', 'method'] }, annotations: rw },
    { name: 'frida_java_instances', title: 'Frida: Java instances', description: 'Find live instances of a Java class on the heap. Returns a summary of each instance.', inputSchema: { type: 'object' as const, properties: { session, class_name: S('Fully qualified class name.') }, required: ['session', 'class_name'] }, annotations: ro },
    { name: 'frida_jni_trace', title: 'Frida: trace JNI calls', description: 'Trace native JNI function calls between Java and native code. Shows JNI function name, arguments and the calling Java/native context.', inputSchema: { type: 'object' as const, properties: { session, filter: S('Optional JNI function name filter, e.g. "FindClass", "GetMethodID".'), max_events: I('Stop after this many events (default 200).'), duration_ms: I('How long to trace (default 5000).') }, required: ['session'] }, annotations: rw },

    // ── iOS / macOS ───────────────────────────────────────────────────────
    { name: 'frida_objc_classes', title: 'Frida: Objective-C classes', description: 'Search loaded Objective-C classes. Requires ObjC runtime (iOS/macOS).', inputSchema: { type: 'object' as const, properties: { session, filter: S('Optional part of a class name, e.g. "ViewController" or "NS".') }, required: ['session'] }, annotations: ro },
    { name: 'frida_objc_hook', title: 'Frida: hook ObjC method', description: 'Hook an Objective-C method to log calls with arguments and return value. Returns a hook_id.', inputSchema: { type: 'object' as const, properties: { session, class_name: S('ObjC class name, e.g. "NSURLSession".'), method: S('Method selector, e.g. "dataTaskWithRequest:completionHandler:" (include colons).') }, required: ['session', 'class_name', 'method'] }, annotations: rw },
    { name: 'frida_swift_symbols', title: 'Frida: Swift symbols', description: 'List Swift symbols from loaded modules, demangled when possible.', inputSchema: { type: 'object' as const, properties: { session, module: S('Optional module name to search in.'), filter: S('Optional part of a symbol name.') }, required: ['session'] }, annotations: ro },

    // ── Monitoring & Logging ──────────────────────────────────────────────
    { name: 'frida_get_events', title: 'Frida: get hook events', description: 'Retrieve collected events from active hooks and traces in a session. Events are buffered since the last read.', inputSchema: { type: 'object' as const, properties: { session, since: S('ISO timestamp or event index to read from (default: all buffered).'), limit: I('Maximum events to return (default 200).'), clear: B('Clear events after reading (default false).') }, required: ['session'] }, annotations: ro },
    { name: 'frida_subscribe_events', title: 'Frida: subscribe to events', description: 'Wait for and return the next batch of hook events in real-time. Blocks until events arrive or timeout.', inputSchema: { type: 'object' as const, properties: { session, timeout_ms: I('How long to wait for events (default 5000).'), event_limit: I('Return after this many events (default 100).'), clear: B('Clear events after reading (default true).') }, required: ['session'] }, annotations: rw },
    { name: 'frida_export_trace', title: 'Frida: export trace', description: 'Export all collected trace and hook events from a session as JSON Lines. Returns the data or saves to a file.', inputSchema: { type: 'object' as const, properties: { session, output_path: S('Optional absolute path to save the JSONL file. If omitted, returns the data directly.') }, required: ['session'] }, annotations: rw },
    { name: 'frida_get_errors', title: 'Frida: get script errors', description: 'Retrieve JavaScript exceptions and errors from loaded scripts in a session.', inputSchema: { type: 'object' as const, properties: { session, clear: B('Clear errors after reading (default false).') }, required: ['session'] }, annotations: ro },
    { name: 'frida_cleanup', title: 'Frida: cleanup all', description: 'Close all sessions, unload all scripts, remove all hooks and restore any modified memory. Use when done with a Frida analysis session.', inputSchema: { type: 'object' as const, properties: {} }, annotations: rw },
];

const OP: Record<string, string> = {
    // Device & Process
    frida_list_devices: 'devices',
    frida_device_info: 'device_info',
    frida_connect_device: 'connect_device',
    frida_server_status: 'server_status',
    frida_list_processes: 'processes',
    frida_list_applications: 'applications',
    // Session & Process Control
    frida_attach: 'attach',
    frida_spawn: 'spawn',
    frida_resume: 'resume',
    frida_kill: 'kill',
    frida_list_sessions: 'sessions',
    frida_session_status: 'session_status',
    frida_detach: 'detach',
    // Script Management
    frida_run_script: 'script',
    frida_load_script: 'load_script',
    frida_unload_script: 'unload_script',
    frida_reload_script: 'reload_script',
    // Hook & Instrumentation
    frida_hook_function: 'hook',
    frida_unhook_function: 'unhook',
    frida_replace_function: 'replace',
    frida_call_rpc: 'rpc',
    frida_trace_function: 'trace',
    // Memory
    frida_list_modules: 'modules',
    frida_list_exports: 'exports',
    frida_list_imports: 'imports',
    frida_read_memory: 'read',
    frida_scan_memory: 'scan',
    frida_write_memory: 'write_mem',
    frida_protect_memory: 'protect',
    // Advanced Dynamic Analysis
    frida_list_threads: 'threads',
    frida_get_registers: 'registers',
    frida_get_backtrace: 'backtrace',
    frida_stalker_start: 'stalker_start',
    frida_stalker_stop: 'stalker_stop',
    // Java / JNI
    frida_java_classes: 'java_classes',
    frida_java_methods: 'java_methods',
    frida_java_hook: 'java_hook',
    frida_java_instances: 'java_instances',
    frida_jni_trace: 'jni_trace',
    // iOS / macOS
    frida_objc_classes: 'objc_classes',
    frida_objc_hook: 'objc_hook',
    frida_swift_symbols: 'swift_symbols',
    // Monitoring
    frida_get_events: 'get_events',
    frida_subscribe_events: 'subscribe_events',
    frida_export_trace: 'export_trace',
    frida_get_errors: 'get_errors',
    frida_cleanup: 'cleanup',
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
        if (op === 'processes') return text(Array.isArray(result) ? result.map((p: any) => `${p.pid}  ${p.name}`).join('\n') || '(no matching processes)' : JSON.stringify(result, null, 2));
        if (op === 'modules') return text(Array.isArray(result) ? result.map((m: any) => `${m.base}  ${String(m.size).padStart(10)}  ${m.name}  ${m.path}`).join('\n') || '(no matching modules)' : JSON.stringify(result, null, 2));
        if (op === 'exports') return text(Array.isArray(result) ? result.map((e: any) => `${e.address}  ${e.type}  ${e.name}`).join('\n') || '(no matching exports)' : JSON.stringify(result, null, 2));
        if (op === 'imports') return text(Array.isArray(result) ? result.map((e: any) => `${e.address || '?'}  ${e.type}  ${e.module || ''}!${e.name}`).join('\n') || '(no matching imports)' : JSON.stringify(result, null, 2));
        if (op === 'devices') return text(Array.isArray(result) ? result.map((d: any) => `${d.id}  ${d.type}  ${d.name}`).join('\n') || '(no devices found)' : JSON.stringify(result, null, 2));
        if (op === 'applications') return text(Array.isArray(result) ? result.map((a: any) => `${a.identifier}  ${a.name}${a.pid ? '  (pid ' + a.pid + ')' : ''}`).join('\n') || '(no matching applications)' : JSON.stringify(result, null, 2));
        if (op === 'threads') return text(Array.isArray(result) ? result.map((t: any) => `${t.id}  ${t.state}  pc=${t.pc}  sp=${t.sp}`).join('\n') || '(no threads)' : JSON.stringify(result, null, 2));
        return text(JSON.stringify(result, null, 2));
    } catch (error) {
        return text(`ERROR: ${error instanceof Error ? error.message : String(error)}`, true);
    }
}

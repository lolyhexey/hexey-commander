import { spawn } from 'child_process';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import os from 'os';
import path from 'path';

/**
 * adb tools a remote AI can call on this device: list connected Android
 * devices, run shell commands, install, pull and push files, read logcat and
 * pull an installed app's APKs. Offered only when the person at the device
 * opts in with ADB_ENABLED=1 and adb can be found.
 */

export const ADB_TOOL_PREFIX = 'adb_';
const MAX_OUTPUT_CHARS = 400_000;

const SERIAL = { type: 'string', description: 'Device serial from adb_devices. Needed when more than one device is connected.' };

export const ADB_TOOLS = [
    {
        name: 'adb_devices',
        title: 'adb: devices',
        description: 'Android devices and emulators connected to this computer, with serial, state (device, unauthorized, offline), model and Android version.',
        inputSchema: { type: 'object' as const, properties: {} },
        annotations: { readOnlyHint: true, openWorldHint: false },
    },
    {
        name: 'adb_shell',
        title: 'adb: shell command',
        description: 'Run a shell command on an Android device (adb shell) and return its output and exit code. Use "su -c \'...\'" for root on a rooted device.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                serial: SERIAL,
                command: { type: 'string', description: 'Shell command, e.g. "pm list packages -3" or "getprop ro.build.version.release".' },
                timeout_ms: { type: 'integer', description: 'Stop waiting after this long (default 60000, max 600000).' },
            },
            required: ['command'],
        },
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    {
        name: 'adb_install',
        title: 'adb: install APK',
        description: 'Install an APK from this computer on a device (adb install -r, keeping app data). Several split APKs of one app can be given together.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                serial: SERIAL,
                apk: { type: 'string', description: 'Absolute path of the APK on this computer.' },
                splits: { type: 'array', items: { type: 'string' }, description: 'Optional more APKs of the same app (installed together with adb install-multiple).' },
                downgrade: { type: 'boolean', description: 'Allow a lower version code (-d).' },
                grant: { type: 'boolean', description: 'Grant all runtime permissions (-g).' },
            },
            required: ['apk'],
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    {
        name: 'adb_pull',
        title: 'adb: pull file',
        description: 'Copy a file or folder from a device to this computer.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                serial: SERIAL,
                remote: { type: 'string', description: 'Path on the device, e.g. "/sdcard/Download/a.txt".' },
                local: { type: 'string', description: 'Absolute path on this computer to copy to.' },
            },
            required: ['remote', 'local'],
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    {
        name: 'adb_push',
        title: 'adb: push file',
        description: 'Copy a file or folder from this computer to a device, replacing a file of the same name.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                serial: SERIAL,
                local: { type: 'string', description: 'Absolute path on this computer.' },
                remote: { type: 'string', description: 'Path on the device, e.g. "/data/local/tmp/".' },
            },
            required: ['local', 'remote'],
        },
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    {
        name: 'adb_logcat',
        title: 'adb: logcat',
        description: 'Recent device log lines (logcat -d), newest last. Filter by app package, by tag/priority spec, or by text.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                serial: SERIAL,
                package: { type: 'string', description: 'Only lines from the running process of this app, e.g. "com.example".' },
                spec: { type: 'string', description: 'logcat filter spec, e.g. "ActivityManager:I *:S" or "*:E".' },
                grep: { type: 'string', description: 'Only lines containing this text (case-insensitive).' },
                lines: { type: 'integer', description: 'Most recent lines to read (default 500, max 20000).' },
                clear: { type: 'boolean', description: 'Clear the log after reading, so the next read shows only new lines.' },
            },
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    {
        name: 'adb_pull_apk',
        title: 'adb: pull installed app',
        description: 'Copy an installed app\'s APK files (base and splits) from a device to a folder on this computer, ready for jadx_decompile or apktool_decode.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                serial: SERIAL,
                package: { type: 'string', description: 'App package, e.g. "com.example". Use adb_shell "pm list packages" to find it.' },
                local_dir: { type: 'string', description: 'Absolute folder on this computer to copy into (created if missing).' },
            },
            required: ['package', 'local_dir'],
        },
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
];

const NAMES = new Set(ADB_TOOLS.map((t) => t.name));
export function isAdbTool(name: string): boolean {
    return NAMES.has(name);
}

export interface AdbSetup { adb: string }

const exe = (name: string) => process.platform === 'win32' ? `${name}.exe` : name;

/** The adb to use from ANDROID_HOME, ANDROID_SDK_ROOT or the default SDK folder, else `adb` on PATH. */
export function findAdb(env: NodeJS.ProcessEnv = process.env): string {
    const sdks = [env.ANDROID_HOME, env.ANDROID_SDK_ROOT,
        process.platform === 'win32' && env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Android', 'Sdk') : path.join(os.homedir(), 'Android', 'Sdk')];
    for (const sdk of sdks) {
        if (!sdk) continue;
        const p = path.join(sdk, 'platform-tools', exe('adb'));
        if (existsSync(p)) return p;
    }
    return 'adb';
}

/** adb tools are offered only with ADB_ENABLED=1. */
export function resolveAdbSetup(env: NodeJS.ProcessEnv = process.env): AdbSetup | undefined {
    if (env.ADB_ENABLED !== '1') return undefined;
    return { adb: env.ADB_PATH && existsSync(env.ADB_PATH) ? env.ADB_PATH : findAdb(env) };
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const cap = (t: string) => t.length > MAX_OUTPUT_CHARS ? `${t.slice(0, MAX_OUTPUT_CHARS)}\n... (cut at ${MAX_OUTPUT_CHARS} characters)` : t;
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: cap(t) }], ...(isError && { isError: true }) });

interface Run { code: number | null; stdout: string; stderr: string; timedOut: boolean }
function run(cmd: string, args: string[], timeoutMs: number): Promise<Run> {
    return new Promise((resolve) => {
        const child = spawn(cmd, args, { windowsHide: true, shell: false });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (b: Buffer) => { if (stdout.length < MAX_OUTPUT_CHARS * 2) stdout += b.toString('utf8'); });
        child.stderr.on('data', (b: Buffer) => { if (stderr.length < MAX_OUTPUT_CHARS) stderr += b.toString('utf8'); });
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
        child.on('error', (e) => { stderr += `\n${e.message}`; });
        child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr, timedOut }); });
    });
}

const both = (r: Run) => [r.stdout.trim(), r.stderr.trim()].filter(Boolean).join('\n');
const str = (v: unknown) => typeof v === 'string' ? v.trim() : '';
const PKG = /^[A-Za-z][\w]*(\.[A-Za-z_][\w]*)+$/;

export async function callAdbTool(setup: AdbSetup, name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
        const serial = str(args.serial);
        const s = serial ? ['-s', serial] : [];
        const adb = (a: string[], timeoutMs = 120_000) => run(setup.adb, [...s, ...a], timeoutMs);

        if (name === 'adb_devices') {
            const r = await run(setup.adb, ['devices', '-l'], 30_000);
            if (r.code !== 0) return text(`ERROR: adb devices failed (is adb installed? set ANDROID_HOME or ADB_PATH).\n${both(r)}`, true);
            const rows = r.stdout.split(/\r?\n/).slice(1).map((l) => l.trim()).filter(Boolean);
            if (rows.length === 0) return text('No device connected. Plug one in with USB debugging on, or start an emulator.');
            const out: string[] = [];
            for (const row of rows) {
                const [id, state] = row.split(/\s+/);
                let extra = row.slice(id.length + state.length + 2).trim();
                if (state === 'device') {
                    const v = await run(setup.adb, ['-s', id, 'shell', 'getprop ro.build.version.release; getprop ro.build.version.sdk'], 15_000);
                    const [rel, sdk] = v.stdout.trim().split(/\r?\n/);
                    if (rel) extra += ` android:${rel.trim()} api:${(sdk ?? '').trim()}`;
                }
                out.push(`${id}\t${state}\t${extra}`);
            }
            return text(out.join('\n'));
        }

        if (name === 'adb_shell') {
            const command = typeof args.command === 'string' ? args.command : '';
            if (!command.trim()) return text('ERROR: command is required.', true);
            const timeout = Math.min(Math.max(Number(args.timeout_ms) || 60_000, 1000), 600_000);
            // Exit code of the device command, appended so it survives adb's own exit code.
            const r = await adb(['shell', `${command}; echo "__HEXEY_EXIT=$?"`], timeout);
            const m = /__HEXEY_EXIT=(\d+)\s*$/.exec(r.stdout);
            const out = r.stdout.replace(/\r?\n?__HEXEY_EXIT=\d+\s*$/, '');
            const code = m ? Number(m[1]) : r.code;
            const parts = [out.trimEnd(), r.stderr.trim() && `[stderr]\n${r.stderr.trim()}`, r.timedOut ? `[stopped after ${timeout} ms]` : `[exit ${code}]`].filter(Boolean);
            return text(parts.join('\n'), r.timedOut || code !== 0);
        }

        if (name === 'adb_install') {
            const apk = str(args.apk);
            if (!apk || !existsSync(apk)) return text(`ERROR: no such APK: ${apk}`, true);
            const splits = Array.isArray(args.splits) ? args.splits.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : [];
            for (const sp of splits) if (!existsSync(sp)) return text(`ERROR: no such APK: ${sp}`, true);
            const flags = ['-r', ...(args.downgrade === true ? ['-d'] : []), ...(args.grant === true ? ['-g'] : [])];
            const r = splits.length ? await adb(['install-multiple', ...flags, apk, ...splits], 600_000) : await adb(['install', ...flags, apk], 600_000);
            const success = r.code === 0 && /Success/.test(r.stdout);
            let note = '';
            if (/INSTALL_FAILED_UPDATE_INCOMPATIBLE|signatures do not match/i.test(both(r))) note = '\nThe installed app is signed with another key; uninstall it first (adb_shell "pm uninstall <package>", which deletes its data).';
            if (/INSTALL_FAILED_VERSION_DOWNGRADE/.test(both(r))) note = '\nThe installed version is newer; set downgrade to allow it.';
            return text(success ? `Installed ${path.basename(apk)}${splits.length ? ` with ${splits.length} split(s)` : ''}: Success` : `install FAILED:\n${both(r)}${note}`, !success);
        }

        if (name === 'adb_pull' || name === 'adb_push') {
            const remote = str(args.remote);
            const local = str(args.local);
            if (!remote || !local) return text('ERROR: remote and local are required.', true);
            if (!path.isAbsolute(local)) return text('ERROR: local must be an absolute path.', true);
            if (name === 'adb_push' && !existsSync(local)) return text(`ERROR: no such file: ${local}`, true);
            if (name === 'adb_pull') await fs.mkdir(path.dirname(local), { recursive: true });
            const r = name === 'adb_pull' ? await adb(['pull', remote, local], 600_000) : await adb(['push', local, remote], 600_000);
            return text(both(r) || `exit ${r.code}`, r.code !== 0);
        }

        if (name === 'adb_logcat') {
            const lines = Math.min(Math.max(Number(args.lines) || 500, 1), 20_000);
            const a = ['logcat', '-d', '-v', 'threadtime', '-t', String(lines)];
            const pkg = str(args.package);
            if (pkg) {
                if (!PKG.test(pkg)) return text(`ERROR: not a package name: ${pkg}`, true);
                const p = await adb(['shell', `pidof ${pkg}`], 15_000);
                const pid = p.stdout.trim().split(/\s+/)[0];
                if (!pid) return text(`ERROR: ${pkg} is not running, so its log lines cannot be picked out. Start it first.`, true);
                a.push(`--pid=${pid}`);
            }
            const spec = str(args.spec);
            if (spec) a.push(...spec.split(/\s+/));
            const r = await adb(a, 120_000);
            if (r.code !== 0) return text(`ERROR: logcat failed.\n${both(r)}`, true);
            let out = r.stdout.split(/\r?\n/);
            const grep = str(args.grep).toLowerCase();
            if (grep) out = out.filter((l) => l.toLowerCase().includes(grep));
            if (args.clear === true) await adb(['logcat', '-c'], 30_000);
            return text(out.join('\n').trim() || '(no matching lines)');
        }

        if (name === 'adb_pull_apk') {
            const pkg = str(args.package);
            const dir = str(args.local_dir);
            if (!PKG.test(pkg)) return text(`ERROR: not a package name: ${pkg}`, true);
            if (!dir || !path.isAbsolute(dir)) return text('ERROR: local_dir must be an absolute folder.', true);
            const p = await adb(['shell', `pm path ${pkg}`], 30_000);
            const paths = p.stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith('package:')).map((l) => l.slice(8));
            if (paths.length === 0) return text(`ERROR: ${pkg} is not installed on the device.\n${both(p)}`, true);
            await fs.mkdir(dir, { recursive: true });
            const pulled: string[] = [];
            for (const remote of paths) {
                const local = path.join(dir, path.posix.basename(remote));
                const r = await adb(['pull', remote, local], 600_000);
                if (r.code !== 0 || !existsSync(local)) return text(`ERROR: pulling ${remote} failed.\n${both(r)}`, true);
                pulled.push(`${local} (${(await fs.stat(local)).size} bytes)`);
            }
            return text(`Pulled ${pulled.length} APK(s) of ${pkg}:\n${pulled.join('\n')}`);
        }

        return text(`ERROR: unknown adb tool: ${name}`, true);
    } catch (e: any) {
        return text(`ERROR: ${e?.message ?? e}`, true);
    }
}

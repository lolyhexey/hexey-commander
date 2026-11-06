import path from 'path';
import type { FridaSetup } from './frida-tools.js';
import type { GhidraSetup } from './ghidra-tools.js';
import { callFridaTool } from './frida-tools.js';
import { callGhidraTool } from './ghidra-tools.js';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t }], ...(isError && { isError: true }) });

const S = (description: string) => ({ type: 'string', description });
const I = (description: string) => ({ type: 'integer', description });
const ro = { readOnlyHint: true, openWorldHint: false };

function extractText(result: ToolResult): string {
    return result.content.map((c) => c.text).join('\n');
}

function parseImageBase(infoText: string): bigint | undefined {
    const m = /image base:\s*(0x)?([0-9a-fA-F]+)/i.exec(infoText);
    if (m) return BigInt('0x' + m[2]);
    const jm = /"imageBase"\s*:\s*"?(0x)?([0-9a-fA-F]+)"?/i.exec(infoText);
    if (jm) return BigInt('0x' + jm[2]);
    return undefined;
}

function parseModuleBase(modulesText: string): bigint | undefined {
    const m = /^(0x[0-9a-fA-F]+)/m.exec(modulesText);
    if (m) return BigInt(m[1]);
    return undefined;
}

function parseFunctionEntry(funcText: string): bigint | undefined {
    const m = /entry:\s*(0x)?([0-9a-fA-F]+)/i.exec(funcText);
    if (m) return BigInt('0x' + m[2]);
    return undefined;
}

function addr(v: bigint): string {
    return '0x' + v.toString(16);
}

async function getImageBase(ghidra: GhidraSetup, file: string): Promise<bigint> {
    const r = await callGhidraTool(ghidra, 'ghidra_info', { file });
    if (r.isError) throw new Error(extractText(r));
    const base = parseImageBase(extractText(r));
    if (base === undefined) throw new Error('Could not parse image base from ghidra_info output');
    return base;
}

async function getRuntimeBase(frida: FridaSetup, session: string, moduleName: string): Promise<bigint> {
    const r = await callFridaTool(frida, 'frida_list_modules', { session, filter: moduleName });
    if (r.isError) throw new Error(extractText(r));
    const base = parseModuleBase(extractText(r));
    if (base === undefined) throw new Error(`Module "${moduleName}" not found in the running process`);
    return base;
}

// ---------------------------------------------------------------------------
// Tool definitions

export const BRIDGE_TOOLS = [
    {
        name: 'reverse_resolve_runtime_address',
        title: 'Bridge: resolve address (Ghidra <-> Frida)',
        description: 'Convert a Ghidra static address to a runtime address (accounting for ASLR), or vice versa. Prefix the address with "rt:" for runtime-to-static.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                session: S('Frida session id.'),
                file: S('Absolute path of the binary (must be analyzed in Ghidra).'),
                address: S('Static address like "140001cb0", or runtime address prefixed "rt:0x7ff6a1b21234".'),
                module: S('Module name in the running process (default: filename of the binary).'),
            },
            required: ['session', 'file', 'address'],
        },
        annotations: ro,
    },
    {
        name: 'reverse_trace_ghidra_function',
        title: 'Bridge: trace Ghidra function live',
        description: 'Pick a function from Ghidra and trace it with Frida at runtime. Returns the decompiled C alongside the live call trace with arguments and return values.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                session: S('Frida session id.'),
                file: S('Absolute path of the binary (must be analyzed in Ghidra).'),
                target: S('Function name (e.g. "entry", "FUN_140001af0") or Ghidra address in hex.'),
                module: S('Module name in the running process (default: filename of the binary).'),
                duration_ms: I('How long to trace (default 5000).'),
                args: I('Arguments to capture per call (default 4).'),
            },
            required: ['session', 'file', 'target'],
        },
        annotations: ro,
    },
    {
        name: 'reverse_correlate_trace',
        title: 'Bridge: full static+dynamic correlation',
        description: 'Complete reverse engineering report: function signature, decompiled C, variables, and live runtime trace with arguments and return values — all correlated between Ghidra and Frida.',
        inputSchema: {
            type: 'object' as const,
            properties: {
                session: S('Frida session id.'),
                file: S('Absolute path of the binary (must be analyzed in Ghidra).'),
                target: S('Function name or Ghidra address in hex.'),
                module: S('Module name in the running process (default: filename of the binary).'),
                duration_ms: I('How long to trace (default 5000).'),
                args: I('Arguments to capture per call (default 4).'),
            },
            required: ['session', 'file', 'target'],
        },
        annotations: ro,
    },
];

const TOOL_NAMES = new Set(BRIDGE_TOOLS.map((t) => t.name));

export function isBridgeTool(name: string): boolean {
    return TOOL_NAMES.has(name);
}

// ---------------------------------------------------------------------------
// Implementations

async function resolveAddress(ghidra: GhidraSetup, frida: FridaSetup, args: Record<string, unknown>): Promise<ToolResult> {
    const session = args.session as string;
    const file = args.file as string;
    const addressRaw = (args.address as string).trim();
    const moduleName = (args.module as string) || path.basename(file);

    const [ghidraBase, runtimeBase] = await Promise.all([
        getImageBase(ghidra, file),
        getRuntimeBase(frida, session, moduleName),
    ]);

    let direction: string;
    let staticAddr: bigint;
    let runtimeAddr: bigint;

    if (addressRaw.toLowerCase().startsWith('rt:')) {
        direction = 'runtime → static';
        runtimeAddr = BigInt(addressRaw.slice(3).trim());
        staticAddr = runtimeAddr - runtimeBase + ghidraBase;
    } else {
        direction = 'static → runtime';
        staticAddr = BigInt(addressRaw.startsWith('0x') ? addressRaw : '0x' + addressRaw);
        runtimeAddr = staticAddr - ghidraBase + runtimeBase;
    }

    return text(JSON.stringify({
        direction,
        static_address: addr(staticAddr),
        runtime_address: addr(runtimeAddr),
        ghidra_image_base: addr(ghidraBase),
        runtime_module_base: addr(runtimeBase),
        module: moduleName,
    }, null, 2));
}

async function traceGhidraFunction(ghidra: GhidraSetup, frida: FridaSetup, args: Record<string, unknown>): Promise<ToolResult> {
    const session = args.session as string;
    const file = args.file as string;
    const target = args.target as string;
    const moduleName = (args.module as string) || path.basename(file);
    const durationMs = args.duration_ms ?? 5000;
    const nargs = args.args ?? 4;

    const [funcResult, decompileResult, ghidraBase, runtimeBase] = await Promise.all([
        callGhidraTool(ghidra, 'ghidra_get_function', { file, target }),
        callGhidraTool(ghidra, 'ghidra_decompile', { file, target }),
        getImageBase(ghidra, file),
        getRuntimeBase(frida, session, moduleName),
    ]);

    const funcText = extractText(funcResult);
    const decompText = extractText(decompileResult);

    const entryAddr = parseFunctionEntry(funcText);
    if (!entryAddr) return text(`ERROR: could not parse entry address from function details:\n${funcText}`, true);

    const runtimeAddr = entryAddr - ghidraBase + runtimeBase;

    const traceResult = await callFridaTool(frida, 'frida_trace_function', {
        session,
        target: addr(runtimeAddr),
        duration_ms: durationMs,
        args: nargs,
    });

    const sections = [
        '╔══════════════════════════════════════════════════════════════',
        '║  Static + Dynamic Analysis Report',
        '╠══════════════════════════════════════════════════════════════',
        '',
        '── Address Resolution ──',
        `Ghidra image base:    ${addr(ghidraBase)}`,
        `Runtime module base:  ${addr(runtimeBase)}  (${moduleName})`,
        `Static entry:         ${addr(entryAddr)}`,
        `Runtime entry:        ${addr(runtimeAddr)}`,
        '',
        '── Function Details (Ghidra) ──',
        funcText,
        '',
        '── Decompiled C (Ghidra) ──',
        decompText,
        '',
        '── Runtime Trace (Frida) ──',
        extractText(traceResult),
        '',
        '╚══════════════════════════════════════════════════════════════',
    ];

    return text(sections.join('\n'), traceResult.isError);
}

async function correlateTrace(ghidra: GhidraSetup, frida: FridaSetup, args: Record<string, unknown>): Promise<ToolResult> {
    const session = args.session as string;
    const file = args.file as string;
    const target = args.target as string;
    const moduleName = (args.module as string) || path.basename(file);
    const durationMs = args.duration_ms ?? 5000;
    const nargs = args.args ?? 4;

    const [funcResult, decompileResult, varsResult, ghidraBase, runtimeBase] = await Promise.all([
        callGhidraTool(ghidra, 'ghidra_get_function', { file, target }),
        callGhidraTool(ghidra, 'ghidra_decompile', { file, target }),
        callGhidraTool(ghidra, 'ghidra_get_variables', { file, target }),
        getImageBase(ghidra, file),
        getRuntimeBase(frida, session, moduleName),
    ]);

    const funcText = extractText(funcResult);
    const decompText = extractText(decompileResult);
    const varsText = extractText(varsResult);

    const entryAddr = parseFunctionEntry(funcText);
    if (!entryAddr) return text(`ERROR: could not parse entry address from function details:\n${funcText}`, true);

    const runtimeAddr = entryAddr - ghidraBase + runtimeBase;

    const traceResult = await callFridaTool(frida, 'frida_trace_function', {
        session,
        target: addr(runtimeAddr),
        duration_ms: durationMs,
        args: nargs,
    });

    const sections = [
        '╔══════════════════════════════════════════════════════════════',
        '║  Full Static + Dynamic Correlation Report',
        '╠══════════════════════════════════════════════════════════════',
        '',
        '── Address Resolution ──',
        `Ghidra image base:    ${addr(ghidraBase)}`,
        `Runtime module base:  ${addr(runtimeBase)}  (${moduleName})`,
        `Static entry:         ${addr(entryAddr)}`,
        `Runtime entry:        ${addr(runtimeAddr)}`,
        '',
        '── Function Signature (Ghidra) ──',
        funcText,
        '',
        '── Variables & Parameters (Ghidra) ──',
        varsText,
        '',
        '── Decompiled C (Ghidra) ──',
        decompText,
        '',
        '── Runtime Trace (Frida) ──',
        extractText(traceResult),
        '',
        '╚══════════════════════════════════════════════════════════════',
    ];

    return text(sections.join('\n'), traceResult.isError);
}

// ---------------------------------------------------------------------------
// Dispatcher

export async function callBridgeTool(
    ghidra: GhidraSetup,
    frida: FridaSetup,
    name: string,
    args: Record<string, unknown>,
): Promise<ToolResult> {
    try {
        switch (name) {
            case 'reverse_resolve_runtime_address': return await resolveAddress(ghidra, frida, args);
            case 'reverse_trace_ghidra_function': return await traceGhidraFunction(ghidra, frida, args);
            case 'reverse_correlate_trace': return await correlateTrace(ghidra, frida, args);
            default: return text(`ERROR: unknown bridge tool: ${name}`, true);
        }
    } catch (error) {
        return text(`ERROR: ${error instanceof Error ? error.message : String(error)}`, true);
    }
}

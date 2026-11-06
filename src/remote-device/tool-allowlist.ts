/**
 * Tools a remote AI must not call on this device. They change the device's own
 * configuration, read its call history, send feedback in the user's name or
 * stop the device, so only the person at the device may use them. The backend
 * filters these too; this is the device's own check in case that is bypassed.
 */
export const REMOTE_BLOCKED_TOOLS: ReadonlySet<string> = new Set([
    'set_config_value',
    'get_recent_tool_calls',
    'give_feedback_to_desktop_commander',
    'shutdown',
]);

/** Whether a remote call may run the tool `name` on this device */
export function isRemoteToolAllowed(name: string): boolean {
    return !REMOTE_BLOCKED_TOOLS.has(name);
}

/**
 * Limits on the list a device publishes in its `capabilities`. They match what
 * the backend will serve (MAX_DEVICE_TOOLS and MAX_DEVICE_TOOLS_BYTES in
 * backend/src/mcp/tools.ts, which fall back to the built-in list beyond them)
 * and stay under the database's size check on the whole column, which refuses
 * the entire write, not just the list.
 */
export const MAX_PUBLISHED_TOOLS = 100;
export const MAX_PUBLISHED_TOOLS_BYTES = 480 * 1024;

/**
 * The tools this device tells the backend it has: the local server's own
 * `tools/list` entries, whole and in order, without tools a remote caller may
 * not use and without `ping` (the device answers that itself, so the backend
 * adds it). Empty when there is nothing usable or the list is too large to
 * publish; the backend then serves its built-in list.
 */
export function selectPublishedTools(listed: unknown): Record<string, unknown>[] {
    if (!Array.isArray(listed)) return [];
    const tools = listed.filter((entry): entry is Record<string, unknown> => {
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return false;
        const name = (entry as { name?: unknown }).name;
        return typeof name === 'string' && name !== 'ping' && isRemoteToolAllowed(name);
    });
    if (tools.length > MAX_PUBLISHED_TOOLS) return [];
    try {
        if (Buffer.byteLength(JSON.stringify(tools)) > MAX_PUBLISHED_TOOLS_BYTES) return [];
    } catch {
        return [];
    }
    return tools;
}

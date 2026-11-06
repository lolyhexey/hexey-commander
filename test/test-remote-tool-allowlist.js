#!/usr/bin/env node
// A remote AI must not call the device's management tools: the device refuses
// them itself in case the backend's own filter is bypassed.
import assert from 'node:assert/strict';
import { MCPDevice } from '../dist/remote-device/device.js';
import { REMOTE_BLOCKED_TOOLS, isRemoteToolAllowed } from '../dist/remote-device/tool-allowlist.js';

process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';

const BLOCKED = ['set_config_value', 'get_recent_tool_calls', 'give_feedback_to_desktop_commander', 'shutdown'];
const DEVICE_ID = 'device-1';

for (const name of BLOCKED) {
  assert.equal(isRemoteToolAllowed(name), false, `${name} should be blocked for remote calls`);
  assert.ok(REMOTE_BLOCKED_TOOLS.has(name), `${name} should be in REMOTE_BLOCKED_TOOLS`);
}
assert.equal(REMOTE_BLOCKED_TOOLS.size, BLOCKED.length, 'only the four management tools are blocked');
for (const name of ['read_file', 'ping', 'start_process', 'get_config']) {
  assert.equal(isRemoteToolAllowed(name), true, `${name} should be allowed for remote calls`);
}

/** Handles one call on a device with the desktop and channel stubbed; returns what it did. */
async function handle(callId, toolName) {
  const device = new MCPDevice();
  const executed = [];
  const writes = [];
  let shutdowns = 0;
  device.deviceId = DEVICE_ID;
  device.desktop = { callClientTool: async (name) => { executed.push(name); return { content: [{ type: 'text', text: 'ok' }] }; } };
  device.remoteChannel = {
    user: { id: 'user-1' },
    markCallExecuting: async () => true,
    updateCallResult: async (id, status, result, error) => { writes.push({ id, status, result, error }); },
  };
  device.shutdown = async () => { shutdowns++; };
  await device.handleNewToolCall({ new: { id: callId, tool_name: toolName, tool_args: {}, device_id: DEVICE_ID, metadata: {} } });
  return { executed, writes, shutdowns: () => shutdowns };
}

for (const name of BLOCKED) {
  const call = await handle(`call-${name}`, name);
  assert.equal(call.writes.length, 1, `${name}: exactly one result row should be written`);
  assert.equal(call.writes[0].status, 'failed', `${name}: the result should be failed, got ${call.writes[0].status}`);
  assert.equal(call.writes[0].result, null, `${name}: a blocked call has no result`);
  assert.ok(call.writes[0].error.includes(name) && call.writes[0].error.includes('not available'),
    `${name}: the error should name the tool as not available remotely: ${call.writes[0].error}`);
  assert.deepEqual(call.executed, [], `${name}: must not reach the local Desktop Commander`);
  if (name === 'shutdown') {
    // The old path closed the device 1 s after answering
    await new Promise((resolve) => setTimeout(resolve, 1300));
    assert.equal(call.shutdowns(), 0, 'a blocked shutdown must not shut the device down');
  }
}

const ping = await handle('call-ping', 'ping');
assert.equal(ping.writes[0].status, 'completed', 'ping still works remotely');
const read = await handle('call-read', 'read_file');
assert.deepEqual(read.executed, ['read_file'], 'read_file still reaches the local server');
assert.equal(read.writes[0].status, 'completed');

console.log('PASS remote tool allowlist: management tools are refused on the device, others still run');

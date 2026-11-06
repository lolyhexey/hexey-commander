#!/usr/bin/env node
// The device publishes the local server's tool list in its `capabilities`, minus
// what a remote caller may not use. Runs the production RemoteChannel with its
// backend calls stubbed; nothing touches the network.
import assert from 'node:assert/strict';
process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
delete process.env.MQTT_BROKER_URL;
const { RemoteChannel } = await import('../dist/remote-device/remote-channel.js');
const { VERSION } = await import('../dist/version.js');

const tool = (name, extra = {}) => ({
    name,
    description: `Does ${name}`,
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
    annotations: { readOnlyHint: true },
    ...extra,
});

/** Registers a device and returns the capabilities the channel wrote for it, plus the channel. */
async function register(capabilities) {
    const channel = new RemoteChannel();
    const writes = [];
    Object.assign(channel, {
        _user: { id: 'owner' }, client: {}, deviceId: 'device',
        findDevice: async () => ({ id: 'device' }),
        updateDevice: async (id, fields) => { writes.push(fields); return { error: null }; },
        createChannel: async () => {},
    });
    await channel.registerDevice(capabilities, 'device', 'fixture', () => {});
    assert.equal(writes.length, 1, 'one registration write');
    return { channel, written: writes[0].capabilities };
}

const checks = [];
const check = (name, fn) => checks.push([name, fn]);

check('publishes the local tools in order, whole, without blocked tools or ping', async () => {
    const list = [
        tool('read_file'), tool('set_config_value'), tool('ping'), tool('start_process', { title: 'Start' }),
        tool('get_recent_tool_calls'), tool('give_feedback_to_desktop_commander'), tool('shutdown'), tool('write_file'),
    ];
    const { written } = await register({ tools: list });
    assert.deepEqual(written.tools, [list[0], list[3], list[7]]);
});

check('keeps the existing keys', async () => {
    const { written } = await register({ tools: [tool('read_file')] });
    assert.equal(written.app_version, VERSION);
    assert.deepEqual(Object.keys(written).sort(), ['app_version', 'tools']);
});

check('the MQTT-ready rewrite carries the same tools', async () => {
    const { channel } = await register({ tools: [tool('read_file'), tool('ping')] });
    channel.mqttReady = true;
    const payload = channel.capabilitiesPayload();
    assert.equal(payload.transport_mqtt_v1, true);
    assert.deepEqual(payload.tools.map((entry) => entry.name), ['read_file']);
});

check('no tools key when none were listed or none are left', async () => {
    for (const capabilities of [undefined, {}, { tools: [] }, { tools: 'nope' }, { tools: [tool('ping'), tool('shutdown')] }]) {
        const { written } = await register(capabilities);
        assert.equal('tools' in written, false, JSON.stringify(capabilities));
        assert.equal(written.app_version, VERSION);
    }
});

check('skips entries that are not tools instead of failing the registration', async () => {
    const { written } = await register({ tools: [null, 'x', { description: 'no name' }, tool('read_file')] });
    assert.deepEqual(written.tools.map((entry) => entry.name), ['read_file']);
});

check('a list too large for the backend is left out, so the registration write cannot be refused', async () => {
    const tooMany = Array.from({ length: 201 }, (_, index) => tool(`tool_${index}`));
    const tooBig = [tool('read_file', { description: 'x'.repeat(600 * 1024) })];
    for (const tools of [tooMany, tooBig]) {
        const { written } = await register({ tools });
        assert.equal('tools' in written, false);
        assert.equal(written.app_version, VERSION);
    }
    const { written } = await register({ tools: Array.from({ length: 200 }, (_, index) => tool(`tool_${index}`)) });
    assert.equal(written.tools.length, 200, 'exactly the limit is published');
});

let failed = 0;
for (const [name, fn] of checks) {
    try {
        await fn();
        console.log(`PASS ${name}`);
    } catch (error) {
        failed++;
        console.error(`FAIL ${name}\n${error.stack ?? error}`);
    }
}
if (failed) {
    console.error(`${failed} of ${checks.length} checks failed`);
    process.exit(1);
}
console.log(`PASS remote capabilities tools: ${checks.length} checks`);

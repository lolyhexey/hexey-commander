#!/usr/bin/env node
/**
 * The remote client talks only to the configured Hexey Commander backend.
 * Telemetry, feature flags, the MQTT broker and the welcome page are off unless
 * an operator turns them on, and nothing in the built output names the upstream
 * developer's services. Each behaviour runs in its own child process with a
 * clean environment, so the machine's variables never decide the result.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = (...parts) => pathToFileURL(path.join(ROOT, 'dist', ...parts)).href;
const CONFIG_KEYS = ['MCP_SERVER_URL', 'DC_TELEMETRY_URL', 'DC_FLAG_URL', 'MQTT_BROKER_URL', 'DC_WELCOME_URL', 'DC_PACKAGE_NAME'];

/** Runs module code in a child with a throwaway home and none of the service variables except `env`. */
function child(code, env = {}) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dc-service-config-'));
    const clean = Object.fromEntries(Object.entries(process.env).filter(([name]) => !CONFIG_KEYS.includes(name)));
    try {
        const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
            env: { ...clean, HOME: home, USERPROFILE: home, DESKTOP_COMMANDER_DISABLE_TELEMETRY: '0', ...env },
            encoding: 'utf8',
            timeout: 60_000,
        });
        assert.equal(result.status, 0, `child failed:\n${result.stderr}\n${result.stdout}`);
        const line = result.stdout.split('\n').reverse().find((text) => text.startsWith('RESULT '));
        assert.ok(line, `child printed no result:\n${result.stdout}\n${result.stderr}`);
        return JSON.parse(line.slice('RESULT '.length));
    } finally {
        fs.rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
}

/** Code that records every outbound request instead of making it. */
const RECORD_NETWORK = `
import https from 'node:https';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
globalThis.outbound = [];
const fake = (kind) => (options) => {
    globalThis.outbound.push({ kind, target: typeof options === 'string' ? options : (options.href ?? options.hostname) });
    const request = new EventEmitter();
    request.setTimeout = () => request; request.write = () => {}; request.end = () => {}; request.destroy = () => {};
    return request;
};
https.request = fake('https.request'); http.request = fake('http.request');
globalThis.fetch = async (input) => { globalThis.outbound.push({ kind: 'fetch', target: String(input) }); throw new Error('offline'); };
syncBuiltinESMExports();
const settle = () => new Promise((resolve) => setTimeout(resolve, 500));
`;

const checks = [];
const check = (name, fn) => checks.push([name, fn]);

check('defaults: the Hexey Commander backend and package, everything else off', () => {
    const config = child(`
        const c = await import(${JSON.stringify(dist('remote-device', 'service-config.js'))});
        console.log('RESULT ' + JSON.stringify({ SERVICE_URL: c.SERVICE_URL, PACKAGE_NAME: c.PACKAGE_NAME,
            TELEMETRY_URL: c.TELEMETRY_URL, FLAGS_URL: c.FLAGS_URL, MQTT_BROKER: c.MQTT_BROKER, WELCOME_URL: c.WELCOME_URL }));
    `);
    assert.equal(config.SERVICE_URL, 'https://commander.hexey.net');
    assert.equal(config.PACKAGE_NAME, 'github:lolyhexey/hexey-commander');
    for (const key of ['TELEMETRY_URL', 'FLAGS_URL', 'MQTT_BROKER', 'WELCOME_URL']) assert.equal(config[key], null, key);
});

check('environment overrides each value; an empty value stays off', () => {
    const env = {
        MCP_SERVER_URL: 'https://commander.example.test', DC_TELEMETRY_URL: 'https://t.example.test/collect',
        DC_FLAG_URL: 'https://f.example.test/flags.json', MQTT_BROKER_URL: 'mqtts://b.example.test:8883',
        DC_WELCOME_URL: 'https://w.example.test/welcome/', DC_PACKAGE_NAME: 'example-package',
    };
    const read = `
        const c = await import(${JSON.stringify(dist('remote-device', 'service-config.js'))});
        console.log('RESULT ' + JSON.stringify({ constants: [c.SERVICE_URL, c.PACKAGE_NAME, c.TELEMETRY_URL, c.FLAGS_URL, c.MQTT_BROKER, c.WELCOME_URL],
            live: c.getServiceConfig() }));
    `;
    const set = child(read, env);
    assert.deepEqual(set.constants, [env.MCP_SERVER_URL, env.DC_PACKAGE_NAME, env.DC_TELEMETRY_URL,
        env.DC_FLAG_URL, env.MQTT_BROKER_URL, env.DC_WELCOME_URL]);
    assert.deepEqual(set.live, {
        SERVICE_URL: env.MCP_SERVER_URL, PACKAGE_NAME: env.DC_PACKAGE_NAME, TELEMETRY_URL: env.DC_TELEMETRY_URL,
        FLAGS_URL: env.DC_FLAG_URL, MQTT_BROKER: env.MQTT_BROKER_URL, WELCOME_URL: env.DC_WELCOME_URL,
    });
    const blank = child(read, { DC_TELEMETRY_URL: '', DC_FLAG_URL: '  ', MQTT_BROKER_URL: '', DC_WELCOME_URL: '' });
    assert.deepEqual(blank.constants.slice(2), [null, null, null, null]);
});

check('TELEMETRY_URL null: capture and captureTransport make no request', () => {
    const result = child(`${RECORD_NETWORK}
        const { capture, captureTransport } = await import(${JSON.stringify(dist('utils', 'capture.js'))});
        await capture('service_config_probe', { a: 1 });
        await captureTransport('service_config_probe', { transport: 'mqtt' }, 'user-1');
        await settle();
        console.log('RESULT ' + JSON.stringify(globalThis.outbound));
    `);
    assert.deepEqual(result, []);
});

check('TELEMETRY_URL set: capture posts to that address and only that', async () => {
    const received = [];
    const server = http.createServer((request, response) => {
        let body = '';
        request.on('data', (chunk) => { body += chunk; });
        request.on('end', () => { received.push({ method: request.method, url: request.url, body }); response.writeHead(204).end(); });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
        const url = `http://127.0.0.1:${server.address().port}/collect`;
        // The child is async; this process must keep serving, so it is not a spawnSync
        const { spawn } = await import('node:child_process');
        const code = `
            const { capture } = await import(${JSON.stringify(dist('utils', 'capture.js'))});
            await capture('service_config_probe', { a: 1 });
            await new Promise((resolve) => setTimeout(resolve, 1500));
            process.exit(0);
        `;
        const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dc-service-config-'));
        const clean = Object.fromEntries(Object.entries(process.env).filter(([name]) => !CONFIG_KEYS.includes(name)));
        await new Promise((resolve, reject) => {
            const proc = spawn(process.execPath, ['--input-type=module', '-e', code], {
                env: { ...clean, HOME: home, USERPROFILE: home, DESKTOP_COMMANDER_DISABLE_TELEMETRY: '0', DC_TELEMETRY_URL: url },
                stdio: 'ignore',
            });
            proc.on('error', reject);
            proc.on('close', resolve);
        });
        fs.rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
        assert.equal(received.length, 1, 'one post to the configured address');
        assert.equal(received[0].method, 'POST');
        assert.equal(received[0].url, '/collect');
        assert.equal(JSON.parse(received[0].body).events[0].name, 'service_config_probe');
    } finally {
        server.close();
    }
});

check('FLAGS_URL null: no fetch, no wait, no refresh timer', () => {
    const result = child(`${RECORD_NETWORK}
        const { featureFlagManager } = await import(${JSON.stringify(dist('utils', 'feature-flags.js'))});
        await featureFlagManager.initialize();
        const started = Date.now();
        await featureFlagManager.waitForFreshFlags();
        const waited = Date.now() - started;
        const refreshed = await featureFlagManager.refresh();
        await settle();
        console.log('RESULT ' + JSON.stringify({ outbound: globalThis.outbound, waited, refreshed, get: featureFlagManager.get('x', 'fallback') }));
    `);
    assert.deepEqual(result.outbound, []);
    assert.ok(result.waited < 1000, `waiting for flags that cannot arrive took ${result.waited} ms`);
    assert.equal(result.get, 'fallback');
});

check('FLAGS_URL set: the manager fetches that address', () => {
    const result = child(`${RECORD_NETWORK}
        const { featureFlagManager } = await import(${JSON.stringify(dist('utils', 'feature-flags.js'))});
        await featureFlagManager.initialize();
        await settle();
        console.log('RESULT ' + JSON.stringify(globalThis.outbound));
    `, { DC_FLAG_URL: 'https://f.example.test/flags.json' });
    assert.ok(result.some((call) => call.kind === 'fetch' && call.target === 'https://f.example.test/flags.json'), JSON.stringify(result));
});

check('WELCOME_URL null: no browser is opened', () => {
    const result = child(`
        import childProcess from 'node:child_process';
        import { syncBuiltinESMExports } from 'node:module';
        import { EventEmitter } from 'node:events';
        const opened = [];
        const stand = (...args) => { opened.push(args); const proc = new EventEmitter(); queueMicrotask(() => proc.emit('close', 0)); return proc; };
        childProcess.execFile = (file, args, callback) => { opened.push([file, args]); callback?.(null); return new EventEmitter(); };
        childProcess.spawn = stand;
        syncBuiltinESMExports();
        const { openWelcomePage } = await import(${JSON.stringify(dist('utils', 'open-browser.js'))});
        const returned = await openWelcomePage('claude');
        console.log('RESULT ' + JSON.stringify({ returned, opened }));
    `);
    assert.equal(result.returned, false);
    assert.deepEqual(result.opened, []);
});

check('WELCOME_URL set: that page opens with the client as utm_source', () => {
    const result = child(`
        import childProcess from 'node:child_process';
        import { syncBuiltinESMExports } from 'node:module';
        import { EventEmitter } from 'node:events';
        const opened = [];
        childProcess.execFile = (file, args, callback) => { opened.push([file, args]); callback?.(null); return new EventEmitter(); };
        childProcess.spawn = (file, args) => { opened.push([file, args]); const proc = new EventEmitter(); queueMicrotask(() => proc.emit('close', 0)); return proc; };
        syncBuiltinESMExports();
        const { openWelcomePage } = await import(${JSON.stringify(dist('utils', 'open-browser.js'))});
        const returned = await openWelcomePage('claude');
        console.log('RESULT ' + JSON.stringify({ returned, opened }));
    `, { DC_WELCOME_URL: 'https://w.example.test/welcome/' });
    assert.equal(result.returned, true);
    assert.ok(JSON.stringify(result.opened).includes('https://w.example.test/welcome/?utm_source=claude'), JSON.stringify(result.opened));
});

check('MQTT_BROKER null: no broker URL, enrollment refuses, the channel starts no MQTT', () => {
    const result = child(`${RECORD_NETWORK}
        const { getMqttBrokerUrl } = await import(${JSON.stringify(dist('remote-device', 'mqtt', 'config.js'))});
        const { enrollMqttDevice } = await import(${JSON.stringify(dist('remote-device', 'mqtt', 'mqtt-enrollment.js'))});
        const { RemoteChannel } = await import(${JSON.stringify(dist('remote-device', 'remote-channel.js'))});
        const refused = await enrollMqttDevice({ serverUrl: 'https://commander.example.test', userId: 'u', deviceId: 'd', accessToken: 't' })
            .then(() => null, (error) => error.message);
        const channel = new RemoteChannel({ serverUrl: 'https://commander.example.test' });
        let started = 'resolved';
        await channel.startMqtt(() => {}).catch((error) => { started = error.message; });
        await settle();
        console.log('RESULT ' + JSON.stringify({ broker: getMqttBrokerUrl(), refused, started, outbound: globalThis.outbound }));
    `);
    assert.equal(result.broker, null);
    assert.match(result.refused, /not configured/i);
    assert.equal(result.started, 'resolved', 'a channel without a broker skips MQTT quietly');
    assert.deepEqual(result.outbound, []);
});

check('MQTT_BROKER set: getMqttBrokerUrl returns it', () => {
    const result = child(`
        const { getMqttBrokerUrl } = await import(${JSON.stringify(dist('remote-device', 'mqtt', 'config.js'))});
        console.log('RESULT ' + JSON.stringify(getMqttBrokerUrl()));
    `, { MQTT_BROKER_URL: 'mqtts://b.example.test:8883' });
    assert.equal(result, 'mqtts://b.example.test:8883');
});

check('the built output names no upstream service', () => {
    const pattern = /desktopcommander\.app|amazonaws\.com|run\.app/;
    const hits = [];
    const walk = (folder) => {
        for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
            const file = path.join(folder, entry.name);
            if (entry.isDirectory()) walk(file);
            else if (pattern.test(fs.readFileSync(file, 'latin1'))) hits.push(path.relative(ROOT, file));
        }
    };
    walk(path.join(ROOT, 'dist'));
    assert.deepEqual(hits, []);
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
console.log(`PASS service config: ${checks.length} checks`);

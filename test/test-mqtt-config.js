#!/usr/bin/env node
import assert from 'node:assert/strict';
import { getMqttBrokerUrl } from '../dist/remote-device/mqtt/config.js';
import { createMqttConfig } from '../dist/remote-device/mqtt/mqtt-transport.js';

const configuredBroker = 'mqtts://broker.example.test:8883';
const originalBroker = process.env.MQTT_BROKER_URL;
try {
    delete process.env.MQTT_BROKER_URL;
    assert.equal(getMqttBrokerUrl(), null, 'no broker unless one is configured');
    process.env.MQTT_BROKER_URL = '';
    assert.equal(getMqttBrokerUrl(), null, 'an empty value is no broker');
    process.env.MQTT_BROKER_URL = 'mqtts://custom.example.test:8883';
    assert.equal(getMqttBrokerUrl(), process.env.MQTT_BROKER_URL);
} finally {
    if (originalBroker === undefined) delete process.env.MQTT_BROKER_URL;
    else process.env.MQTT_BROKER_URL = originalBroker;
}

const credentials = { url: configuredBroker, cert: 'fixture-cert', key: 'fixture-key' };
const config = createMqttConfig(credentials);
assert.equal(config.url, credentials.url);
assert.equal(config.options.cert, credentials.cert);
assert.equal(config.options.key, credentials.key);
assert.equal(config.options.rejectUnauthorized, true);
assert.equal(config.options.ca, undefined, 'broker verification uses the system trust store');
for (const url of ['mqtt://127.0.0.1:1883', 'mqtt://public.example.test', 'wss://example.test']) {
    assert.throws(() => createMqttConfig({ ...credentials, url }), /must use mqtts/);
}
for (const url of ['invalid', 'mqtts://user:secret@example.test', 'mqtts://example.test/path',
    'mqtts://example.test?secret=yes', 'mqtts://example.test#fragment']) {
    assert.throws(() => createMqttConfig({ ...credentials, url }), /valid URL|credentials, paths, or query/);
}
for (const patch of [{ cert: '' }, { key: '' }]) {
    assert.throws(() => createMqttConfig({ ...credentials, ...patch }), /enrolled device/);
}
console.log('PASS MQTT config: no default broker, environment override, mandatory TLS and enrolled credentials');

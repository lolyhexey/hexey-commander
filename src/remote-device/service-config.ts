/**
 * Where the client sends anything. This is the only place that names a service:
 * the rest of the code asks here, so a build never carries an address it does not
 * mean to call.
 *
 * The remote device talks to one backend, SERVICE_URL. Everything else is off
 * until an operator names an address:
 *
 *   MCP_SERVER_URL    the backend (default: the placeholder below, which never resolves)
 *   DC_TELEMETRY_URL  usage events           (default: none, nothing is sent)
 *   DC_FLAG_URL       remote feature flags   (default: none, nothing is fetched)
 *   MQTT_BROKER_URL   the MQTT broker        (default: none, no enrollment, no connection)
 *   DC_WELCOME_URL    first-run welcome page (default: none, no browser is opened)
 *   DC_PACKAGE_NAME   the npm package users run (default: the placeholder below)
 *
 * An empty or blank value counts as unset. Set a real backend address and
 * package name before publishing.
 */

/** The Hexey Commander backend. */
export const DEFAULT_SERVICE_URL = 'https://commander.hexey.net';
/** The npm package users run with npx. */
export const DEFAULT_PACKAGE_NAME = '@hexey/hexey-commander';

export interface ServiceConfig {
    SERVICE_URL: string;
    PACKAGE_NAME: string;
    TELEMETRY_URL: string | null;
    FLAGS_URL: string | null;
    MQTT_BROKER: string | null;
    WELCOME_URL: string | null;
}

function valueOf(env: NodeJS.ProcessEnv, name: string): string | null {
    const value = env[name]?.trim();
    return value ? value : null;
}

/** The configuration for this environment, read now. */
export function getServiceConfig(env: NodeJS.ProcessEnv = process.env): ServiceConfig {
    return {
        SERVICE_URL: valueOf(env, 'MCP_SERVER_URL') ?? DEFAULT_SERVICE_URL,
        PACKAGE_NAME: valueOf(env, 'DC_PACKAGE_NAME') ?? DEFAULT_PACKAGE_NAME,
        TELEMETRY_URL: valueOf(env, 'DC_TELEMETRY_URL'),
        FLAGS_URL: valueOf(env, 'DC_FLAG_URL'),
        MQTT_BROKER: valueOf(env, 'MQTT_BROKER_URL'),
        WELCOME_URL: valueOf(env, 'DC_WELCOME_URL'),
    };
}

// The environment as this process started. Code that must honour a variable set
// later (a test, a launcher) calls getServiceConfig() instead.
const startup = getServiceConfig();
export const SERVICE_URL = startup.SERVICE_URL;
export const PACKAGE_NAME = startup.PACKAGE_NAME;
export const TELEMETRY_URL = startup.TELEMETRY_URL;
export const FLAGS_URL = startup.FLAGS_URL;
export const MQTT_BROKER = startup.MQTT_BROKER;
export const WELCOME_URL = startup.WELCOME_URL;

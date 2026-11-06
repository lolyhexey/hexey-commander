import { getServiceConfig } from '../service-config.js';

/** The MQTT broker to enroll with, or null when none is configured (MQTT is then off). */
export function getMqttBrokerUrl(): string | null {
    return getServiceConfig().MQTT_BROKER;
}

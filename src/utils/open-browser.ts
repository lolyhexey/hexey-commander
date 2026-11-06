import { execFile, spawn } from 'child_process';
import os from 'os';
import { logToStderr } from './logger.js';
import { resolveProgramPath } from './shell.js';
import { getServiceConfig } from '../remote-device/service-config.js';

/**
 * Open a URL in the default browser (cross-platform)
 * Uses execFile/spawn with args array to avoid shell injection
 */
export async function openBrowser(url: string): Promise<void> {
  const platform = os.platform();
  
  return new Promise((resolve, reject) => {
    const callback = (error: Error | null) => {
      if (error) {
        logToStderr('error', `Failed to open browser: ${error.message}`);
        reject(error);
      } else {
        logToStderr('info', `Opened browser to: ${url}`);
        resolve();
      }
    };

    switch (platform) {
      case 'darwin':
        execFile('open', [url], callback);
        break;
      case 'win32':
        // Windows 'start' is a shell builtin, use spawn with shell but pass URL as separate arg
        spawn(resolveProgramPath('cmd'), ['/c', 'start', '', url], { shell: false, windowsHide: true }).on('close', (code) => {
          code === 0 ? resolve() : reject(new Error(`Exit code ${code}`));
        });
        break;
      default:
        execFile('xdg-open', [url], callback);
        break;
    }
  });
}

/**
 * Open the welcome page, if one is configured (DC_WELCOME_URL; none by default).
 * Returns whether a page was opened.
 */
export async function openWelcomePage(clientName?: string): Promise<boolean> {
  const welcomeUrl = getServiceConfig().WELCOME_URL;
  if (!welcomeUrl) return false;
  let url: URL;
  try {
    url = new URL(welcomeUrl);
  } catch {
    logToStderr('warning', 'DC_WELCOME_URL is not a valid URL; no welcome page opened');
    return false;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
  if (clientName) url.searchParams.set('utm_source', clientName);
  await openBrowser(url.href);
  return true;
}

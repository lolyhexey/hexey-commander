import { existsSync, chmodSync } from 'fs';
import { spawnSync } from 'child_process';
import path from 'path';
import os from 'os';
import { resolveShellPath } from './shell.js';

let cachedRgPath: string | null = null;

/** Whether `rg --version` runs and reports ripgrep. */
export function ripgrepRuns(rgPath: string): boolean {
  try {
    const r = spawnSync(rgPath, ['--version'], { encoding: 'utf8', timeout: 10_000, windowsHide: true });
    return r.status === 0 && /ripgrep/i.test(r.stdout ?? '');
  } catch {
    return false;
  }
}

/**
 * Resolve ripgrep binary path with multiple fallback strategies
 * This handles cases where @vscode/ripgrep postinstall fails in npx environments
 */
export async function getRipgrepPath(): Promise<string> {
  if (cachedRgPath) {
    return cachedRgPath;
  }

  // Strategy 1: Try @vscode/ripgrep package
  try {
    const { rgPath } = await import('@vscode/ripgrep');
    if (existsSync(rgPath)) {
      // Ensure executable permissions on Unix systems
      if (process.platform !== 'win32') {
        try {
          chmodSync(rgPath, 0o755);
        } catch (e) {
          // Ignore chmod errors - might not have write access
        }
      }
      // A copy that is present but cannot run (a damaged download, or a build
      // for another platform) would fail every search, so a ripgrep found by
      // the fallbacks below is preferred. With none, it is still returned, so
      // searches fail as before and log why ripgrep could not start.
      if (ripgrepRuns(rgPath)) {
        cachedRgPath = rgPath;
        return rgPath;
      }
      const other = findOtherRipgrep();
      if (other) {
        console.error(`[ripgrep] ${rgPath} does not run; using ${other}. Reinstall @vscode/ripgrep to fix the bundled copy.`);
        cachedRgPath = other;
        return other;
      }
      return rgPath;
    }
  } catch (e) {
    // @vscode/ripgrep import or binary resolution failed, continue to fallbacks
  }

  // Strategies 2 and 3: a ripgrep installed on this computer
  const other = findOtherRipgrep();
  if (other) {
    cachedRgPath = other;
    return other;
  }

  // No ripgrep found - provide helpful error message
  throw new Error(
    'ripgrep binary not found. Desktop Commander requires ripgrep to perform searches. ' +
    'Please install ripgrep:\n' +
    '  macOS: brew install ripgrep\n' +
    '  Linux: See https://github.com/BurntSushi/ripgrep#installation\n' +
    '  Windows: choco install ripgrep or download from https://github.com/BurntSushi/ripgrep/releases'
  );
}

/** A ripgrep installed outside @vscode/ripgrep: on PATH, or in a usual folder. */
function findOtherRipgrep(): string | undefined {
  // System ripgrep on PATH (never the working folder, which
  // 'where' searched first on Windows)
  const systemRg = resolveShellPath(process.platform === 'win32' ? 'rg.exe' : 'rg');
  if (systemRg) return systemRg;

  // Common installation paths
  const commonPaths: string[] = [];

  if (process.platform === 'win32') {
    // Windows' own Program Files folders, which aren't always on C:
    commonPaths.push(
      path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Ripgrep', 'rg.exe'),
      path.join(process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Ripgrep', 'rg.exe'),
      path.join(os.homedir(), 'scoop', 'apps', 'ripgrep', 'current', 'rg.exe'),
      path.join(os.homedir(), '.cargo', 'bin', 'rg.exe')
    );
  } else {
    commonPaths.push(
      '/usr/local/bin/rg',
      '/usr/bin/rg',
      path.join(os.homedir(), '.cargo', 'bin', 'rg'),
      '/opt/homebrew/bin/rg', // Apple Silicon Homebrew
      ...(process.env.PREFIX ? [path.join(process.env.PREFIX, 'bin', 'rg')] : []) // Termux
    );
  }

  for (const possiblePath of commonPaths) {
    if (existsSync(possiblePath)) return possiblePath;
  }
  return undefined;
}

/**
 * Clear the cached ripgrep path (useful for testing)
 */
export function clearRipgrepCache(): void {
  cachedRgPath = null;
}

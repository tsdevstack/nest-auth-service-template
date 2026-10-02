import { execFileSync } from 'node:child_process';

/** Runs a docker CLI command and returns its stdout (throws on failure) */
export function runDocker(...args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf-8', stdio: 'pipe' });
}

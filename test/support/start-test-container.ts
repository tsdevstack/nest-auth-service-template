import { randomBytes } from 'node:crypto';
import { runDocker } from './run-docker';

export interface TestContainer {
  name: string;
  port: number;
  /** Removes the container (safe to call twice) */
  remove: () => void;
}

/**
 * Starts a throwaway container (`--rm`, unique name, the given container
 * port published on an ephemeral 127.0.0.1 port) and waits until `isReady`
 * (run with `docker exec`) succeeds.
 *
 * @param prefix - Name prefix, for finding leftovers
 * @param runArgs - Everything after `docker run -d --rm --name <n> -p <p>`
 * @param containerPort - Port to publish, for example 6379
 * @param readyCommand - Command run in the container until it exits 0
 */
export async function startTestContainer(
  prefix: string,
  runArgs: string[],
  containerPort: number,
  readyCommand: string[],
): Promise<TestContainer> {
  const name = `${prefix}-${process.pid}-${randomBytes(3).toString('hex')}`;
  const remove = (): void => {
    try {
      runDocker('rm', '-f', name);
    } catch {
      // already gone
    }
  };

  runDocker(
    'run',
    '-d',
    '--rm',
    '--name',
    name,
    '-p',
    `127.0.0.1::${containerPort}`,
    ...runArgs,
  );

  try {
    const port = Number(
      runDocker('port', name, `${containerPort}/tcp`)
        .trim()
        .split('\n')[0]
        .split(':')
        .pop(),
    );
    const deadline = Date.now() + 60_000;
    for (;;) {
      try {
        runDocker('exec', name, ...readyCommand);
        break;
      } catch {
        if (Date.now() > deadline) {
          throw new Error(`${name} did not become ready`);
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    return { name, port, remove };
  } catch (error) {
    remove();
    throw error;
  }
}

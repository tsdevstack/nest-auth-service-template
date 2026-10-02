import { runDocker } from './run-docker';

/** Whether the Docker daemon answers (Docker-backed suites skip otherwise) */
export function isDockerAvailable(): boolean {
  try {
    runDocker('info', '--format', '{{.ServerVersion}}');
    return true;
  } catch {
    return false;
  }
}

import type { LoggerService, RedisService } from '@tsdevstack/nest-common';
import type { PrismaService } from '../prisma/prisma.service';
import { ApiKeyIndexService } from './api-key-index.service';

/**
 * Lifecycle and error handling. Redis behavior (NX, TTLs, undo, rebuild,
 * interleavings) is covered against a real Redis in api-keys.redis.spec.ts.
 */
describe('ApiKeyIndexService', () => {
  let readyListener: (() => void) | undefined;
  let unsubscribe: jest.Mock;
  let redis: { onReady: jest.Mock; isReady: jest.Mock; getClient: jest.Mock };
  let logger: {
    child: () => unknown;
    info: jest.Mock;
    warn: jest.Mock;
    error: jest.Mock;
  };
  let service: ApiKeyIndexService;

  beforeEach(() => {
    unsubscribe = jest.fn();
    redis = {
      onReady: jest.fn((listener: () => void) => {
        readyListener = listener;
        return unsubscribe;
      }),
      isReady: jest.fn().mockReturnValue(true),
      getClient: jest.fn(),
    };
    logger = {
      child: () => logger,
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    service = new ApiKeyIndexService(
      redis as unknown as RedisService,
      {} as PrismaService,
      logger as unknown as LoggerService,
    );
  });

  it('rebuilds when Redis becomes ready and stops listening on shutdown', () => {
    const rebuild = jest.spyOn(service, 'rebuildIfMissing').mockResolvedValue({
      status: 'present',
      recordsWritten: 0,
      countersSeeded: 0,
    });

    service.onModuleInit();
    readyListener?.();
    expect(rebuild).toHaveBeenCalledWith('redis-ready');

    service.onModuleDestroy();
    expect(unsubscribe).toHaveBeenCalled();
  });

  it('rebuilds at startup when Redis is already ready', () => {
    const rebuild = jest.spyOn(service, 'rebuildIfMissing').mockResolvedValue({
      status: 'present',
      recordsWritten: 0,
      countersSeeded: 0,
    });
    service.onApplicationBootstrap();
    expect(rebuild).toHaveBeenCalledWith('startup');
  });

  it('waits for the ready event when Redis is not ready at startup', () => {
    redis.isReady.mockReturnValue(false);
    const rebuild = jest.spyOn(service, 'rebuildIfMissing');
    service.onApplicationBootstrap();
    expect(rebuild).not.toHaveBeenCalled();
  });

  it('logs a failed background rebuild instead of crashing', async () => {
    jest
      .spyOn(service, 'rebuildIfMissing')
      .mockRejectedValue(new Error('Connection is closed.'));
    service.onApplicationBootstrap();
    await new Promise((resolve) => setImmediate(resolve));
    expect(logger.error).toHaveBeenCalledWith(
      'API key index rebuild failed',
      expect.any(Error),
      { trigger: 'startup' },
    );
  });

  it('never throws from an undo; a failure is logged as drift', async () => {
    redis.getClient.mockReturnValue({
      evalsha: jest.fn().mockRejectedValue(new Error('Connection is closed.')),
    });
    await expect(
      service.undoRecordWrite({
        key: 'apikey:{x}:rec',
        written: 'a',
        previous: null,
        previousExpireAtMs: null,
      }),
    ).resolves.toBe(false);
    expect(logger.error).toHaveBeenCalled();
  });
});

import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from './jwt.service';
import { SecretsService } from '@tsdevstack/nest-common';
import * as jose from 'jose';

describe('JwtService', () => {
  let service: JwtService;
  let mockSecretsService: jest.Mocked<SecretsService>;

  // Test RSA key pair (2048-bit for testing)
  let testPrivateKeyPem: string;
  let testPublicKeyPem: string;
  const testKeyId = 'test-key-2024-01-01';

  beforeAll(async () => {
    // Generate a test RSA key pair
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256', {
      modulusLength: 2048,
    });
    testPrivateKeyPem = await jose.exportPKCS8(privateKey);
    testPublicKeyPem = await jose.exportSPKI(publicKey);
  });

  beforeEach(async () => {
    mockSecretsService = {
      get: jest.fn(),
    } as unknown as jest.Mocked<SecretsService>;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtService,
        { provide: SecretsService, useValue: mockSecretsService },
      ],
    }).compile();

    service = module.get<JwtService>(JwtService);
  });

  describe('onModuleInit', () => {
    it('should load current keys from secrets', async () => {
      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem) // JWT_PRIVATE_KEY_CURRENT
        .mockResolvedValueOnce(testPublicKeyPem) // JWT_PUBLIC_KEY_CURRENT
        .mockResolvedValueOnce(testKeyId) // JWT_KEY_ID_CURRENT
        .mockRejectedValueOnce(new Error('Not found')); // JWT_PRIVATE_KEY_PREVIOUS (optional)

      await service.onModuleInit();

      const calls = mockSecretsService.get.mock.calls.map(
        (c: unknown[]) => c[0],
      );
      expect(calls).toContain('JWT_PRIVATE_KEY_CURRENT');
      expect(calls).toContain('JWT_PUBLIC_KEY_CURRENT');
      expect(calls).toContain('JWT_KEY_ID_CURRENT');
    });

    it('should throw error if current keys are missing', async () => {
      mockSecretsService.get.mockRejectedValue(new Error('Secret not found'));

      await expect(service.onModuleInit()).rejects.toThrow();
    });

    it('should load previous keys when available', async () => {
      // Generate a second key pair for previous keys
      const { privateKey: prevPrivate, publicKey: prevPublic } =
        await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const prevPrivatePem = await jose.exportPKCS8(prevPrivate);
      const prevPublicPem = await jose.exportSPKI(prevPublic);
      const prevKeyId = 'prev-key-2023-12-01';

      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem) // JWT_PRIVATE_KEY_CURRENT
        .mockResolvedValueOnce(testPublicKeyPem) // JWT_PUBLIC_KEY_CURRENT
        .mockResolvedValueOnce(testKeyId) // JWT_KEY_ID_CURRENT
        .mockResolvedValueOnce(prevPrivatePem) // JWT_PRIVATE_KEY_PREVIOUS
        .mockResolvedValueOnce(prevPublicPem) // JWT_PUBLIC_KEY_PREVIOUS
        .mockResolvedValueOnce(prevKeyId); // JWT_KEY_ID_PREVIOUS

      await service.onModuleInit();

      // Should have loaded both current and previous keys
      expect(mockSecretsService.get.mock.calls).toHaveLength(6);
    });

    it('should continue without previous keys when they are not available', async () => {
      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem)
        .mockResolvedValueOnce(testPublicKeyPem)
        .mockResolvedValueOnce(testKeyId)
        .mockRejectedValueOnce(new Error('Not found')); // Previous keys not found

      await service.onModuleInit();

      // Should not throw, just skip previous keys
      expect(service.getCurrentKeyId()).toBe(testKeyId);
    });
  });

  describe('sign', () => {
    beforeEach(async () => {
      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem)
        .mockResolvedValueOnce(testPublicKeyPem)
        .mockResolvedValueOnce(testKeyId)
        .mockRejectedValueOnce(new Error('Not found'));

      await service.onModuleInit();
    });

    it('should sign a JWT with RS256 algorithm', async () => {
      const payload = {
        sub: 'user-123',
        email: 'test@example.com',
        role: 'USER',
      };

      const token = await service.sign(payload, '1h');

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should include correct header with kid', async () => {
      const payload = { sub: 'user-123' };

      const token = await service.sign(payload, '1h');

      // Decode header
      const [headerB64] = token.split('.');
      const header = JSON.parse(
        Buffer.from(headerB64, 'base64url').toString('utf8'),
      ) as { alg: string; typ: string; kid: string };

      expect(header.alg).toBe('RS256');
      expect(header.typ).toBe('JWT');
      expect(header.kid).toBe(testKeyId);
    });

    it('should include iat and exp claims', async () => {
      const payload = { sub: 'user-123' };

      const token = await service.sign(payload, '1h');

      // Decode payload
      const [, payloadB64] = token.split('.');
      const decodedPayload = JSON.parse(
        Buffer.from(payloadB64, 'base64url').toString('utf8'),
      ) as { iat: number; exp: number };

      expect(decodedPayload.iat).toBeDefined();
      expect(decodedPayload.exp).toBeDefined();
      expect(decodedPayload.exp).toBeGreaterThan(decodedPayload.iat);
    });

    it('should produce verifiable tokens', async () => {
      const payload = {
        sub: 'user-123',
        email: 'test@example.com',
      };

      const token = await service.sign(payload, '1h');

      // Verify the token using the public key
      const publicKey = await jose.importSPKI(testPublicKeyPem, 'RS256');
      const { payload: verified } = await jose.jwtVerify(token, publicKey);

      expect(verified.sub).toBe('user-123');
      expect(verified.email).toBe('test@example.com');
    });

    it('should throw error if keys are not loaded', async () => {
      // Create a new service instance without initializing
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          JwtService,
          { provide: SecretsService, useValue: mockSecretsService },
        ],
      }).compile();
      const uninitializedService = module.get<JwtService>(JwtService);

      await expect(
        uninitializedService.sign({ sub: 'test' }, '1h'),
      ).rejects.toThrow('RSA keys not loaded');
    });
  });

  describe('getCurrentKeyId', () => {
    it('should return the current key ID', async () => {
      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem)
        .mockResolvedValueOnce(testPublicKeyPem)
        .mockResolvedValueOnce(testKeyId)
        .mockRejectedValueOnce(new Error('Not found'));

      await service.onModuleInit();

      expect(service.getCurrentKeyId()).toBe(testKeyId);
    });

    it('should throw error if keys are not loaded', () => {
      expect(() => service.getCurrentKeyId()).toThrow('RSA keys not loaded');
    });
  });

  describe('getJWKS', () => {
    it('should return JWKS with current key', async () => {
      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem)
        .mockResolvedValueOnce(testPublicKeyPem)
        .mockResolvedValueOnce(testKeyId)
        .mockRejectedValueOnce(new Error('Not found'));

      await service.onModuleInit();

      const jwks = await service.getJWKS();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].kty).toBe('RSA');
      expect(jwks.keys[0].use).toBe('sig');
      expect(jwks.keys[0].alg).toBe('RS256');
      expect(jwks.keys[0].kid).toBe(testKeyId);
      expect(jwks.keys[0].n).toBeDefined(); // RSA modulus
      expect(jwks.keys[0].e).toBeDefined(); // RSA exponent
    });

    it('should include previous key when available', async () => {
      const { privateKey: prevPrivate, publicKey: prevPublic } =
        await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const prevPrivatePem = await jose.exportPKCS8(prevPrivate);
      const prevPublicPem = await jose.exportSPKI(prevPublic);
      const prevKeyId = 'prev-key-2023-12-01';

      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem)
        .mockResolvedValueOnce(testPublicKeyPem)
        .mockResolvedValueOnce(testKeyId)
        .mockResolvedValueOnce(prevPrivatePem)
        .mockResolvedValueOnce(prevPublicPem)
        .mockResolvedValueOnce(prevKeyId);

      await service.onModuleInit();

      const jwks = await service.getJWKS();

      expect(jwks.keys).toHaveLength(2);
      expect(jwks.keys[0].kid).toBe(testKeyId);
      expect(jwks.keys[1].kid).toBe(prevKeyId);
    });

    it('should throw error if keys are not loaded', async () => {
      await expect(service.getJWKS()).rejects.toThrow('RSA keys not loaded');
    });

    it('should return keys usable for JWT verification', async () => {
      mockSecretsService.get
        .mockResolvedValueOnce(testPrivateKeyPem)
        .mockResolvedValueOnce(testPublicKeyPem)
        .mockResolvedValueOnce(testKeyId)
        .mockRejectedValueOnce(new Error('Not found'));

      await service.onModuleInit();

      // Sign a token
      const token = await service.sign({ sub: 'user-123' }, '1h');

      // Get JWKS
      const jwks = await service.getJWKS();

      // Verify token using JWKS
      const jwk = jwks.keys.find((k) => k.kid === testKeyId);
      expect(jwk).toBeDefined();

      const publicKey = await jose.importJWK(jwk!, 'RS256');
      const { payload } = await jose.jwtVerify(token, publicKey);

      expect(payload.sub).toBe('user-123');
    });
  });
});

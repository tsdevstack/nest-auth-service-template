import { Test, TestingModule } from '@nestjs/testing';
import { JwksController } from './jwks.controller';
import { JwtService } from './jwt.service';
import type { Request } from 'express';

describe('JwksController', () => {
  let controller: JwksController;
  let mockJwtService: jest.Mocked<JwtService>;

  const mockJWKS = {
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        kid: 'test-key-2024-01-01',
        n: 'mock-modulus',
        e: 'AQAB',
      },
    ],
  };

  beforeEach(async () => {
    mockJwtService = {
      getJWKS: jest.fn().mockResolvedValue(mockJWKS),
    } as unknown as jest.Mocked<JwtService>;

    const module: TestingModule = await Test.createTestingModule({
      controllers: [JwksController],
      providers: [{ provide: JwtService, useValue: mockJwtService }],
    }).compile();

    controller = module.get<JwksController>(JwksController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getJWKS', () => {
    it('should return JWKS from JwtService', async () => {
      const result = await controller.getJWKS();

      expect(result).toEqual(mockJWKS);
      expect(mockJwtService.getJWKS.mock.calls).toHaveLength(1);
    });

    it('should include all required JWK properties', async () => {
      const result = await controller.getJWKS();

      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]).toHaveProperty('kty', 'RSA');
      expect(result.keys[0]).toHaveProperty('use', 'sig');
      expect(result.keys[0]).toHaveProperty('alg', 'RS256');
      expect(result.keys[0]).toHaveProperty('kid');
      expect(result.keys[0]).toHaveProperty('n');
      expect(result.keys[0]).toHaveProperty('e');
    });
  });

  describe('getOpenIdConfiguration', () => {
    const createMockRequest = (
      protocol: string,
      host: string,
      forwardedProto?: string,
    ): Request => {
      return {
        protocol,
        get: jest.fn((header: string) => {
          if (header === 'host') return host;
          if (header === 'x-forwarded-proto') return forwardedProto;
          return undefined;
        }),
      } as unknown as Request;
    };

    it('should return OpenID configuration with correct URLs', () => {
      const mockReq = createMockRequest('https', 'auth.example.com');

      const result = controller.getOpenIdConfiguration(mockReq);

      expect(result.issuer).toBe('auth-service');
      expect(result.jwks_uri).toBe(
        'https://auth.example.com/auth/.well-known/jwks.json',
      );
      expect(result.authorization_endpoint).toBe(
        'https://auth.example.com/auth/v1/auth/login',
      );
      expect(result.token_endpoint).toBe(
        'https://auth.example.com/auth/v1/auth/refresh-token',
      );
    });

    it('should use x-forwarded-proto header when present', () => {
      // Cloud Run sends http internally but x-forwarded-proto: https
      const mockReq = createMockRequest('http', 'auth.example.com', 'https');

      const result = controller.getOpenIdConfiguration(mockReq);

      expect(result.jwks_uri).toBe(
        'https://auth.example.com/auth/.well-known/jwks.json',
      );
    });

    it('should fall back to request protocol when x-forwarded-proto not set', () => {
      const mockReq = createMockRequest('http', 'localhost:3001');

      const result = controller.getOpenIdConfiguration(mockReq);

      expect(result.jwks_uri).toBe(
        'http://localhost:3001/auth/.well-known/jwks.json',
      );
    });

    it('should include required OpenID Connect fields', () => {
      const mockReq = createMockRequest('https', 'auth.example.com');

      const result = controller.getOpenIdConfiguration(mockReq);

      expect(result.response_types_supported).toEqual(['id_token']);
      expect(result.subject_types_supported).toEqual(['public']);
      expect(result.id_token_signing_alg_values_supported).toEqual(['RS256']);
    });

    it('should work with localhost for local development', () => {
      const mockReq = createMockRequest('http', 'localhost:3001');

      const result = controller.getOpenIdConfiguration(mockReq);

      expect(result.jwks_uri).toBe(
        'http://localhost:3001/auth/.well-known/jwks.json',
      );
      expect(result.authorization_endpoint).toBe(
        'http://localhost:3001/auth/v1/auth/login',
      );
      expect(result.token_endpoint).toBe(
        'http://localhost:3001/auth/v1/auth/refresh-token',
      );
    });

    it('should handle Kong gateway proxy paths', () => {
      // When accessed through Kong, host might be the gateway
      const mockReq = createMockRequest('http', 'localhost:8000', undefined);

      const result = controller.getOpenIdConfiguration(mockReq);

      expect(result.jwks_uri).toContain('localhost:8000');
    });
  });
});

import { Controller, Get, Header, Req } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Public } from '@tsdevstack/nest-common';
import { JwtService } from './jwt.service';
import type { Request } from 'express';

@ApiTags('JWKS')
@Controller('.well-known')
export class JwksController {
  constructor(private readonly jwtService: JwtService) {}

  @Get('jwks.json')
  @Public()
  @Header('Cache-Control', 'public, max-age=300')
  @ApiOperation({
    summary: 'Get JSON Web Key Set (JWKS)',
    description:
      'Returns the public keys used to verify JWT signatures. Kong Gateway uses this endpoint to validate JWT tokens.',
  })
  @ApiResponse({
    status: 200,
    description: 'JWKS in standard format',
    schema: {
      type: 'object',
      properties: {
        keys: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              kty: { type: 'string', example: 'RSA' },
              use: { type: 'string', example: 'sig' },
              kid: { type: 'string', example: '2025-11-11-key-1' },
              n: { type: 'string', description: 'RSA modulus (base64url)' },
              e: { type: 'string', example: 'AQAB' },
              alg: { type: 'string', example: 'RS256' },
            },
          },
        },
      },
    },
  })
  async getJWKS() {
    return this.jwtService.getJWKS();
  }

  @Get('openid-configuration')
  @Public()
  @Header('Cache-Control', 'public, max-age=300')
  @ApiOperation({
    summary: 'Get OpenID Connect discovery document',
    description:
      'Returns OpenID Connect configuration metadata including JWKS endpoint location.',
  })
  @ApiResponse({
    status: 200,
    description: 'OpenID Connect discovery document',
    schema: {
      type: 'object',
      properties: {
        issuer: { type: 'string', example: 'https://auth.example.com' },
        jwks_uri: {
          type: 'string',
          example: 'https://auth.example.com/.well-known/jwks.json',
        },
        authorization_endpoint: {
          type: 'string',
          example: 'https://auth.example.com/auth/login',
        },
        token_endpoint: {
          type: 'string',
          example: 'https://auth.example.com/auth/refresh',
        },
        response_types_supported: {
          type: 'array',
          items: { type: 'string' },
          example: ['id_token'],
        },
        subject_types_supported: {
          type: 'array',
          items: { type: 'string' },
          example: ['public'],
        },
        id_token_signing_alg_values_supported: {
          type: 'array',
          items: { type: 'string' },
          example: ['RS256'],
        },
      },
    },
  })
  getOpenIdConfiguration(@Req() req: Request) {
    // Build base URL from request
    // Use X-Forwarded-Proto header (set by Cloud Run/proxies) to get original protocol
    // Cloud Run terminates HTTPS at the edge, so req.protocol is 'http' internally
    const protocol = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('host');
    const baseUrl = `${protocol}://${host}`;

    return {
      issuer: 'auth-service', // Simple identifier that matches JWT iss claim - works across all environments
      jwks_uri: `${baseUrl}/auth/.well-known/jwks.json`,
      authorization_endpoint: `${baseUrl}/auth/v1/auth/login`,
      token_endpoint: `${baseUrl}/auth/v1/auth/refresh-token`,
      response_types_supported: ['id_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
    };
  }
}

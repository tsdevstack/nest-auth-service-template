import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SecretsService } from '@tsdevstack/nest-common';
import * as jose from 'jose';

interface RSAKeyPair {
  privateKey: jose.KeyLike;
  publicKey: jose.KeyLike;
  keyId: string;
}

@Injectable()
export class JwtService implements OnModuleInit {
  private readonly logger = new Logger(JwtService.name);
  private currentKeys: RSAKeyPair | null = null;
  private previousKeys: RSAKeyPair | null = null;

  constructor(private readonly secrets: SecretsService) {}

  async onModuleInit() {
    await this.loadKeys();
  }

  private async loadKeys() {
    try {
      // Load current keys (required)
      const privateKeyPem = await this.secrets.get('JWT_PRIVATE_KEY_CURRENT');
      const publicKeyPem = await this.secrets.get('JWT_PUBLIC_KEY_CURRENT');
      const keyId = await this.secrets.get('JWT_KEY_ID_CURRENT');

      this.currentKeys = {
        privateKey: await jose.importPKCS8(privateKeyPem, 'RS256'),
        publicKey: await jose.importSPKI(publicKeyPem, 'RS256'),
        keyId,
      };

      this.logger.log(`Loaded current RSA keys (kid: ${keyId})`);

      // Try to load previous keys (optional - for key rotation)
      try {
        const prevPrivateKeyPem = await this.secrets.get(
          'JWT_PRIVATE_KEY_PREVIOUS',
        );
        const prevPublicKeyPem = await this.secrets.get(
          'JWT_PUBLIC_KEY_PREVIOUS',
        );
        const prevKeyId = await this.secrets.get('JWT_KEY_ID_PREVIOUS');

        this.previousKeys = {
          privateKey: await jose.importPKCS8(prevPrivateKeyPem, 'RS256'),
          publicKey: await jose.importSPKI(prevPublicKeyPem, 'RS256'),
          keyId: prevKeyId,
        };

        this.logger.log(`Loaded previous RSA keys (kid: ${prevKeyId})`);
      } catch (error) {
        // Previous keys are optional, log at debug level
        this.logger.debug('No previous keys found (optional for key rotation)');
      }
    } catch (error) {
      this.logger.error('Failed to load RSA keys', error);
      throw error;
    }
  }

  /**
   * Sign a JWT payload with RS256 algorithm using the current private key
   */
  async sign(payload: Record<string, any>, expiresIn: string): Promise<string> {
    if (!this.currentKeys) {
      throw new Error('RSA keys not loaded');
    }

    const jwt = await new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT',
        kid: this.currentKeys.keyId,
      })
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(this.currentKeys.privateKey);

    return jwt;
  }

  /**
   * Get the current key ID
   */
  getCurrentKeyId(): string {
    if (!this.currentKeys) {
      throw new Error('RSA keys not loaded');
    }
    return this.currentKeys.keyId;
  }

  /**
   * Generate JWKS (JSON Web Key Set) for public key distribution
   * Includes current key and previous key (if available) for rotation support
   */
  async getJWKS(): Promise<{ keys: jose.JWK[] }> {
    if (!this.currentKeys) {
      throw new Error('RSA keys not loaded');
    }

    const keys: jose.JWK[] = [];

    // Add current public key
    const currentJWK = await jose.exportJWK(this.currentKeys.publicKey);
    keys.push({
      ...currentJWK,
      use: 'sig',
      alg: 'RS256',
      kid: this.currentKeys.keyId,
    });

    // Add previous public key if available (for key rotation)
    if (this.previousKeys) {
      const previousJWK = await jose.exportJWK(this.previousKeys.publicKey);
      keys.push({
        ...previousJWK,
        use: 'sig',
        alg: 'RS256',
        kid: this.previousKeys.keyId,
      });
    }

    return { keys };
  }
}

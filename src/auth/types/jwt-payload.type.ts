/**
 * Auth service specific JWT payload
 *
 * JWT token payload structure used by the auth service.
 */
export interface JwtPayload {
  sub: string; // User ID
  email: string;
  role: string;
  confirmed: boolean;
  status: 'ACTIVE' | 'INACTIVE';
  iss: string; // Issuer claim (e.g., 'auth-service')
  aud: string; // Audience claim (e.g., 'kong')
  iat?: number; // Issued at
  exp?: number; // Expiration time
}

// Request type with authenticated user
export interface AuthenticatedRequest {
  user?: JwtPayload;
}

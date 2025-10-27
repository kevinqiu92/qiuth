/**
 * Cryptographic Utilities
 *
 * Provides utilities for generating secure credentials:
 * - API keys
 * - TOTP secrets
 * - RSA key pairs
 *
 * @packageDocumentation
 */

import { randomBytes, generateKeyPairSync } from 'node:crypto';

/**
 * Options for generating RSA key pairs
 */
export interface KeyPairOptions {
  /**
   * Key size in bits
   * @default 2048
   */
  modulusLength?: number;

  /**
   * Public key format
   * @default 'spki'
   */
  publicKeyFormat?: 'spki' | 'pkcs1';

  /**
   * Private key format
   * @default 'pkcs8'
   */
  privateKeyFormat?: 'pkcs8' | 'pkcs1';
}

/**
 * Generated key pair
 */
export interface KeyPair {
  /**
   * PEM-encoded public key
   */
  publicKey: string;

  /**
   * PEM-encoded private key
   */
  privateKey: string;
}

/**
 * Generate a cryptographically secure API key
 *
 * @param length - Length of the API key in bytes (default: 32)
 * @returns Base64-encoded API key
 *
 * @example
 * ```typescript
 * const apiKey = generateApiKey();
 * console.log(apiKey); // "xK7j9mP2qR5tW8yB..."
 * ```
 */
export function generateApiKey(length = 32): string {
  const bytes = randomBytes(length);
  return bytes.toString('base64url'); // URL-safe base64
}

/**
 * Generate a TOTP secret
 *
 * @param length - Length of the secret in bytes (default: 20, which is 160 bits)
 * @returns Base32-encoded secret
 *
 * @example
 * ```typescript
 * const secret = generateTotpSecret();
 * console.log(secret); // "JBSWY3DPEHPK3PXP"
 * ```
 */
export function generateTotpSecret(length = 20): string {
  const bytes = randomBytes(length);
  return base32Encode(bytes);
}

/**
 * Generate an RSA key pair for certificate-based authentication
 *
 * @param options - Key pair generation options
 * @returns Object containing public and private keys in PEM format
 *
 * @example
 * ```typescript
 * const { publicKey, privateKey } = generateKeyPair();
 * console.log(publicKey);  // "-----BEGIN PUBLIC KEY-----..."
 * console.log(privateKey); // "-----BEGIN PRIVATE KEY-----..."
 * ```
 */
export function generateKeyPair(options: KeyPairOptions = {}): KeyPair {
  const modulusLength = options.modulusLength ?? 2048;
  const publicKeyFormat = options.publicKeyFormat ?? 'spki';
  const privateKeyFormat = options.privateKeyFormat ?? 'pkcs8';

  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: {
      type: publicKeyFormat,
      format: 'pem',
    },
    privateKeyEncoding: {
      type: privateKeyFormat,
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}

/**
 * Base32 encoding alphabet (RFC 4648)
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode bytes to base32
 *
 * @param buffer - Buffer to encode
 * @returns Base32-encoded string
 */
function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]!;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  // Add padding
  while (output.length % 8 !== 0) {
    output += '=';
  }

  return output;
}

/**
 * Generate a random string of specified length
 *
 * @param length - Length of the string
 * @param charset - Character set to use (default: alphanumeric)
 * @returns Random string
 *
 * @example
 * ```typescript
 * const id = generateRandomString(16);
 * console.log(id); // "a7B9cD2eF4gH6iJ8"
 * ```
 */
export function generateRandomString(
  length: number,
  charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string {
  const bytes = randomBytes(length);
  let result = '';

  for (let i = 0; i < length; i++) {
    result += charset[bytes[i]! % charset.length];
  }

  return result;
}

/**
 * Generate a UUID v4
 *
 * @returns UUID string
 *
 * @example
 * ```typescript
 * const id = generateUuid();
 * console.log(id); // "550e8400-e29b-41d4-a716-446655440000"
 * ```
 */
export function generateUuid(): string {
  const bytes = randomBytes(16);

  // Set version (4) and variant bits
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;

  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Generate multiple API keys at once
 *
 * @param count - Number of keys to generate
 * @param length - Length of each key in bytes
 * @returns Array of API keys
 *
 * @example
 * ```typescript
 * const keys = generateApiKeys(5);
 * console.log(keys); // ["key1...", "key2...", ...]
 * ```
 */
export function generateApiKeys(count: number, length = 32): string[] {
  return Array.from({ length: count }, () => generateApiKey(length));
}

/**
 * Validate that a string is a valid base32-encoded TOTP secret
 *
 * @param secret - Secret to validate
 * @returns true if valid
 */
export function isValidTotpSecret(secret: string): boolean {
  // Remove padding
  const cleaned = secret.replace(/=/g, '');

  // Check if all characters are valid base32
  return /^[A-Z2-7]+$/.test(cleaned);
}

/**
 * Validate that a string is a valid PEM-encoded key
 *
 * @param key - Key to validate
 * @returns true if valid
 */
export function isValidPemKey(key: string): boolean {
  return key.includes('-----BEGIN') && key.includes('-----END') && key.includes('KEY-----');
}

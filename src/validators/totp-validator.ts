/**
 * TOTP (Time-based One-Time Password) Validation Module
 *
 * Implements RFC 6238 compliant TOTP generation and validation.
 * Provides MFA for service accounts without requiring human intervention.
 *
 * @packageDocumentation
 */

import { TotpConfig } from '../types';
import { createHmac } from 'node:crypto';

/**
 * Validator for TOTP MFA security layer
 *
 * Implements RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
 * This allows programmatic MFA for service accounts.
 */
export class TotpValidator {
  private readonly config: TotpConfig;
  private readonly timeStep: number;
  private readonly window: number;

  /**
   * Create a new TOTP validator
   * @param config - TOTP configuration
   */
  constructor(config: TotpConfig) {
    if (!config.enabled) {
      throw new Error('TOTP MFA is not enabled in configuration');
    }
    if (!config.secret) {
      throw new Error('TOTP secret is required when TOTP is enabled');
    }

    this.config = config;
    this.timeStep = config.timeStep ?? 30;
    this.window = config.window ?? 1;

    // Validate time step
    if (this.timeStep <= 0) {
      throw new Error('TOTP time step must be positive');
    }

    // Validate window
    if (this.window < 0) {
      throw new Error('TOTP window cannot be negative');
    }
  }

  /**
   * Validate a TOTP token
   *
   * Checks the token against current time window and adjacent windows
   * to account for clock drift and network latency.
   *
   * @param token - 6-digit TOTP token to validate
   * @param timestamp - Optional timestamp (defaults to current time)
   * @returns true if token is valid, false otherwise
   */
  public validate(token: string, timestamp?: number): boolean {
    if (!token) {
      return false;
    }

    // Normalize token (remove spaces, ensure 6 digits)
    const normalizedToken = token.replace(/\s/g, '');
    if (!/^\d{6}$/.test(normalizedToken)) {
      return false;
    }

    const time = timestamp ?? Date.now();
    const counter = Math.floor(time / 1000 / this.timeStep);

    // Check current window and adjacent windows
    for (let i = -this.window; i <= this.window; i++) {
      const expectedToken = this.generateToken(counter + i);
      if (expectedToken === normalizedToken) {
        return true;
      }
    }

    return false;
  }

  /**
   * Generate a TOTP token for the current time
   *
   * This is primarily used for testing and client-side token generation.
   *
   * @param timestamp - Optional timestamp (defaults to current time)
   * @returns 6-digit TOTP token
   */
  public generate(timestamp?: number): string {
    const time = timestamp ?? Date.now();
    const counter = Math.floor(time / 1000 / this.timeStep);
    return this.generateToken(counter);
  }

  /**
   * Generate a TOTP token for a specific counter value
   *
   * Implements the HOTP algorithm (RFC 4226) with time-based counter.
   *
   * @param counter - Time counter value
   * @returns 6-digit TOTP token
   */
  private generateToken(counter: number): string {
    // Decode base32 secret
    const secret = this.base32Decode(this.config.secret);

    // Convert counter to 8-byte buffer (big-endian)
    const counterBuffer = Buffer.alloc(8);
    // Write as big-endian 64-bit integer
    let c = counter;
    for (let i = 7; i >= 0; i--) {
      counterBuffer[i] = c & 0xff;
      c = Math.floor(c / 256);
    }

    // Generate HMAC-SHA1
    const hmac = createHmac('sha1', secret);
    hmac.update(counterBuffer);
    const hash = hmac.digest();

    // Dynamic truncation (RFC 4226 Section 5.3)
    const offset = hash[hash.length - 1]! & 0x0f;
    const binary =
      ((hash[offset]! & 0x7f) << 24) |
      (hash[offset + 1]! << 16) |
      (hash[offset + 2]! << 8) |
      hash[offset + 3]!;

    // Generate 6-digit token
    const token = binary % 1000000;
    return token.toString().padStart(6, '0');
  }

  /**
   * Decode a base32-encoded string to a Buffer
   *
   * Base32 is commonly used for TOTP secrets as it's case-insensitive
   * and avoids ambiguous characters.
   *
   * @param base32 - Base32-encoded string
   * @returns Decoded buffer
   */
  private base32Decode(base32: string): Buffer {
    // Remove spaces and convert to uppercase
    const cleanBase32 = base32.replace(/\s/g, '').toUpperCase();

    // Base32 alphabet (RFC 4648)
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bits: number[] = [];

    // Convert each character to 5 bits
    for (const char of cleanBase32) {
      if (char === '=') {
        break; // Padding
      }
      const value = alphabet.indexOf(char);
      if (value === -1) {
        throw new Error(`Invalid base32 character: ${char}`);
      }
      // Add 5 bits
      for (let i = 4; i >= 0; i--) {
        bits.push((value >> i) & 1);
      }
    }

    // Convert bits to bytes
    const bytes: number[] = [];
    for (let i = 0; i < bits.length; i += 8) {
      if (i + 8 <= bits.length) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
          byte = (byte << 1) | (bits[i + j] ?? 0);
        }
        bytes.push(byte);
      }
    }

    return Buffer.from(bytes);
  }

  /**
   * Generate a random base32 secret for TOTP
   *
   * This is a utility function for generating new TOTP secrets.
   * The secret should be securely stored and shared with the client.
   *
   * @param length - Length of secret in bytes (default: 20)
   * @returns Base32-encoded secret
   */
  public static generateSecret(length: number = 20): string {
    const crypto = require('node:crypto');
    const bytes = crypto.randomBytes(length);
    return TotpValidator.base32Encode(bytes);
  }

  /**
   * Encode a buffer to base32
   *
   * @param buffer - Buffer to encode
   * @returns Base32-encoded string
   */
  private static base32Encode(buffer: Buffer): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let result = '';

    // Convert bytes to bits
    for (const byte of buffer) {
      bits += byte.toString(2).padStart(8, '0');
    }

    // Convert 5-bit chunks to base32 characters
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.slice(i, i + 5).padEnd(5, '0');
      const value = parseInt(chunk, 2);
      result += alphabet[value];
    }

    // Add padding
    while (result.length % 8 !== 0) {
      result += '=';
    }

    return result;
  }

  /**
   * Get the current time window counter
   *
   * Useful for debugging and testing.
   *
   * @param timestamp - Optional timestamp (defaults to current time)
   * @returns Current counter value
   */
  public getCurrentCounter(timestamp?: number): number {
    const time = timestamp ?? Date.now();
    return Math.floor(time / 1000 / this.timeStep);
  }

  /**
   * Get the remaining time in the current window
   *
   * Useful for UI display to show when the token will expire.
   *
   * @param timestamp - Optional timestamp (defaults to current time)
   * @returns Remaining seconds in current window
   */
  public getRemainingTime(timestamp?: number): number {
    const time = timestamp ?? Date.now();
    const timeInSeconds = Math.floor(time / 1000);
    const windowStart = Math.floor(timeInSeconds / this.timeStep) * this.timeStep;
    const windowEnd = windowStart + this.timeStep;
    return windowEnd - timeInSeconds;
  }
}

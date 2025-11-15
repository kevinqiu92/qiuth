/**
 * Certificate-Based Authentication Module
 *
 * Provides request signing and verification using RSA-SHA256.
 * Transforms API keys from bearer tokens to proof-of-possession tokens.
 *
 * @packageDocumentation
 */

import { CertificateConfig } from '../types';
import { createSign, createVerify, createHash } from 'node:crypto';

/**
 * Validator for certificate-based authentication layer
 *
 * This is the strongest security layer, requiring proof of private key possession.
 * Prevents replay attacks through timestamp validation.
 */
export class CertificateValidator {
  private readonly maxAge: number;
  private readonly maxAgeMs: number;
  private readonly publicKeyBuffer: Buffer;

  /**
   * Create a new certificate validator
   * @param config - Certificate configuration
   */
  constructor(config: CertificateConfig) {
    if (!config.enabled) {
      throw new Error('Certificate authentication is not enabled in configuration');
    }
    if (!config.publicKey) {
      throw new Error('Public key is required when certificate authentication is enabled');
    }

    this.maxAge = config.maxAge ?? 300; // Default 5 minutes
    this.maxAgeMs = this.maxAge * 1000; // Pre-calculate for performance

    if (this.maxAge <= 0) {
      throw new Error('Certificate maxAge must be positive');
    }

    // Pre-convert public key to buffer for faster verification
    this.publicKeyBuffer = Buffer.from(config.publicKey);
  }

  /**
   * Verify a signed request
   *
   * Validates that:
   * 1. The signature is valid for the request
   * 2. The timestamp is within acceptable range (not too old, not in future)
   * 3. The request hasn't been tampered with
   *
   * @param signature - Base64-encoded signature
   * @param method - HTTP method (GET, POST, etc.)
   * @param url - Full request URL
   * @param body - Request body (if any)
   * @param timestamp - Request timestamp (ISO 8601 or Unix timestamp in ms)
   * @returns true if signature is valid and request is fresh
   */
  public verify(
    signature: string,
    method: string,
    url: string,
    body?: string | Buffer,
    timestamp?: string | number
  ): boolean {
    // Fast-fail on empty inputs
    if (!signature || !timestamp || !method || !url) {
      return false;
    }

    // Validate timestamp first (cheapest check)
    const timestampMs = this.parseTimestamp(timestamp);
    if (!this.isTimestampValid(timestampMs)) {
      return false;
    }

    // Decode signature early to catch invalid base64
    let signatureBuffer: Buffer;
    try {
      signatureBuffer = Buffer.from(signature, 'base64');
    } catch {
      return false;
    }

    // Create canonical request representation
    const canonical = this.createCanonicalRequest(method, url, body, timestampMs);

    // Verify signature
    try {
      const verifier = createVerify('RSA-SHA256');
      verifier.update(canonical);
      verifier.end();

      return verifier.verify(this.publicKeyBuffer, signatureBuffer);
    } catch {
      // Invalid signature format or verification error
      return false;
    }
  }

  /**
   * Sign a request (used by clients)
   *
   * Creates a signature that proves possession of the private key
   * without revealing the key itself.
   *
   * @param privateKey - PEM-encoded private key
   * @param method - HTTP method
   * @param url - Full request URL
   * @param body - Request body (if any)
   * @param timestamp - Request timestamp (defaults to current time)
   * @returns Base64-encoded signature
   */
  public static sign(
    privateKey: string,
    method: string,
    url: string,
    body?: string | Buffer,
    timestamp?: number
  ): string {
    const timestampMs = timestamp ?? Date.now();
    const canonical = CertificateValidator.createCanonicalRequestStatic(
      method,
      url,
      body,
      timestampMs
    );

    const signer = createSign('RSA-SHA256');
    signer.update(canonical);
    signer.end();

    const signature = signer.sign(privateKey);
    return signature.toString('base64');
  }

  /**
   * Parse timestamp from various formats
   *
   * Accepts:
   * - Unix timestamp in milliseconds (number)
   * - Unix timestamp in milliseconds (string)
   * - ISO 8601 date string
   *
   * @param timestamp - Timestamp in various formats
   * @returns Unix timestamp in milliseconds
   */
  private parseTimestamp(timestamp: string | number): number {
    if (typeof timestamp === 'number') {
      return timestamp;
    }

    // Try parsing as ISO 8601 first (contains non-digit characters)
    if (/[^\d]/.test(timestamp)) {
      const asDate = new Date(timestamp);
      if (!isNaN(asDate.getTime())) {
        return asDate.getTime();
      }
      return NaN;
    }

    // Parse as number
    const asNumber = parseInt(timestamp, 10);
    if (!isNaN(asNumber)) {
      return asNumber;
    }

    return NaN;
  }

  /**
   * Check if timestamp is within acceptable range
   *
   * Rejects timestamps that are:
   * - Too old (older than maxAge)
   * - In the future (with small tolerance for clock skew)
   *
   * @param timestampMs - Timestamp in milliseconds
   * @returns true if timestamp is valid
   */
  private isTimestampValid(timestampMs: number): boolean {
    if (isNaN(timestampMs) || timestampMs <= 0) {
      return false;
    }

    const now = Date.now();
    const age = now - timestampMs;

    // Reject if too old (using pre-calculated maxAgeMs)
    if (age > this.maxAgeMs) {
      return false;
    }

    // Reject if in the future (with 60 second tolerance for clock skew)
    if (age < -60000) {
      return false;
    }

    return true;
  }

  /**
   * Create canonical representation of a request
   *
   * This ensures that the same request always produces the same signature,
   * regardless of how it's formatted.
   *
   * Format:
   * METHOD\n
   * URL\n
   * TIMESTAMP\n
   * BODY_HASH
   *
   * @param method - HTTP method
   * @param url - Full request URL
   * @param body - Request body
   * @param timestampMs - Timestamp in milliseconds
   * @returns Canonical request string
   */
  private createCanonicalRequest(
    method: string,
    url: string,
    body: string | Buffer | undefined,
    timestampMs: number
  ): string {
    return CertificateValidator.createCanonicalRequestStatic(method, url, body, timestampMs);
  }

  /**
   * Static version of createCanonicalRequest for use in signing
   */
  private static createCanonicalRequestStatic(
    method: string,
    url: string,
    body: string | Buffer | undefined,
    timestampMs: number
  ): string {
    // Normalize method to uppercase
    const normalizedMethod = method.toUpperCase();

    // Normalize URL (remove fragment, preserve query string)
    const normalizedUrl = url.split('#')[0] || url;

    // Hash body if present
    const bodyHash = body ? this.hashBody(body) : '';

    // Create canonical string
    return `${normalizedMethod}\n${normalizedUrl}\n${timestampMs}\n${bodyHash}`;
  }

  /**
   * Hash request body for inclusion in signature
   *
   * Uses SHA-256 to create a fixed-size representation of the body.
   *
   * @param body - Request body
   * @returns Hex-encoded SHA-256 hash
   */
  private static hashBody(body: string | Buffer): string {
    const hash = createHash('sha256');
    hash.update(body);
    return hash.digest('hex');
  }

  /**
   * Get the maximum age for signed requests
   *
   * @returns Maximum age in seconds
   */
  public getMaxAge(): number {
    return this.maxAge;
  }

  /**
   * Check if a timestamp would be considered valid
   *
   * Useful for testing and debugging.
   *
   * @param timestamp - Timestamp to check
   * @returns true if timestamp is valid
   */
  public isTimestampAcceptable(timestamp: string | number): boolean {
    const timestampMs = this.parseTimestamp(timestamp);
    return this.isTimestampValid(timestampMs);
  }
}

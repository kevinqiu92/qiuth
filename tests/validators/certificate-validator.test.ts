import { describe, it, expect, beforeAll } from 'vitest';
import { CertificateValidator } from '../../src/validators/certificate-validator';
import { CertificateConfig } from '../../src/types';
import { generateKeyPairSync } from 'node:crypto';

describe('CertificateValidator', () => {
  let publicKey: string;
  let privateKey: string;

  beforeAll(() => {
    // Generate test RSA key pair
    const { publicKey: pubKey, privateKey: privKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });
    publicKey = pubKey;
    privateKey = privKey;
  });

  describe('constructor', () => {
    it('should throw error if certificate auth is not enabled', () => {
      const config: CertificateConfig = {
        enabled: false,
        publicKey: publicKey,
      };
      expect(() => new CertificateValidator(config)).toThrow(
        'Certificate authentication is not enabled'
      );
    });

    it('should throw error if public key is missing', () => {
      const config: CertificateConfig = {
        enabled: true,
        publicKey: '',
      };
      expect(() => new CertificateValidator(config)).toThrow('Public key is required');
    });

    it('should throw error if maxAge is invalid', () => {
      const config: CertificateConfig = {
        enabled: true,
        publicKey: publicKey,
        maxAge: 0,
      };
      expect(() => new CertificateValidator(config)).toThrow('Certificate maxAge must be positive');
    });

    it('should create validator with valid config', () => {
      const config: CertificateConfig = {
        enabled: true,
        publicKey: publicKey,
      };
      expect(() => new CertificateValidator(config)).not.toThrow();
    });

    it('should use default maxAge of 300 seconds', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });
      expect(validator.getMaxAge()).toBe(300);
    });

    it('should use custom maxAge', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
        maxAge: 600,
      });
      expect(validator.getMaxAge()).toBe(600);
    });
  });

  describe('sign and verify', () => {
    it('should verify correctly signed request', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);
    });

    it('should verify signed POST request with body', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'POST';
      const url = 'https://api.example.com/users';
      const body = JSON.stringify({ name: 'John Doe' });
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, method, url, body, timestamp);
      expect(validator.verify(signature, method, url, body, timestamp)).toBe(true);
    });

    it('should verify signed request with Buffer body', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'POST';
      const url = 'https://api.example.com/upload';
      const body = Buffer.from('binary data');
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, method, url, body, timestamp);
      expect(validator.verify(signature, method, url, body, timestamp)).toBe(true);
    });

    it('should reject signature with wrong private key', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      // Generate different key pair
      const { privateKey: wrongPrivateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(wrongPrivateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(false);
    });

    it('should reject empty signature', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      expect(validator.verify('', 'GET', 'https://api.example.com', undefined, Date.now())).toBe(
        false
      );
    });

    it('should reject invalid signature format', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      expect(
        validator.verify('not-a-valid-signature', 'GET', 'https://api.example.com', undefined, Date.now())
      ).toBe(false);
    });
  });

  describe('request tampering detection', () => {
    it('should reject if method is changed', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, 'GET', url, undefined, timestamp);
      expect(validator.verify(signature, 'POST', url, undefined, timestamp)).toBe(false);
    });

    it('should reject if URL is changed', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(
        privateKey,
        method,
        'https://api.example.com/users',
        undefined,
        timestamp
      );
      expect(
        validator.verify(signature, method, 'https://api.example.com/admin', undefined, timestamp)
      ).toBe(false);
    });

    it('should reject if body is changed', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'POST';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(
        privateKey,
        method,
        url,
        JSON.stringify({ name: 'John' }),
        timestamp
      );
      expect(
        validator.verify(signature, method, url, JSON.stringify({ name: 'Jane' }), timestamp)
      ).toBe(false);
    });

    it('should reject if timestamp is changed', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp + 1000)).toBe(false);
    });

    it('should handle URL fragments correctly', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const timestamp = Date.now();

      // Fragments should be ignored in signature
      const signature = CertificateValidator.sign(
        privateKey,
        method,
        'https://api.example.com/users#section',
        undefined,
        timestamp
      );
      expect(
        validator.verify(signature, method, 'https://api.example.com/users', undefined, timestamp)
      ).toBe(true);
    });

    it('should preserve query strings', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users?page=1&limit=10';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);

      // Different query string should fail
      expect(
        validator.verify(
          signature,
          method,
          'https://api.example.com/users?page=2&limit=10',
          undefined,
          timestamp
        )
      ).toBe(false);
    });
  });

  describe('timestamp validation', () => {
    it('should accept recent timestamp', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
        maxAge: 300,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() - 10000; // 10 seconds ago

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);
    });

    it('should reject old timestamp', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
        maxAge: 300,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() - 400000; // 400 seconds ago (> maxAge)

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(false);
    });

    it('should reject future timestamp beyond tolerance', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() + 120000; // 2 minutes in future (> 60s tolerance)

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(false);
    });

    it('should accept slightly future timestamp within tolerance', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now() + 30000; // 30 seconds in future (< 60s tolerance)

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp)).toBe(true);
    });

    it('should reject missing timestamp', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const signature = CertificateValidator.sign(
        privateKey,
        'GET',
        'https://api.example.com',
        undefined,
        Date.now()
      );
      expect(validator.verify(signature, 'GET', 'https://api.example.com', undefined, undefined as any)).toBe(
        false
      );
    });

    it('should handle ISO 8601 timestamp format', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();
      const isoTimestamp = new Date(timestamp).toISOString();

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, isoTimestamp)).toBe(true);
    });

    it('should handle timestamp as string number', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const method = 'GET';
      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);
      expect(validator.verify(signature, method, url, undefined, timestamp.toString())).toBe(true);
    });
  });

  describe('isTimestampAcceptable', () => {
    it('should accept current timestamp', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      expect(validator.isTimestampAcceptable(Date.now())).toBe(true);
    });

    it('should reject old timestamp', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
        maxAge: 300,
      });

      const oldTimestamp = Date.now() - 400000;
      expect(validator.isTimestampAcceptable(oldTimestamp)).toBe(false);
    });

    it('should accept ISO 8601 format', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const isoTimestamp = new Date().toISOString();
      expect(validator.isTimestampAcceptable(isoTimestamp)).toBe(true);
    });
  });

  describe('method normalization', () => {
    it('should normalize method to uppercase', () => {
      const validator = new CertificateValidator({
        enabled: true,
        publicKey: publicKey,
      });

      const url = 'https://api.example.com/users';
      const timestamp = Date.now();

      const signature = CertificateValidator.sign(privateKey, 'get', url, undefined, timestamp);
      expect(validator.verify(signature, 'GET', url, undefined, timestamp)).toBe(true);
      expect(validator.verify(signature, 'get', url, undefined, timestamp)).toBe(true);
    });
  });
});


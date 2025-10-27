import { describe, it, expect } from 'vitest';
import {
  generateApiKey,
  generateTotpSecret,
  generateKeyPair,
  generateRandomString,
  generateUuid,
  generateApiKeys,
  isValidTotpSecret,
  isValidPemKey,
} from '../../src/utils/crypto';

describe('Crypto Utilities', () => {
  describe('generateApiKey', () => {
    it('should generate API key with default length', () => {
      const key = generateApiKey();
      expect(key).toBeDefined();
      expect(typeof key).toBe('string');
      expect(key.length).toBeGreaterThan(0);
    });

    it('should generate API key with custom length', () => {
      const key = generateApiKey(64);
      expect(key).toBeDefined();
      // Base64url encoding increases length
      expect(key.length).toBeGreaterThan(64);
    });

    it('should generate unique keys', () => {
      const key1 = generateApiKey();
      const key2 = generateApiKey();
      expect(key1).not.toBe(key2);
    });

    it('should generate URL-safe keys', () => {
      const key = generateApiKey();
      // Base64url should not contain +, /, or =
      expect(key).not.toMatch(/[+/=]/);
    });
  });

  describe('generateTotpSecret', () => {
    it('should generate TOTP secret with default length', () => {
      const secret = generateTotpSecret();
      expect(secret).toBeDefined();
      expect(typeof secret).toBe('string');
      expect(secret.length).toBeGreaterThan(0);
    });

    it('should generate base32-encoded secret', () => {
      const secret = generateTotpSecret();
      // Base32 uses A-Z and 2-7
      expect(secret).toMatch(/^[A-Z2-7=]+$/);
    });

    it('should generate unique secrets', () => {
      const secret1 = generateTotpSecret();
      const secret2 = generateTotpSecret();
      expect(secret1).not.toBe(secret2);
    });

    it('should generate secret with custom length', () => {
      const secret = generateTotpSecret(32);
      expect(secret).toBeDefined();
      // Longer input should produce longer base32 output
      expect(secret.length).toBeGreaterThan(32);
    });
  });

  describe('generateKeyPair', () => {
    it('should generate RSA key pair with default options', () => {
      const { publicKey, privateKey } = generateKeyPair();
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(publicKey).toContain('-----END PUBLIC KEY-----');
      expect(privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(privateKey).toContain('-----END PRIVATE KEY-----');
    });

    it('should generate key pair with custom modulus length', () => {
      const { publicKey, privateKey } = generateKeyPair({ modulusLength: 1024 });
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      // Smaller key should have shorter PEM encoding
      expect(privateKey.length).toBeLessThan(2000);
    });

    it('should generate unique key pairs', () => {
      const pair1 = generateKeyPair();
      const pair2 = generateKeyPair();
      expect(pair1.publicKey).not.toBe(pair2.publicKey);
      expect(pair1.privateKey).not.toBe(pair2.privateKey);
    });

    it('should generate key pair with PKCS1 format', () => {
      const { publicKey, privateKey } = generateKeyPair({
        publicKeyFormat: 'pkcs1',
        privateKeyFormat: 'pkcs1',
      });
      expect(publicKey).toContain('-----BEGIN RSA PUBLIC KEY-----');
      expect(privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
    });
  });

  describe('generateRandomString', () => {
    it('should generate random string with default charset', () => {
      const str = generateRandomString(16);
      expect(str).toBeDefined();
      expect(str.length).toBe(16);
      expect(str).toMatch(/^[A-Za-z0-9]+$/);
    });

    it('should generate random string with custom charset', () => {
      const str = generateRandomString(10, '0123456789');
      expect(str).toBeDefined();
      expect(str.length).toBe(10);
      expect(str).toMatch(/^[0-9]+$/);
    });

    it('should generate unique strings', () => {
      const str1 = generateRandomString(16);
      const str2 = generateRandomString(16);
      expect(str1).not.toBe(str2);
    });
  });

  describe('generateUuid', () => {
    it('should generate valid UUID v4', () => {
      const uuid = generateUuid();
      expect(uuid).toBeDefined();
      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    });

    it('should generate unique UUIDs', () => {
      const uuid1 = generateUuid();
      const uuid2 = generateUuid();
      expect(uuid1).not.toBe(uuid2);
    });
  });

  describe('generateApiKeys', () => {
    it('should generate multiple API keys', () => {
      const keys = generateApiKeys(5);
      expect(keys).toHaveLength(5);
      expect(keys.every((key) => typeof key === 'string')).toBe(true);
    });

    it('should generate unique keys', () => {
      const keys = generateApiKeys(10);
      const uniqueKeys = new Set(keys);
      expect(uniqueKeys.size).toBe(10);
    });

    it('should generate keys with custom length', () => {
      const keys = generateApiKeys(3, 64);
      expect(keys).toHaveLength(3);
      keys.forEach((key) => {
        expect(key.length).toBeGreaterThan(64);
      });
    });
  });

  describe('isValidTotpSecret', () => {
    it('should validate valid TOTP secret', () => {
      const secret = generateTotpSecret();
      expect(isValidTotpSecret(secret)).toBe(true);
    });

    it('should validate secret without padding', () => {
      expect(isValidTotpSecret('JBSWY3DPEHPK3PXP')).toBe(true);
    });

    it('should validate secret with padding', () => {
      expect(isValidTotpSecret('JBSWY3DPEHPK3PXP====')).toBe(true);
    });

    it('should reject invalid characters', () => {
      expect(isValidTotpSecret('invalid-secret')).toBe(false);
      expect(isValidTotpSecret('JBSWY3DPEHPK3PXP!')).toBe(false);
    });

    it('should reject lowercase', () => {
      expect(isValidTotpSecret('jbswy3dpehpk3pxp')).toBe(false);
    });
  });

  describe('isValidPemKey', () => {
    it('should validate valid PEM public key', () => {
      const { publicKey } = generateKeyPair();
      expect(isValidPemKey(publicKey)).toBe(true);
    });

    it('should validate valid PEM private key', () => {
      const { privateKey } = generateKeyPair();
      expect(isValidPemKey(privateKey)).toBe(true);
    });

    it('should reject invalid PEM', () => {
      expect(isValidPemKey('not a key')).toBe(false);
      expect(isValidPemKey('-----BEGIN KEY-----')).toBe(false);
      expect(isValidPemKey('some random text')).toBe(false);
    });
  });
});


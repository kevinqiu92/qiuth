import { describe, it, expect } from 'vitest';
import { TotpValidator } from '../../src/validators/totp-validator';
import { TotpConfig } from '../../src/types';

describe('TotpValidator', () => {
  // Test secret from RFC 6238 test vectors
  const TEST_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890" in base32

  describe('constructor', () => {
    it('should throw error if TOTP is not enabled', () => {
      const config: TotpConfig = {
        enabled: false,
        secret: TEST_SECRET,
      };
      expect(() => new TotpValidator(config)).toThrow('TOTP MFA is not enabled');
    });

    it('should throw error if secret is missing', () => {
      const config: TotpConfig = {
        enabled: true,
        secret: '',
      };
      expect(() => new TotpValidator(config)).toThrow('TOTP secret is required');
    });

    it('should throw error if time step is invalid', () => {
      const config: TotpConfig = {
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 0,
      };
      expect(() => new TotpValidator(config)).toThrow('TOTP time step must be positive');
    });

    it('should throw error if window is negative', () => {
      const config: TotpConfig = {
        enabled: true,
        secret: TEST_SECRET,
        window: -1,
      };
      expect(() => new TotpValidator(config)).toThrow('TOTP window cannot be negative');
    });

    it('should create validator with valid config', () => {
      const config: TotpConfig = {
        enabled: true,
        secret: TEST_SECRET,
      };
      expect(() => new TotpValidator(config)).not.toThrow();
    });

    it('should use default time step of 30 seconds', () => {
      const config: TotpConfig = {
        enabled: true,
        secret: TEST_SECRET,
      };
      const validator = new TotpValidator(config);
      expect(validator.getCurrentCounter(30000)).toBe(1);
    });

    it('should use custom time step', () => {
      const config: TotpConfig = {
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 60,
      };
      const validator = new TotpValidator(config);
      expect(validator.getCurrentCounter(60000)).toBe(1);
    });
  });

  describe('generate', () => {
    it('should generate 6-digit token', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      const token = validator.generate();
      expect(token).toMatch(/^\d{6}$/);
    });

    it('should generate consistent token for same timestamp', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      const timestamp = 1234567890000;
      const token1 = validator.generate(timestamp);
      const token2 = validator.generate(timestamp);
      expect(token1).toBe(token2);
    });

    it('should generate different tokens for different time windows', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      const token1 = validator.generate(0);
      const token2 = validator.generate(30000);
      expect(token1).not.toBe(token2);
    });

    it('should generate same token within time window', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      const token1 = validator.generate(30000);
      const token2 = validator.generate(30001);
      const token3 = validator.generate(59999);
      expect(token1).toBe(token2);
      expect(token1).toBe(token3);
    });

    // RFC 6238 test vectors
    it('should match RFC 6238 test vector for time 59', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      const token = validator.generate(59000);
      expect(token).toBe('287082');
    });

    it('should match RFC 6238 test vector for time 1111111109', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      const token = validator.generate(1111111109000);
      expect(token).toBe('081804');
    });

    it('should match RFC 6238 test vector for time 1234567890', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      const token = validator.generate(1234567890000);
      expect(token).toBe('005924');
    });
  });

  describe('validate', () => {
    it('should validate correct token', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      const timestamp = 1234567890000;
      const token = validator.generate(timestamp);
      expect(validator.validate(token, timestamp)).toBe(true);
    });

    it('should reject incorrect token', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      expect(validator.validate('000000', 1234567890000)).toBe(false);
    });

    it('should reject empty token', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      expect(validator.validate('', 1234567890000)).toBe(false);
    });

    it('should reject non-numeric token', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      expect(validator.validate('abcdef', 1234567890000)).toBe(false);
    });

    it('should reject token with wrong length', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      expect(validator.validate('12345', 1234567890000)).toBe(false);
      expect(validator.validate('1234567', 1234567890000)).toBe(false);
    });

    it('should accept token with spaces', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      const timestamp = 1234567890000;
      const token = validator.generate(timestamp);
      const tokenWithSpaces = `${token.slice(0, 3)} ${token.slice(3)}`;
      expect(validator.validate(tokenWithSpaces, timestamp)).toBe(true);
    });

    it('should accept token from previous window with window=1', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
        window: 1,
      });
      const timestamp = 60000; // Window 2
      const previousToken = validator.generate(30000); // Window 1
      expect(validator.validate(previousToken, timestamp)).toBe(true);
    });

    it('should accept token from next window with window=1', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
        window: 1,
      });
      const timestamp = 30000; // Window 1
      const nextToken = validator.generate(60000); // Window 2
      expect(validator.validate(nextToken, timestamp)).toBe(true);
    });

    it('should reject token from 2 windows ago with window=1', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
        window: 1,
      });
      const timestamp = 90000; // Window 3
      const oldToken = validator.generate(30000); // Window 1
      expect(validator.validate(oldToken, timestamp)).toBe(false);
    });

    it('should accept token from 2 windows ago with window=2', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
        window: 2,
      });
      const timestamp = 90000; // Window 3
      const oldToken = validator.generate(30000); // Window 1
      expect(validator.validate(oldToken, timestamp)).toBe(true);
    });

    it('should work with window=0 (no drift tolerance)', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
        window: 0,
      });
      const timestamp = 60000;
      const currentToken = validator.generate(timestamp);
      const previousToken = validator.generate(30000);
      expect(validator.validate(currentToken, timestamp)).toBe(true);
      expect(validator.validate(previousToken, timestamp)).toBe(false);
    });
  });

  describe('generateSecret', () => {
    it('should generate valid base32 secret', () => {
      const secret = TotpValidator.generateSecret();
      expect(secret).toMatch(/^[A-Z2-7]+=*$/);
    });

    it('should generate secrets of correct length', () => {
      const secret = TotpValidator.generateSecret(20);
      // 20 bytes = 160 bits = 32 base32 chars (with padding)
      expect(secret.replace(/=/g, '').length).toBeGreaterThanOrEqual(26);
    });

    it('should generate different secrets each time', () => {
      const secret1 = TotpValidator.generateSecret();
      const secret2 = TotpValidator.generateSecret();
      expect(secret1).not.toBe(secret2);
    });

    it('should generate usable secrets', () => {
      const secret = TotpValidator.generateSecret();
      const validator = new TotpValidator({
        enabled: true,
        secret,
      });
      const token = validator.generate();
      expect(token).toMatch(/^\d{6}$/);
    });
  });

  describe('getCurrentCounter', () => {
    it('should return correct counter for timestamp', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      expect(validator.getCurrentCounter(0)).toBe(0);
      expect(validator.getCurrentCounter(30000)).toBe(1);
      expect(validator.getCurrentCounter(60000)).toBe(2);
    });

    it('should handle custom time step', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 60,
      });
      expect(validator.getCurrentCounter(0)).toBe(0);
      expect(validator.getCurrentCounter(60000)).toBe(1);
      expect(validator.getCurrentCounter(120000)).toBe(2);
    });
  });

  describe('getRemainingTime', () => {
    it('should return remaining seconds in window', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 30,
      });
      expect(validator.getRemainingTime(0)).toBe(30);
      expect(validator.getRemainingTime(1000)).toBe(29);
      expect(validator.getRemainingTime(29000)).toBe(1);
      expect(validator.getRemainingTime(30000)).toBe(30);
    });

    it('should handle custom time step', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
        timeStep: 60,
      });
      expect(validator.getRemainingTime(0)).toBe(60);
      expect(validator.getRemainingTime(30000)).toBe(30);
      expect(validator.getRemainingTime(60000)).toBe(60);
    });
  });

  describe('base32 encoding/decoding', () => {
    it('should correctly decode base32 secret', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET,
      });
      // If decoding works, token generation should work
      const token = validator.generate(59000);
      expect(token).toBe('287082'); // RFC 6238 test vector
    });

    it('should handle base32 with padding', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: 'JBSWY3DPEHPK3PXP', // "Hello!" in base32
      });
      const token = validator.generate();
      expect(token).toMatch(/^\d{6}$/);
    });

    it('should handle base32 without padding', () => {
      const validator = new TotpValidator({
        enabled: true,
        secret: 'JBSWY3DPEHPK3PXP'.replace(/=/g, ''),
      });
      const token = validator.generate();
      expect(token).toMatch(/^\d{6}$/);
    });

    it('should be case-insensitive', () => {
      const validator1 = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET.toUpperCase(),
      });
      const validator2 = new TotpValidator({
        enabled: true,
        secret: TEST_SECRET.toLowerCase(),
      });
      const timestamp = 1234567890000;
      expect(validator1.generate(timestamp)).toBe(validator2.generate(timestamp));
    });
  });
});


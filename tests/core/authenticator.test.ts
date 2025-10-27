import { describe, it, expect, beforeAll } from 'vitest';
import { QiuthAuthenticator } from '../../src/core/authenticator';
import { QiuthConfig, AuthenticationRequest, SecurityLayer } from '../../src/types';
import { TotpValidator } from '../../src/validators/totp-validator';
import { CertificateValidator } from '../../src/validators/certificate-validator';
import { generateKeyPairSync } from 'node:crypto';

describe('QiuthAuthenticator', () => {
  const TEST_API_KEY = 'test-api-key-12345';
  const TEST_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  let publicKey: string;
  let privateKey: string;

  beforeAll(() => {
    const { publicKey: pubKey, privateKey: privKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    publicKey = pubKey;
    privateKey = privKey;
  });

  describe('constructor', () => {
    it('should create authenticator with default options', () => {
      const authenticator = new QiuthAuthenticator();
      expect(authenticator).toBeDefined();
    });

    it('should create authenticator with custom options', () => {
      const authenticator = new QiuthAuthenticator({
        debug: true,
        logger: () => {},
        collectMetrics: false,
      });
      expect(authenticator).toBeDefined();
    });
  });

  describe('hashApiKey', () => {
    it('should hash API key consistently', () => {
      const hash1 = QiuthAuthenticator.hashApiKey(TEST_API_KEY);
      const hash2 = QiuthAuthenticator.hashApiKey(TEST_API_KEY);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different keys', () => {
      const hash1 = QiuthAuthenticator.hashApiKey('key1');
      const hash2 = QiuthAuthenticator.hashApiKey('key2');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('authenticate - API key validation', () => {
    it('should reject invalid API key', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
      };
      const request: AuthenticationRequest = {
        apiKey: 'wrong-key',
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      expect(result.errors).toContain('Invalid API key');
    });

    it('should accept valid API key with no security layers', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('authenticate - IP allowlist', () => {
    it('should pass with allowed IP', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        ipAllowlist: {
          enabled: true,
          allowedIps: ['192.168.1.0/24'],
        },
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.100',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(true);
      expect(result.layerResults).toHaveLength(1);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.IP_ALLOWLIST);
      expect(result.layerResults[0]?.passed).toBe(true);
    });

    it('should fail with disallowed IP', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        ipAllowlist: {
          enabled: true,
          allowedIps: ['192.168.1.0/24'],
        },
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '10.0.0.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      expect(result.layerResults).toHaveLength(1);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.IP_ALLOWLIST);
      expect(result.layerResults[0]?.passed).toBe(false);
      expect(result.errors[0]).toContain('not in allowlist');
    });
  });

  describe('authenticate - TOTP', () => {
    it('should pass with valid TOTP token', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        totp: {
          enabled: true,
          secret: TEST_SECRET,
        },
      };

      const totpValidator = new TotpValidator({ enabled: true, secret: TEST_SECRET });
      const token = totpValidator.generate();

      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
        totpToken: token,
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(true);
      expect(result.layerResults).toHaveLength(1);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.TOTP_MFA);
      expect(result.layerResults[0]?.passed).toBe(true);
    });

    it('should fail with invalid TOTP token', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        totp: {
          enabled: true,
          secret: TEST_SECRET,
        },
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
        totpToken: '000000',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.TOTP_MFA);
      expect(result.layerResults[0]?.passed).toBe(false);
    });

    it('should fail when TOTP token is missing', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        totp: {
          enabled: true,
          secret: TEST_SECRET,
        },
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('TOTP token is required');
    });
  });

  describe('authenticate - Certificate', () => {
    it('should pass with valid signature', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        certificate: {
          enabled: true,
          publicKey: publicKey,
        },
      };

      const method = 'GET';
      const url = 'https://api.example.com/test';
      const timestamp = Date.now();
      const signature = CertificateValidator.sign(privateKey, method, url, undefined, timestamp);

      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method,
        url,
        signature,
        timestamp,
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(true);
      expect(result.layerResults).toHaveLength(1);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.CERTIFICATE);
      expect(result.layerResults[0]?.passed).toBe(true);
    });

    it('should fail with invalid signature', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        certificate: {
          enabled: true,
          publicKey: publicKey,
        },
      };

      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
        signature: 'invalid-signature',
        timestamp: Date.now(),
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.CERTIFICATE);
      expect(result.layerResults[0]?.passed).toBe(false);
    });

    it('should fail when signature is missing', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        certificate: {
          enabled: true,
          publicKey: publicKey,
        },
      };

      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
        timestamp: Date.now(),
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('signature is required');
    });
  });

  describe('authenticate - Multiple layers', () => {
    it('should pass all three layers', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        ipAllowlist: {
          enabled: true,
          allowedIps: ['192.168.1.0/24'],
        },
        totp: {
          enabled: true,
          secret: TEST_SECRET,
        },
        certificate: {
          enabled: true,
          publicKey: publicKey,
        },
      };

      const totpValidator = new TotpValidator({ enabled: true, secret: TEST_SECRET });
      const token = totpValidator.generate();

      const method = 'POST';
      const url = 'https://api.example.com/test';
      const body = JSON.stringify({ data: 'test' });
      const timestamp = Date.now();
      const signature = CertificateValidator.sign(privateKey, method, url, body, timestamp);

      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.100',
        method,
        url,
        body,
        totpToken: token,
        signature,
        timestamp,
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(true);
      expect(result.layerResults).toHaveLength(3);
      expect(result.layerResults.every((r) => r.passed)).toBe(true);
    });

    it('should fail fast on first layer failure', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        ipAllowlist: {
          enabled: true,
          allowedIps: ['192.168.1.0/24'],
        },
        totp: {
          enabled: true,
          secret: TEST_SECRET,
        },
      };

      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '10.0.0.1', // Wrong IP
        method: 'GET',
        url: 'https://api.example.com/test',
        totpToken: '123456',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.success).toBe(false);
      // Should only have IP layer result (fail-fast)
      expect(result.layerResults).toHaveLength(1);
      expect(result.layerResults[0]?.layer).toBe(SecurityLayer.IP_ALLOWLIST);
    });
  });

  describe('validation result metadata', () => {
    it('should include correlation ID', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.correlationId).toBeDefined();
      expect(result.correlationId).toMatch(/^qiuth_/);
    });

    it('should include validation time', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.validationTimeMs).toBeDefined();
      expect(result.validationTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should include validated timestamp', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.validatedAt).toBeInstanceOf(Date);
    });

    it('should include config on success', async () => {
      const authenticator = new QiuthAuthenticator();
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
      };
      const request: AuthenticationRequest = {
        apiKey: TEST_API_KEY,
        clientIp: '192.168.1.1',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);
      expect(result.config).toBeDefined();
      expect(result.config).toBe(config);
    });
  });
});


import { describe, it, expect } from 'vitest';
import { QiuthConfigBuilder, createConfig } from '../../src/config/config-builder';
import { QiuthAuthenticator } from '../../src/core/authenticator';

describe('QiuthConfigBuilder', () => {
  const TEST_API_KEY = 'test-api-key';
  const TEST_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const TEST_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----';

  describe('basic configuration', () => {
    it('should build config with API key', () => {
      const config = new QiuthConfigBuilder().withApiKey(TEST_API_KEY).build();

      expect(config.hashedApiKey).toBe(QiuthAuthenticator.hashApiKey(TEST_API_KEY));
    });

    it('should build config with hashed API key', () => {
      const hashedKey = QiuthAuthenticator.hashApiKey(TEST_API_KEY);
      const config = new QiuthConfigBuilder().withHashedApiKey(hashedKey).build();

      expect(config.hashedApiKey).toBe(hashedKey);
    });

    it('should throw error if API key is missing', () => {
      expect(() => new QiuthConfigBuilder().build()).toThrow('API key is required');
    });
  });

  describe('IP allowlist', () => {
    it('should configure IP allowlist', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlist(['192.168.1.0/24', '10.0.0.1'])
        .build();

      expect(config.ipAllowlist).toBeDefined();
      expect(config.ipAllowlist?.enabled).toBe(true);
      expect(config.ipAllowlist?.allowedIps).toEqual(['192.168.1.0/24', '10.0.0.1']);
      expect(config.ipAllowlist?.trustProxy).toBe(false);
    });

    it('should configure IP allowlist with trustProxy', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlist(['192.168.1.0/24'], true)
        .build();

      expect(config.ipAllowlist?.trustProxy).toBe(true);
    });

    it('should configure IP allowlist with full config', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlistConfig({
          enabled: true,
          allowedIps: ['192.168.1.0/24'],
          trustProxy: true,
        })
        .build();

      expect(config.ipAllowlist?.enabled).toBe(true);
      expect(config.ipAllowlist?.trustProxy).toBe(true);
    });

    it('should disable IP allowlist', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlist(['192.168.1.0/24'])
        .withoutIpAllowlist()
        .build();

      expect(config.ipAllowlist?.enabled).toBe(false);
    });
  });

  describe('TOTP', () => {
    it('should configure TOTP with defaults', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withTotp(TEST_SECRET)
        .build();

      expect(config.totp).toBeDefined();
      expect(config.totp?.enabled).toBe(true);
      expect(config.totp?.secret).toBe(TEST_SECRET);
      expect(config.totp?.timeStep).toBe(30);
      expect(config.totp?.window).toBe(1);
    });

    it('should configure TOTP with custom values', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withTotp(TEST_SECRET, 60, 2)
        .build();

      expect(config.totp?.timeStep).toBe(60);
      expect(config.totp?.window).toBe(2);
    });

    it('should configure TOTP with full config', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withTotpConfig({
          enabled: true,
          secret: TEST_SECRET,
          timeStep: 45,
          window: 3,
        })
        .build();

      expect(config.totp?.timeStep).toBe(45);
      expect(config.totp?.window).toBe(3);
    });

    it('should disable TOTP', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withTotp(TEST_SECRET)
        .withoutTotp()
        .build();

      expect(config.totp?.enabled).toBe(false);
    });
  });

  describe('Certificate', () => {
    it('should configure certificate with defaults', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withCertificate(TEST_PUBLIC_KEY)
        .build();

      expect(config.certificate).toBeDefined();
      expect(config.certificate?.enabled).toBe(true);
      expect(config.certificate?.publicKey).toBe(TEST_PUBLIC_KEY);
      expect(config.certificate?.maxAge).toBe(300);
    });

    it('should configure certificate with custom maxAge', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withCertificate(TEST_PUBLIC_KEY, 600)
        .build();

      expect(config.certificate?.maxAge).toBe(600);
    });

    it('should configure certificate with full config', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withCertificateConfig({
          enabled: true,
          publicKey: TEST_PUBLIC_KEY,
          maxAge: 120,
        })
        .build();

      expect(config.certificate?.maxAge).toBe(120);
    });

    it('should disable certificate', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withCertificate(TEST_PUBLIC_KEY)
        .withoutCertificate()
        .build();

      expect(config.certificate?.enabled).toBe(false);
    });
  });

  describe('fluent API', () => {
    it('should chain multiple configurations', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlist(['192.168.1.0/24'])
        .withTotp(TEST_SECRET)
        .withCertificate(TEST_PUBLIC_KEY)
        .build();

      expect(config.hashedApiKey).toBeDefined();
      expect(config.ipAllowlist?.enabled).toBe(true);
      expect(config.totp?.enabled).toBe(true);
      expect(config.certificate?.enabled).toBe(true);
    });
  });

  describe('from existing config', () => {
    it('should create builder from existing config', () => {
      const originalConfig = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlist(['192.168.1.0/24'])
        .build();

      const newConfig = QiuthConfigBuilder.from(originalConfig)
        .withTotp(TEST_SECRET)
        .build();

      expect(newConfig.hashedApiKey).toBe(originalConfig.hashedApiKey);
      expect(newConfig.ipAllowlist).toEqual(originalConfig.ipAllowlist);
      expect(newConfig.totp?.enabled).toBe(true);
    });
  });

  describe('validation', () => {
    it('should validate valid config', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withIpAllowlist(['192.168.1.0/24'])
        .build();

      expect(() => QiuthConfigBuilder.validate(config)).not.toThrow();
    });

    it('should throw on missing hashedApiKey', () => {
      const config = {} as any;
      expect(() => QiuthConfigBuilder.validate(config)).toThrow('hashedApiKey is required');
    });

    it('should throw on empty allowedIps when IP allowlist is enabled', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .build();
      config.ipAllowlist = { enabled: true, allowedIps: [] };

      expect(() => QiuthConfigBuilder.validate(config)).toThrow('allowedIps must contain at least one IP');
    });

    it('should throw on missing TOTP secret', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .build();
      config.totp = { enabled: true, secret: '' };

      expect(() => QiuthConfigBuilder.validate(config)).toThrow('secret is required');
    });

    it('should throw on invalid timeStep', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .withTotp(TEST_SECRET, -1)
        .build();

      expect(() => QiuthConfigBuilder.validate(config)).toThrow('timeStep must be positive');
    });

    it('should throw on missing certificate publicKey', () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(TEST_API_KEY)
        .build();
      config.certificate = { enabled: true, publicKey: '' };

      expect(() => QiuthConfigBuilder.validate(config)).toThrow('publicKey is required');
    });
  });

  describe('createConfig helper', () => {
    it('should create new builder', () => {
      const config = createConfig()
        .withApiKey(TEST_API_KEY)
        .build();

      expect(config.hashedApiKey).toBeDefined();
    });
  });
});


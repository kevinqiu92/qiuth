import { describe, it, expect } from 'vitest';
import { loadFromEnv, isConfigured, getConfiguredLayers } from '../../src/config/env-loader';
import { QiuthAuthenticator } from '../../src/core/authenticator';

describe('Environment Loader', () => {
  const TEST_API_KEY = 'test-api-key';
  const TEST_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const TEST_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----';

  describe('loadFromEnv', () => {
    it('should load config with API key', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
      };

      const config = loadFromEnv({ env });
      expect(config.hashedApiKey).toBe(QiuthAuthenticator.hashApiKey(TEST_API_KEY));
    });

    it('should load config with hashed API key', () => {
      const hashedKey = QiuthAuthenticator.hashApiKey(TEST_API_KEY);
      const env = {
        QIUTH_HASHED_API_KEY: hashedKey,
      };

      const config = loadFromEnv({ env });
      expect(config.hashedApiKey).toBe(hashedKey);
    });

    it('should prefer hashed API key over plain key', () => {
      const hashedKey = QiuthAuthenticator.hashApiKey(TEST_API_KEY);
      const env = {
        QIUTH_API_KEY: 'different-key',
        QIUTH_HASHED_API_KEY: hashedKey,
      };

      const config = loadFromEnv({ env });
      expect(config.hashedApiKey).toBe(hashedKey);
    });

    it('should throw if no API key is provided', () => {
      const env = {};
      expect(() => loadFromEnv({ env })).toThrow('Either QIUTH_API_KEY or QIUTH_HASHED_API_KEY must be set');
    });

    it('should load IP allowlist', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_IP_ALLOWLIST: '192.168.1.0/24,10.0.0.1',
      };

      const config = loadFromEnv({ env });
      expect(config.ipAllowlist).toBeDefined();
      expect(config.ipAllowlist?.enabled).toBe(true);
      expect(config.ipAllowlist?.allowedIps).toEqual(['192.168.1.0/24', '10.0.0.1']);
      expect(config.ipAllowlist?.trustProxy).toBe(false);
    });

    it('should load IP allowlist with trustProxy', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_IP_ALLOWLIST: '192.168.1.0/24',
        QIUTH_IP_TRUST_PROXY: 'true',
      };

      const config = loadFromEnv({ env });
      expect(config.ipAllowlist?.trustProxy).toBe(true);
    });

    it('should handle whitespace in IP allowlist', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_IP_ALLOWLIST: ' 192.168.1.0/24 , 10.0.0.1 ',
      };

      const config = loadFromEnv({ env });
      expect(config.ipAllowlist?.allowedIps).toEqual(['192.168.1.0/24', '10.0.0.1']);
    });

    it('should load TOTP config', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_TOTP_SECRET: TEST_SECRET,
      };

      const config = loadFromEnv({ env });
      expect(config.totp).toBeDefined();
      expect(config.totp?.enabled).toBe(true);
      expect(config.totp?.secret).toBe(TEST_SECRET);
      expect(config.totp?.timeStep).toBe(30);
      expect(config.totp?.window).toBe(1);
    });

    it('should load TOTP config with custom values', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_TOTP_SECRET: TEST_SECRET,
        QIUTH_TOTP_TIME_STEP: '60',
        QIUTH_TOTP_WINDOW: '2',
      };

      const config = loadFromEnv({ env });
      expect(config.totp?.timeStep).toBe(60);
      expect(config.totp?.window).toBe(2);
    });

    it('should load certificate config', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_CERTIFICATE_PUBLIC_KEY: TEST_PUBLIC_KEY,
      };

      const config = loadFromEnv({ env });
      expect(config.certificate).toBeDefined();
      expect(config.certificate?.enabled).toBe(true);
      expect(config.certificate?.publicKey).toBe(TEST_PUBLIC_KEY);
      expect(config.certificate?.maxAge).toBe(300);
    });

    it('should load certificate config with custom maxAge', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_CERTIFICATE_PUBLIC_KEY: TEST_PUBLIC_KEY,
        QIUTH_CERTIFICATE_MAX_AGE: '600',
      };

      const config = loadFromEnv({ env });
      expect(config.certificate?.maxAge).toBe(600);
    });

    it('should load all security layers', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_IP_ALLOWLIST: '192.168.1.0/24',
        QIUTH_TOTP_SECRET: TEST_SECRET,
        QIUTH_CERTIFICATE_PUBLIC_KEY: TEST_PUBLIC_KEY,
      };

      const config = loadFromEnv({ env });
      expect(config.hashedApiKey).toBeDefined();
      expect(config.ipAllowlist?.enabled).toBe(true);
      expect(config.totp?.enabled).toBe(true);
      expect(config.certificate?.enabled).toBe(true);
    });

    it('should use custom prefix', () => {
      const env = {
        CUSTOM_API_KEY: TEST_API_KEY,
      };

      const config = loadFromEnv({ env, prefix: 'CUSTOM_' });
      expect(config.hashedApiKey).toBeDefined();
    });

    it('should not hash API key when hashApiKey is false', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
      };

      const config = loadFromEnv({ env, hashApiKey: false });
      expect(config.hashedApiKey).toBe(TEST_API_KEY);
    });
  });

  describe('isConfigured', () => {
    it('should return true when API key is set', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
      };

      expect(isConfigured({ env })).toBe(true);
    });

    it('should return true when hashed API key is set', () => {
      const env = {
        QIUTH_HASHED_API_KEY: 'hashed-key',
      };

      expect(isConfigured({ env })).toBe(true);
    });

    it('should return false when no API key is set', () => {
      const env = {};
      expect(isConfigured({ env })).toBe(false);
    });

    it('should use custom prefix', () => {
      const env = {
        CUSTOM_API_KEY: TEST_API_KEY,
      };

      expect(isConfigured({ env, prefix: 'CUSTOM_' })).toBe(true);
    });
  });

  describe('getConfiguredLayers', () => {
    it('should return all layers as false when nothing is configured', () => {
      const env = {};
      const layers = getConfiguredLayers({ env });

      expect(layers.apiKey).toBe(false);
      expect(layers.ipAllowlist).toBe(false);
      expect(layers.totp).toBe(false);
      expect(layers.certificate).toBe(false);
    });

    it('should return true for configured layers', () => {
      const env = {
        QIUTH_API_KEY: TEST_API_KEY,
        QIUTH_IP_ALLOWLIST: '192.168.1.0/24',
        QIUTH_TOTP_SECRET: TEST_SECRET,
      };

      const layers = getConfiguredLayers({ env });
      expect(layers.apiKey).toBe(true);
      expect(layers.ipAllowlist).toBe(true);
      expect(layers.totp).toBe(true);
      expect(layers.certificate).toBe(false);
    });

    it('should use custom prefix', () => {
      const env = {
        CUSTOM_API_KEY: TEST_API_KEY,
      };

      const layers = getConfiguredLayers({ env, prefix: 'CUSTOM_' });
      expect(layers.apiKey).toBe(true);
    });
  });
});


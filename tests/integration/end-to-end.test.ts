import { describe, it, expect, beforeAll } from 'vitest';
import { QiuthAuthenticator } from '../../src/core/authenticator';
import { QiuthClient } from '../../src/client/qiuth-client';
import { QiuthConfigBuilder } from '../../src/config/config-builder';
import { CredentialRotator } from '../../src/rotation/credential-rotator';
import { MetricsCollector } from '../../src/observability/metrics';
import { Logger, LogLevel } from '../../src/observability/logger';
import { generateApiKey, generateTotpSecret, generateKeyPair } from '../../src/utils/crypto';
import { SecurityLayer, AuthenticationRequest } from '../../src/types';
import { TotpValidator } from '../../src/validators/totp-validator';
import { CertificateValidator } from '../../src/validators/certificate-validator';

describe('End-to-End Integration Tests', () => {
  let apiKey: string;
  let hashedApiKey: string;
  let totpSecret: string;
  let publicKey: string;
  let privateKey: string;

  beforeAll(() => {
    // Generate test credentials
    apiKey = generateApiKey();
    hashedApiKey = QiuthAuthenticator.hashApiKey(apiKey);
    totpSecret = generateTotpSecret();
    const keyPair = generateKeyPair({ modulusLength: 2048 });
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
  });

  describe('Full Authentication Flow', () => {
    it('should authenticate with all three security layers', async () => {
      const config = new QiuthConfigBuilder()
        .withHashedApiKey(hashedApiKey)
        .withIpAllowlist(['0.0.0.0/0']) // Allow all IPs for simplicity
        .withTotp(totpSecret)
        .withCertificate(publicKey)
        .build();

      const authenticator = new QiuthAuthenticator();
      const totpValidator = new TotpValidator({ enabled: true, secret: totpSecret, timeStep: 30, window: 1 });

      // Generate TOTP token
      const totp = totpValidator.generateToken();

      // Create signed request
      const timestamp = Date.now();
      const signature = CertificateValidator.sign(
        privateKey,
        'GET',
        'https://api.example.com/test',
        '',
        timestamp
      );

      const request: AuthenticationRequest = {
        apiKey,
        clientIp: '1.2.3.4',
        totpToken: totp,
        method: 'GET',
        url: 'https://api.example.com/test',
        timestamp: timestamp.toString(),
        signature,
      };

      const result = await authenticator.authenticate(request, config);

      // If it fails, log the errors for debugging
      if (!result.success) {
        console.log('Authentication failed:', result.errors);
        console.log('Layer results:', JSON.stringify(result.layerResults, null, 2));
      }

      expect(result.success).toBe(true);
      expect(result.layerResults).toHaveLength(3);
      expect(result.layerResults.every((r) => r.passed)).toBe(true);
    });

    it('should fail if any layer fails', async () => {
      const config = new QiuthConfigBuilder()
        .withHashedApiKey(hashedApiKey)
        .withIpAllowlist(['10.0.0.0/8'])
        .withTotp(totpSecret)
        .build();

      const authenticator = new QiuthAuthenticator();
      const totpValidator = new TotpValidator({ enabled: true, secret: totpSecret, timeStep: 30, window: 1 });
      const totp = totpValidator.generateToken();

      const request: AuthenticationRequest = {
        apiKey,
        clientIp: '192.168.1.100', // Not in allowlist
        totpToken: totp,
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('Credential Rotation Integration', () => {
    it('should support zero-downtime credential rotation', async () => {
      const oldApiKey = generateApiKey();
      const newApiKey = generateApiKey();

      const oldConfig = new QiuthConfigBuilder()
        .withApiKey(oldApiKey)
        .withIpAllowlist(['0.0.0.0/0'])
        .build();

      const newConfig = new QiuthConfigBuilder()
        .withApiKey(newApiKey)
        .withIpAllowlist(['0.0.0.0/0'])
        .build();

      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 60000,
        autoComplete: false,
      });

      // Start rotation
      rotator.startRotation(newConfig);

      // Old credentials should still work
      const oldRequest: AuthenticationRequest = {
        apiKey: oldApiKey,
        clientIp: '1.2.3.4',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const oldResult = await rotator.authenticate(oldRequest);
      expect(oldResult.success).toBe(true);
      expect(oldResult.credentialVersion).toBe('old');

      // New credentials should also work
      const newRequest: AuthenticationRequest = {
        apiKey: newApiKey,
        clientIp: '1.2.3.4',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const newResult = await rotator.authenticate(newRequest);
      expect(newResult.success).toBe(true);
      expect(newResult.credentialVersion).toBe('new');

      // Complete rotation
      rotator.completeRotation();

      // Old credentials should no longer work
      const oldResultAfter = await rotator.authenticate(oldRequest);
      expect(oldResultAfter.success).toBe(false);

      // New credentials should still work
      const newResultAfter = await rotator.authenticate(newRequest);
      expect(newResultAfter.success).toBe(true);

      rotator.destroy();
    });
  });

  describe('Observability Integration', () => {
    it('should collect metrics during authentication', async () => {
      const metrics = new MetricsCollector();
      const testApiKey = generateApiKey();
      const testHashedApiKey = QiuthAuthenticator.hashApiKey(testApiKey);

      const config = new QiuthConfigBuilder()
        .withApiKey(testApiKey)
        .withIpAllowlist(['0.0.0.0/0'])
        .build();

      const authenticator = new QiuthAuthenticator();

      // Perform multiple authentications
      for (let i = 0; i < 10; i++) {
        const request: AuthenticationRequest = {
          apiKey: testApiKey,
          clientIp: '1.2.3.4',
          method: 'GET',
          url: 'https://api.example.com/test',
        };

        const startTime = Date.now();
        const result = await authenticator.authenticate(request, config);
        const duration = Date.now() - startTime;

        metrics.recordAuthentication({
          success: result.success,
          layers: [SecurityLayer.IP_ALLOWLIST],
          duration,
          timestamp: new Date(),
        });
      }

      const summary = metrics.getSummary();
      expect(summary.totalAttempts).toBe(10);
      expect(summary.successfulAttempts).toBe(10);
      expect(summary.successRate).toBe(1.0);
      expect(summary.averageDuration).toBeGreaterThanOrEqual(0);
    });

    it('should log authentication events', async () => {
      const logs: any[] = [];
      const logger = new Logger({
        level: LogLevel.DEBUG,
        handler: (entry) => logs.push(entry),
      });

      const config = new QiuthConfigBuilder()
        .withApiKey(hashedApiKey)
        .withIpAllowlist(['0.0.0.0/0'])
        .build();

      const authenticator = new QiuthAuthenticator();

      logger.info('Starting authentication', { apiKey: 'hidden' });

      const request: AuthenticationRequest = {
        apiKey,
        clientIp: '1.2.3.4',
        method: 'GET',
        url: 'https://api.example.com/test',
      };

      const result = await authenticator.authenticate(request, config);

      if (result.success) {
        logger.info('Authentication successful', {
          layers: result.layerResults.map((r) => r.layer),
        });
      } else {
        logger.error('Authentication failed', { errors: result.errors });
      }

      expect(logs.length).toBeGreaterThan(0);
      expect(logs.some((log) => log.message.includes('Authentication'))).toBe(true);
    });
  });

  describe('Configuration Builder Integration', () => {
    it('should build complex configurations', () => {
      const testApiKey = generateApiKey();

      const config = new QiuthConfigBuilder()
        .withApiKey(testApiKey)
        .withIpAllowlist(['192.168.1.0/24', '10.0.0.0/8'])
        .withTotp(totpSecret, 30, 2)
        .withCertificate(publicKey, 300000)
        .build();

      expect(config.hashedApiKey).toBe(QiuthAuthenticator.hashApiKey(testApiKey));
      expect(config.ipAllowlist?.enabled).toBe(true);
      expect(config.ipAllowlist?.allowedIps).toHaveLength(2);
      expect(config.totp?.enabled).toBe(true);
      expect(config.totp?.window).toBe(2);
      expect(config.certificate?.enabled).toBe(true);
      expect(config.certificate?.maxAge).toBe(300000);
    });
  });

  describe('Client Integration', () => {
    it('should create authenticated client', () => {
      const client = new QiuthClient({
        baseUrl: 'https://api.example.com',
        apiKey,
        totpSecret,
        privateKey,
      });

      expect(client).toBeDefined();
    });
  });

  describe('Performance Tests', () => {
    it('should handle high-volume authentication', async () => {
      const config = new QiuthConfigBuilder()
        .withApiKey(hashedApiKey)
        .withIpAllowlist(['0.0.0.0/0'])
        .build();

      const authenticator = new QiuthAuthenticator();
      const iterations = 100;
      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        const request: AuthenticationRequest = {
          apiKey,
          clientIp: '1.2.3.4',
          method: 'GET',
          url: 'https://api.example.com/test',
        };

        await authenticator.authenticate(request, config);
      }

      const duration = Date.now() - startTime;
      const avgTime = duration / iterations;

      // Should average less than 10ms per authentication
      expect(avgTime).toBeLessThan(10);
    });
  });
});


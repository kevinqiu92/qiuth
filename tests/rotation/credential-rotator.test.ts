import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CredentialRotator, CredentialRotationState } from '../../src/rotation/credential-rotator';
import { QiuthConfig, AuthenticationRequest } from '../../src/types';
import { QiuthAuthenticator } from '../../src/core/authenticator';

describe('CredentialRotator', () => {
  const OLD_API_KEY = 'old-api-key';
  const NEW_API_KEY = 'new-api-key';

  const oldConfig: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(OLD_API_KEY),
    ipAllowlist: {
      enabled: true,
      allowedIps: ['192.168.1.0/24'],
    },
  };

  const newConfig: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(NEW_API_KEY),
    ipAllowlist: {
      enabled: true,
      allowedIps: ['192.168.1.0/24'],
    },
  };

  const createRequest = (apiKey: string): AuthenticationRequest => ({
    apiKey,
    clientIp: '192.168.1.100',
    method: 'GET',
    url: 'https://api.example.com/test',
  });

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('should create rotator with initial config', () => {
      const rotator = new CredentialRotator(oldConfig);
      expect(rotator.getState()).toBe(CredentialRotationState.ACTIVE);
      expect(rotator.isRotating()).toBe(false);
    });

    it('should accept rotation config', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 3600000,
        autoComplete: false,
      });
      expect(rotator).toBeDefined();
    });
  });

  describe('startRotation', () => {
    it('should start rotation', () => {
      const rotator = new CredentialRotator(oldConfig);
      const metadata = rotator.startRotation(newConfig);

      expect(metadata.state).toBe(CredentialRotationState.ROTATING);
      expect(metadata.startedAt).toBeInstanceOf(Date);
      expect(metadata.completesAt).toBeInstanceOf(Date);
      expect(metadata.oldConfig).toEqual(oldConfig);
      expect(metadata.newConfig).toEqual(newConfig);
    });

    it('should throw if rotation already in progress', () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);

      expect(() => rotator.startRotation(newConfig)).toThrow('Rotation already in progress');
    });

    it('should call onRotationStart callback', () => {
      const onRotationStart = vi.fn();
      const rotator = new CredentialRotator(oldConfig, { onRotationStart });

      rotator.startRotation(newConfig);
      expect(onRotationStart).toHaveBeenCalledWith(oldConfig, newConfig);
    });

    it('should schedule auto-completion', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 1000,
        autoComplete: true,
      });

      rotator.startRotation(newConfig);
      expect(rotator.isRotating()).toBe(true);

      vi.advanceTimersByTime(1000);
      expect(rotator.getState()).toBe(CredentialRotationState.ROTATED);

      rotator.destroy();
    });

    it('should not auto-complete if disabled', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 1000,
        autoComplete: false,
      });

      rotator.startRotation(newConfig);
      vi.advanceTimersByTime(1000);
      expect(rotator.getState()).toBe(CredentialRotationState.ROTATING);

      rotator.destroy();
    });
  });

  describe('completeRotation', () => {
    it('should complete rotation', () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);

      const metadata = rotator.completeRotation();
      expect(metadata.state).toBe(CredentialRotationState.ROTATED);
      expect(metadata.completedAt).toBeInstanceOf(Date);
      expect(metadata.oldConfig).toBeUndefined();
    });

    it('should throw if no rotation in progress', () => {
      const rotator = new CredentialRotator(oldConfig);
      expect(() => rotator.completeRotation()).toThrow('No rotation in progress');
    });

    it('should call onRotationComplete callback', () => {
      const onRotationComplete = vi.fn();
      const rotator = new CredentialRotator(oldConfig, { onRotationComplete });

      rotator.startRotation(newConfig);
      rotator.completeRotation();

      expect(onRotationComplete).toHaveBeenCalledWith(newConfig);
    });

    it('should clear auto-completion timer', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 10000,
        autoComplete: true,
      });

      rotator.startRotation(newConfig);
      rotator.completeRotation();

      // Timer should be cleared, so advancing time shouldn't do anything
      vi.advanceTimersByTime(10000);
      expect(rotator.getState()).toBe(CredentialRotationState.ROTATED);

      rotator.destroy();
    });
  });

  describe('revokeCredentials', () => {
    it('should revoke credentials', () => {
      const rotator = new CredentialRotator(oldConfig);
      const metadata = rotator.revokeCredentials('Security breach');

      expect(metadata.state).toBe(CredentialRotationState.REVOKED);
      expect(metadata.revocationReason).toBe('Security breach');
    });

    it('should call onRotationRevoke callback', () => {
      const onRotationRevoke = vi.fn();
      const rotator = new CredentialRotator(oldConfig, { onRotationRevoke });

      rotator.revokeCredentials('Test revocation');
      expect(onRotationRevoke).toHaveBeenCalledWith('Test revocation');
    });

    it('should clear auto-completion timer', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 10000,
        autoComplete: true,
      });

      rotator.startRotation(newConfig);
      rotator.revokeCredentials('Emergency');

      vi.advanceTimersByTime(10000);
      expect(rotator.getState()).toBe(CredentialRotationState.REVOKED);

      rotator.destroy();
    });
  });

  describe('authenticate', () => {
    it('should authenticate with new credentials when active', async () => {
      const rotator = new CredentialRotator(oldConfig);
      const request = createRequest(OLD_API_KEY);

      const result = await rotator.authenticate(request);
      expect(result.success).toBe(true);
    });

    it('should authenticate with new credentials during rotation', async () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);

      const request = createRequest(NEW_API_KEY);
      const result = await rotator.authenticate(request);

      expect(result.success).toBe(true);
      expect(result.credentialVersion).toBe('new');
    });

    it('should authenticate with old credentials during rotation', async () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);

      const request = createRequest(OLD_API_KEY);
      const result = await rotator.authenticate(request);

      expect(result.success).toBe(true);
      expect(result.credentialVersion).toBe('old');
      expect(result.warning).toContain('old credentials');
    });

    it('should reject old credentials after rotation completes', async () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);
      rotator.completeRotation();

      const request = createRequest(OLD_API_KEY);
      const result = await rotator.authenticate(request);

      expect(result.success).toBe(false);
    });

    it('should reject all credentials when revoked', async () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.revokeCredentials('Test');

      const request = createRequest(OLD_API_KEY);
      const result = await rotator.authenticate(request);

      expect(result.success).toBe(false);
      expect(result.errors).toContain('Credentials have been revoked');
    });
  });

  describe('getTimeRemaining', () => {
    it('should return 0 when not rotating', () => {
      const rotator = new CredentialRotator(oldConfig);
      expect(rotator.getTimeRemaining()).toBe(0);
    });

    it('should return time remaining during rotation', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 10000,
      });

      rotator.startRotation(newConfig);
      expect(rotator.getTimeRemaining()).toBeGreaterThan(9000);

      vi.advanceTimersByTime(5000);
      expect(rotator.getTimeRemaining()).toBeGreaterThan(4000);
      expect(rotator.getTimeRemaining()).toBeLessThan(6000);

      rotator.destroy();
    });

    it('should return 0 after rotation completes', () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);
      rotator.completeRotation();

      expect(rotator.getTimeRemaining()).toBe(0);
    });
  });

  describe('cancelRotation', () => {
    it('should cancel rotation and revert to old config', () => {
      const rotator = new CredentialRotator(oldConfig);
      rotator.startRotation(newConfig);

      const metadata = rotator.cancelRotation();
      expect(metadata.state).toBe(CredentialRotationState.ACTIVE);
      expect(metadata.newConfig).toEqual(oldConfig);
    });

    it('should throw if no rotation in progress', () => {
      const rotator = new CredentialRotator(oldConfig);
      expect(() => rotator.cancelRotation()).toThrow('No rotation in progress');
    });

    it('should clear auto-completion timer', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 10000,
        autoComplete: true,
      });

      rotator.startRotation(newConfig);
      rotator.cancelRotation();

      vi.advanceTimersByTime(10000);
      expect(rotator.getState()).toBe(CredentialRotationState.ACTIVE);

      rotator.destroy();
    });
  });

  describe('getMetadata', () => {
    it('should return rotation metadata', () => {
      const rotator = new CredentialRotator(oldConfig);
      const metadata = rotator.getMetadata();

      expect(metadata.state).toBe(CredentialRotationState.ACTIVE);
      expect(metadata.newConfig).toEqual(oldConfig);
    });

    it('should return copy of metadata', () => {
      const rotator = new CredentialRotator(oldConfig);
      const metadata1 = rotator.getMetadata();
      const metadata2 = rotator.getMetadata();

      expect(metadata1).not.toBe(metadata2);
      expect(metadata1).toEqual(metadata2);
    });
  });

  describe('destroy', () => {
    it('should clean up resources', () => {
      const rotator = new CredentialRotator(oldConfig, {
        transitionPeriod: 10000,
        autoComplete: true,
      });

      rotator.startRotation(newConfig);
      rotator.destroy();

      // Timer should be cleared
      vi.advanceTimersByTime(10000);
      expect(rotator.getState()).toBe(CredentialRotationState.ROTATING);
    });
  });
});


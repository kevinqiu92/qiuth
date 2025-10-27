import { describe, it, expect, vi } from 'vitest';
import { createQiuthMiddleware, QiuthRequest } from '../../src/middleware/express';
import { QiuthConfig } from '../../src/types';
import { QiuthAuthenticator } from '../../src/core/authenticator';
import { Request, Response, NextFunction } from 'express';

describe('Express Middleware', () => {
  const TEST_API_KEY = 'test-api-key-12345';
  const TEST_CONFIG: QiuthConfig = {
    hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
    ipAllowlist: {
      enabled: true,
      allowedIps: ['192.168.1.0/24'],
    },
  };

  function createMockRequest(overrides: Partial<Request> = {}): Request {
    return {
      headers: {},
      query: {},
      body: undefined,
      method: 'GET',
      url: '/test',
      originalUrl: '/test',
      protocol: 'https',
      ip: '192.168.1.100',
      socket: { remoteAddress: '192.168.1.100' },
      get: (name: string) => {
        if (name === 'host') return 'api.example.com';
        return undefined;
      },
      ...overrides,
    } as Request;
  }

  function createMockResponse(): Response {
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    };
    return res as unknown as Response;
  }

  function createMockNext(): NextFunction {
    return vi.fn() as NextFunction;
  }

  describe('API key extraction', () => {
    it('should extract API key from header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
      expect(next).toHaveBeenCalled();
    });

    it('should extract API key from custom header', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({
        configLookup,
        apiKeyHeader: 'authorization',
      });

      const req = createMockRequest({
        headers: { authorization: TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should extract API key from query when allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({
        configLookup,
        allowQueryKey: true,
      });

      const req = createMockRequest({
        query: { api_key: TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should not extract API key from query when not allowed', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({
        configLookup,
        allowQueryKey: false,
      });

      const req = createMockRequest({
        query: { api_key: TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Authentication failed',
        })
      );
    });

    it('should return 401 when API key is missing', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest();
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'API key is required',
        })
      );
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('configuration lookup', () => {
    it('should call configLookup with API key', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(configLookup).toHaveBeenCalledWith(TEST_API_KEY);
    });

    it('should return 401 when config is not found', async () => {
      const configLookup = vi.fn().mockResolvedValue(null);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': 'unknown-key' },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid API key',
        })
      );
    });

    it('should handle synchronous configLookup', async () => {
      const configLookup = vi.fn().mockReturnValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('authentication', () => {
    it('should authenticate successfully with valid credentials', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        ip: '192.168.1.100',
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as QiuthRequest).qiuth).toBeDefined();
      expect((req as QiuthRequest).qiuth?.result.success).toBe(true);
    });

    it('should fail authentication with invalid IP', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        ip: '10.0.0.1', // Not in allowlist
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should attach qiuth object to request on success', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      const qiuthReq = req as QiuthRequest;
      expect(qiuthReq.qiuth).toBeDefined();
      expect(qiuthReq.qiuth?.apiKey).toBe(TEST_API_KEY);
      expect(qiuthReq.qiuth?.config).toBe(TEST_CONFIG);
      expect(qiuthReq.qiuth?.result).toBeDefined();
    });
  });

  describe('custom handlers', () => {
    it('should call custom error handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onError = vi.fn();
      const middleware = createQiuthMiddleware({ configLookup, onError });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        ip: '10.0.0.1', // Invalid IP
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(onError).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should call custom success handler', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const onSuccess = vi.fn();
      const middleware = createQiuthMiddleware({ configLookup, onSuccess });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(onSuccess).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('request parsing', () => {
    it('should extract TOTP token from header', async () => {
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        totp: {
          enabled: true,
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        },
      };
      const configLookup = vi.fn().mockResolvedValue(config);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-totp-token': '123456',
        },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      // Should fail because token is invalid, but it was extracted
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should extract signature and timestamp from headers', async () => {
      const config: QiuthConfig = {
        hashedApiKey: QiuthAuthenticator.hashApiKey(TEST_API_KEY),
        certificate: {
          enabled: true,
          publicKey: 'dummy-key',
        },
      };
      const configLookup = vi.fn().mockResolvedValue(config);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: {
          'x-api-key': TEST_API_KEY,
          'x-signature': 'dummy-signature',
          'x-timestamp': Date.now().toString(),
        },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      // Should fail because signature is invalid, but it was extracted
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('should serialize JSON body', async () => {
      const configLookup = vi.fn().mockResolvedValue(TEST_CONFIG);
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
        body: { data: 'test' },
        method: 'POST',
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle internal errors gracefully', async () => {
      const configLookup = vi.fn().mockRejectedValue(new Error('Database error'));
      const middleware = createQiuthMiddleware({ configLookup });

      const req = createMockRequest({
        headers: { 'x-api-key': TEST_API_KEY },
      });
      const res = createMockResponse();
      const next = createMockNext();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Authentication failed',
        })
      );
    });
  });
});


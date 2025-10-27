import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { QiuthClient } from '../../src/client/qiuth-client';
import { generateKeyPairSync } from 'node:crypto';

describe('QiuthClient', () => {
  const TEST_API_KEY = 'test-api-key';
  const TEST_BASE_URL = 'https://api.example.com';
  const TEST_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  let publicKey: string;
  let privateKey: string;

  beforeEach(() => {
    const { publicKey: pubKey, privateKey: privKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    publicKey = pubKey;
    privateKey = privKey;

    // Mock fetch
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create client with minimal options', () => {
      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });
      expect(client).toBeDefined();
    });

    it('should create client with all options', () => {
      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
        totpSecret: TEST_SECRET,
        privateKey: privateKey,
        headers: { 'custom-header': 'value' },
        timeout: 5000,
        retries: 5,
        retryDelay: 2000,
      });
      expect(client).toBeDefined();
    });

    it('should remove trailing slash from baseUrl', () => {
      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: 'https://api.example.com/',
      });
      expect(client).toBeDefined();
    });
  });

  describe('HTTP methods', () => {
    it('should make GET request', async () => {
      const mockResponse = { data: 'test' };
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Map([['content-type', 'application/json']]),
        json: async () => mockResponse,
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      const response = await client.get('/users');
      expect(response.data).toEqual(mockResponse);
      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users',
        expect.objectContaining({
          method: 'GET',
        })
      );
    });

    it('should make POST request with body', async () => {
      const mockResponse = { id: 1 };
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 201,
        statusText: 'Created',
        headers: new Map([['content-type', 'application/json']]),
        json: async () => mockResponse,
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      const body = { name: 'John' };
      const response = await client.post('/users', body);
      expect(response.data).toEqual(mockResponse);
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(body),
        })
      );
    });

    it('should make PUT request', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      await client.put('/users/1', { name: 'Jane' });
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users/1',
        expect.objectContaining({
          method: 'PUT',
        })
      );
    });

    it('should make PATCH request', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      await client.patch('/users/1', { name: 'Jane' });
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users/1',
        expect.objectContaining({
          method: 'PATCH',
        })
      );
    });

    it('should make DELETE request', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 204,
        headers: new Map(),
        text: async () => '',
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      await client.delete('/users/1');
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users/1',
        expect.objectContaining({
          method: 'DELETE',
        })
      );
    });
  });

  describe('authentication headers', () => {
    it('should include API key header', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      await client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-api-key': TEST_API_KEY,
          }),
        })
      );
    });

    it('should include TOTP token when secret is provided', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
        totpSecret: TEST_SECRET,
      });

      await client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-totp-token': expect.stringMatching(/^\d{6}$/),
          }),
        })
      );
    });

    it('should include signature when private key is provided', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
        privateKey: privateKey,
      });

      await client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-signature': expect.any(String),
            'x-timestamp': expect.any(String),
          }),
        })
      );
    });

    it('should include custom headers', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
        headers: { 'custom-header': 'value' },
      });

      await client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'custom-header': 'value',
          }),
        })
      );
    });
  });

  describe('query parameters', () => {
    it('should append query parameters to URL', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({}),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      await client.get('/users', { params: { page: '1', limit: '10' } });
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users?page=1&limit=10',
        expect.any(Object)
      );
    });
  });

  describe('error handling', () => {
    it('should throw error on HTTP error status', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({ error: 'Not found' }),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      await expect(client.get('/users/999')).rejects.toThrow('HTTP 404');
    });

    it('should not retry on 4xx errors', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        headers: new Map([['content-type', 'application/json']]),
        json: async () => ({ error: 'Unauthorized' }),
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
        retries: 3,
      });

      await expect(client.get('/test')).rejects.toThrow();
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should retry on 5xx errors', async () => {
      (global.fetch as ReturnType<typeof vi.fn>)
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          headers: new Map([['content-type', 'application/json']]),
          json: async () => ({ error: 'Server error' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Map([['content-type', 'application/json']]),
          json: async () => ({ data: 'success' }),
        });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
        retries: 3,
        retryDelay: 10,
      });

      const response = await client.get('/test');
      expect(response.data).toEqual({ data: 'success' });
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('response parsing', () => {
    it('should parse JSON response', async () => {
      const mockData = { id: 1, name: 'Test' };
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        json: async () => mockData,
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      const response = await client.get('/test');
      expect(response.data).toEqual(mockData);
    });

    it('should parse text response', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([['content-type', 'text/plain']]),
        text: async () => 'plain text',
      });

      const client = new QiuthClient({
        apiKey: TEST_API_KEY,
        baseUrl: TEST_BASE_URL,
      });

      const response = await client.get('/test');
      expect(response.data).toBe('plain text');
    });
  });
});


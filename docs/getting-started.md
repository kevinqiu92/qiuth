# Getting Started with Qiuth

Qiuth (pronounced "cue-ith") is a TypeScript SDK that transforms API keys from simple bearer tokens into multi-factor authenticated credentials. This guide will help you get started quickly.

## Installation

```bash
npm install qiuth
# or
yarn add qiuth
# or
pnpm add qiuth
```

## Quick Start

### 1. Basic API Key Authentication

The simplest use case - just validate API keys:

```typescript
import { QiuthAuthenticator, QiuthConfigBuilder } from 'qiuth';

// Create configuration
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .build();

// Create authenticator
const authenticator = new QiuthAuthenticator();

// Authenticate a request
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);

if (result.success) {
  console.log('Authentication successful!');
} else {
  console.error('Authentication failed:', result.errors);
}
```

### 2. Add IP Allowlisting

Restrict API key usage to specific IP addresses or ranges:

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withIpAllowlist([
    '192.168.1.0/24',  // CIDR notation
    '10.0.0.1',        // Single IP
    '2001:db8::/32',   // IPv6 support
  ])
  .build();
```

### 3. Add TOTP-based MFA

Require time-based one-time passwords for service accounts:

```typescript
import { generateTotpSecret } from 'qiuth';

// Generate a secret (do this once, store securely)
const totpSecret = generateTotpSecret();
console.log('TOTP Secret:', totpSecret);

// Configure with TOTP
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withTotp(totpSecret, 30, 1) // timeStep=30s, window=1
  .build();

// Client must provide TOTP token
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  totpToken: '123456', // 6-digit TOTP code
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);
```

### 4. Add Certificate-based Authentication

Require cryptographic proof of private key possession:

```typescript
import { generateKeyPair } from 'qiuth';

// Generate key pair (do this once)
const { publicKey, privateKey } = generateKeyPair({ modulusLength: 2048 });

// Server configuration
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key-here')
  .withCertificate(publicKey, 300) // maxAge=300 seconds
  .build();

// Client signs requests
import { CertificateValidator } from 'qiuth';

const timestamp = Date.now();
const signature = CertificateValidator.sign(
  privateKey,
  'GET',
  'https://api.example.com/resource',
  '', // request body (empty for GET)
  timestamp
);

// Authenticate with signature
const result = await authenticator.authenticate({
  apiKey: 'user-provided-api-key',
  clientIp: '192.168.1.100',
  method: 'GET',
  url: 'https://api.example.com/resource',
  timestamp: timestamp.toString(),
  signature,
}, config);
```

## Express Middleware

Qiuth provides Express middleware for easy integration:

```typescript
import express from 'express';
import { createQiuthMiddleware } from 'qiuth';

const app = express();

// Create middleware
const qiuthAuth = createQiuthMiddleware({
  config: new QiuthConfigBuilder()
    .withApiKey('your-api-key-here')
    .withIpAllowlist(['0.0.0.0/0'])
    .build(),
  onSuccess: (req, res, result) => {
    console.log('Auth successful:', result);
  },
  onFailure: (req, res, result) => {
    console.error('Auth failed:', result.errors);
  },
});

// Apply to routes
app.get('/api/protected', qiuthAuth, (req, res) => {
  res.json({ message: 'Access granted!' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Client Library

Use the QiuthClient for making authenticated requests:

```typescript
import { QiuthClient } from 'qiuth';

const client = new QiuthClient({
  baseUrl: 'https://api.example.com',
  apiKey: 'your-api-key',
  totpSecret: 'your-totp-secret', // optional
  privateKey: 'your-private-key', // optional
});

// Make authenticated requests
const response = await client.get('/resource');
console.log(response);

// POST with body
const created = await client.post('/resource', {
  name: 'New Resource',
  value: 42,
});
```

## CLI Tool

Generate credentials using the CLI:

```bash
# Generate API key
npx qiuth generate api-key

# Generate TOTP secret
npx qiuth generate totp

# Generate RSA key pair
npx qiuth generate keypair --bits 2048

# Generate all credentials at once
npx qiuth generate all
```

## Environment Variables

Load configuration from environment variables:

```typescript
import { loadConfigFromEnv } from 'qiuth';

// Set environment variables:
// QIUTH_API_KEY=your-api-key
// QIUTH_IP_ALLOWLIST=192.168.1.0/24,10.0.0.1
// QIUTH_TOTP_SECRET=BASE32SECRET
// QIUTH_CERTIFICATE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----...

const config = loadConfigFromEnv();
const authenticator = new QiuthAuthenticator();
```

## Next Steps

- Read the [Configuration Guide](./configuration.md) for detailed configuration options
- Learn about [Security Best Practices](./security-best-practices.md)
- Explore [Example Applications](../examples/)
- Check out the [API Reference](./api-reference.md)
- Review [Troubleshooting](./troubleshooting.md) for common issues

## Common Patterns

### All Three Layers

For maximum security, use all three authentication layers:

```typescript
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp(totpSecret)
  .withCertificate(publicKey)
  .build();
```

### Credential Rotation

Rotate credentials with zero downtime:

```typescript
import { CredentialRotator } from 'qiuth';

const rotator = new CredentialRotator(oldConfig, {
  transitionPeriod: 3600000, // 1 hour
  autoComplete: true,
});

// Start rotation
rotator.startRotation(newConfig);

// Both old and new credentials work during transition
// After transition period, only new credentials work
```

### Observability

Track authentication metrics and logs:

```typescript
import { MetricsCollector, Logger, LogLevel } from 'qiuth';

const metrics = new MetricsCollector();
const logger = new Logger({ level: LogLevel.INFO });

// Record authentication events
metrics.recordAuthentication({
  success: result.success,
  layers: [SecurityLayer.IP_ALLOWLIST, SecurityLayer.TOTP_MFA],
  duration: 15,
  timestamp: new Date(),
});

// Get summary
const summary = metrics.getSummary();
console.log(`Success rate: ${summary.successRate * 100}%`);
```

## Support

- **GitHub Issues**: https://github.com/clay-good/qiuth/issues
- **Documentation**: https://github.com/clay-good/qiuth/tree/main/docs
- **Examples**: https://github.com/clay-good/qiuth/tree/main/examples


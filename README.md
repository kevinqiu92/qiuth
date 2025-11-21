# 🔐 Qiuth

**Multi-Factor Authentication for API Keys** - Stop treating API keys like passwords.

> **Qiuth** transforms API keys from bearer tokens into proof-of-possession tokens, requiring multiple authentication factors to prevent unauthorized access even if your API key is leaked.

Pronounced **chew-auth**. Inspired by [Kevin Qiu](https://www.linkedin.com/in/kevinmqiu)

---

## 🚨 The Problem

**API keys are single points of failure.** If your API key is leaked (committed to GitHub, intercepted in transit, stolen from logs), an attacker has **unlimited access** to your API.

```bash
# Your .env file accidentally committed to GitHub
API_KEY=sk_live_abc123def456

# Attacker finds it and has full access
curl -H "Authorization: Bearer sk_live_abc123def456" https://api.yourapp.com/data
# ✅ Success - Attacker downloads all your data
```

**This happens more often than you think:**
- 🔴 Thousands of API keys leaked on GitHub every day
- 🔴 `.env` files accidentally committed to public repos
- 🔴 API keys logged in error messages or monitoring tools
- 🔴 Keys intercepted in transit or stolen from compromised systems
- 🔴 Even with key pairs, if the private key is leaked, it's game over

---

## ✨ The Solution

**Qiuth adds multi-factor authentication to your API keys**, transforming them from bearer tokens (anyone with the key can use it) into **proof-of-possession tokens** (you need the key PLUS additional factors).

### Three Layers of Defense

1. **🌐 IP Allowlisting** - First line of defense
   - Verify requests come from authorized locations
   - Support for IPv4/IPv6 CIDR notation
   - Blocks unauthorized networks immediately

2. **🔢 TOTP MFA** - Time-based one-time passwords
   - Works for service accounts (programmatic)
   - Tokens change every 30 seconds
   - Even if API key is leaked, attacker needs TOTP secret

3. **🔑 Certificate Authentication** - Cryptographic proof
   - Requires private key to sign each request
   - Prevents replay attacks with timestamp validation
   - Even if API key + TOTP are leaked, attacker needs private key

### Real-World Impact

**After Qiuth:**
```bash
# API key leaked in GitHub
API_KEY=sk_live_abc123def456

# Attacker tries to use it
curl -H "X-API-Key: sk_live_abc123def456" https://api.yourapp.com/data
# ❌ 401 Unauthorized - IP not in allowlist

# Attacker would need ALL THREE:
# 1. API key (leaked)
# 2. TOTP secret (stored separately)
# 3. Private key (never leaves secure environment)
# = Virtually impossible to compromise
```

---

## 🎯 Quick Start

### Installation

```bash
npm install qiuth
```

### Basic Usage

```typescript
import { QiuthConfigBuilder, QiuthAuthenticator } from 'qiuth';

// Configure security layers
const config = new QiuthConfigBuilder()
  .withApiKey('your-api-key')
  .withIpAllowlist(['192.168.1.0/24'])
  .withTotp('your-totp-secret')
  .build();

// Authenticate requests
const authenticator = new QiuthAuthenticator();
const result = await authenticator.authenticate({
  apiKey: 'user-provided-key',
  clientIp: '192.168.1.100',
  totpToken: '123456',
  method: 'GET',
  url: 'https://api.example.com/resource',
}, config);

if (result.success) {
  console.log('✅ Authentication successful!');
} else {
  console.error('❌ Authentication failed:', result.errors);
}
```

### Express Middleware

```typescript
import express from 'express';
import { createQiuthMiddleware, QiuthConfigBuilder } from 'qiuth';

const app = express();

const qiuthAuth = createQiuthMiddleware({
  config: new QiuthConfigBuilder()
    .withApiKey('your-api-key')
    .withIpAllowlist(['0.0.0.0/0'])
    .withTotp('your-totp-secret')
    .build(),
});

app.get('/api/protected', qiuthAuth, (req, res) => {
  res.json({ message: 'Access granted!' });
});
```

---

## 🎬 Interactive Demo

**See Qiuth in action in 5 minutes!**

```bash
# Clone the repo
git clone https://github.com/clay-good/qiuth.git
cd qiuth

# Install dependencies
npm install

# Start the interactive demo
npm run demo
```

The demo server will start and display test credentials. Open a new terminal and try the test commands to see all three security layers in action!

**What you'll experience:**
- ✅ Level 1: Basic API key authentication
- ✅ Level 2: API key + IP allowlisting
- ✅ Level 3: API key + IP + TOTP MFA
- ✅ Level 4: Full security (all three layers)
- ❌ Failure scenarios (wrong credentials, expired tokens, invalid signatures)

[**📖 Full Demo Guide →**](./demo/README.md)

---

## 🚀 Features

### Security
- ✅ **Three-layer authentication** - IP, TOTP, and certificate-based
- ✅ **Fail-fast validation** - Stop at first failure for performance
- ✅ **Replay attack prevention** - Timestamp validation
- ✅ **Secure credential generation** - Cryptographically secure random generation
- ✅ **API key hashing** - SHA-256 for secure storage

### Developer Experience
- ✅ **TypeScript-first** - Full type definitions included
- ✅ **Fluent API** - Intuitive configuration builder
- ✅ **Express middleware** - Drop-in authentication
- ✅ **HTTP client** - Automatic request signing
- ✅ **CLI tool** - Generate credentials easily

### Production Ready
- ✅ **Zero-downtime credential rotation** - Transition periods for updates
- ✅ **Structured logging** - Comprehensive observability
- ✅ **Metrics collection** - Track authentication performance
- ✅ **Environment configuration** - Load from env vars
- ✅ **Comprehensive error handling** - Detailed error messages

### Build & Distribution
- ✅ **Dual module support** - ESM and CommonJS
- ✅ **Tree-shakeable** - Import only what you need
- ✅ **Zero dependencies** - Only Node.js built-ins
- ✅ **Well-tested** - 318 tests with 90%+ coverage

---

## 🎯 Use Cases

### 1. Service-to-Service Authentication
Secure microservices communication with MFA:
```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(process.env.API_KEY)
  .withIpAllowlist(['10.0.0.0/8']) // Internal network
  .withTotp(process.env.TOTP_SECRET)
  .build();
```

### 2. API Key Management
Add MFA to your existing API key system:
```typescript
app.use('/api', createQiuthMiddleware({ config }));
```

### 3. Compliance Requirements
Meet PCI DSS, SOC 2, HIPAA security requirements:
```typescript
const config = new QiuthConfigBuilder()
  .withApiKey(apiKey)
  .withIpAllowlist(allowedIps)
  .withTotp(totpSecret)
  .withCertificate(publicKey) // Maximum security
  .build();
```

### 4. CI/CD Pipeline Security
Secure automated deployments:
```typescript
// GitHub Actions, Jenkins, etc.
const client = new QiuthClient({
  apiKey: process.env.API_KEY,
  totpSecret: process.env.TOTP_SECRET,
  privateKey: process.env.PRIVATE_KEY,
});
```

---

## 🔒 Security

Qiuth is designed with security as the top priority:

- **No sensitive data logging** - API keys and secrets never logged
- **Cryptographically secure** - Uses Node.js crypto module
- **RFC compliant** - TOTP follows RFC 6238
- **Industry standards** - RSA-SHA256 signatures
- **Regular audits** - Automated security scanning

---

## 📊 Performance

Qiuth is designed for production use with minimal overhead:

- **IP Validation**: < 1ms
- **TOTP Validation**: < 5ms
- **Certificate Validation**: < 10ms
- **Total**: < 20ms for all three layers

**Bundle Size:**
- ESM: ~60 KB
- CommonJS: ~61 KB
- TypeScript declarations: ~48 KB

---

<div align="center">

**Stop treating API keys like passwords. Add multi-factor authentication today.** 🔐

[Get Started](./docs/getting-started.md) • [Try the Demo](./demo/README.md) • [Readme](https://github.com/clay-good/qiuth/readme.md)

</div>


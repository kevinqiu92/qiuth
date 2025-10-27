/**
 * Environment Variable Loader
 *
 * Loads Qiuth configuration from environment variables.
 * Useful for 12-factor app deployments.
 *
 * @packageDocumentation
 */

import { QiuthConfig } from '../types';
import { QiuthAuthenticator } from '../core/authenticator';

/**
 * Environment variable prefix
 */
const DEFAULT_PREFIX = 'QIUTH_';

/**
 * Options for loading configuration from environment
 */
export interface EnvLoaderOptions {
  /**
   * Environment variable prefix
   * @default 'QIUTH_'
   */
  prefix?: string;

  /**
   * Whether to hash the API key if it's not already hashed
   * @default true
   */
  hashApiKey?: boolean;

  /**
   * Custom environment object (useful for testing)
   * @default process.env
   */
  env?: Record<string, string | undefined>;
}

/**
 * Load Qiuth configuration from environment variables
 *
 * Expected environment variables:
 * - QIUTH_API_KEY or QIUTH_HASHED_API_KEY
 * - QIUTH_IP_ALLOWLIST (comma-separated IPs)
 * - QIUTH_IP_TRUST_PROXY (true/false)
 * - QIUTH_TOTP_SECRET
 * - QIUTH_TOTP_TIME_STEP
 * - QIUTH_TOTP_WINDOW
 * - QIUTH_CERTIFICATE_PUBLIC_KEY
 * - QIUTH_CERTIFICATE_MAX_AGE
 *
 * @param options - Loader options
 * @returns Qiuth configuration
 * @throws Error if required variables are missing
 *
 * @example
 * ```typescript
 * // Set environment variables
 * process.env.QIUTH_API_KEY = 'my-api-key';
 * process.env.QIUTH_IP_ALLOWLIST = '192.168.1.0/24,10.0.0.1';
 *
 * // Load configuration
 * const config = loadFromEnv();
 * ```
 */
export function loadFromEnv(options: EnvLoaderOptions = {}): QiuthConfig {
  const prefix = options.prefix ?? DEFAULT_PREFIX;
  const hashApiKey = options.hashApiKey ?? true;
  const env = options.env ?? process.env;

  const getEnv = (key: string): string | undefined => {
    return env[`${prefix}${key}`];
  };

  // API Key (required)
  const apiKey = getEnv('API_KEY');
  const hashedApiKey = getEnv('HASHED_API_KEY');

  if (!apiKey && !hashedApiKey) {
    throw new Error(`Either ${prefix}API_KEY or ${prefix}HASHED_API_KEY must be set`);
  }

  const finalHashedApiKey =
    hashedApiKey || (hashApiKey && apiKey ? QiuthAuthenticator.hashApiKey(apiKey) : apiKey!);

  const config: QiuthConfig = {
    hashedApiKey: finalHashedApiKey,
  };

  // IP Allowlist (optional)
  const ipAllowlist = getEnv('IP_ALLOWLIST');
  if (ipAllowlist) {
    const allowedIps = ipAllowlist
      .split(',')
      .map((ip) => ip.trim())
      .filter(Boolean);
    const trustProxy = getEnv('IP_TRUST_PROXY')?.toLowerCase() === 'true';

    config.ipAllowlist = {
      enabled: true,
      allowedIps,
      trustProxy,
    };
  }

  // TOTP (optional)
  const totpSecret = getEnv('TOTP_SECRET');
  if (totpSecret) {
    const timeStep = parseInt(getEnv('TOTP_TIME_STEP') || '30', 10);
    const window = parseInt(getEnv('TOTP_WINDOW') || '1', 10);

    config.totp = {
      enabled: true,
      secret: totpSecret,
      timeStep,
      window,
    };
  }

  // Certificate (optional)
  const certificatePublicKey = getEnv('CERTIFICATE_PUBLIC_KEY');
  if (certificatePublicKey) {
    const maxAge = parseInt(getEnv('CERTIFICATE_MAX_AGE') || '300', 10);

    config.certificate = {
      enabled: true,
      publicKey: certificatePublicKey,
      maxAge,
    };
  }

  return config;
}

/**
 * Check if environment is configured for Qiuth
 *
 * @param options - Loader options
 * @returns true if API key is present
 */
export function isConfigured(options: EnvLoaderOptions = {}): boolean {
  const prefix = options.prefix ?? DEFAULT_PREFIX;
  const env = options.env ?? process.env;

  const apiKey = env[`${prefix}API_KEY`];
  const hashedApiKey = env[`${prefix}HASHED_API_KEY`];

  return !!(apiKey || hashedApiKey);
}

/**
 * Get a summary of configured security layers
 *
 * @param options - Loader options
 * @returns Object with boolean flags for each layer
 */
export function getConfiguredLayers(options: EnvLoaderOptions = {}): {
  apiKey: boolean;
  ipAllowlist: boolean;
  totp: boolean;
  certificate: boolean;
} {
  const prefix = options.prefix ?? DEFAULT_PREFIX;
  const env = options.env ?? process.env;

  return {
    apiKey: !!(env[`${prefix}API_KEY`] || env[`${prefix}HASHED_API_KEY`]),
    ipAllowlist: !!env[`${prefix}IP_ALLOWLIST`],
    totp: !!env[`${prefix}TOTP_SECRET`],
    certificate: !!env[`${prefix}CERTIFICATE_PUBLIC_KEY`],
  };
}

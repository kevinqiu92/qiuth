import { describe, it, expect } from 'vitest';
import { IpValidator } from '../../src/validators/ip-validator';
import { IpAllowlistConfig } from '../../src/types';

describe('IpValidator', () => {
  describe('constructor', () => {
    it('should throw error if IP allowlist is not enabled', () => {
      const config: IpAllowlistConfig = {
        enabled: false,
        allowedIps: ['192.168.1.1'],
      };
      expect(() => new IpValidator(config)).toThrow('IP allowlist is not enabled');
    });

    it('should throw error if allowedIps is empty', () => {
      const config: IpAllowlistConfig = {
        enabled: true,
        allowedIps: [],
      };
      expect(() => new IpValidator(config)).toThrow('IP allowlist cannot be empty');
    });

    it('should create validator with valid config', () => {
      const config: IpAllowlistConfig = {
        enabled: true,
        allowedIps: ['192.168.1.1'],
      };
      expect(() => new IpValidator(config)).not.toThrow();
    });
  });

  describe('IPv4 exact matching', () => {
    it('should allow exact IPv4 match', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.100'],
      });
      expect(validator.isAllowed('192.168.1.100')).toBe(true);
    });

    it('should reject IPv4 not in allowlist', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.100'],
      });
      expect(validator.isAllowed('192.168.1.101')).toBe(false);
    });

    it('should allow localhost IPv4', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['127.0.0.1'],
      });
      expect(validator.isAllowed('127.0.0.1')).toBe(true);
    });

    it('should handle multiple allowed IPs', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.100', '10.0.0.1', '172.16.0.1'],
      });
      expect(validator.isAllowed('192.168.1.100')).toBe(true);
      expect(validator.isAllowed('10.0.0.1')).toBe(true);
      expect(validator.isAllowed('172.16.0.1')).toBe(true);
      expect(validator.isAllowed('8.8.8.8')).toBe(false);
    });
  });

  describe('IPv4 CIDR matching', () => {
    it('should allow IP in /24 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.0/24'],
      });
      expect(validator.isAllowed('192.168.1.1')).toBe(true);
      expect(validator.isAllowed('192.168.1.100')).toBe(true);
      expect(validator.isAllowed('192.168.1.255')).toBe(true);
    });

    it('should reject IP outside /24 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.0/24'],
      });
      expect(validator.isAllowed('192.168.2.1')).toBe(false);
      expect(validator.isAllowed('192.168.0.255')).toBe(false);
    });

    it('should handle /16 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['10.0.0.0/16'],
      });
      expect(validator.isAllowed('10.0.0.1')).toBe(true);
      expect(validator.isAllowed('10.0.255.255')).toBe(true);
      expect(validator.isAllowed('10.1.0.1')).toBe(false);
    });

    it('should handle /8 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['10.0.0.0/8'],
      });
      expect(validator.isAllowed('10.0.0.1')).toBe(true);
      expect(validator.isAllowed('10.255.255.255')).toBe(true);
      expect(validator.isAllowed('11.0.0.1')).toBe(false);
    });

    it('should handle /32 CIDR (single IP)', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.100/32'],
      });
      expect(validator.isAllowed('192.168.1.100')).toBe(true);
      expect(validator.isAllowed('192.168.1.101')).toBe(false);
    });

    it('should handle private IP ranges', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      });
      expect(validator.isAllowed('10.1.2.3')).toBe(true);
      expect(validator.isAllowed('172.16.0.1')).toBe(true);
      expect(validator.isAllowed('172.31.255.255')).toBe(true);
      expect(validator.isAllowed('192.168.100.100')).toBe(true);
      expect(validator.isAllowed('8.8.8.8')).toBe(false);
    });
  });

  describe('IPv6 exact matching', () => {
    it('should allow exact IPv6 match', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:0db8:85a3:0000:0000:8a2e:0370:7334'],
      });
      expect(validator.isAllowed('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
    });

    it('should allow IPv6 with shorthand notation', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8:85a3::8a2e:370:7334'],
      });
      expect(validator.isAllowed('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
      expect(validator.isAllowed('2001:db8:85a3::8a2e:370:7334')).toBe(true);
    });

    it('should allow localhost IPv6', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['::1'],
      });
      expect(validator.isAllowed('::1')).toBe(true);
      expect(validator.isAllowed('0000:0000:0000:0000:0000:0000:0000:0001')).toBe(true);
    });

    it('should reject IPv6 not in allowlist', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8:85a3::8a2e:370:7334'],
      });
      expect(validator.isAllowed('2001:db8:85a3::8a2e:370:7335')).toBe(false);
    });
  });

  describe('IPv6 CIDR matching', () => {
    it('should allow IP in /64 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8::/64'],
      });
      expect(validator.isAllowed('2001:db8::1')).toBe(true);
      expect(validator.isAllowed('2001:db8::ffff:ffff:ffff:ffff')).toBe(true);
    });

    it('should reject IP outside /64 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8::/64'],
      });
      expect(validator.isAllowed('2001:db8:0:1::1')).toBe(false);
      expect(validator.isAllowed('2001:db9::1')).toBe(false);
    });

    it('should handle /48 CIDR range', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8::/48'],
      });
      expect(validator.isAllowed('2001:db8:0:1::1')).toBe(true);
      expect(validator.isAllowed('2001:db8:0:ffff::1')).toBe(true);
      expect(validator.isAllowed('2001:db8:1:0::1')).toBe(false);
    });

    it('should handle /128 CIDR (single IP)', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8::1/128'],
      });
      expect(validator.isAllowed('2001:db8::1')).toBe(true);
      expect(validator.isAllowed('2001:db8::2')).toBe(false);
    });
  });

  describe('proxy header handling', () => {
    it('should use direct IP when trustProxy is false', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.100'],
        trustProxy: false,
      });
      const headers = { 'x-forwarded-for': '10.0.0.1' };
      expect(validator.isAllowed('192.168.1.100', headers)).toBe(true);
      expect(validator.isAllowed('10.0.0.1', headers)).toBe(false);
    });

    it('should use X-Forwarded-For when trustProxy is true', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['10.0.0.1'],
        trustProxy: true,
      });
      const headers = { 'x-forwarded-for': '10.0.0.1' };
      expect(validator.isAllowed('192.168.1.100', headers)).toBe(true);
    });

    it('should take leftmost IP from X-Forwarded-For chain', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['10.0.0.1'],
        trustProxy: true,
      });
      const headers = { 'x-forwarded-for': '10.0.0.1, 192.168.1.1, 172.16.0.1' };
      expect(validator.isAllowed('192.168.1.100', headers)).toBe(true);
    });

    it('should handle X-Forwarded-For as array', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['10.0.0.1'],
        trustProxy: true,
      });
      const headers = { 'x-forwarded-for': ['10.0.0.1, 192.168.1.1'] };
      expect(validator.isAllowed('192.168.1.100', headers)).toBe(true);
    });

    it('should fallback to direct IP if X-Forwarded-For is missing', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.100'],
        trustProxy: true,
      });
      expect(validator.isAllowed('192.168.1.100', {})).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('should reject invalid IP addresses', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.0/24'],
      });
      expect(validator.isAllowed('not-an-ip')).toBe(false);
      expect(validator.isAllowed('999.999.999.999')).toBe(false);
      expect(validator.isAllowed('')).toBe(false);
    });

    it('should reject malformed CIDR notation', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.0/invalid'],
      });
      expect(validator.isAllowed('192.168.1.1')).toBe(false);
    });

    it('should handle mixed IPv4 and IPv6 in allowlist', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.0/24', '2001:db8::/64'],
      });
      expect(validator.isAllowed('192.168.1.100')).toBe(true);
      expect(validator.isAllowed('2001:db8::1')).toBe(true);
      expect(validator.isAllowed('10.0.0.1')).toBe(false);
    });

    it('should not match IPv4 against IPv6 CIDR', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['2001:db8::/64'],
      });
      expect(validator.isAllowed('192.168.1.1')).toBe(false);
    });

    it('should not match IPv6 against IPv4 CIDR', () => {
      const validator = new IpValidator({
        enabled: true,
        allowedIps: ['192.168.1.0/24'],
      });
      expect(validator.isAllowed('2001:db8::1')).toBe(false);
    });
  });
});


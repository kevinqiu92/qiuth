import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  MetricsCollector,
  MetricType,
  AuthenticationEvent,
  createMetricsCollector,
  getMetricsCollector,
} from '../../src/observability/metrics';
import { SecurityLayer, ValidationErrorType } from '../../src/types';

describe('MetricsCollector', () => {
  beforeEach(() => {
    MetricsCollector.resetInstance();
  });

  describe('constructor', () => {
    it('should create metrics collector with default config', () => {
      const metrics = new MetricsCollector();
      expect(metrics).toBeDefined();
      expect(metrics.isEnabled()).toBe(true);
    });

    it('should create metrics collector with custom config', () => {
      const metrics = new MetricsCollector({
        enabled: false,
        maxEvents: 500,
      });

      expect(metrics.isEnabled()).toBe(false);
    });
  });

  describe('recordAuthentication', () => {
    it('should record successful authentication', () => {
      const metrics = new MetricsCollector();
      const event: AuthenticationEvent = {
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 50,
        timestamp: new Date(),
      };

      metrics.recordAuthentication(event);

      const summary = metrics.getSummary();
      expect(summary.totalAttempts).toBe(1);
      expect(summary.successfulAttempts).toBe(1);
      expect(summary.failedAttempts).toBe(0);
    });

    it('should record failed authentication', () => {
      const metrics = new MetricsCollector();
      const event: AuthenticationEvent = {
        success: false,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 25,
        errorType: ValidationErrorType.INVALID_API_KEY,
        timestamp: new Date(),
      };

      metrics.recordAuthentication(event);

      const summary = metrics.getSummary();
      expect(summary.totalAttempts).toBe(1);
      expect(summary.successfulAttempts).toBe(0);
      expect(summary.failedAttempts).toBe(1);
    });

    it('should track errors by type', () => {
      const metrics = new MetricsCollector();

      metrics.recordAuthentication({
        success: false,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 10,
        errorType: ValidationErrorType.INVALID_API_KEY,
        timestamp: new Date(),
      });

      metrics.recordAuthentication({
        success: false,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 10,
        errorType: ValidationErrorType.IP_NOT_ALLOWED,
        timestamp: new Date(),
      });

      const summary = metrics.getSummary();
      expect(summary.errorsByType[ValidationErrorType.INVALID_API_KEY]).toBe(1);
      expect(summary.errorsByType[ValidationErrorType.IP_NOT_ALLOWED]).toBe(1);
    });

    it('should track attempts by layer', () => {
      const metrics = new MetricsCollector();

      metrics.recordAuthentication({
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST, SecurityLayer.TOTP],
        duration: 50,
        timestamp: new Date(),
      });

      const summary = metrics.getSummary();
      expect(summary.attemptsByLayer[SecurityLayer.IP_ALLOWLIST]).toBe(1);
      expect(summary.attemptsByLayer[SecurityLayer.TOTP]).toBe(1);
    });

    it('should limit events to maxEvents', () => {
      const metrics = new MetricsCollector({ maxEvents: 3 });

      for (let i = 0; i < 5; i++) {
        metrics.recordAuthentication({
          success: true,
          layers: [SecurityLayer.IP_ALLOWLIST],
          duration: 10,
          timestamp: new Date(),
        });
      }

      const events = metrics.getEvents();
      expect(events.length).toBe(3);
    });

    it('should call event handler', () => {
      const eventHandler = vi.fn();
      const metrics = new MetricsCollector({ eventHandler });

      const event: AuthenticationEvent = {
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 50,
        timestamp: new Date(),
      };

      metrics.recordAuthentication(event);
      expect(eventHandler).toHaveBeenCalledWith(event);
    });

    it('should not record when disabled', () => {
      const metrics = new MetricsCollector({ enabled: false });

      metrics.recordAuthentication({
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 50,
        timestamp: new Date(),
      });

      const summary = metrics.getSummary();
      expect(summary.totalAttempts).toBe(0);
    });
  });

  describe('counters', () => {
    it('should increment counter', () => {
      const metrics = new MetricsCollector();
      metrics.incrementCounter('test_counter', 5);

      expect(metrics.getCounter('test_counter')).toBe(5);
    });

    it('should increment counter multiple times', () => {
      const metrics = new MetricsCollector();
      metrics.incrementCounter('test_counter', 3);
      metrics.incrementCounter('test_counter', 2);

      expect(metrics.getCounter('test_counter')).toBe(5);
    });

    it('should support counter labels', () => {
      const metrics = new MetricsCollector();
      metrics.incrementCounter('requests', 1, { method: 'GET' });
      metrics.incrementCounter('requests', 1, { method: 'POST' });

      expect(metrics.getCounter('requests', { method: 'GET' })).toBe(1);
      expect(metrics.getCounter('requests', { method: 'POST' })).toBe(1);
    });

    it('should call metric handler', () => {
      const metricHandler = vi.fn();
      const metrics = new MetricsCollector({ metricHandler });

      metrics.incrementCounter('test', 5);

      expect(metricHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'test',
          type: MetricType.COUNTER,
          value: 5,
        })
      );
    });
  });

  describe('gauges', () => {
    it('should set gauge value', () => {
      const metrics = new MetricsCollector();
      metrics.setGauge('memory_usage', 1024);

      expect(metrics.getGauge('memory_usage')).toBe(1024);
    });

    it('should update gauge value', () => {
      const metrics = new MetricsCollector();
      metrics.setGauge('memory_usage', 1024);
      metrics.setGauge('memory_usage', 2048);

      expect(metrics.getGauge('memory_usage')).toBe(2048);
    });

    it('should support gauge labels', () => {
      const metrics = new MetricsCollector();
      metrics.setGauge('cpu_usage', 50, { core: '0' });
      metrics.setGauge('cpu_usage', 75, { core: '1' });

      expect(metrics.getGauge('cpu_usage', { core: '0' })).toBe(50);
      expect(metrics.getGauge('cpu_usage', { core: '1' })).toBe(75);
    });
  });

  describe('histograms', () => {
    it('should record histogram values', () => {
      const metrics = new MetricsCollector();
      metrics.recordHistogram('response_time', 100);
      metrics.recordHistogram('response_time', 200);
      metrics.recordHistogram('response_time', 150);

      const values = metrics.getHistogram('response_time');
      expect(values).toEqual([100, 200, 150]);
    });

    it('should support histogram labels', () => {
      const metrics = new MetricsCollector();
      metrics.recordHistogram('latency', 10, { endpoint: '/api/users' });
      metrics.recordHistogram('latency', 20, { endpoint: '/api/posts' });

      expect(metrics.getHistogram('latency', { endpoint: '/api/users' })).toEqual([10]);
      expect(metrics.getHistogram('latency', { endpoint: '/api/posts' })).toEqual([20]);
    });
  });

  describe('getSummary', () => {
    it('should calculate success rate', () => {
      const metrics = new MetricsCollector();

      for (let i = 0; i < 7; i++) {
        metrics.recordAuthentication({
          success: true,
          layers: [SecurityLayer.IP_ALLOWLIST],
          duration: 50,
          timestamp: new Date(),
        });
      }

      for (let i = 0; i < 3; i++) {
        metrics.recordAuthentication({
          success: false,
          layers: [SecurityLayer.IP_ALLOWLIST],
          duration: 25,
          errorType: ValidationErrorType.INVALID_API_KEY,
          timestamp: new Date(),
        });
      }

      const summary = metrics.getSummary();
      expect(summary.totalAttempts).toBe(10);
      expect(summary.successfulAttempts).toBe(7);
      expect(summary.failedAttempts).toBe(3);
      expect(summary.successRate).toBe(0.7);
    });

    it('should calculate average duration', () => {
      const metrics = new MetricsCollector();

      metrics.recordAuthentication({
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 100,
        timestamp: new Date(),
      });

      metrics.recordAuthentication({
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 200,
        timestamp: new Date(),
      });

      const summary = metrics.getSummary();
      expect(summary.averageDuration).toBe(150);
    });

    it('should handle empty metrics', () => {
      const metrics = new MetricsCollector();
      const summary = metrics.getSummary();

      expect(summary.totalAttempts).toBe(0);
      expect(summary.successRate).toBe(0);
      expect(summary.averageDuration).toBe(0);
    });
  });

  describe('clear', () => {
    it('should clear all metrics', () => {
      const metrics = new MetricsCollector();

      metrics.recordAuthentication({
        success: true,
        layers: [SecurityLayer.IP_ALLOWLIST],
        duration: 50,
        timestamp: new Date(),
      });

      metrics.incrementCounter('test', 5);
      metrics.setGauge('gauge', 10);
      metrics.recordHistogram('hist', 100);

      metrics.clear();

      expect(metrics.getEvents()).toEqual([]);
      expect(metrics.getCounter('test')).toBe(0);
      expect(metrics.getGauge('gauge')).toBeUndefined();
      expect(metrics.getHistogram('hist')).toEqual([]);
    });
  });

  describe('enable/disable', () => {
    it('should not collect when disabled', () => {
      const metrics = new MetricsCollector({ enabled: false });

      metrics.incrementCounter('test');
      expect(metrics.getCounter('test')).toBe(0);
    });

    it('should collect after enabling', () => {
      const metrics = new MetricsCollector({ enabled: false });
      metrics.enable();

      metrics.incrementCounter('test');
      expect(metrics.getCounter('test')).toBe(1);
    });
  });

  describe('singleton', () => {
    it('should return same instance', () => {
      const metrics1 = MetricsCollector.getInstance();
      const metrics2 = MetricsCollector.getInstance();

      expect(metrics1).toBe(metrics2);
    });

    it('should reset instance', () => {
      const metrics1 = MetricsCollector.getInstance();
      MetricsCollector.resetInstance();
      const metrics2 = MetricsCollector.getInstance();

      expect(metrics1).not.toBe(metrics2);
    });
  });

  describe('factory functions', () => {
    it('should create metrics collector with createMetricsCollector', () => {
      const metrics = createMetricsCollector({ maxEvents: 500 });
      expect(metrics).toBeInstanceOf(MetricsCollector);
    });

    it('should get singleton with getMetricsCollector', () => {
      const metrics1 = getMetricsCollector();
      const metrics2 = getMetricsCollector();
      expect(metrics1).toBe(metrics2);
    });
  });
});


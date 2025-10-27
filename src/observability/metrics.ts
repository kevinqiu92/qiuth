/**
 * Metrics Collection System
 *
 * Provides metrics collection for authentication events and performance monitoring.
 *
 * @packageDocumentation
 */

import { SecurityLayer, ValidationErrorType } from '../types';

/**
 * Metric types
 */
export enum MetricType {
  /** Counter metric (increments only) */
  COUNTER = 'counter',
  /** Gauge metric (can go up or down) */
  GAUGE = 'gauge',
  /** Histogram metric (distribution of values) */
  HISTOGRAM = 'histogram',
}

/**
 * Authentication event
 */
export interface AuthenticationEvent {
  /** Whether authentication succeeded */
  success: boolean;
  /** Security layers that were validated */
  layers: SecurityLayer[];
  /** Duration in milliseconds */
  duration: number;
  /** Error type (if failed) */
  errorType?: ValidationErrorType;
  /** Timestamp */
  timestamp: Date;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * Metric data point
 */
export interface MetricDataPoint {
  /** Metric name */
  name: string;
  /** Metric type */
  type: MetricType;
  /** Metric value */
  value: number;
  /** Labels/tags */
  labels?: Record<string, string>;
  /** Timestamp */
  timestamp: Date;
}

/**
 * Metrics summary
 */
export interface MetricsSummary {
  /** Total authentication attempts */
  totalAttempts: number;
  /** Successful authentications */
  successfulAttempts: number;
  /** Failed authentications */
  failedAttempts: number;
  /** Success rate (0-1) */
  successRate: number;
  /** Average authentication duration (ms) */
  averageDuration: number;
  /** Errors by type */
  errorsByType: Record<string, number>;
  /** Attempts by layer */
  attemptsByLayer: Record<string, number>;
}

/**
 * Metrics collector configuration
 */
export interface MetricsConfig {
  /**
   * Whether to enable metrics collection
   * @default true
   */
  enabled?: boolean;

  /**
   * Maximum number of events to keep in memory
   * @default 1000
   */
  maxEvents?: number;

  /**
   * Custom event handler
   */
  eventHandler?: (event: AuthenticationEvent) => void;

  /**
   * Custom metric handler
   */
  metricHandler?: (metric: MetricDataPoint) => void;
}

/**
 * Metrics Collector
 *
 * Collects and aggregates authentication metrics.
 *
 * @example
 * ```typescript
 * const metrics = new MetricsCollector();
 *
 * // Record authentication event
 * metrics.recordAuthentication({
 *   success: true,
 *   layers: [SecurityLayer.IP_ALLOWLIST, SecurityLayer.TOTP],
 *   duration: 45,
 *   timestamp: new Date(),
 * });
 *
 * // Get summary
 * const summary = metrics.getSummary();
 * console.log(`Success rate: ${summary.successRate * 100}%`);
 * ```
 */
export class MetricsCollector {
  private config: Required<MetricsConfig>;
  private events: AuthenticationEvent[] = [];
  private counters: Map<string, number> = new Map();
  private gauges: Map<string, number> = new Map();
  private histograms: Map<string, number[]> = new Map();
  private static instance?: MetricsCollector;

  /**
   * Create a new metrics collector
   * @param config - Metrics configuration
   */
  constructor(config: MetricsConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      maxEvents: config.maxEvents ?? 1000,
      eventHandler: config.eventHandler ?? (() => {}),
      metricHandler: config.metricHandler ?? (() => {}),
    };
  }

  /**
   * Get or create singleton instance
   */
  public static getInstance(config?: MetricsConfig): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector(config);
    }
    return MetricsCollector.instance;
  }

  /**
   * Reset singleton instance (useful for testing)
   */
  public static resetInstance(): void {
    MetricsCollector.instance = undefined;
  }

  /**
   * Record an authentication event
   */
  public recordAuthentication(event: AuthenticationEvent): void {
    if (!this.config.enabled) {
      return;
    }

    // Add to events list
    this.events.push(event);

    // Trim events if exceeds max
    if (this.events.length > this.config.maxEvents) {
      this.events.shift();
    }

    // Update counters
    this.incrementCounter('auth_attempts_total');
    if (event.success) {
      this.incrementCounter('auth_success_total');
    } else {
      this.incrementCounter('auth_failure_total');
      if (event.errorType) {
        this.incrementCounter(`auth_error_${event.errorType}`);
      }
    }

    // Update layer counters
    for (const layer of event.layers) {
      this.incrementCounter(`auth_layer_${layer}`);
    }

    // Record duration
    this.recordHistogram('auth_duration_ms', event.duration);

    // Call custom handler
    this.config.eventHandler(event);
  }

  /**
   * Increment a counter
   */
  public incrementCounter(name: string, value: number = 1, labels?: Record<string, string>): void {
    if (!this.config.enabled) {
      return;
    }

    const key = this.getMetricKey(name, labels);
    const current = this.counters.get(key) || 0;
    this.counters.set(key, current + value);

    this.emitMetric({
      name,
      type: MetricType.COUNTER,
      value: current + value,
      labels,
      timestamp: new Date(),
    });
  }

  /**
   * Set a gauge value
   */
  public setGauge(name: string, value: number, labels?: Record<string, string>): void {
    if (!this.config.enabled) {
      return;
    }

    const key = this.getMetricKey(name, labels);
    this.gauges.set(key, value);

    this.emitMetric({
      name,
      type: MetricType.GAUGE,
      value,
      labels,
      timestamp: new Date(),
    });
  }

  /**
   * Record a histogram value
   */
  public recordHistogram(name: string, value: number, labels?: Record<string, string>): void {
    if (!this.config.enabled) {
      return;
    }

    const key = this.getMetricKey(name, labels);
    const values = this.histograms.get(key) || [];
    values.push(value);
    this.histograms.set(key, values);

    this.emitMetric({
      name,
      type: MetricType.HISTOGRAM,
      value,
      labels,
      timestamp: new Date(),
    });
  }

  /**
   * Get metrics summary
   */
  public getSummary(): MetricsSummary {
    const totalAttempts = this.events.length;
    const successfulAttempts = this.events.filter((e) => e.success).length;
    const failedAttempts = totalAttempts - successfulAttempts;
    const successRate = totalAttempts > 0 ? successfulAttempts / totalAttempts : 0;

    const durations = this.events.map((e) => e.duration);
    const averageDuration =
      durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : 0;

    const errorsByType: Record<string, number> = {};
    for (const event of this.events) {
      if (!event.success && event.errorType) {
        errorsByType[event.errorType] = (errorsByType[event.errorType] || 0) + 1;
      }
    }

    const attemptsByLayer: Record<string, number> = {};
    for (const event of this.events) {
      for (const layer of event.layers) {
        attemptsByLayer[layer] = (attemptsByLayer[layer] || 0) + 1;
      }
    }

    return {
      totalAttempts,
      successfulAttempts,
      failedAttempts,
      successRate,
      averageDuration,
      errorsByType,
      attemptsByLayer,
    };
  }

  /**
   * Get counter value
   */
  public getCounter(name: string, labels?: Record<string, string>): number {
    const key = this.getMetricKey(name, labels);
    return this.counters.get(key) || 0;
  }

  /**
   * Get gauge value
   */
  public getGauge(name: string, labels?: Record<string, string>): number | undefined {
    const key = this.getMetricKey(name, labels);
    return this.gauges.get(key);
  }

  /**
   * Get histogram values
   */
  public getHistogram(name: string, labels?: Record<string, string>): number[] {
    const key = this.getMetricKey(name, labels);
    return this.histograms.get(key) || [];
  }

  /**
   * Get all events
   */
  public getEvents(): AuthenticationEvent[] {
    return [...this.events];
  }

  /**
   * Clear all metrics
   */
  public clear(): void {
    this.events = [];
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
  }

  /**
   * Enable metrics collection
   */
  public enable(): void {
    this.config.enabled = true;
  }

  /**
   * Disable metrics collection
   */
  public disable(): void {
    this.config.enabled = false;
  }

  /**
   * Check if metrics collection is enabled
   */
  public isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Get metric key with labels
   */
  private getMetricKey(name: string, labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) {
      return name;
    }

    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${v}"`)
      .join(',');

    return `${name}{${labelStr}}`;
  }

  /**
   * Emit metric to handler
   */
  private emitMetric(metric: MetricDataPoint): void {
    this.config.metricHandler(metric);
  }
}

/**
 * Create a metrics collector instance
 */
export function createMetricsCollector(config?: MetricsConfig): MetricsCollector {
  return new MetricsCollector(config);
}

/**
 * Get the singleton metrics collector instance
 */
export function getMetricsCollector(config?: MetricsConfig): MetricsCollector {
  return MetricsCollector.getInstance(config);
}

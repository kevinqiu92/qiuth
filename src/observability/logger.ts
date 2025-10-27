/**
 * Structured Logging System
 *
 * Provides structured logging with multiple levels and customizable output.
 *
 * @packageDocumentation
 */

/**
 * Log levels
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

/**
 * Log entry structure
 */
export interface LogEntry {
  /** Log level */
  level: LogLevel;
  /** Log message */
  message: string;
  /** Timestamp */
  timestamp: Date;
  /** Additional context data */
  context?: Record<string, any>;
  /** Error object (for error logs) */
  error?: Error;
}

/**
 * Logger configuration
 */
export interface LoggerConfig {
  /**
   * Minimum log level to output
   * @default LogLevel.INFO
   */
  level?: LogLevel;

  /**
   * Whether to include timestamps
   * @default true
   */
  includeTimestamp?: boolean;

  /**
   * Whether to pretty-print JSON
   * @default false
   */
  prettyPrint?: boolean;

  /**
   * Custom log handler
   */
  handler?: (entry: LogEntry) => void;

  /**
   * Whether to enable logging
   * @default true
   */
  enabled?: boolean;
}

/**
 * Logger class for structured logging
 *
 * @example
 * ```typescript
 * const logger = new Logger({ level: LogLevel.DEBUG });
 *
 * logger.info('User authenticated', { userId: '123' });
 * logger.error('Authentication failed', { reason: 'Invalid token' }, error);
 * logger.debug('Request details', { method: 'GET', url: '/api/test' });
 * ```
 */
export class Logger {
  private config: Required<LoggerConfig>;
  private static instance?: Logger;

  /**
   * Create a new logger
   * @param config - Logger configuration
   */
  constructor(config: LoggerConfig = {}) {
    this.config = {
      level: config.level ?? LogLevel.INFO,
      includeTimestamp: config.includeTimestamp ?? true,
      prettyPrint: config.prettyPrint ?? false,
      handler: config.handler ?? this.defaultHandler.bind(this),
      enabled: config.enabled ?? true,
    };
  }

  /**
   * Get or create singleton logger instance
   */
  public static getInstance(config?: LoggerConfig): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger(config);
    }
    return Logger.instance;
  }

  /**
   * Reset singleton instance (useful for testing)
   */
  public static resetInstance(): void {
    Logger.instance = undefined;
  }

  /**
   * Log a debug message
   */
  public debug(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  /**
   * Log an info message
   */
  public info(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.INFO, message, context);
  }

  /**
   * Log a warning message
   */
  public warn(message: string, context?: Record<string, any>): void {
    this.log(LogLevel.WARN, message, context);
  }

  /**
   * Log an error message
   */
  public error(message: string, context?: Record<string, any>, error?: Error): void {
    this.log(LogLevel.ERROR, message, context, error);
  }

  /**
   * Log a message
   */
  private log(
    level: LogLevel,
    message: string,
    context?: Record<string, any>,
    error?: Error
  ): void {
    if (!this.config.enabled) {
      return;
    }

    if (!this.shouldLog(level)) {
      return;
    }

    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date(),
      context,
      error,
    };

    this.config.handler(entry);
  }

  /**
   * Check if a log level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR];
    const currentLevelIndex = levels.indexOf(this.config.level);
    const messageLevelIndex = levels.indexOf(level);
    return messageLevelIndex >= currentLevelIndex;
  }

  /**
   * Default log handler (outputs to console)
   */
  private defaultHandler(entry: LogEntry): void {
    const output: any = {
      level: entry.level,
      message: entry.message,
    };

    if (this.config.includeTimestamp) {
      output.timestamp = entry.timestamp.toISOString();
    }

    if (entry.context) {
      output.context = entry.context;
    }

    if (entry.error) {
      output.error = {
        name: entry.error.name,
        message: entry.error.message,
        stack: entry.error.stack,
      };
    }

    const json = this.config.prettyPrint ? JSON.stringify(output, null, 2) : JSON.stringify(output);

    // Output to appropriate console method
    switch (entry.level) {
      case LogLevel.DEBUG:
        console.debug(json);
        break;
      case LogLevel.INFO:
        console.info(json);
        break;
      case LogLevel.WARN:
        console.warn(json);
        break;
      case LogLevel.ERROR:
        console.error(json);
        break;
    }
  }

  /**
   * Update logger configuration
   */
  public configure(config: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration
   */
  public getConfig(): Readonly<Required<LoggerConfig>> {
    return { ...this.config };
  }

  /**
   * Create a child logger with additional context
   */
  public child(context: Record<string, any>): Logger {
    const childLogger = new Logger(this.config);
    const originalHandler = this.config.handler;

    childLogger.configure({
      handler: (entry: LogEntry) => {
        const mergedEntry = {
          ...entry,
          context: { ...context, ...entry.context },
        };
        originalHandler(mergedEntry);
      },
    });

    return childLogger;
  }

  /**
   * Enable logging
   */
  public enable(): void {
    this.config.enabled = true;
  }

  /**
   * Disable logging
   */
  public disable(): void {
    this.config.enabled = false;
  }

  /**
   * Check if logging is enabled
   */
  public isEnabled(): boolean {
    return this.config.enabled;
  }
}

/**
 * Create a logger instance
 */
export function createLogger(config?: LoggerConfig): Logger {
  return new Logger(config);
}

/**
 * Get the singleton logger instance
 */
export function getLogger(config?: LoggerConfig): Logger {
  return Logger.getInstance(config);
}

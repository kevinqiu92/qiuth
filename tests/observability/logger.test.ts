import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Logger, LogLevel, LogEntry, createLogger, getLogger } from '../../src/observability/logger';

describe('Logger', () => {
  let mockHandler: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockHandler = vi.fn();
    Logger.resetInstance();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create logger with default config', () => {
      const logger = new Logger();
      expect(logger).toBeDefined();
      expect(logger.isEnabled()).toBe(true);
    });

    it('should create logger with custom config', () => {
      const logger = new Logger({
        level: LogLevel.DEBUG,
        includeTimestamp: false,
        prettyPrint: true,
        enabled: false,
      });

      const config = logger.getConfig();
      expect(config.level).toBe(LogLevel.DEBUG);
      expect(config.includeTimestamp).toBe(false);
      expect(config.prettyPrint).toBe(true);
      expect(config.enabled).toBe(false);
    });
  });

  describe('log levels', () => {
    it('should log debug messages', () => {
      const logger = new Logger({ level: LogLevel.DEBUG, handler: mockHandler });
      logger.debug('Debug message', { foo: 'bar' });

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          level: LogLevel.DEBUG,
          message: 'Debug message',
          context: { foo: 'bar' },
        })
      );
    });

    it('should log info messages', () => {
      const logger = new Logger({ handler: mockHandler });
      logger.info('Info message');

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          level: LogLevel.INFO,
          message: 'Info message',
        })
      );
    });

    it('should log warn messages', () => {
      const logger = new Logger({ handler: mockHandler });
      logger.warn('Warning message');

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          level: LogLevel.WARN,
          message: 'Warning message',
        })
      );
    });

    it('should log error messages', () => {
      const logger = new Logger({ handler: mockHandler });
      const error = new Error('Test error');
      logger.error('Error message', { code: 500 }, error);

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          level: LogLevel.ERROR,
          message: 'Error message',
          context: { code: 500 },
          error,
        })
      );
    });
  });

  describe('log level filtering', () => {
    it('should not log debug when level is INFO', () => {
      const logger = new Logger({ level: LogLevel.INFO, handler: mockHandler });
      logger.debug('Debug message');

      expect(mockHandler).not.toHaveBeenCalled();
    });

    it('should log info when level is INFO', () => {
      const logger = new Logger({ level: LogLevel.INFO, handler: mockHandler });
      logger.info('Info message');

      expect(mockHandler).toHaveBeenCalled();
    });

    it('should log warn when level is INFO', () => {
      const logger = new Logger({ level: LogLevel.INFO, handler: mockHandler });
      logger.warn('Warning message');

      expect(mockHandler).toHaveBeenCalled();
    });

    it('should log error when level is INFO', () => {
      const logger = new Logger({ level: LogLevel.INFO, handler: mockHandler });
      logger.error('Error message');

      expect(mockHandler).toHaveBeenCalled();
    });

    it('should only log errors when level is ERROR', () => {
      const logger = new Logger({ level: LogLevel.ERROR, handler: mockHandler });

      logger.debug('Debug');
      logger.info('Info');
      logger.warn('Warn');
      logger.error('Error');

      expect(mockHandler).toHaveBeenCalledTimes(1);
      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({ level: LogLevel.ERROR })
      );
    });
  });

  describe('enable/disable', () => {
    it('should not log when disabled', () => {
      const logger = new Logger({ enabled: false, handler: mockHandler });
      logger.info('Test message');

      expect(mockHandler).not.toHaveBeenCalled();
    });

    it('should log after enabling', () => {
      const logger = new Logger({ enabled: false, handler: mockHandler });
      logger.enable();
      logger.info('Test message');

      expect(mockHandler).toHaveBeenCalled();
    });

    it('should not log after disabling', () => {
      const logger = new Logger({ handler: mockHandler });
      logger.disable();
      logger.info('Test message');

      expect(mockHandler).not.toHaveBeenCalled();
    });
  });

  describe('configure', () => {
    it('should update configuration', () => {
      const logger = new Logger({ level: LogLevel.INFO });
      logger.configure({ level: LogLevel.DEBUG });

      expect(logger.getConfig().level).toBe(LogLevel.DEBUG);
    });

    it('should merge configuration', () => {
      const logger = new Logger({
        level: LogLevel.INFO,
        includeTimestamp: true,
      });

      logger.configure({ level: LogLevel.DEBUG });

      const config = logger.getConfig();
      expect(config.level).toBe(LogLevel.DEBUG);
      expect(config.includeTimestamp).toBe(true);
    });
  });

  describe('child logger', () => {
    it('should create child logger with additional context', () => {
      const logger = new Logger({ handler: mockHandler });
      const child = logger.child({ requestId: '123' });

      child.info('Test message', { userId: '456' });

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          context: {
            requestId: '123',
            userId: '456',
          },
        })
      );
    });

    it('should merge child context with log context', () => {
      const logger = new Logger({ handler: mockHandler });
      const child = logger.child({ service: 'api' });

      child.info('Test', { action: 'login' });

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          context: {
            service: 'api',
            action: 'login',
          },
        })
      );
    });
  });

  describe('singleton', () => {
    it('should return same instance', () => {
      const logger1 = Logger.getInstance();
      const logger2 = Logger.getInstance();

      expect(logger1).toBe(logger2);
    });

    it('should reset instance', () => {
      const logger1 = Logger.getInstance();
      Logger.resetInstance();
      const logger2 = Logger.getInstance();

      expect(logger1).not.toBe(logger2);
    });
  });

  describe('factory functions', () => {
    it('should create logger with createLogger', () => {
      const logger = createLogger({ level: LogLevel.DEBUG });
      expect(logger).toBeInstanceOf(Logger);
    });

    it('should get singleton with getLogger', () => {
      const logger1 = getLogger();
      const logger2 = getLogger();
      expect(logger1).toBe(logger2);
    });
  });

  describe('default handler', () => {
    let consoleDebugSpy: ReturnType<typeof vi.spyOn>;
    let consoleInfoSpy: ReturnType<typeof vi.spyOn>;
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
    let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      consoleDebugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      consoleInfoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
      consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    it('should output to console.debug for debug level', () => {
      const logger = new Logger({ level: LogLevel.DEBUG });
      logger.debug('Test');

      expect(consoleDebugSpy).toHaveBeenCalled();
    });

    it('should output to console.info for info level', () => {
      const logger = new Logger();
      logger.info('Test');

      expect(consoleInfoSpy).toHaveBeenCalled();
    });

    it('should output to console.warn for warn level', () => {
      const logger = new Logger();
      logger.warn('Test');

      expect(consoleWarnSpy).toHaveBeenCalled();
    });

    it('should output to console.error for error level', () => {
      const logger = new Logger();
      logger.error('Test');

      expect(consoleErrorSpy).toHaveBeenCalled();
    });

    it('should include timestamp by default', () => {
      const logger = new Logger();
      logger.info('Test');

      const output = JSON.parse(consoleInfoSpy.mock.calls[0][0]);
      expect(output.timestamp).toBeDefined();
    });

    it('should not include timestamp when disabled', () => {
      const logger = new Logger({ includeTimestamp: false });
      logger.info('Test');

      const output = JSON.parse(consoleInfoSpy.mock.calls[0][0]);
      expect(output.timestamp).toBeUndefined();
    });

    it('should pretty print when enabled', () => {
      const logger = new Logger({ prettyPrint: true });
      logger.info('Test');

      const output = consoleInfoSpy.mock.calls[0][0];
      expect(output).toContain('\n');
    });
  });
});


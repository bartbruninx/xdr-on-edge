/**
 * Audit Logger Module - Comprehensive Security Event Logging and Tracking
 * This module provides centralized audit logging functionality for security events across the extension
 * SECURITY: Handles sensitive data masking and provides secure audit trail management
 */

import browser from 'webextension-polyfill';
import { getStorageManager } from './storage-manager.js';
import type { AuditLogEntry } from '../types/security.d.ts';
import type { ExtensionConfig } from '../types/security.d.ts';

// ============================================================================
// Audit Log Storage Management
// ============================================================================

/**
 * In-memory audit log storage with size limits
 */
class AuditLogStorage {
  private logs: AuditLogEntry[] = [];
  private readonly maxEntries = 1000; // Maximum entries to keep in memory
  private sessionId: string;

  constructor() {
    this.sessionId = this.generateSecureSessionId();
  }

  /**
   * Generate a cryptographically secure session ID
   */
  private generateSecureSessionId(): string {
    try {
      // Use crypto.getRandomValues() for cryptographically secure randomness
      const array = new Uint8Array(16);
      crypto.getRandomValues(array);
      
      // Convert to hex string
      const hexString = Array.from(array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
      
      return `session_${Date.now()}_${hexString}`;
    } catch (error) {
      // Fallback for environments where crypto.getRandomValues is not available
      // This should not happen in modern browsers, but provides a safe fallback
      console.warn('crypto.getRandomValues not available, using timestamp-based fallback');
      return `session_${Date.now()}_${performance.now().toString(36).replace('.', '')}`;
    }
  }

  /**
   * Add a new audit log entry
   */
  addEntry(entry: AuditLogEntry): void {
    // Ensure we don't exceed maximum entries
    if (this.logs.length >= this.maxEntries) {
      this.logs = this.logs.slice(-Math.floor(this.maxEntries * 0.8)); // Keep 80% of max
    }
    
    this.logs.push(entry);
  }

  /**
   * Get all audit log entries
   */
  getAllEntries(): AuditLogEntry[] {
    return [...this.logs];
  }

  /**
   * Get audit log entries filtered by criteria
   */
  getFilteredEntries(filter: {
    level?: AuditLogEntry['level'];
    category?: AuditLogEntry['category'];
    action?: string;
    since?: number;
    limit?: number;
  }): AuditLogEntry[] {
    let filtered = this.logs;

    if (filter.level) {
      filtered = filtered.filter(log => log.level === filter.level);
    }

    if (filter.category) {
      filtered = filtered.filter(log => log.category === filter.category);
    }

    if (filter.action) {
      filtered = filtered.filter(log => log.action.includes(filter.action!));
    }

    if (filter.since) {
      filtered = filtered.filter(log => log.timestamp >= filter.since!);
    }

    // Apply limit and return most recent entries
    if (filter.limit && filter.limit > 0) {
      filtered = filtered.slice(-filter.limit);
    }

    return filtered;
  }

  /**
   * Clear all audit log entries
   */
  clearEntries(): void {
    this.logs = [];
  }

  /**
   * Get current session ID
   */
  getSessionId(): string {
    return this.sessionId;
  }

  /**
   * Get audit log statistics
   */
  getStatistics(): {
    totalEntries: number;
    levels: Record<string, number>;
    categories: Record<string, number>;
    oldestEntry?: number;
    newestEntry?: number;
  } {
    const stats = {
      totalEntries: this.logs.length,
      levels: {} as Record<string, number>,
      categories: {} as Record<string, number>,
      oldestEntry: undefined as number | undefined,
      newestEntry: undefined as number | undefined
    };

    if (this.logs.length > 0) {
      stats.oldestEntry = Math.min(...this.logs.map(log => log.timestamp));
      stats.newestEntry = Math.max(...this.logs.map(log => log.timestamp));

      // Count by level
      this.logs.forEach(log => {
        stats.levels[log.level] = (stats.levels[log.level] || 0) + 1;
        stats.categories[log.category] = (stats.categories[log.category] || 0) + 1;
      });
    }

    return stats;
  }
}

// ============================================================================
// Sensitive Data Masking
// ============================================================================

/**
 * Mask sensitive data in audit log details
 */
function maskSensitiveData(data: Record<string, any>): Record<string, any> {
  const sensitiveFields = [
    'token', 'password', 'secret', 'key', 'authorization', 
    'clientSecret', 'refreshToken', 'accessToken', 'apiKey',
    'credential', 'auth', 'bearer', 'cookie', 'session'
  ];
  
  const masked = { ...data };
  
  function maskValue(value: any, fieldName: string): any {
    if (typeof value === 'string' && value.length > 0) {
      // For sensitive fields, show first 4 characters and mask the rest
      if (sensitiveFields.some(field => fieldName.toLowerCase().includes(field))) {
        return value.length <= 4 ? '[MASKED]' : value.substring(0, 4) + '*'.repeat(Math.max(0, value.length - 4));
      }
      // For other potentially sensitive long strings, truncate
      if (value.length > 100) {
        return value.substring(0, 100) + '...[TRUNCATED]';
      }
    } else if (typeof value === 'object' && value !== null) {
      // Recursively mask nested objects
      if (Array.isArray(value)) {
        return value.map((item, index) => maskValue(item, `${fieldName}[${index}]`));
      } else {
        const maskedObj: Record<string, any> = {};
        for (const [key, val] of Object.entries(value)) {
          maskedObj[key] = maskValue(val, key);
        }
        return maskedObj;
      }
    }
    
    return value;
  }
  
  for (const [key, value] of Object.entries(masked)) {
    masked[key] = maskValue(value, key);
  }
  
  return masked;
}

// ============================================================================
// Audit Logger Class
// ============================================================================

/**
 * Main audit logger class with configuration management
 */
class AuditLogger {
  private storage: AuditLogStorage;
  private config: ExtensionConfig | null = null;
  private debugMode: boolean = false;

  constructor() {
    this.storage = new AuditLogStorage();
  }

  /**
   * Update audit logger configuration
   */
  updateConfig(config: ExtensionConfig): void {
    this.config = config;
    this.debugMode = config.debug?.enabled ?? false;
  }

  /**
   * Set debug mode (can be used independently of config)
   */
  setDebugMode(enabled: boolean): void {
    this.debugMode = enabled;
  }

  /**
   * Check if debug mode is enabled
   */
  isDebugEnabled(): boolean {
    return this.debugMode;
  }

  /**
   * Log an audit event
   */
  logEvent(
    level: AuditLogEntry['level'], 
    category: AuditLogEntry['category'], 
    action: string, 
    details: Record<string, any> = {}
  ): void {
    // Check if audit logging is enabled
    if (!this.config?.audit?.enabled) {
      return;
    }

    try {
      const logEntry: AuditLogEntry = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        level,
        category,
        action,
        sessionId: this.storage.getSessionId(),
        details: this.config.audit.sensitiveDataMask ? maskSensitiveData(details) : details,
        userAgent: navigator.userAgent
      };

      // Add to storage
      this.storage.addEntry(logEntry);

      // Console output with formatting (only if debug mode is enabled)
      if (this.debugMode) {
        const levelEmoji = {
          'info': 'ℹ️',
          'warn': '⚠️',
          'error': '❌'
        };

        // Show all audit events when debug mode is enabled
        console.log(
          `[AUDIT] ${levelEmoji[level] || '📝'} ${level.toUpperCase()} ${category}:${action}`,
          logEntry.details
        );
      }

      // For critical security events, also store in extension storage
      if (level === 'error' || (category === 'auth' && action.includes('failed'))) {
        this.persistCriticalEvent(logEntry).catch(error => {
          console.error('Failed to persist critical audit event:', error);
        });
      }

    } catch (error) {
      console.error('Failed to log audit event:', error);
    }
  }

  /**
   * Debug logging - only outputs when debug mode is enabled
   */
  debug(message: string, ...args: any[]): void {
    if (this.debugMode) {
      // Debug messages always show when debug mode is enabled
      console.log(`[DEBUG] ${message}`, ...args);
      
      // Also log as audit event for tracking when debug mode is enabled
      this.logEvent('info', 'user', 'debug_log', { 
        message, 
        argsCount: args.length,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Info logging - always outputs important information
   */
  info(message: string, details?: Record<string, any>): void {
    console.log(`[INFO] ${message}`, details || '');
    this.logEvent('info', 'user', 'info_log', { message, ...details });
  }

  /**
   * Warning logging - always outputs warnings
   */
  warn(message: string, details?: Record<string, any>): void {
    console.warn(`[WARN] ${message}`, details || '');
    this.logEvent('warn', 'security', 'warning_log', { message, ...details });
  }

  /**
   * Error logging - always outputs errors
   */
  error(message: string, error?: Error | any, details?: Record<string, any>): void {
    const errorDetails = {
      message,
      error: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : undefined,
      ...details
    };
    
    console.error(`[ERROR] ${message}`, errorDetails);
    this.logEvent('error', 'security', 'error_log', errorDetails);
  }

  /**
   * Persist critical events to extension storage
   */
  private async persistCriticalEvent(entry: AuditLogEntry): Promise<void> {
    try {
      const storageManager = getStorageManager();
      await storageManager.addCriticalAuditEvent(entry);
    } catch (error) {
      console.error('Failed to persist critical audit event:', error);
    }
  }

  /**
   * Get audit log entries
   */
  getAuditLog(filter?: {
    level?: AuditLogEntry['level'];
    category?: AuditLogEntry['category'];
    action?: string;
    since?: number;
    limit?: number;
  }): AuditLogEntry[] {
    return filter ? this.storage.getFilteredEntries(filter) : this.storage.getAllEntries();
  }

  /**
   * Get critical events from storage
   */
  async getCriticalEvents(): Promise<AuditLogEntry[]> {
    try {
      const storageManager = getStorageManager();
      return await storageManager.getCriticalAuditEvents();
    } catch (error) {
      console.error('Failed to retrieve critical events:', error);
      return [];
    }
  }

  /**
   * Clear audit log
   */
  clearAuditLog(): void {
    this.storage.clearEntries();
  }

  /**
   * Clear critical events from storage
   */
  async clearCriticalEvents(): Promise<void> {
    try {
      const storageManager = getStorageManager();
      // Clear by setting empty array through storage manager
      await storageManager.setCriticalAuditEvents([]);
    } catch (error) {
      console.error('Failed to clear critical events:', error);
    }
  }

  /**
   * Get audit log statistics
   */
  getStatistics(): {
    memory: ReturnType<AuditLogStorage['getStatistics']>;
    sessionId: string;
    configEnabled: boolean;
    maskingEnabled: boolean;
  } {
    return {
      memory: this.storage.getStatistics(),
      sessionId: this.storage.getSessionId(),
      configEnabled: this.config?.audit?.enabled ?? false,
      maskingEnabled: this.config?.audit?.sensitiveDataMask ?? false
    };
  }

  /**
   * Export audit log for debugging/analysis
   */
  exportAuditLog(options: {
    format?: 'json' | 'csv';
    filter?: {
      level?: AuditLogEntry['level'];
      category?: AuditLogEntry['category'];
      action?: string;
      since?: number;
      limit?: number;
    };
  } = {}): string {
    const logs = this.getAuditLog(options.filter);
    
    if (options.format === 'csv') {
      const headers = ['timestamp', 'level', 'category', 'action', 'sessionId', 'details'];
      const csvLines = [headers.join(',')];
      
      logs.forEach(log => {
        const row = [
          new Date(log.timestamp).toISOString(),
          log.level,
          log.category,
          log.action,
          log.sessionId,
          JSON.stringify(log.details).replace(/"/g, '""')
        ];
        csvLines.push(row.map(field => `"${field}"`).join(','));
      });
      
      return csvLines.join('\n');
    }
    
    // Default to JSON format
    return JSON.stringify(logs, null, 2);
  }
}

// ============================================================================
// Singleton Instance and Factory Functions
// ============================================================================

/**
 * Global audit logger instance
 */
const auditLogger = new AuditLogger();

/**
 * Initialize audit logger with configuration
 */
export function initializeAuditLogger(config: ExtensionConfig): void {
  auditLogger.updateConfig(config);
  
  // Log initialization with debug mode status
  auditLogger.logEvent('info', 'security', 'audit_logger_initialized', {
    enabled: config.audit.enabled,
    sensitiveDataMask: config.audit.sensitiveDataMask,
    debugMode: config.debug?.enabled ?? false
  });

  // Force a debug message to test if debug logging is working
  if (config.debug?.enabled) {
    auditLogger.debug('Debug logging is now active', { 
      timestamp: new Date().toISOString() 
    });
  }
}

/**
 * Create audit event logger function with configuration
 */
export function createAuditEventLogger(config: ExtensionConfig) {
  auditLogger.updateConfig(config);
  
  return (
    level: AuditLogEntry['level'], 
    category: AuditLogEntry['category'], 
    action: string, 
    details: Record<string, any> = {}
  ): void => {
    auditLogger.logEvent(level, category, action, details);
  };
}

/**
 * Get the global audit logger instance
 */
export function getAuditLogger(): AuditLogger {
  return auditLogger;
}

/**
 * Direct audit event logging function (uses global instance)
 */
export function logAuditEvent(
  level: AuditLogEntry['level'], 
  category: AuditLogEntry['category'], 
  action: string, 
  details: Record<string, any> = {}
): void {
  auditLogger.logEvent(level, category, action, details);
}

/**
 * Convenient debug logging functions that use the global audit logger
 */
export const logger = {
  debug: (message: string, ...args: any[]) => auditLogger.debug(message, ...args),
  info: (message: string, details?: Record<string, any>) => auditLogger.info(message, details),
  warn: (message: string, details?: Record<string, any>) => auditLogger.warn(message, details),
  error: (message: string, error?: Error | any, details?: Record<string, any>) => auditLogger.error(message, error, details),
  
  // Audit event shortcuts
  audit: {
    auth: (action: string, details?: Record<string, any>) => auditLogger.logEvent('info', 'auth', action, details || {}),
    api: (action: string, details?: Record<string, any>) => auditLogger.logEvent('info', 'api', action, details || {}),
    security: (action: string, details?: Record<string, any>) => auditLogger.logEvent('info', 'security', action, details || {}),
    user: (action: string, details?: Record<string, any>) => auditLogger.logEvent('info', 'user', action, details || {}),
  },
  
  // Set debug mode
  setDebug: (enabled: boolean) => auditLogger.setDebugMode(enabled),
  isDebugEnabled: () => auditLogger.isDebugEnabled()
};

// Export types for external use
export type { AuditLogEntry };
export { AuditLogger, maskSensitiveData };

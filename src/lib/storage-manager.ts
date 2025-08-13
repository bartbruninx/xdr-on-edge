/**
 * Storage Manager Module - Centralized Browser Storage Management
 * This module provides a clean abstraction layer for all browser storage operations
 * SECURITY: Handles data serialization, validation, and secure storage practices
 */

import browser from 'webextension-polyfill';
import type { 
  ExtensionConfig, 
  SecurityApiConfig, 
  AuditLogEntry,
  IncidentDashboardData
} from '../types/security.d.ts';
import { logger } from './audit-logger.js';

// ============================================================================
// Storage Key Constants
// ============================================================================

/**
 * Centralized storage keys to prevent typos and ensure consistency
 */
export const STORAGE_KEYS = {
  // Settings
  XDR_SETTINGS: 'xdr_settings',
  
  // State Management
  BACKGROUND_STATE: 'backgroundState',
  LAST_KNOWN_COUNTS: 'lastKnownCounts',
  KEEPALIVE: 'keepalive',
  
  // Incident Data
  INCIDENT_DASHBOARD_DATA: 'incident_dashboard_data',
  
  // Audit & Security
  AUDIT_CRITICAL_EVENTS: 'audit_critical_events',
  
  // OAuth & Authentication
  OAUTH_STATE: 'oauth_state',
  AUTH_TOKENS: 'auth_tokens',
  
  // Cache & Performance
  CACHE_PREFIX: 'cache_',
  TEMP_PREFIX: 'temp_'
} as const;

// ============================================================================
// Storage Value Types
// ============================================================================

/**
 * Background state structure for persistent service worker state
 */
export interface BackgroundState {
  lastAssignedCount: number | null;
  lastHighSeverityCount: number | null;
  lastMediumSeverityCount: number | null;
  lastLowSeverityCount: number | null;
  lastInformationalSeverityCount: number | null;
  lastRefreshTime: number;
  isServiceActive: boolean;
  sessionId: string;
  version: string;
}

/**
 * Known counts for tracking changes
 */
export interface LastKnownCounts {
  incidents: number;
  alerts: number;
  lastUpdated: number;
}

/**
 * Storage change callback type
 */
export type StorageChangeCallback = (
  changes: { [key: string]: browser.Storage.StorageChange },
  area: string
) => void | Promise<void>;

// ============================================================================
// Storage Manager Class
// ============================================================================

/**
 * Main storage manager providing abstraction over browser.storage API
 */
class StorageManager {
  private changeListeners: Map<string, Set<StorageChangeCallback>> = new Map();
  private isInitialized = false;

  constructor() {
    this.setupStorageListener();
  }

  /**
   * Initialize storage manager and perform any necessary migrations
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      // Perform storage migrations if needed
      await this.performMigrations();
      
      // Validate storage structure
      await this.validateStorageStructure();
      
      this.isInitialized = true;
      logger.info('Storage Manager initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Storage Manager', error);
      throw error;
    }
  }

  // ============================================================================
  // Generic Storage Operations
  // ============================================================================

  /**
   * Get a value from storage with optional default
   */
  async get<T>(key: string, defaultValue?: T): Promise<T | undefined> {
    try {
      logger.debug('Storage get operation', { key });
      const result = await browser.storage.local.get([key]);
      logger.debug('Storage get result', { key, resultKeys: Object.keys(result) });
      const value = result[key] as T;
      logger.debug('Storage get extracted value', { key, hasValue: value !== undefined });
      return value !== undefined ? value : defaultValue;
    } catch (error) {
      logger.error(`Failed to get storage value for key "${key}"`, error);
      return defaultValue;
    }
  }

  /**
   * Get multiple values from storage
   */
  async getMultiple<T extends Record<string, any>>(
    keys: (keyof T)[] | Record<keyof T, any>
  ): Promise<Partial<T>> {
    try {
      const keysToGet = Array.isArray(keys) 
        ? keys.reduce((acc, key) => ({ ...acc, [key]: undefined }), {})
        : keys;
      
      const result = await browser.storage.local.get(keysToGet);
      return result as Partial<T>;
    } catch (error) {
      logger.error('Failed to get multiple storage values', error);
      return {};
    }
  }

  /**
   * Set a value in storage
   */
  async set<T>(key: string, value: T): Promise<void> {
    try {
      // Validate and serialize the value
      const serializedValue = this.serializeValue(value);
      await browser.storage.local.set({ [key]: serializedValue });
    } catch (error) {
      logger.error(`Failed to set storage value for key "${key}"`, error);
      throw error;
    }
  }

  /**
   * Set multiple values in storage
   */
  async setMultiple<T extends Record<string, any>>(values: T): Promise<void> {
    try {
      const serializedValues: Record<string, any> = {};
      for (const [key, value] of Object.entries(values)) {
        serializedValues[key] = this.serializeValue(value);
      }
      await browser.storage.local.set(serializedValues);
    } catch (error) {
      logger.error('Failed to set multiple storage values', error);
      throw error;
    }
  }

  /**
   * Remove a value from storage
   */
  async remove(key: string): Promise<void> {
    try {
      await browser.storage.local.remove(key);
    } catch (error) {
      logger.error(`Failed to remove storage value for key "${key}"`, error);
      throw error;
    }
  }

  /**
   * Remove multiple values from storage
   */
  async removeMultiple(keys: string[]): Promise<void> {
    try {
      await browser.storage.local.remove(keys);
    } catch (error) {
      logger.error('Failed to remove multiple storage values', error);
      throw error;
    }
  }

  /**
   * Clear all storage (use with caution)
   */
  async clear(): Promise<void> {
    try {
      await browser.storage.local.clear();
    } catch (error) {
      logger.error('Failed to clear storage', error);
      throw error;
    }
  }

  // ============================================================================
  // Specialized Storage Operations
  // ============================================================================

  /**
   * Get XDR settings with defaults
   */
  async getXdrSettings(): Promise<ExtensionConfig | null> {
    const result = await this.get<ExtensionConfig>(STORAGE_KEYS.XDR_SETTINGS);
    return result ?? null;
  }

  /**
   * Set XDR settings
   */
  async setXdrSettings(settings: ExtensionConfig): Promise<void> {
    await this.set(STORAGE_KEYS.XDR_SETTINGS, settings);
  }

  /**
   * Get background state
   */
  async getBackgroundState(): Promise<BackgroundState | null> {
    const result = await this.get<BackgroundState>(STORAGE_KEYS.BACKGROUND_STATE);
    return result ?? null;
  }

  /**
   * Set background state
   */
  async setBackgroundState(state: BackgroundState): Promise<void> {
    await this.set(STORAGE_KEYS.BACKGROUND_STATE, state);
  }

  /**
   * Update background state partially
   */
  async updateBackgroundState(updates: Partial<BackgroundState>): Promise<void> {
    const currentState = await this.getBackgroundState();
    const newState: BackgroundState = {
      lastAssignedCount: null,
      lastHighSeverityCount: null,
      lastMediumSeverityCount: null,
      lastLowSeverityCount: null,
      lastInformationalSeverityCount: null,
      lastRefreshTime: Date.now(),
      isServiceActive: false,
      sessionId: crypto.randomUUID(),
      version: '1.0.0',
      ...currentState,
      ...updates
    };
    await this.setBackgroundState(newState);
  }

  /**
   * Get last known counts
   */
  async getLastKnownCounts(): Promise<LastKnownCounts | null> {
    const result = await this.get<LastKnownCounts>(STORAGE_KEYS.LAST_KNOWN_COUNTS);
    return result ?? null;
  }

  /**
   * Set last known counts
   */
  async setLastKnownCounts(counts: LastKnownCounts): Promise<void> {
    await this.set(STORAGE_KEYS.LAST_KNOWN_COUNTS, counts);
  }

  /**
   * Get critical audit events
   */
  async getCriticalAuditEvents(): Promise<AuditLogEntry[]> {
    const result = await this.get<AuditLogEntry[]>(STORAGE_KEYS.AUDIT_CRITICAL_EVENTS, []);
    return result ?? [];
  }

  /**
   * Set critical audit events (with size limit)
   */
  async setCriticalAuditEvents(events: AuditLogEntry[]): Promise<void> {
    // Keep only the last 50 critical events
    const limitedEvents = events.slice(-50);
    await this.set(STORAGE_KEYS.AUDIT_CRITICAL_EVENTS, limitedEvents);
  }

  /**
   * Add a critical audit event
   */
  async addCriticalAuditEvent(event: AuditLogEntry): Promise<void> {
    const existingEvents = await this.getCriticalAuditEvents();
    const updatedEvents = [...existingEvents, event];
    await this.setCriticalAuditEvents(updatedEvents);
  }

  /**
   * Update keepalive timestamp
   */
  async updateKeepalive(): Promise<void> {
    await this.set(STORAGE_KEYS.KEEPALIVE, Date.now());
  }

  // ============================================================================
  // Incident Dashboard Data Management
  // ============================================================================

  /**
   * Get incident dashboard data
   */
  async getIncidentDashboardData(): Promise<IncidentDashboardData | null> {
    logger.debug('Getting incident dashboard data', { key: STORAGE_KEYS.INCIDENT_DASHBOARD_DATA });
    const result = await this.get<IncidentDashboardData>(STORAGE_KEYS.INCIDENT_DASHBOARD_DATA);
    logger.debug('Incident dashboard data retrieved', { hasResult: !!result });
    return result ?? null;
  }

  /**
   * Set incident dashboard data
   */
  async setIncidentDashboardData(data: IncidentDashboardData): Promise<void> {
    await this.set(STORAGE_KEYS.INCIDENT_DASHBOARD_DATA, data);
  }

  /**
   * Check if incident dashboard data is fresh (within specified minutes)
   */
  async isIncidentDashboardDataFresh(maxAgeMinutes: number = 5): Promise<boolean> {
    const data = await this.getIncidentDashboardData();
    if (!data || !data.lastUpdated) {
      return false;
    }
    
    const maxAge = maxAgeMinutes * 60 * 1000; // Convert to milliseconds
    return (Date.now() - data.lastUpdated) < maxAge;
  }

  /**
   * Clear expired incident dashboard data
   */
  async clearExpiredIncidentData(maxAgeMinutes: number = 30): Promise<void> {
    const isFresh = await this.isIncidentDashboardDataFresh(maxAgeMinutes);
    if (!isFresh) {
      await this.remove(STORAGE_KEYS.INCIDENT_DASHBOARD_DATA);
      logger.info('Cleared expired incident dashboard data');
    }
  }

  // ============================================================================
  // Cache Management
  // ============================================================================

  /**
   * Set a cached value with optional TTL
   */
  async setCache<T>(key: string, value: T, ttlMinutes?: number): Promise<void> {
    const cacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${key}`;
    const cacheEntry = {
      value,
      timestamp: Date.now(),
      ttl: ttlMinutes ? ttlMinutes * 60 * 1000 : null
    };
    await this.set(cacheKey, cacheEntry);
  }

  /**
   * Get a cached value (returns null if expired)
   */
  async getCache<T>(key: string): Promise<T | null> {
    const cacheKey = `${STORAGE_KEYS.CACHE_PREFIX}${key}`;
    const cacheEntry = await this.get<{
      value: T;
      timestamp: number;
      ttl: number | null;
    }>(cacheKey);

    if (!cacheEntry) return null;

    // Check if expired
    if (cacheEntry.ttl && Date.now() - cacheEntry.timestamp > cacheEntry.ttl) {
      await this.remove(cacheKey);
      return null;
    }

    return cacheEntry.value;
  }

  /**
   * Clear expired cache entries
   */
  async clearExpiredCache(): Promise<void> {
    try {
      const allData = await browser.storage.local.get();
      const expiredKeys: string[] = [];

      for (const [key, value] of Object.entries(allData)) {
        if (key.startsWith(STORAGE_KEYS.CACHE_PREFIX) && 
            typeof value === 'object' && 
            value && 
            'ttl' in value && 
            'timestamp' in value) {
          const cacheEntry = value as any;
          if (cacheEntry.ttl && Date.now() - cacheEntry.timestamp > cacheEntry.ttl) {
            expiredKeys.push(key);
          }
        }
      }

      if (expiredKeys.length > 0) {
        await this.removeMultiple(expiredKeys);
        logger.info(`Cleared ${expiredKeys.length} expired cache entries`);
      }
    } catch (error) {
      logger.error('Failed to clear expired cache', error);
    }
  }

  // ============================================================================
  // Storage Change Monitoring
  // ============================================================================

  /**
   * Add a storage change listener for specific keys
   */
  addChangeListener(keys: string | string[], callback: StorageChangeCallback): void {
    const keyList = Array.isArray(keys) ? keys : [keys];
    
    for (const key of keyList) {
      if (!this.changeListeners.has(key)) {
        this.changeListeners.set(key, new Set());
      }
      this.changeListeners.get(key)!.add(callback);
    }
  }

  /**
   * Remove a storage change listener
   */
  removeChangeListener(keys: string | string[], callback: StorageChangeCallback): void {
    const keyList = Array.isArray(keys) ? keys : [keys];
    
    for (const key of keyList) {
      const listeners = this.changeListeners.get(key);
      if (listeners) {
        listeners.delete(callback);
        if (listeners.size === 0) {
          this.changeListeners.delete(key);
        }
      }
    }
  }

  /**
   * Setup the global storage change listener
   */
  private setupStorageListener(): void {
    browser.storage.onChanged.addListener(async (changes, area) => {
      if (area !== 'local') return;

      for (const [key, change] of Object.entries(changes)) {
        const listeners = this.changeListeners.get(key);
        if (listeners) {
          for (const callback of listeners) {
            try {
              await callback({ [key]: change }, area);
            } catch (error) {
              logger.error(`Storage change listener error for key "${key}":`, error);
            }
          }
        }
      }
    });
  }

  // ============================================================================
  // Data Serialization & Validation
  // ============================================================================

  /**
   * Serialize a value for storage (handles complex objects)
   */
  private serializeValue<T>(value: T): T {
    if (value === null || value === undefined) {
      return value;
    }

    // Handle dates by converting to ISO strings
    if (value instanceof Date) {
      return value.toISOString() as unknown as T;
    }

    // Handle objects recursively
    if (typeof value === 'object' && !Array.isArray(value)) {
      const serialized: any = {};
      for (const [key, val] of Object.entries(value)) {
        serialized[key] = this.serializeValue(val);
      }
      return serialized;
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return value.map(item => this.serializeValue(item)) as unknown as T;
    }

    return value;
  }

  /**
   * Validate storage structure and perform any necessary repairs
   */
  private async validateStorageStructure(): Promise<void> {
    try {
      const requiredKeys = [
        STORAGE_KEYS.XDR_SETTINGS
      ];

      const existingData = await this.getMultiple<Record<string, any>>(requiredKeys);
      
      // Log validation results
      logger.info('Storage structure validation', {
        hasXdrSettings: !!existingData[STORAGE_KEYS.XDR_SETTINGS]
      });
    } catch (error) {
      logger.error('Storage structure validation failed', error);
    }
  }

  /**
   * Perform storage migrations for version updates
   */
  private async performMigrations(): Promise<void> {
    try {
      // Get current version from storage
      const currentVersion = await this.get<string>('storage_version', '1.0.0');
      
      // Perform migrations based on version
      if (currentVersion === '1.0.0') {
        // Future migration logic would go here
        await this.set('storage_version', '1.1.0');
      }
    } catch (error) {
      logger.error('Storage migration failed', error);
    }
  }

  // ============================================================================
  // Storage Statistics & Debugging
  // ============================================================================

  /**
   * Get storage usage statistics
   */
  async getStorageStats(): Promise<{
    totalKeys: number;
    totalSize: number;
    keysByType: Record<string, number>;
    cacheEntries: number;
    tempEntries: number;
  }> {
    try {
      const allData = await browser.storage.local.get();
      const stats = {
        totalKeys: Object.keys(allData).length,
        totalSize: JSON.stringify(allData).length,
        keysByType: {} as Record<string, number>,
        cacheEntries: 0,
        tempEntries: 0
      };

      for (const key of Object.keys(allData)) {
        if (key.startsWith(STORAGE_KEYS.CACHE_PREFIX)) {
          stats.cacheEntries++;
        } else if (key.startsWith(STORAGE_KEYS.TEMP_PREFIX)) {
          stats.tempEntries++;
        } else {
          const keyType = Object.values(STORAGE_KEYS).find(storageKey => 
            key === storageKey
          ) || 'unknown';
          stats.keysByType[keyType] = (stats.keysByType[keyType] || 0) + 1;
        }
      }

      return stats;
    } catch (error) {
      logger.error('Failed to get storage stats', error);
      return {
        totalKeys: 0,
        totalSize: 0,
        keysByType: {},
        cacheEntries: 0,
        tempEntries: 0
      };
    }
  }

  /**
   * Export all storage data for debugging
   */
  async exportStorageData(): Promise<Record<string, any>> {
    try {
      const allData = await browser.storage.local.get();
      
      // Remove sensitive data for export
      const sanitized: Record<string, any> = {};
      for (const [key, value] of Object.entries(allData)) {
        if (key.includes('token') || key.includes('secret') || key.includes('auth')) {
          sanitized[key] = '[REDACTED]';
        } else {
          sanitized[key] = value;
        }
      }
      
      return sanitized;
    } catch (error) {
      logger.error('Failed to export storage data', error);
      return {};
    }
  }
}

// ============================================================================
// Singleton Instance and Factory Functions
// ============================================================================

/**
 * Global storage manager instance
 */
const storageManager = new StorageManager();

/**
 * Initialize storage manager
 */
export async function initializeStorageManager(): Promise<void> {
  await storageManager.initialize();
}

/**
 * Get the global storage manager instance
 */
export function getStorageManager(): StorageManager {
  return storageManager;
}

/**
 * Create a storage change listener factory for specific keys
 */
export function createStorageChangeListener(
  keys: string | string[],
  callback: StorageChangeCallback
): () => void {
  storageManager.addChangeListener(keys, callback);
  
  // Return cleanup function
  return () => {
    storageManager.removeChangeListener(keys, callback);
  };
}

// Export factory functions and main class
export { StorageManager };

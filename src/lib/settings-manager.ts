/**
 * Settings Manager Module - Extension Configuration and Settings Management
 * This module handles all settings loading, validation, persistence, and configuration management
 * SECURITY: Validates settings and manages secure configuration updates
 */

import browser from 'webextension-polyfill';
import type { ExtensionConfig, ExtensionSettings } from '../types/security.d.ts';
import { logger } from './audit-logger.js';

// ============================================================================
// Default Configuration
// ============================================================================

/**
 * Default extension configuration - core system defaults
 */
export const DEFAULT_EXTENSION_CONFIG: ExtensionConfig = {
  oauth: {
    clientId: 'YOUR_MICROSOFT_APP_CLIENT_ID', // Replace with your actual client ID
    tenantId: '', // REQUIRED: Must be a specific tenant GUID - multi-tenant authentication disabled for security
    redirectUri: '', // Will be set dynamically based on browser
    scopes: [
      'https://graph.microsoft.com/SecurityIncident.Read.All',
      'openid',
      'profile',
      'offline_access'
    ]
  },
  api: {
    baseUrl: 'https://graph.microsoft.com',
    apiVersion: 'beta', // FIXED: Security incidents require beta API version
    timeout: 30000,
    retryAttempts: 3,
    retryDelay: 1000,
    timeRangeDays: 30,
    rateLimiting: {
      requestsPerMinute: 600, // Microsoft Graph limit is typically 10,000/minute, being conservative
      burstLimit: 100
    }
  },
  security: {
    encryptionAlgorithm: 'AES-GCM',
    keyLength: 256,
    ivLength: 12,
    saltLength: 16,
    tokenRefreshThreshold: 300 // Refresh token 5 minutes before expiry
  },
  audit: {
    enabled: true,
    maxLogEntries: 1000,
    sensitiveDataMask: true
  },
  debug: {
    enabled: false // Disabled by default for production
  }
};

/**
 * Default user settings - stored in browser.storage.local
 * This now contains ALL extension settings including security configuration
 */
export const DEFAULT_XDR_SETTINGS: ExtensionSettings = {
  oauth: {
    clientId: '',
    tenantId: '', // REQUIRED: Must be a specific tenant GUID for security
    customScopes: []
  },
  api: {
    timeout: 30,
    retryAttempts: 3,
    timeRangeDays: 30
  },
  ui: {
    theme: 'auto',
    autoRefresh: true,
    refreshInterval: 5,
    notifications: true,
    notifyOnNewAssignments: true,
    notifyOnHighSeverity: true,
    notifyOnMediumSeverity: true,
    notifyOnLowSeverity: true,
    notifyOnInformationalSeverity: true
  },
  security: {
    autoRefreshInterval: 300000, // 5 minutes
    notificationsEnabled: true,
    defaultIncidentFilters: {
      status: ['active'],
      severity: ['high', 'medium']
    }
  },
  debug: {
    enabled: false
  }
};

// ============================================================================
// Settings Manager Class
// ============================================================================

export class SettingsManager {
  private extensionConfig: ExtensionConfig;
  private isInitialized = false;

  constructor() {
    // Create a deep copy of the default configuration
    this.extensionConfig = JSON.parse(JSON.stringify(DEFAULT_EXTENSION_CONFIG));
  }

  /**
   * Initialize the settings manager and load user settings
   */
  async initialize(): Promise<void> {
    try {
      await this.loadSettingsFromStorage();
      this.isInitialized = true;
      logger.info('Settings manager initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize settings manager:', error);
      throw error;
    }
  }

  /**
   * Get the current extension configuration
   */
  getExtensionConfig(): ExtensionConfig {
    if (!this.isInitialized) {
      logger.warn('Settings manager not initialized, returning default config');
    }
    return this.extensionConfig;
  }

  /**
   * Load and apply user settings from storage
   */
  async loadSettingsFromStorage(): Promise<void> {
    try {
      const result = await browser.storage.local.get({ xdr_settings: null });
      
      if (result.xdr_settings) {
        const settings = result.xdr_settings as ExtensionSettings;
        this.applyUserSettings(settings);
        logger.info('User settings loaded and applied successfully');
      } else {
        logger.info('No user settings found, using defaults');
      }
    } catch (error) {
      logger.error('Failed to load settings from storage:', error);
      throw error;
    }
  }

  /**
   * Apply user settings to the extension configuration
   */
  private applyUserSettings(settings: ExtensionSettings): void {
    try {
      // Validate and apply OAuth configuration
      if (settings.oauth?.clientId && settings.oauth.clientId !== 'YOUR_MICROSOFT_APP_CLIENT_ID') {
        this.extensionConfig.oauth.clientId = settings.oauth.clientId;
      }
      
      if (settings.oauth?.tenantId) {
        this.extensionConfig.oauth.tenantId = settings.oauth.tenantId;
      }
      
      if (settings.oauth?.customScopes && Array.isArray(settings.oauth.customScopes) && settings.oauth.customScopes.length > 0) {
        // Merge custom scopes with default ones
        const defaultScopes = [
          'https://graph.microsoft.com/SecurityIncident.Read.All',
          'openid',
          'profile',
          'offline_access'
        ];
        this.extensionConfig.oauth.scopes = [...defaultScopes, ...settings.oauth.customScopes];
      }
      
      // Validate and apply API configuration
      if (settings.api?.timeout && typeof settings.api.timeout === 'number' && settings.api.timeout > 0) {
        this.extensionConfig.api.timeout = settings.api.timeout * 1000; // Convert to milliseconds
      }
      
      if (settings.api?.retryAttempts && typeof settings.api.retryAttempts === 'number' && settings.api.retryAttempts >= 0) {
        this.extensionConfig.api.retryAttempts = settings.api.retryAttempts;
      }
      
      if (settings.api?.timeRangeDays && typeof settings.api.timeRangeDays === 'number' && settings.api.timeRangeDays > 0 && settings.api.timeRangeDays <= 180) {
        this.extensionConfig.api.timeRangeDays = settings.api.timeRangeDays;
      }

      // Apply debug configuration if present
      if (settings.debug !== undefined) {
        if (typeof settings.debug.enabled === 'boolean') {
          this.extensionConfig.debug.enabled = settings.debug.enabled;
        }
      }
      
      logger.info('User settings applied to extension configuration');
    } catch (error) {
      logger.error('Failed to apply user settings:', error);
      throw error;
    }
  }

  /**
   * Validate user settings structure and values
   */
  validateSettings(settings: any): settings is ExtensionSettings {
    try {
      // Basic structure validation
      if (!settings || typeof settings !== 'object') {
        return false;
      }

      // Validate OAuth settings
      if (settings.oauth) {
        if (settings.oauth.clientId && typeof settings.oauth.clientId !== 'string') {
          return false;
        }
        if (settings.oauth.tenantId && typeof settings.oauth.tenantId !== 'string') {
          return false;
        }
        
        // SECURITY: Enhanced tenant ID validation - single-tenant only
        if (settings.oauth.tenantId) {
          const tenantId = settings.oauth.tenantId;
          
          // Reject multi-tenant configurations entirely
          if (tenantId === 'common' || tenantId === 'organizations' || tenantId === 'consumers') {
            logger.error('Multi-tenant configuration rejected for security', { tenantId });
            return false;
          }
          
          // Validate tenant ID is a proper GUID format
          const isValidGuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId);
          
          if (!isValidGuid) {
            logger.error('Invalid tenant ID format - must be a valid GUID', { tenantId });
            return false;
          }
          
          logger.info('Single-tenant configuration validated', { tenantId });
        } else {
          // Require tenant ID to be configured
          logger.error('Tenant ID is required for security - multi-tenant authentication is disabled');
          return false;
        }
        
        if (settings.oauth.customScopes && !Array.isArray(settings.oauth.customScopes)) {
          return false;
        }
      }

      // Validate API settings
      if (settings.api) {
        if (settings.api.timeout && (typeof settings.api.timeout !== 'number' || settings.api.timeout <= 0)) {
          return false;
        }
        if (settings.api.retryAttempts && (typeof settings.api.retryAttempts !== 'number' || settings.api.retryAttempts < 0)) {
          return false;
        }
        if (settings.api.timeRangeDays && (typeof settings.api.timeRangeDays !== 'number' || settings.api.timeRangeDays <= 0 || settings.api.timeRangeDays > 180)) {
          return false;
        }
      }

      // Validate UI settings
      if (settings.ui) {
        if (settings.ui.theme && !['auto', 'light', 'dark'].includes(settings.ui.theme)) {
          return false;
        }
        if (settings.ui.autoRefresh && typeof settings.ui.autoRefresh !== 'boolean') {
          return false;
        }
        if (settings.ui.refreshInterval && (typeof settings.ui.refreshInterval !== 'number' || settings.ui.refreshInterval <= 0)) {
          return false;
        }
        if (settings.ui.notifications && typeof settings.ui.notifications !== 'boolean') {
          return false;
        }
        if (settings.ui.notifyOnNewAssignments && typeof settings.ui.notifyOnNewAssignments !== 'boolean') {
          return false;
        }
      }

      // Validate security settings
      if (settings.security) {
        if (settings.security.autoRefreshInterval && (typeof settings.security.autoRefreshInterval !== 'number' || settings.security.autoRefreshInterval <= 0)) {
          return false;
        }
        if (settings.security.notificationsEnabled && typeof settings.security.notificationsEnabled !== 'boolean') {
          return false;
        }
        if (settings.security.defaultIncidentFilters) {
          const filters = settings.security.defaultIncidentFilters;
          if (filters.status && !Array.isArray(filters.status)) {
            return false;
          }
          if (filters.severity && !Array.isArray(filters.severity)) {
            return false;
          }
        }
      }

      return true;
    } catch (error) {
      logger.error('Settings validation error:', error);
      return false;
    }
  }

  /**
   * Save settings to storage with validation
   */
  async saveSettings(settings: ExtensionSettings): Promise<void> {
    try {
      // Validate settings before saving
      if (!this.validateSettings(settings)) {
        throw new Error('Invalid settings structure or values');
      }

      // Save to storage
      await browser.storage.local.set({ xdr_settings: settings });
      
      // Apply the new settings
      this.applyUserSettings(settings);
      
      logger.info('Settings saved and applied successfully');
    } catch (error) {
      logger.error('Failed to save settings:', error);
      throw error;
    }
  }

  /**
   * Get current user settings from storage
   */
  async getUserSettings(): Promise<ExtensionSettings> {
    try {
      const result = await browser.storage.local.get({ xdr_settings: DEFAULT_XDR_SETTINGS });
      return result.xdr_settings as ExtensionSettings;
    } catch (error) {
      logger.error('Failed to get user settings:', error);
      return DEFAULT_XDR_SETTINGS;
    }
  }

  /**
   * Reset settings to defaults
   */
  async resetToDefaults(): Promise<void> {
    try {
      await this.saveSettings(DEFAULT_XDR_SETTINGS);
      logger.info('Settings reset to defaults');
    } catch (error) {
      logger.error('Failed to reset settings:', error);
      throw error;
    }
  }

  /**
   * Update redirect URI based on browser capabilities
   */
  updateRedirectUri(redirectUri: string): void {
    this.extensionConfig.oauth.redirectUri = redirectUri;
    logger.info('Redirect URI updated', { value: redirectUri });
  }

  /**
   * Export current settings for backup/migration
   */
  async exportSettings(): Promise<{ xdr_settings: ExtensionSettings }> {
    try {
      const xdrSettings = await this.getUserSettings();

      return {
        xdr_settings: xdrSettings
      };
    } catch (error) {
      logger.error('Failed to export settings:', error);
      throw error;
    }
  }

  /**
   * Import settings from backup/migration
   */
  async importSettings(data: { xdr_settings?: ExtensionSettings }): Promise<void> {
    try {
      if (data.xdr_settings) {
        await this.saveSettings(data.xdr_settings);
      }

      logger.info('Settings imported successfully');
    } catch (error) {
      logger.error('Failed to import settings:', error);
      throw error;
    }
  }
}

// ============================================================================
// Default Settings Creation Functions
// ============================================================================

/**
 * Create default settings on extension installation
 */
export async function createDefaultSettings(): Promise<void> {
  try {
    // Check if settings already exist
    const existingSettings = await browser.storage.local.get({ 
      xdr_settings: null 
    });
    
    // Set default xdr_settings only if they don't exist
    if (!existingSettings.xdr_settings) {
      logger.info('Setting default xdr_settings');
      await browser.storage.local.set({ xdr_settings: DEFAULT_XDR_SETTINGS });
    } else {
      logger.info('xdr_settings already exist, preserving user settings');
    }

    logger.info('Default settings creation completed');
  } catch (error) {
    logger.error('Failed to create default settings:', error);
    throw error;
  }
}

/**
 * Handle settings change events
 */
export function createSettingsChangeHandler(
  onSettingsChanged: (newSettings: ExtensionSettings) => Promise<void>
) {
  return async (changes: { [key: string]: browser.Storage.StorageChange }, area: string) => {
    if (area === 'local' && changes.xdr_settings) {
      try {
        const newSettings = changes.xdr_settings.newValue as ExtensionSettings;
        if (newSettings) {
          logger.info('Settings changed, notifying handlers');
          await onSettingsChanged(newSettings);
        }
      } catch (error) {
        logger.error('Failed to handle settings change:', error);
      }
    }
  };
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Global settings manager instance
 */
export const settingsManager = new SettingsManager();

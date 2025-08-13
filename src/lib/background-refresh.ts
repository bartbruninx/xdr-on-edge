/**
 * Background Refresh Module - Auto-refresh and Background System Management
 * This module handles all background refresh operations, alarm management, and state persistence
 * SECURITY: Ensures secure background operations with proper error handling and audit logging
 */

import browser from 'webextension-polyfill';
import { showBackgroundNotification, createHighSeverityNotification, createMediumSeverityNotification, createLowSeverityNotification, createInformationalSeverityNotification } from './notifications.js';
import { getStorageManager, type BackgroundState } from './storage-manager.js';
import type { OAuthService } from './oauth.js';
import type { MicrosoftSecurityApiClient } from './security-api.js';
import type { AuditLogEntry } from '../types/security.d.ts';
import { logger } from './audit-logger.js';

// ============================================================================
// Constants and State
// ============================================================================

const AUTO_REFRESH_ALARM = 'xdr-auto-refresh';
// Track last known counts for notification purposes
let lastAssignedCount: number | null = null;
let lastHighSeverityCount: number | null = null;
let lastMediumSeverityCount: number | null = null;
let lastLowSeverityCount: number | null = null;
let lastInformationalSeverityCount: number | null = null;
const storageManager = getStorageManager();

// ============================================================================
// State Persistence
// ============================================================================

/**
 * Load persistent background state from storage
 */
export async function loadBackgroundState(): Promise<void> {
  try {
    const backgroundState = await storageManager.getBackgroundState();
    
    if (backgroundState?.lastAssignedCount !== undefined) {
      lastAssignedCount = backgroundState.lastAssignedCount;
      logger.debug('Restored persistent lastAssignedCount', { count: lastAssignedCount });
    } else {
      logger.debug('No persistent lastAssignedCount found');
    }
    
    if (backgroundState?.lastHighSeverityCount !== undefined) {
      lastHighSeverityCount = backgroundState.lastHighSeverityCount;
      logger.debug('Restored persistent lastHighSeverityCount', { count: lastHighSeverityCount });
    } else {
      logger.debug('No persistent lastHighSeverityCount found');
    }
    
    if (backgroundState?.lastMediumSeverityCount !== undefined) {
      lastMediumSeverityCount = backgroundState.lastMediumSeverityCount;
      logger.debug('Restored persistent lastMediumSeverityCount', { count: lastMediumSeverityCount });
    } else {
      logger.debug('No persistent lastMediumSeverityCount found');
    }
    
    if (backgroundState?.lastLowSeverityCount !== undefined) {
      lastLowSeverityCount = backgroundState.lastLowSeverityCount;
      logger.debug('Restored persistent lastLowSeverityCount', { count: lastLowSeverityCount });
    } else {
      logger.debug('No persistent lastLowSeverityCount found');
    }
    
    if (backgroundState?.lastInformationalSeverityCount !== undefined) {
      lastInformationalSeverityCount = backgroundState.lastInformationalSeverityCount;
      logger.debug('Restored persistent lastInformationalSeverityCount', { count: lastInformationalSeverityCount });
    } else {
      logger.debug('No persistent lastInformationalSeverityCount found');
    }
  } catch (error) {
    logger.error('Failed to load background state', error);
  }
}

/**
 * Save persistent background state to storage
 */
export async function saveBackgroundState(): Promise<void> {
  try {
    const backgroundState: BackgroundState = {
      lastAssignedCount: lastAssignedCount,
      lastHighSeverityCount: lastHighSeverityCount,
      lastMediumSeverityCount: lastMediumSeverityCount,
      lastLowSeverityCount: lastLowSeverityCount,
      lastInformationalSeverityCount: lastInformationalSeverityCount,
      lastRefreshTime: Date.now(),
      isServiceActive: true,
      sessionId: crypto.randomUUID(),
      version: '1.0.0'
    };
    
    await storageManager.setBackgroundState(backgroundState);
    logger.debug('Saved persistent severity counts', { 
      assigned: lastAssignedCount,
      high: lastHighSeverityCount,
      medium: lastMediumSeverityCount,
      low: lastLowSeverityCount,
      informational: lastInformationalSeverityCount
    });
  } catch (error) {
    logger.error('Failed to save background state', error);
  }
}

// ============================================================================
// Auto-Refresh Alarm Management
// ============================================================================

/**
 * Set up auto-refresh alarm based on user settings
 */
export async function setupAutoRefreshAlarm(): Promise<void> {
  try {
    // Note: For now, use direct storage access until settings manager is updated to use storage manager
    const result = await browser.storage.local.get({ xdr_settings: null });
    const settings = result.xdr_settings as any;
    
    // Clear existing alarm
    await browser.alarms.clear(AUTO_REFRESH_ALARM);
    
    if (settings?.ui?.autoRefresh && settings?.ui?.refreshInterval) {
      // Create alarm that repeats every refreshInterval minutes
      await browser.alarms.create(AUTO_REFRESH_ALARM, {
        delayInMinutes: settings.ui.refreshInterval,
        periodInMinutes: settings.ui.refreshInterval
      });
      
      logger.debug('Auto-refresh alarm set', { intervalMinutes: settings.ui.refreshInterval });
    } else {
      logger.debug('Auto-refresh disabled or no interval set');
    }
  } catch (error) {
    logger.error('Failed to setup auto-refresh alarm', error);
  }
}

// ============================================================================
// Background Refresh Execution
// ============================================================================

/**
 * Perform background incident count refresh and check for new assignments
 * Now uses optimized dashboard data fetching for better performance
 */
export async function performBackgroundRefresh(
  isInitialized: boolean,
  oauthService: OAuthService | null,
  apiClient: MicrosoftSecurityApiClient | null,
  initializeServices: () => Promise<void>,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<void> {
  try {
    logger.debug('Background refresh started with optimized data fetching');
    
    // Ensure services are properly initialized
    if (!isInitialized) {
      logger.info('Services not initialized, attempting initialization');
      await initializeServices();
      return; // Let the caller check initialization status again
    }
    
    // Check if services are available
    if (!oauthService || !apiClient) {
      logger.error('OAuth service or API client not available, skipping background refresh');
      return;
    }
    
    const authStatus = await oauthService.getAuthenticationState();
    if (!authStatus.isAuthenticated) {
      logger.debug('User not authenticated, skipping background refresh');
      return;
    }
    
    // Get current user email
    const userInfo = authStatus.user;
    if (!userInfo?.userPrincipalName) {
      logger.debug('User email not available, skipping assigned incidents check');
      return;
    }
    
    logger.debug('Fetching comprehensive incident dashboard data', { user: userInfo.userPrincipalName });
    
    try {
      const accessToken = await oauthService.getValidAccessToken();
      
      // Use the new optimized dashboard data fetching method
      const dashboardData = await apiClient.getDashboardIncidentData(accessToken, userInfo.userPrincipalName);
      
      const currentAssignedCount = dashboardData.incidentCounts.assigned;
      const currentActiveCount = dashboardData.incidentCounts.active;
      
      logger.debug('Background refresh incident counts', { 
        assigned: currentAssignedCount, 
        previousAssigned: lastAssignedCount,
        active: currentActiveCount,
        severityBreakdown: dashboardData.incidentCounts.bySeverity
      });
      
      // Check for new assignments and send notification
      // Only notify if we have a previous count to compare against (not initial load)
      if (lastAssignedCount !== null && currentAssignedCount > lastAssignedCount) {
        await showBackgroundNotification(currentAssignedCount, lastAssignedCount, userInfo.userPrincipalName, logAuditEvent);
      }
      
      // Check for new high severity incidents and send notification
      const currentHighSeverityCount = dashboardData.incidentCounts.bySeverity.high;
      logger.debug('Background refresh high severity check', { 
        current: currentHighSeverityCount, 
        previous: lastHighSeverityCount 
      });
      
      if (lastHighSeverityCount !== null && currentHighSeverityCount > lastHighSeverityCount) {
        try {
          const notificationId = await createHighSeverityNotification(currentHighSeverityCount, lastHighSeverityCount);
          if (notificationId) {
            logger.info('High severity notification sent', { notificationId });
            // Log audit event for high severity notification
            await logAuditEvent('info', 'security', 'high_severity_notification_sent', {
              currentCount: currentHighSeverityCount,
              previousCount: lastHighSeverityCount,
              newIncidents: currentHighSeverityCount - lastHighSeverityCount,
              notificationId: notificationId
            });
          }
        } catch (error) {
          logger.error('Failed to send high severity notification', error);
          await logAuditEvent('error', 'security', 'high_severity_notification_failed', {
            currentCount: currentHighSeverityCount,
            previousCount: lastHighSeverityCount,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
      
      // Check for new medium severity incidents and send notification
      const currentMediumSeverityCount = dashboardData.incidentCounts.bySeverity.medium;
      logger.debug('Background refresh medium severity check', { 
        current: currentMediumSeverityCount, 
        previous: lastMediumSeverityCount 
      });
      
      if (lastMediumSeverityCount !== null && currentMediumSeverityCount > lastMediumSeverityCount) {
        try {
          const notificationId = await createMediumSeverityNotification(currentMediumSeverityCount, lastMediumSeverityCount);
          if (notificationId) {
            logger.info('Medium severity notification sent', { notificationId });
            // Log audit event for medium severity notification
            await logAuditEvent('info', 'security', 'medium_severity_notification_sent', {
              currentCount: currentMediumSeverityCount,
              previousCount: lastMediumSeverityCount,
              newIncidents: currentMediumSeverityCount - lastMediumSeverityCount,
              notificationId: notificationId
            });
          }
        } catch (error) {
          logger.error('Failed to send medium severity notification', error);
          await logAuditEvent('error', 'security', 'medium_severity_notification_failed', {
            currentCount: currentMediumSeverityCount,
            previousCount: lastMediumSeverityCount,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
      
      // Check for new low severity incidents and send notification
      const currentLowSeverityCount = dashboardData.incidentCounts.bySeverity.low;
      logger.debug('Background refresh low severity check', { 
        current: currentLowSeverityCount, 
        previous: lastLowSeverityCount 
      });
      
      if (lastLowSeverityCount !== null && currentLowSeverityCount > lastLowSeverityCount) {
        try {
          const notificationId = await createLowSeverityNotification(currentLowSeverityCount, lastLowSeverityCount);
          if (notificationId) {
            logger.info('Low severity notification sent', { notificationId });
            // Log audit event for low severity notification
            await logAuditEvent('info', 'security', 'low_severity_notification_sent', {
              currentCount: currentLowSeverityCount,
              previousCount: lastLowSeverityCount,
              newIncidents: currentLowSeverityCount - lastLowSeverityCount,
              notificationId: notificationId
            });
          }
        } catch (error) {
          logger.error('Failed to send low severity notification', error);
          await logAuditEvent('error', 'security', 'low_severity_notification_failed', {
            currentCount: currentLowSeverityCount,
            previousCount: lastLowSeverityCount,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
      
      // Check for new informational severity incidents and send notification
      const currentInformationalSeverityCount = dashboardData.incidentCounts.bySeverity.informational;
      logger.debug('Background refresh informational severity check', { 
        current: currentInformationalSeverityCount, 
        previous: lastInformationalSeverityCount 
      });
      
      if (lastInformationalSeverityCount !== null && currentInformationalSeverityCount > lastInformationalSeverityCount) {
        try {
          const notificationId = await createInformationalSeverityNotification(currentInformationalSeverityCount, lastInformationalSeverityCount);
          if (notificationId) {
            logger.info('Informational severity notification sent', { notificationId });
            // Log audit event for informational severity notification
            await logAuditEvent('info', 'security', 'informational_severity_notification_sent', {
              currentCount: currentInformationalSeverityCount,
              previousCount: lastInformationalSeverityCount,
              newIncidents: currentInformationalSeverityCount - lastInformationalSeverityCount,
              notificationId: notificationId
            });
          }
        } catch (error) {
          logger.error('Failed to send informational severity notification', error);
          await logAuditEvent('error', 'security', 'informational_severity_notification_failed', {
            currentCount: currentInformationalSeverityCount,
            previousCount: lastInformationalSeverityCount,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
      
      // Update last known counts and store in persistent storage
      lastAssignedCount = currentAssignedCount;
      lastHighSeverityCount = currentHighSeverityCount;
      lastMediumSeverityCount = dashboardData.incidentCounts.bySeverity.medium;
      lastLowSeverityCount = dashboardData.incidentCounts.bySeverity.low;
      lastInformationalSeverityCount = dashboardData.incidentCounts.bySeverity.informational;
      await saveBackgroundState();
      
      // Store the comprehensive dashboard data for frontend consumption
      await storageManager.setIncidentDashboardData(dashboardData);
      
      // Also maintain backward compatibility with simple counts
      await storageManager.setLastKnownCounts({
        incidents: currentAssignedCount,
        alerts: currentActiveCount, 
        lastUpdated: Date.now()
      });
      
      logger.debug('Stored comprehensive dashboard data', { 
        active: currentActiveCount, 
        assigned: currentAssignedCount, 
        highSeverity: dashboardData.incidentCounts.bySeverity.high 
      });
      
      // Log audit event for successful refresh
      logAuditEvent('info', 'api', 'background_refresh_success', {
        assignedCount: currentAssignedCount,
        activeCount: currentActiveCount,
        severityBreakdown: dashboardData.incidentCounts.bySeverity,
        userEmail: userInfo.userPrincipalName
      });
      
    } catch (error) {
      logger.error('Background refresh failed', error);
      
      // Handle authentication errors gracefully
      if (error instanceof Error && 'code' in error) {
        const authError = error as any;
        if (['AUTH_REQUIRED', 'TOKEN_EXPIRED'].includes(authError.code)) {
          logger.info('Authentication expired during background refresh, user will need to re-login');
          logAuditEvent('warn', 'auth', 'background_auth_expired', {
            error: authError.message,
            code: authError.code,
            userEmail: userInfo.userPrincipalName
          });
          
          // Clear authentication state to force re-login on next interaction
          await oauthService.logout();
          return; // Don't throw error to prevent alarm system from stopping
        }
        
        // Handle rate limit errors gracefully - don't break alarm system
        if (authError.code === 'RATE_LIMITED') {
          logger.warn('Rate limit exceeded during background refresh, will retry on next scheduled refresh');
          logAuditEvent('warn', 'api', 'background_rate_limited', {
            error: authError.message,
            retryAfter: authError.details?.retryAfter,
            userEmail: userInfo.userPrincipalName
          });
          return; // Don't throw error to prevent alarm system from stopping
        }
        
        // Handle network/timeout errors gracefully - don't break alarm system
        if (authError.code === 'NETWORK_ERROR') {
          logger.warn('Network timeout during background refresh, will retry on next scheduled refresh');
          logAuditEvent('warn', 'api', 'background_network_timeout', {
            error: authError.message,
            originalError: authError.details?.originalError,
            userEmail: userInfo.userPrincipalName
          });
          return; // Don't throw error to prevent alarm system from stopping
        }
        
        // Handle other API errors gracefully
        if (authError.code === 'API_ERROR') {
          logger.error('API error during background refresh', authError);
          logAuditEvent('error', 'api', 'background_api_error', {
            error: authError.message,
            status: authError.details?.status,
            code: authError.code,
            userEmail: userInfo.userPrincipalName
          });
          return; // Don't throw error to prevent alarm system from stopping
        }
      }
      
      throw error; // Re-throw non-auth errors to be caught by alarm handler
    }
  } catch (error) {
    logger.error('Background refresh failed', error);
    logAuditEvent('error', 'security', 'background_refresh_failed', {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

// ============================================================================
// Alarm Event Handler
// ============================================================================

// ============================================================================
// Alarm Event Handler
// ============================================================================

/**
 * Handle alarm events for auto-refresh
 */
export function createAlarmHandler(
  performRefresh: () => Promise<void>,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
) {
  return async (alarm: browser.Alarms.Alarm) => {
    logger.debug('Alarm event received', { alarmName: alarm.name, time: new Date().toLocaleTimeString() });
    
    if (alarm.name === AUTO_REFRESH_ALARM) {
      logger.info('Auto-refresh alarm triggered', { time: new Date().toLocaleTimeString() });
      try {
        await performRefresh();
        logger.debug('Auto-refresh completed successfully');
      } catch (error) {
        logger.error('Auto-refresh failed', error);
        // Log the error but don't stop the alarm system
        logAuditEvent('error', 'security', 'auto_refresh_failed', {
          error: error instanceof Error ? error.message : String(error),
          timestamp: new Date().toISOString()
        });
      }
    }
  };
}

// ============================================================================
// Chrome Service Worker Keepalive
// ============================================================================

/**
 * Set up Chrome service worker keepalive to prevent termination
 */
export function setupChromeKeepalive(): void {
  if (typeof (globalThis as any).chrome !== 'undefined' && (globalThis as any).chrome.runtime) {
    // Chrome-specific: prevent service worker from sleeping
    (globalThis as any).chrome.runtime.onStartup.addListener(() => {
      logger.info('Chrome service worker startup');
    });
    
    (globalThis as any).chrome.runtime.onInstalled.addListener(() => {
      logger.info('Chrome service worker installed');
    });
    
    // Periodic keepalive to prevent Chrome service worker termination
    setInterval(() => {
      try {
        if ((globalThis as any).chrome.runtime?.id) {
          logger.debug('Chrome service worker keepalive ping');
          // Trigger a small storage operation to maintain service worker activity
          storageManager.updateKeepalive().catch(() => {
            // Ignore keepalive storage errors
          });
        }
      } catch (error) {
        logger.warn('Chrome keepalive failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      }
    }, 20000); // Every 20 seconds
  }
}

// ============================================================================
// Storage Change Listener
// ============================================================================

/**
 * Create storage change listener for settings updates
 */
export function createStorageChangeListener() {
  return async (changes: { [key: string]: browser.Storage.StorageChange }, area: string) => {
    if (area === 'local' && changes.xdr_settings) {
      logger.debug('Settings changed, updating auto-refresh alarm');
      logger.debug('Settings change details', {
        area,
        hasOldValue: !!changes.xdr_settings.oldValue,
        hasNewValue: !!changes.xdr_settings.newValue
      });
      
      // Add browser-specific debugging
      const userAgent = navigator.userAgent.toLowerCase();
      const isFirefox = userAgent.includes('firefox');
      if (isFirefox) {
        logger.debug('Firefox storage change', { 
          newSettingsUI: (changes.xdr_settings.newValue as any)?.ui 
        });
      }
      
      await setupAutoRefreshAlarm();
    }
  };
}

// ============================================================================
// Background System Initialization
// ============================================================================

/**
 * Initialize background systems
 */
export async function initializeBackgroundSystems(): Promise<void> {
  try {
    logger.debug('initializeBackgroundSystems called');
    
    // Always setup alarm on initialization (important for Chrome service worker restarts)
    await setupAutoRefreshAlarm();
    
    // Load background state including all severity counts
    await loadBackgroundState();
    
    // Fallback: Initialize last assigned count from legacy storage if background state is empty
    if (lastAssignedCount === null) {
      const lastKnownCounts = await storageManager.getLastKnownCounts();
      if (lastKnownCounts?.incidents !== undefined) {
        lastAssignedCount = lastKnownCounts.incidents;
        logger.debug('Restored last known assigned count from legacy storage', { count: lastAssignedCount });
      } else {
        logger.debug('No previous assigned count found in legacy storage');
      }
    }
    
    // Verify alarms are working
    const alarms = await browser.alarms.getAll();
    logger.debug('Active alarms after initialization', { alarmCount: alarms.length });
    
    logger.debug('Background systems initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize background systems', error);
  }
}

// ============================================================================
// Exports for Testing and Access
// ============================================================================

export function getLastAssignedCount(): number | null {
  return lastAssignedCount;
}

export function setLastAssignedCount(count: number | null): void {
  lastAssignedCount = count;
}

export function getLastHighSeverityCount(): number | null {
  return lastHighSeverityCount;
}

export function setLastHighSeverityCount(count: number | null): void {
  lastHighSeverityCount = count;
}

export function getLastMediumSeverityCount(): number | null {
  return lastMediumSeverityCount;
}

export function setLastMediumSeverityCount(count: number | null): void {
  lastMediumSeverityCount = count;
}

export function getLastLowSeverityCount(): number | null {
  return lastLowSeverityCount;
}

export function setLastLowSeverityCount(count: number | null): void {
  lastLowSeverityCount = count;
}

export function getLastInformationalSeverityCount(): number | null {
  return lastInformationalSeverityCount;
}

export function setLastInformationalSeverityCount(count: number | null): void {
  lastInformationalSeverityCount = count;
}

export function getAutoRefreshAlarmName(): string {
  return AUTO_REFRESH_ALARM;
}

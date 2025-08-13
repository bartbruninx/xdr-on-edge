/**
 * Notification Manager Module - Complete Notification System for XDR on Edge Extension
 * Provides centralized notification handling, background notifications, event listeners, and permission management
 */

import browser from 'webextension-polyfill';
import type { AuditLogEntry } from '../types/security.d.ts';
import { logger } from './audit-logger.js';

/**
 * Configuration options for notifications
 */
export interface NotificationOptions {
  priority?: 0 | 1 | 2;
  id?: string;
  buttons?: Array<{ title: string; iconUrl?: string }>;
}

/**
 * Pre-resolve the icon URL for notifications
 * This helps avoid runtime context issues
 */
let cachedIconUrl: string | null = null;

async function getIconUrl(): Promise<string | null> {
  if (cachedIconUrl !== null) {
    return cachedIconUrl;
  }
  
  try {
    if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.getURL) {
      cachedIconUrl = browser.runtime.getURL('logo.png');
      logger.debug('Successfully resolved icon URL', { url: cachedIconUrl });
      return cachedIconUrl;
    } else {
      logger.warn('browser.runtime.getURL not available');
      cachedIconUrl = '';
      return null;
    }
  } catch (error) {
    logger.error('Failed to resolve icon URL', error);
    cachedIconUrl = '';
    return null;
  }
}

/**
 * Standardized notification creation function for the XDR on Edge extension
 * Uses the extension logo and provides consistent notification behavior
 */
export async function createStandardNotification(
  title: string,
  message: string,
  options: NotificationOptions = {}
): Promise<string> {
  const iconUrl = await getIconUrl();

  const notificationOptions: browser.Notifications.CreateNotificationOptions = {
    type: 'basic',
    title: title,
    message: message,
    priority: options.priority || 1
  };

  // Only add iconUrl if we successfully got it
  if (iconUrl) {
    notificationOptions.iconUrl = iconUrl;
    logger.debug('Creating notification with icon', { iconUrl });
  } else {
    logger.debug('Creating notification without icon');
  }

  // Add buttons if provided (for action notifications)
  if (options.buttons && options.buttons.length > 0) {
    (notificationOptions as any).buttons = options.buttons;
  }
  
  try {
    const notificationId = await browser.notifications.create(options.id, notificationOptions);
    logger.debug('Notification created successfully', { notificationId });
    return notificationId;
  } catch (error) {
    logger.error('Failed to create notification', error);
    
    // Retry without icon if the error might be icon-related
    if (iconUrl && error && (error as any).message?.includes('image')) {
      logger.debug('Retrying notification without icon due to image error');
      delete notificationOptions.iconUrl;
      const retryNotificationId = await browser.notifications.create(options.id, notificationOptions);
      return retryNotificationId;
    }
    
    throw error;
  }
}

/**
 * Initialize notification system - call this early in background script
 * This pre-resolves the icon URL to avoid runtime context issues
 */
export async function initializeNotificationSystem(): Promise<void> {
  await getIconUrl();
}

/**
 * Check if notifications are enabled in user settings and browser permissions
 */
export async function areNotificationsEnabled(): Promise<boolean> {
  try {
    // Check user settings
    const result = await browser.storage.local.get({ xdr_settings: null });
    const settings = result.xdr_settings as any;
    
    const notificationsEnabled = settings?.ui?.notifications !== false; // Default to true
    
    if (!notificationsEnabled) {
      return false;
    }
    
    // Check browser permissions
    const permission = await browser.permissions.contains({ permissions: ['notifications'] });
    if (!permission) {
      return false;
    }
    
    return true;
  } catch (error) {
    logger.error('Error checking notification permissions', error);
    return false;
  }
}

/**
 * Check if specific notification type is enabled (like new assignment notifications)
 */
export async function isNotificationTypeEnabled(notificationType: 'assignments' | 'high-severity' | 'medium-severity' | 'low-severity' | 'informational-severity' | 'general'): Promise<boolean> {
  try {
    const result = await browser.storage.local.get({ xdr_settings: null });
    const settings = result.xdr_settings as any;
    
    // Check general notifications first
    const notificationsEnabled = settings?.ui?.notifications !== false;
    if (!notificationsEnabled) {
      return false;
    }
    
    // Check specific notification type
    switch (notificationType) {
      case 'assignments':
        return settings?.ui?.notifyOnNewAssignments !== false; // Default to true
      case 'high-severity':
        return settings?.ui?.notifyOnHighSeverity !== false; // Default to true
      case 'medium-severity':
        return settings?.ui?.notifyOnMediumSeverity !== false; // Default to true
      case 'low-severity':
        return settings?.ui?.notifyOnLowSeverity !== false; // Default to true
      case 'informational-severity':
        return settings?.ui?.notifyOnInformationalSeverity !== false; // Default to true
      case 'general':
        return true; // General notifications follow the main setting
      default:
        return false;
    }
  } catch (error) {
    logger.error('Error checking notification type settings', error);
    return false;
  }
}

/**
 * Create a notification for new security incident assignments
 */
export async function createAssignmentNotification(newCount: number, previousCount: number): Promise<string | null> {
  try {
    // Check if assignment notifications are enabled
    const canNotify = await areNotificationsEnabled();
    const assignmentNotificationsEnabled = await isNotificationTypeEnabled('assignments');
    
    if (!canNotify || !assignmentNotificationsEnabled) {
      return null;
    }
    
    const newAssignments = newCount - previousCount;
    const title = newAssignments === 1 
      ? 'New Security Incident Assigned'
      : `${newAssignments} New Security Incidents Assigned`;
    
    const message = newAssignments === 1
      ? 'You have been assigned a new security incident'
      : `You have been assigned ${newAssignments} new security incidents`;

    const notificationId = await createStandardNotification(title, message, { 
      priority: 1,
      id: `assignment-${Date.now()}`
    });
    
    return notificationId;
    
  } catch (error) {
    logger.error('Failed to create assignment notification', error);
    throw error;
  }
}

/**
 * Creates notification for high severity incidents
 * Follows the same pattern as assignment notifications for consistency
 */
export async function createHighSeverityNotification(newHighSeverityCount: number, previousHighSeverityCount: number): Promise<string | null> {
  try {
    // Check if high severity notifications are enabled
    const canNotify = await areNotificationsEnabled();
    const highSeverityNotificationsEnabled = await isNotificationTypeEnabled('high-severity');
    
    if (!canNotify || !highSeverityNotificationsEnabled) {
      return null;
    }
    
    const newIncidents = newHighSeverityCount - previousHighSeverityCount;
    const title = newIncidents === 1 
      ? 'High Severity Security Incident Detected'
      : `${newIncidents} High Severity Security Incidents Detected`;
    
    const message = newIncidents === 1
      ? 'A high severity security incident has been detected'
      : `${newIncidents} high severity security incidents have been detected`;

    const notificationId = await createStandardNotification(title, message, { 
      priority: 2, // Higher priority for high severity incidents
      id: `high-severity-${Date.now()}`
    });
    
    return notificationId;
    
  } catch (error) {
    logger.error('Failed to create high severity notification', error);
    throw error;
  }
}

/**
 * Creates notification for medium severity incidents
 * Follows the same pattern as high severity notifications
 */
export async function createMediumSeverityNotification(newMediumSeverityCount: number, previousMediumSeverityCount: number): Promise<string | null> {
  try {
    // Check if medium severity notifications are enabled
    const canNotify = await areNotificationsEnabled();
    const mediumSeverityNotificationsEnabled = await isNotificationTypeEnabled('medium-severity');
    
    if (!canNotify || !mediumSeverityNotificationsEnabled) {
      return null;
    }
    
    const newIncidents = newMediumSeverityCount - previousMediumSeverityCount;
    const title = newIncidents === 1 
      ? 'Medium Severity Security Incident Detected'
      : `${newIncidents} Medium Severity Security Incidents Detected`;
    
    const message = newIncidents === 1
      ? 'A medium severity security incident has been detected'
      : `${newIncidents} medium severity security incidents have been detected`;

    const notificationId = await createStandardNotification(title, message, { 
      priority: 1, // Standard priority for medium severity incidents
      id: `medium-severity-${Date.now()}`
    });
    
    return notificationId;
    
  } catch (error) {
    logger.error('Failed to create medium severity notification', error);
    throw error;
  }
}

/**
 * Creates notification for low severity incidents
 * Follows the same pattern as other severity notifications
 */
export async function createLowSeverityNotification(newLowSeverityCount: number, previousLowSeverityCount: number): Promise<string | null> {
  try {
    // Check if low severity notifications are enabled
    const canNotify = await areNotificationsEnabled();
    const lowSeverityNotificationsEnabled = await isNotificationTypeEnabled('low-severity');
    
    if (!canNotify || !lowSeverityNotificationsEnabled) {
      return null;
    }
    
    const newIncidents = newLowSeverityCount - previousLowSeverityCount;
    const title = newIncidents === 1 
      ? 'Low Severity Security Incident Detected'
      : `${newIncidents} Low Severity Security Incidents Detected`;
    
    const message = newIncidents === 1
      ? 'A low severity security incident has been detected'
      : `${newIncidents} low severity security incidents have been detected`;

    const notificationId = await createStandardNotification(title, message, { 
      priority: 0, // Lower priority for low severity incidents
      id: `low-severity-${Date.now()}`
    });
    
    return notificationId;
    
  } catch (error) {
    logger.error('Failed to create low severity notification', error);
    throw error;
  }
}

/**
 * Creates notification for informational severity incidents
 * Follows the same pattern as other severity notifications
 */
export async function createInformationalSeverityNotification(newInformationalSeverityCount: number, previousInformationalSeverityCount: number): Promise<string | null> {
  try {
    // Check if informational severity notifications are enabled
    const canNotify = await areNotificationsEnabled();
    const informationalSeverityNotificationsEnabled = await isNotificationTypeEnabled('informational-severity');
    
    if (!canNotify || !informationalSeverityNotificationsEnabled) {
      return null;
    }
    
    const newIncidents = newInformationalSeverityCount - previousInformationalSeverityCount;
    const title = newIncidents === 1 
      ? 'Informational Security Incident Detected'
      : `${newIncidents} Informational Security Incidents Detected`;
    
    const message = newIncidents === 1
      ? 'An informational security incident has been detected'
      : `${newIncidents} informational security incidents have been detected`;

    const notificationId = await createStandardNotification(title, message, { 
      priority: 0, // Lower priority for informational incidents
      id: `informational-severity-${Date.now()}`
    });
    
    return notificationId;
    
  } catch (error) {
    logger.error('Failed to create informational severity notification', error);
    throw error;
  }
}

// ============================================================================
// Background Notification Management
// ============================================================================

/**
 * Show notification for new assignments in background context
 */
export async function showBackgroundNotification(
  newCount: number, 
  previousCount: number, 
  userEmail: string,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<void> {
  try {
    const notificationId = await createAssignmentNotification(newCount, previousCount);
    
    if (notificationId) {
      // Log audit event
      logAuditEvent('info', 'security', 'new_assignment_notification', {
        newCount,
        previousCount,
        newAssignments: newCount - previousCount,
        userEmail,
        notificationId
      });
    }
    
  } catch (error) {
    logger.error('Failed to show background notification', error);
  }
}

// ============================================================================
// Notification Permission Management
// ============================================================================

/**
 * Request notification permissions from the browser
 */
export async function requestNotificationPermission(): Promise<boolean> {
  try {
    const hasPermission = await browser.permissions.request({ permissions: ['notifications'] });
    return hasPermission;
  } catch (error) {
    logger.error('Failed to request notification permission', error);
    return false;
  }
}

/**
 * Check current notification permission status
 */
export async function getNotificationPermissionStatus(): Promise<'granted' | 'denied' | 'unknown'> {
  try {
    const hasPermission = await browser.permissions.contains({ permissions: ['notifications'] });
    return hasPermission ? 'granted' : 'denied';
  } catch (error) {
    logger.error('Failed to check notification permission', error);
    return 'unknown';
  }
}

/**
 * Validate notification settings and permissions comprehensively
 */
export async function validateNotificationSettings(): Promise<{
  settingsEnabled: boolean;
  permissionGranted: boolean;
  apiAvailable: boolean;
  canNotify: boolean;
  details: Record<string, any>;
}> {
  try {
    // Check if notifications API is available
    const apiAvailable = typeof browser.notifications !== 'undefined';
    
    // Check user settings
    const result = await browser.storage.local.get({ xdr_settings: null });
    const settings = result.xdr_settings as any;
    const settingsEnabled = settings?.ui?.notifications !== false;
    
    // Check browser permissions
    const permissionGranted = await browser.permissions.contains({ permissions: ['notifications'] });
    
    // Overall capability
    const canNotify = apiAvailable && settingsEnabled && permissionGranted;
    
    const details = {
      userSettings: settings?.ui?.notifications,
      assignmentNotifications: settings?.ui?.notifyOnNewAssignments,
      browserPermission: permissionGranted,
      notificationAPI: apiAvailable
    };
    
    return {
      settingsEnabled,
      permissionGranted,
      apiAvailable,
      canNotify,
      details
    };
    
  } catch (error) {
    logger.error('Failed to validate notification settings', error);
    return {
      settingsEnabled: false,
      permissionGranted: false,
      apiAvailable: false,
      canNotify: false,
      details: { error: error instanceof Error ? error.message : 'Unknown error' }
    };
  }
}

// ============================================================================
// Notification Event Handler Factories
// ============================================================================

/**
 * Create notification click event handler
 */
export function createNotificationClickHandler(
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
) {
  return (notificationId: string) => {
    logAuditEvent('info', 'user', 'notification_clicked', { notificationId });
    
    // Clear the notification after click
    browser.notifications.clear(notificationId).catch(error => {
      logger.error('Could not clear notification', error);
    });
  };
}

/**
 * Create notification closed event handler
 */
export function createNotificationClosedHandler(
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
) {
  return (notificationId: string, byUser: boolean) => {
    logAuditEvent('info', 'user', 'notification_closed', { notificationId, byUser });
  };
}

/**
 * Setup all notification event listeners
 */
export function setupNotificationEventListeners(
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): void {
  // Handle notification clicks
  browser.notifications.onClicked.addListener(
    createNotificationClickHandler(logAuditEvent)
  );

  // Handle notification closed
  browser.notifications.onClosed.addListener(
    createNotificationClosedHandler(logAuditEvent)
  );
}

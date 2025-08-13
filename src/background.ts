/**
 * Background Script - Secure API Gateway for Microsoft Graph Security Integration
 * This script handles all Microsoft Graph API communication and token management
 * SECURITY: All tokens and API calls are handled exclusively in this background context
 */

import browser from 'webextension-polyfill';
import { OAuthService } from './lib/oauth.js';
import { MicrosoftSecurityApiClient } from './lib/security-api.js';
import { encryptionService } from './lib/encryption.js';
import { 
  setupNotificationEventListeners,
  initializeNotificationSystem
} from './lib/notifications.js';
import {
  initializeAuditLogger,
  createAuditEventLogger,
  getAuditLogger,
  logger
} from './lib/audit-logger.js';
import {
  createSuccessResponse,
  createErrorResponse,
  createStandardErrorResponse,
  createResponseFactory,
  ERROR_CODES
} from './lib/response-utils.js';
import {
  initializeStorageManager,
  getStorageManager
} from './lib/storage-manager.js';
import {
  isValidSecurityMessage,
  handleAuthMessage,
  handleIncidentsMessage,
  handleAlertsMessage,
  handleHuntMessage,
  handleUpdateIncidentMessage,
  handleUpdateAlertMessage,
  handleSettingsUpdatedMessage,
  handleStatusMessage,
  handleRefreshMessage
} from './lib/message-handlers.js';
import {
  loadBackgroundState,
  saveBackgroundState,
  setupAutoRefreshAlarm,
  performBackgroundRefresh,
  createAlarmHandler,
  setupChromeKeepalive,
  createStorageChangeListener,
  initializeBackgroundSystems
} from './lib/background-refresh.js';
import {
  settingsManager,
  createDefaultSettings,
  createSettingsChangeHandler
} from './lib/settings-manager.js';
import {
  handleIOCScanRequest,
  type IOCScanRequest
} from './lib/ioc-scanner.js';
import type {
  SecurityMessage,
  MessageResponse,
  ExtensionConfig,
  AuthenticationState,
  SecurityApiError,
  AuditLogEntry
} from './types/security.d.ts';

logger.info('XDR on Edge background script loaded', { component: 'Microsoft Security Gateway' });

// ============================================================================
// Configuration and Services
// ============================================================================

// Initialize services
let oauthService: OAuthService | null = null;
let apiClient: MicrosoftSecurityApiClient | null = null;
let isInitialized = false;

// ============================================================================
// Service Initialization
// ============================================================================

async function initializeServices(): Promise<void> {
  try {
    logger.info('Initializing Microsoft Security services...');
    
    // Initialize storage manager first
    await initializeStorageManager();
    logger.debug('Storage manager initialized');
    
    // Initialize settings manager
    await settingsManager.initialize();
    const EXTENSION_CONFIG = settingsManager.getExtensionConfig();
    
    // Initialize audit logger with configuration
    initializeAuditLogger(EXTENSION_CONFIG);
    logger.debug('Audit logger initialized with config');
    
    // Set browser-specific redirect URI
    const manifest = browser.runtime.getManifest();
    const isFirefox = navigator.userAgent.toLowerCase().includes('firefox');
    
    // Use Mozilla best practices: browser.identity.getRedirectURL() for Firefox
    const redirectUri = isFirefox 
      ? browser.identity.getRedirectURL()
      : `https://${browser.runtime.id}.chromiumapp.org/`;
    
    settingsManager.updateRedirectUri(redirectUri);
    logger.debug('Redirect URI configured', { redirectUri, isFirefox });
    
    // Initialize encryption service
    await encryptionService.generateSessionKey();
    logger.debug('Encryption service initialized');
    
    // Initialize OAuth service
    oauthService = new OAuthService(EXTENSION_CONFIG.oauth);
    logger.debug('OAuth service initialized');
    
    // Initialize API client
    apiClient = new MicrosoftSecurityApiClient(EXTENSION_CONFIG.api);
    logger.debug('API client initialized');
    
    // Initialize notification system
    await initializeNotificationSystem();
    logger.debug('Notification system initialized');
    
    isInitialized = true;
    logger.info('Microsoft Security services initialization complete');
    
    // Log initialization audit event
    logger.audit.security('services_initialized', {
      redirectUri: redirectUri,
      scopes: EXTENSION_CONFIG.oauth.scopes.length
    });
    
  } catch (error) {
    logger.error('Failed to initialize services', error);
    isInitialized = false;
    
    throw error;
  }
}

// ============================================================================
// Message Handling - Secure API Gateway
// ============================================================================

/**
 * Main message handler - processes all requests from popup/content scripts
 */
browser.runtime.onMessage.addListener((message: any, sender, sendResponse) => {
  // Async handler that returns a promise to indicate async response
  handleMessage(message, sender).then(response => {
    sendResponse(response);
  }).catch(error => {
    logger.error('Message handling error', error, { messageType: message?.type, requestId: message?.requestId });
    const errorResponse = createStandardErrorResponse(
      'API_ERROR',
      message?.requestId || 'unknown',
      error instanceof Error ? error.message : 'Unknown error'
    );
    sendResponse(errorResponse);
  });
  
  // Return true to indicate we'll send response asynchronously
  return true;
});

async function handleMessage(message: any, sender: any): Promise<MessageResponse> {
  try {
    // Validate message structure
    if (!isValidSecurityMessage(message)) {
      return createStandardErrorResponse('VALIDATION_ERROR', message?.requestId || 'unknown', 'Invalid message format');
    }

    logger.debug(`Processing ${message.type} request`, { requestId: message.requestId });
    
    // Ensure services are initialized
    if (!isInitialized) {
      await initializeServices();
    }

    if (!oauthService || !apiClient) {
      throw new Error('Services not properly initialized');
    }

    // Route message to appropriate handler
    let response: MessageResponse;
    
    switch (message.type) {
      case 'MS_SECURITY_AUTH':
        response = await handleAuthMessage(message, oauthService, logAuditEvent);
        break;
        
      case 'MS_SECURITY_STATUS':
        response = await handleStatusMessage(message, oauthService, apiClient, encryptionService);
        break;
        
      case 'MS_SECURITY_INCIDENTS':
        response = await handleIncidentsMessage(message, oauthService, apiClient, logAuditEvent);
        break;
        
      case 'MS_SECURITY_ALERTS':
        response = await handleAlertsMessage(message, oauthService, apiClient, logAuditEvent);
        break;
        
      case 'MS_SECURITY_HUNT':
        response = await handleHuntMessage(message, oauthService, apiClient, logAuditEvent);
        break;
        
      case 'MS_SECURITY_UPDATE_INCIDENT':
        response = await handleUpdateIncidentMessage(message, oauthService, apiClient, logAuditEvent);
        break;
        
      case 'MS_SECURITY_UPDATE_ALERT':
        response = await handleUpdateAlertMessage(message, oauthService, apiClient, logAuditEvent);
        break;
        
      case 'SETTINGS_UPDATED':
        response = await handleSettingsUpdatedMessage(message, settingsManager, reinitializeServices, logAuditEvent);
        break;
        
      case 'MS_SECURITY_REFRESH_NOW':
        response = await handleRefreshMessage(message, async () => {
          await performBackgroundRefresh(isInitialized, oauthService, apiClient, initializeServices, logAuditEvent);
        });
        break;
        
      case 'IOC_SCAN_REQUEST':
        // Handle IOC scan requests
        response = await handleIOCScanMessage(message, logAuditEvent);
        break;
        
      default:
        response = createStandardErrorResponse('VALIDATION_ERROR', (message as any).requestId || 'unknown', `Unknown message type: ${(message as any).type}`);
    }
    
    logger.debug(`${message.type} request completed`, { 
      success: response.success, 
      requestId: message.requestId 
    });
    return response;
    
  } catch (error) {
    logger.error('Message handling error', error, { 
      messageType: message?.type, 
      requestId: message?.requestId 
    });
    
    const errorResponse = createStandardErrorResponse(
      'API_ERROR',
      message?.requestId || 'unknown',
      error instanceof Error ? error.message : 'Unknown error'
    );
    
    return errorResponse;
  }
}

// ============================================================================
// IOC Scan Message Handler
// ============================================================================

async function handleIOCScanMessage(
  message: any,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<MessageResponse> {
  try {
    // Create IOC scan request from message
    const iocScanRequest: IOCScanRequest = {
      tabId: message.data?.tabId || 0,
      requestId: message.requestId,
      timestamp: message.timestamp
    };
    
    // Handle the IOC scan request
    const scanResponse = await handleIOCScanRequest(iocScanRequest, logAuditEvent);
    
    return {
      success: scanResponse.success,
      data: scanResponse.data,
      error: scanResponse.error ? {
        code: scanResponse.error.code || 'IOC_SCAN_ERROR',
        message: scanResponse.error.message,
        details: scanResponse.error
      } : undefined,
      requestId: message.requestId,
      timestamp: Date.now()
    };
    
  } catch (error) {
    logger.error('IOC scan message handler error', error);
    
    return createStandardErrorResponse(
      'API_ERROR',
      message.requestId,
      error instanceof Error ? error.message : 'Unknown error'
    );
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

function logAuditEvent(
  level: AuditLogEntry['level'], 
  category: AuditLogEntry['category'], 
  action: string, 
  details: Record<string, any> = {}
): void {
  getAuditLogger().logEvent(level, category, action, details);
}

// Helper function to create services reinitializer
async function reinitializeServices(): Promise<void> {
  if (isInitialized && oauthService && apiClient) {
    logger.info('Reinitializing services with new settings');
    
    const config = settingsManager.getExtensionConfig();
    
    // Update audit logger with new configuration
    initializeAuditLogger(config);
    
    // Reinitialize OAuth service with new config
    oauthService = new OAuthService(config.oauth);
    
    // Reinitialize API client with new config
    apiClient = new MicrosoftSecurityApiClient(config.api);
    
    logAuditEvent('info', 'security', 'services_reinitialized', {
      clientId: config.oauth.clientId.substring(0, 8) + '...',
      tenantId: config.oauth.tenantId
    });
  }
}

// ============================================================================
// Extension Lifecycle
// ============================================================================

// Handle extension installation/startup
browser.runtime.onInstalled.addListener(async (details) => {
  logger.info('Extension installed/updated', { reason: details.reason });
  
  try {
    await loadBackgroundState();
    await initializeServices();
    await initializeBackgroundSystems();
    
    // Create default settings if they don't exist
    await createDefaultSettings();
    
    logAuditEvent('info', 'security', 'extension_installed', {
      reason: details.reason,
      version: browser.runtime.getManifest().version
    });
    
  } catch (error) {
    logger.error('Extension initialization failed', error);
  }
});

// Handle extension startup
browser.runtime.onStartup.addListener(async () => {
  logger.info('Extension starting up');
  
  try {
    await loadBackgroundState();
    await initializeServices();
    await initializeBackgroundSystems();
    logAuditEvent('info', 'security', 'extension_startup', {});
  } catch (error) {
    logger.error('Extension startup failed', error);
  }
});

// Clean up on extension shutdown (if supported)
if (browser.runtime.onSuspend) {
  browser.runtime.onSuspend.addListener(async () => {
    logger.info('Extension suspending');
    await saveBackgroundState();
    encryptionService.clearSessionKey();
    logAuditEvent('info', 'security', 'extension_suspend', {});
  });
}

// Initialize services immediately
initializeServices().then(async () => {
  await initializeBackgroundSystems();
}).catch(error => {
  logger.error('Initial service initialization failed', error);
});

// ============================================================================
// Background System Event Listeners
// ============================================================================

// Set up alarm handler for auto-refresh
const alarmHandler = createAlarmHandler(async () => {
  await performBackgroundRefresh(isInitialized, oauthService, apiClient, initializeServices, logAuditEvent);
}, logAuditEvent);
browser.alarms.onAlarm.addListener(alarmHandler);

// Set up storage change listener for settings updates
const storageChangeListener = createStorageChangeListener();
browser.storage.onChanged.addListener(storageChangeListener);

// Set up Chrome service worker keepalive
setupChromeKeepalive();

// ============================================================================
// Notification System Setup
// ============================================================================

// Setup notification event listeners
setupNotificationEventListeners(logAuditEvent);

// ============================================================================
// Global Error Handlers
// ============================================================================

// Handle unhandled promise rejections to prevent silent failures
if (typeof self !== 'undefined') {
  // Service Worker environment
  self.addEventListener('unhandledrejection', (event) => {
    logger.error('Unhandled promise rejection in background script', event.reason);
    
    // Log specific details for API errors
    if (event.reason instanceof Error && 'code' in event.reason) {
      const apiError = event.reason as any;
      if (apiError.code === 'RATE_LIMITED') {
        logAuditEvent('error', 'api', 'unhandled_rate_limit_error', {
          error: apiError.message,
          retryAfter: apiError.details?.retryAfter,
          stack: apiError.stack
        });
      } else if (apiError.code === 'NETWORK_ERROR') {
        logAuditEvent('error', 'api', 'unhandled_network_timeout', {
          error: apiError.message,
          originalError: apiError.details?.originalError,
          stack: apiError.stack
        });
      } else {
        logAuditEvent('error', 'security', 'unhandled_promise_rejection', {
          error: apiError.message,
          code: apiError.code,
          stack: apiError.stack
        });
      }
    } else {
      logAuditEvent('error', 'security', 'unhandled_promise_rejection', {
        error: event.reason instanceof Error ? event.reason.message : String(event.reason),
        stack: event.reason instanceof Error ? event.reason.stack : undefined
      });
    }
    
    // Prevent the default unhandled rejection behavior
    event.preventDefault();
  });
  
  // Handle general errors
  self.addEventListener('error', (event) => {
    logger.error('Unhandled error in background script', event.error);
    logAuditEvent('error', 'security', 'unhandled_script_error', {
      error: event.error?.message || String(event.error),
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno,
      stack: event.error?.stack
    });
  });
}

export {};

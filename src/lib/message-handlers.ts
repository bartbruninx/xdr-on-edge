/**
 * Message Handler Module - Secure API Gateway Message Processing
 * This module handles all incoming messages from popup/content scripts and routes them appropriately
 * SECURITY: All token operations and API calls are processed securely through service instances
 */

import browser from 'webextension-polyfill';
import { encryptionService } from './encryption.js';
import { logger } from './audit-logger.js';
import { 
  createSuccessResponse, 
  createErrorResponse, 
  createErrorResponseFromError,
  createStandardErrorResponse,
  createResponseFactory,
  ERROR_CODES,
  isAuthenticationError
} from './response-utils.js';
import type {
  SecurityMessage,
  MessageResponse,
  AuditLogEntry,
  AuthenticationState
} from '../types/security.d.ts';
import type { OAuthService } from './oauth.js';
import type { MicrosoftSecurityApiClient } from './security-api.js';

// ============================================================================
// Message Validation
// ============================================================================

/**
 * Validates that incoming message has the required structure for security processing
 */
export function isValidSecurityMessage(message: any): message is SecurityMessage {
  return message &&
         typeof message === 'object' &&
         typeof message.type === 'string' &&
         typeof message.requestId === 'string' &&
         typeof message.timestamp === 'number' &&
         message.data !== undefined;
}

// ============================================================================
// Authentication Message Handler
// ============================================================================

export async function handleAuthMessage(
  message: SecurityMessage, 
  oauth: OAuthService,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<MessageResponse> {
  try {
    const { action, tenantId } = message.data as any;
    
    logAuditEvent('info', 'auth', `auth_${action}`, { tenantId });
    
    switch (action) {
      case 'login':
        const authState = await oauth.authenticate();
        logAuditEvent('info', 'auth', 'login_success', { 
          userId: authState.user?.id,
          scopes: authState.scopes.length 
        });
        return createSuccessResponse(authState, message.requestId);
        
      case 'logout':
        await oauth.logout();
        logAuditEvent('info', 'auth', 'logout_success', {});
        return createSuccessResponse({ isAuthenticated: false, scopes: [] }, message.requestId);
        
      case 'clear_storage':
        // Clear all extension storage to fix corruption issues
        await browser.storage.local.clear();
        await oauth.logout();
        encryptionService.clearSessionKey();
        logAuditEvent('info', 'auth', 'storage_cleared', {});
        return createSuccessResponse({ 
          isAuthenticated: false, 
          scopes: [],
          message: 'All extension data cleared successfully' 
        }, message.requestId);
        
      case 'refresh':
        try {
          const refreshedState = await oauth.refreshTokens();
          logAuditEvent('info', 'auth', 'token_refresh_success', { 
            userId: refreshedState.user?.id 
          });
          return createSuccessResponse(refreshedState, message.requestId);
        } catch (error) {
          logAuditEvent('error', 'auth', 'token_refresh_failed', {
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          
          // If refresh fails, user needs to re-authenticate
          if (error instanceof Error && 'code' in error) {
            const authError = error as any;
            if (authError.code === 'TOKEN_EXPIRED') {
              return createErrorResponse('TOKEN_EXPIRED', 'Refresh token expired - please login again', message.requestId);
            }
          }
          
          return createErrorResponse('AUTH_FAILED', 'Token refresh failed - please login again', message.requestId);
        }
        
      case 'check':
        const currentState = await oauth.getAuthenticationState();
        return createSuccessResponse(currentState, message.requestId);
        
      default:
        return createErrorResponse('VALIDATION_ERROR', `Unknown auth action: ${action}`, message.requestId);
    }
    
  } catch (error) {
    logAuditEvent('error', 'auth', 'auth_error', {
      action: (message.data as any).action,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    
    throw error;
  }
}

// ============================================================================
// Incidents Message Handler
// ============================================================================

export async function handleIncidentsMessage(
  message: SecurityMessage, 
  oauth: OAuthService, 
  api: MicrosoftSecurityApiClient,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<MessageResponse> {
  try {
    const accessToken = await oauth.getValidAccessToken();
    const { filters } = message.data as any;
    
    const incidents = await api.getIncidents(accessToken, filters);
    
    logAuditEvent('info', 'api', 'incidents_retrieved', {
      count: incidents.value?.length || 0,
      hasFilters: !!filters
    });
    
    return createSuccessResponse(incidents, message.requestId);
    
  } catch (error) {
    // Handle authentication errors specifically
    if (error instanceof Error && 'code' in error) {
      const authError = error as any;
      if (['AUTH_REQUIRED', 'TOKEN_EXPIRED'].includes(authError.code)) {
        logAuditEvent('warn', 'auth', 'token_refresh_needed', {
          error: authError.message,
          code: authError.code
        });
        return createErrorResponse('AUTH_REQUIRED', 'Authentication required - please login again', message.requestId);
      }
      
      // Handle rate limit errors specifically
      if (authError.code === 'RATE_LIMITED') {
        logAuditEvent('warn', 'api', 'rate_limit_exceeded', {
          error: authError.message,
          retryAfter: authError.details?.retryAfter
        });
        return createErrorResponse('RATE_LIMITED', 'API rate limit exceeded - please try again later', message.requestId);
      }
      
      // Handle network/timeout errors specifically
      if (authError.code === 'NETWORK_ERROR') {
        logAuditEvent('warn', 'api', 'incidents_network_timeout', {
          error: authError.message,
          originalError: authError.details?.originalError
        });
        return createErrorResponse('NETWORK_ERROR', 'Request timeout - please try again', message.requestId);
      }
      
      // Handle other API errors
      if (authError.code === 'API_ERROR') {
        logAuditEvent('error', 'api', 'incidents_api_error', {
          error: authError.message,
          status: authError.details?.status,
          code: authError.code
        });
        return createErrorResponse('API_ERROR', authError.message, message.requestId);
      }
    }
    
    logAuditEvent('error', 'api', 'incidents_error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      errorName: error instanceof Error ? error.name : 'Unknown',
      stack: error instanceof Error ? error.stack : undefined
    });
    
    // Return a proper error response instead of throwing
    return createErrorResponse(
      'API_ERROR', 
      error instanceof Error ? error.message : 'Unknown error occurred while fetching incidents', 
      message.requestId
    );
  }
}

// ============================================================================
// Update Incident Message Handler
// ============================================================================

export async function handleUpdateIncidentMessage(
  message: SecurityMessage, 
  oauth: OAuthService, 
  api: MicrosoftSecurityApiClient,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<MessageResponse> {
  try {
    const accessToken = await oauth.getValidAccessToken();
    const { incidentId, update } = message.data as any;
    
    const updatedIncident = await api.updateIncident(accessToken, incidentId, update);
    
    logAuditEvent('info', 'api', 'incident_updated', {
      incidentId,
      updateFields: Object.keys(update)
    });
    
    return createSuccessResponse(updatedIncident, message.requestId);
    
  } catch (error) {
    // Handle authentication errors specifically
    if (error instanceof Error && 'code' in error) {
      const authError = error as any;
      if (['AUTH_REQUIRED', 'TOKEN_EXPIRED'].includes(authError.code)) {
        logAuditEvent('warn', 'auth', 'token_refresh_needed', {
          error: authError.message,
          code: authError.code
        });
        return createErrorResponse('AUTH_REQUIRED', 'Authentication required - please login again', message.requestId);
      }
      
      // Handle rate limit errors specifically
      if (authError.code === 'RATE_LIMITED') {
        logAuditEvent('warn', 'api', 'rate_limit_exceeded', {
          error: authError.message,
          retryAfter: authError.details?.retryAfter
        });
        return createErrorResponse('RATE_LIMITED', 'API rate limit exceeded - please try again later', message.requestId);
      }
      
      // Handle network/timeout errors specifically
      if (authError.code === 'NETWORK_ERROR') {
        logAuditEvent('warn', 'api', 'incident_update_network_timeout', {
          error: authError.message,
          originalError: authError.details?.originalError
        });
        return createErrorResponse('NETWORK_ERROR', 'Request timeout - please try again', message.requestId);
      }
      
      // Handle other API errors
      if (authError.code === 'API_ERROR') {
        logAuditEvent('error', 'api', 'incident_update_api_error', {
          error: authError.message,
          status: authError.details?.status,
          code: authError.code
        });
        return createErrorResponse('API_ERROR', authError.message, message.requestId);
      }
    }
    
    logAuditEvent('error', 'api', 'incident_update_error', {
      incidentId: (message.data as any).incidentId,
      error: error instanceof Error ? error.message : 'Unknown error',
      errorName: error instanceof Error ? error.name : 'Unknown',
      stack: error instanceof Error ? error.stack : undefined
    });
    
    // Return a proper error response instead of throwing
    return createErrorResponse(
      'API_ERROR', 
      error instanceof Error ? error.message : 'Unknown error occurred while updating incident', 
      message.requestId
    );
  }
}

// ============================================================================
// Settings Updated Message Handler
// ============================================================================

export async function handleSettingsUpdatedMessage(
  message: SecurityMessage,
  settingsManager: any, // SettingsManager type
  reinitializeServices: () => Promise<void>,
  logAuditEvent: (level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>) => void
): Promise<MessageResponse> {
  try {
    logger.info('Settings updated, reloading configuration');
    
    // Reload settings from storage using settings manager
    await settingsManager.loadSettingsFromStorage();
    
    // Reinitialize services with new configuration
    await reinitializeServices();
    
    const config = settingsManager.getExtensionConfig();
    logAuditEvent('info', 'security', 'settings_updated', {
      clientId: config.oauth.clientId.substring(0, 8) + '...',
      tenantId: config.oauth.tenantId
    });
    
    return createSuccessResponse(
      { message: 'Settings updated successfully' },
      message.requestId
    );
    
  } catch (error) {
    logAuditEvent('error', 'security', 'settings_update_error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      errorName: error instanceof Error ? error.name : 'Unknown',
      stack: error instanceof Error ? error.stack : undefined
    });
    
    // Return a proper error response instead of throwing
    return createErrorResponse(
      'SETTINGS_ERROR', 
      error instanceof Error ? error.message : 'Unknown error occurred while updating settings', 
      message.requestId
    );
  }
}

// ============================================================================
// Status Message Handler
// ============================================================================

export async function handleStatusMessage(
  message: SecurityMessage, 
  oauth: OAuthService,
  apiClient: MicrosoftSecurityApiClient | null,
  encryptionService: any
): Promise<MessageResponse> {
  try {
    const authState = await oauth.getAuthenticationState();
    
    const status = {
      authentication: authState,
      apiHealth: 'unknown', // Could be enhanced with health check
      services: {
        oauth: !!oauth,
        apiClient: !!apiClient,
        encryption: !!encryptionService
      },
      browserInfo: {
        userAgent: navigator.userAgent,
        extensionId: browser.runtime.id
      }
    };
    
    return createSuccessResponse(status, message.requestId);
    
  } catch (error) {
    // Return a proper error response instead of throwing
    return createErrorResponse(
      'STATUS_ERROR', 
      error instanceof Error ? error.message : 'Unknown error occurred while getting status', 
      message.requestId
    );
  }
}

// ============================================================================
// Refresh Message Handler
// ============================================================================

export async function handleRefreshMessage(
  message: SecurityMessage,
  performBackgroundRefresh: () => Promise<void>
): Promise<MessageResponse> {
  try {
    logger.info('Manual refresh requested');
    await performBackgroundRefresh();
    return createSuccessResponse('Manual refresh completed', message.requestId);
  } catch (error) {
    return createErrorResponse('REFRESH_ERROR', 
      error instanceof Error ? error.message : 'Failed to refresh data', 
      message.requestId);
  }
}



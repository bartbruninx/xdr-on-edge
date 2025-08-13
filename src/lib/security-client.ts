/**
 * Microsoft Security API Client for UI Components
 * Secure message passing interface to background script
 */

import browser from 'webextension-polyfill';
import type {
  SecurityMessage,
  MessageResponse,
  AuthenticationState,
  SecurityIncident,
  SecurityAlert,
  AdvancedHuntingResult,
  IncidentFilters,
  AlertFilters,
  AdvancedHuntingQuery,
  ApiResponse
} from '../types/security.d.ts';
import { logger } from './audit-logger.js';

export class MicrosoftSecurityClient {
  private requestCounter = 0;

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${++this.requestCounter}`;
  }

  /**
   * Send message to background script with timeout
   */
  private async sendMessage<T>(message: SecurityMessage): Promise<MessageResponse<T>> {
    try {
      // Create a timeout promise
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error('Request timeout'));
        }, 30000); // 30 second timeout
      });

      // Race between the actual message and timeout
      const response = await Promise.race([
        browser.runtime.sendMessage(message),
        timeoutPromise
      ]);
      
      if (!response || typeof response !== 'object') {
        throw new Error('Invalid response from background script');
      }

      return response as MessageResponse<T>;
      
    } catch (error) {
      logger.error('Failed to communicate with background script', error);
      
      return {
        success: false,
        error: {
          code: 'COMMUNICATION_ERROR',
          message: error instanceof Error ? error.message : 'Communication failed',
          details: null
        },
        requestId: message.requestId,
        timestamp: Date.now()
      };
    }
  }

  // ============================================================================
  // Authentication Methods
  // ============================================================================

  /**
   * Initiate OAuth login flow
   */
  async login(tenantId?: string): Promise<MessageResponse<AuthenticationState>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_AUTH',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        action: 'login',
        tenantId
      }
    };

    return await this.sendMessage<AuthenticationState>(message);
  }

  /**
   * Logout and clear tokens
   */
  async logout(): Promise<MessageResponse<{ isAuthenticated: false; scopes: [] }>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_AUTH',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        action: 'logout'
      }
    };

    return await this.sendMessage<{ isAuthenticated: false; scopes: [] }>(message);
  }

  /**
   * Refresh authentication tokens
   */
  async refreshAuth(): Promise<MessageResponse<AuthenticationState>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_AUTH',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        action: 'refresh'
      }
    };

    return await this.sendMessage<AuthenticationState>(message);
  }

  /**
   * Check current authentication status
   */
  async getAuthStatus(): Promise<MessageResponse<AuthenticationState>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_AUTH',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        action: 'check'
      }
    };

    return await this.sendMessage<AuthenticationState>(message);
  }

  // ============================================================================
  // Security Incidents
  // ============================================================================

  /**
   * Get security incidents with optional filtering
   */
  async getIncidents(filters?: IncidentFilters): Promise<MessageResponse<ApiResponse<SecurityIncident>>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_INCIDENTS',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        filters
      }
    };

    return await this.sendMessage<ApiResponse<SecurityIncident>>(message);
  }

  /**
   * Update an incident
   */
  async updateIncident(incidentId: string, update: Partial<SecurityIncident>): Promise<MessageResponse<SecurityIncident>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_UPDATE_INCIDENT',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        incidentId,
        update
      }
    };

    return await this.sendMessage<SecurityIncident>(message);
  }

  // ============================================================================
  // Security Alerts
  // ============================================================================

  /**
   * Get security alerts with optional filtering
   */
  async getAlerts(filters?: AlertFilters): Promise<MessageResponse<ApiResponse<SecurityAlert>>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_ALERTS',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        filters
      }
    };

    return await this.sendMessage<ApiResponse<SecurityAlert>>(message);
  }

  /**
   * Update an alert
   */
  async updateAlert(alertId: string, update: Partial<SecurityAlert>): Promise<MessageResponse<SecurityAlert>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_UPDATE_ALERT',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        alertId,
        update
      }
    };

    return await this.sendMessage<SecurityAlert>(message);
  }

  // ============================================================================
  // Advanced Hunting
  // ============================================================================

  /**
   * Run advanced hunting query
   */
  async runAdvancedHuntingQuery(query: string, timespan?: string): Promise<MessageResponse<AdvancedHuntingResult>> {
    const huntingQuery: AdvancedHuntingQuery = {
      query,
      timespan
    };

    const message: SecurityMessage = {
      type: 'MS_SECURITY_HUNT',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: huntingQuery
    };

    return await this.sendMessage<AdvancedHuntingResult>(message);
  }

  // ============================================================================
  // System Status
  // ============================================================================

  /**
   * Get system status and health
   */
  async getStatus(): Promise<MessageResponse<any>> {
    const message: SecurityMessage = {
      type: 'MS_SECURITY_STATUS',
      requestId: this.generateRequestId(),
      timestamp: Date.now(),
      data: {
        checkAuth: true
      }
    };

    return await this.sendMessage<any>(message);
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    try {
      const response = await this.getAuthStatus();
      return response.success && response.data?.isAuthenticated === true;
    } catch (error) {
      logger.error('Failed to check authentication status', error);
      return false;
    }
  }

  /**
   * Ensure user is authenticated, redirect to login if not
   */
  async requireAuthentication(): Promise<AuthenticationState | null> {
    try {
      const statusResponse = await this.getAuthStatus();
      
      if (statusResponse.success && statusResponse.data?.isAuthenticated) {
        return statusResponse.data;
      }

      // Try to refresh if we have a refresh token
      const refreshResponse = await this.refreshAuth();
      
      if (refreshResponse.success && refreshResponse.data?.isAuthenticated) {
        return refreshResponse.data;
      }

      // Need fresh authentication
      return null;
      
    } catch (error) {
      logger.error('Authentication check failed', error);
      return null;
    }
  }

  /**
   * Get user-friendly error message
   */
  getErrorMessage(response: MessageResponse<any>): string {
    if (response.success) {
      return '';
    }

    if (!response.error) {
      return 'Unknown error occurred';
    }

    switch (response.error.code) {
      case 'AUTH_REQUIRED':
        return 'Please sign in to access Microsoft Security data';
      case 'AUTH_FAILED':
        return 'Authentication failed. Please try signing in again';
      case 'TOKEN_EXPIRED':
        return 'Your session has expired. Please sign in again';
      case 'INSUFFICIENT_SCOPE':
        return 'Insufficient permissions. Please contact your administrator';
      case 'RATE_LIMITED':
        return 'Too many requests. Please wait a moment and try again';
      case 'API_ERROR':
        return response.error.message || 'Microsoft Security API error';
      case 'NETWORK_ERROR':
        return 'Network error. Please check your internet connection';
      case 'VALIDATION_ERROR':
        return response.error.message || 'Invalid request data';
      case 'BROWSER_NOT_SUPPORTED':
        return 'Your browser does not support this feature';
      default:
        return response.error.message || 'An error occurred';
    }
  }

  /**
   * Create human-readable filters description
   */
  getFiltersDescription(filters: IncidentFilters | AlertFilters | undefined): string {
    if (!filters) {
      return 'All items';
    }

    const parts: string[] = [];

    if (filters.status?.length) {
      parts.push(`Status: ${filters.status.join(', ')}`);
    }

    if (filters.severity?.length) {
      parts.push(`Severity: ${filters.severity.join(', ')}`);
    }

    if (filters.assignedTo) {
      parts.push(`Assigned to: ${filters.assignedTo}`);
    }

    if ('category' in filters && filters.category?.length) {
      parts.push(`Category: ${filters.category.join(', ')}`);
    }

    if (filters.$top) {
      parts.push(`Limit: ${filters.$top}`);
    }

    return parts.length > 0 ? parts.join(', ') : 'All items';
  }
}

/**
 * Singleton client instance
 */
export const msSecurityClient = new MicrosoftSecurityClient();

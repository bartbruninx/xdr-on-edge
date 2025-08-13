/**
 * Response Utilities Module - Centralized Response Creation and Error Handling
 * This module provides standardized response creation, formatting, and error handling utilities
 * SECURITY: Ensures consistent response structure and secure error information exposure
 */

import type { MessageResponse, SecurityApiError, ErrorCode } from '../types/security.d.ts';

// ============================================================================
// Error Code Definitions and Constants
// ============================================================================

/**
 * Standard error codes used throughout the extension
 */
export const ERROR_CODES = {
  // Authentication Errors
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  AUTH_FAILED: 'AUTH_FAILED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  
  // API Errors
  API_ERROR: 'API_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT_ERROR: 'TIMEOUT_ERROR',
  RATE_LIMITED: 'RATE_LIMITED',
  
  // Validation Errors
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_REQUEST: 'INVALID_REQUEST',
  MISSING_PARAMETER: 'MISSING_PARAMETER',
  INVALID_FORMAT: 'INVALID_FORMAT',
  
  // System Errors
  INITIALIZATION_ERROR: 'INITIALIZATION_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  CONFIGURATION_ERROR: 'CONFIGURATION_ERROR',
  STORAGE_ERROR: 'STORAGE_ERROR',
  
  // Operation Errors
  OPERATION_FAILED: 'OPERATION_FAILED',
  REFRESH_ERROR: 'REFRESH_ERROR',
  RESTART_ERROR: 'RESTART_ERROR',
  NOTIFICATION_ERROR: 'NOTIFICATION_ERROR',
  
  // Permission Errors
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  INSUFFICIENT_SCOPE: 'INSUFFICIENT_SCOPE',
  
  // Unknown/Generic
  UNKNOWN_ERROR: 'UNKNOWN_ERROR'
} as const;

/**
 * Error severity levels
 */
export const ERROR_SEVERITY = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
} as const;

/**
 * User-friendly error messages for common error codes
 */
export const ERROR_MESSAGES = {
  [ERROR_CODES.AUTH_REQUIRED]: 'Authentication required - please login again',
  [ERROR_CODES.TOKEN_EXPIRED]: 'Session expired - please login again',
  [ERROR_CODES.AUTH_FAILED]: 'Authentication failed - please check your credentials',
  [ERROR_CODES.INVALID_CREDENTIALS]: 'Invalid credentials provided',
  
  [ERROR_CODES.API_ERROR]: 'API request failed - please try again',
  [ERROR_CODES.NETWORK_ERROR]: 'Network connection error - please check your internet connection',
  [ERROR_CODES.TIMEOUT_ERROR]: 'Request timed out - please try again',
  [ERROR_CODES.RATE_LIMITED]: 'Too many requests - please wait before trying again',
  
  [ERROR_CODES.VALIDATION_ERROR]: 'Invalid data provided',
  [ERROR_CODES.INVALID_REQUEST]: 'Invalid request format',
  [ERROR_CODES.MISSING_PARAMETER]: 'Required parameter missing',
  [ERROR_CODES.INVALID_FORMAT]: 'Invalid data format',
  
  [ERROR_CODES.INITIALIZATION_ERROR]: 'Service initialization failed',
  [ERROR_CODES.SERVICE_UNAVAILABLE]: 'Service temporarily unavailable',
  [ERROR_CODES.CONFIGURATION_ERROR]: 'Configuration error detected',
  [ERROR_CODES.STORAGE_ERROR]: 'Storage operation failed',
  
  [ERROR_CODES.OPERATION_FAILED]: 'Operation failed - please try again',
  [ERROR_CODES.REFRESH_ERROR]: 'Failed to refresh data',
  [ERROR_CODES.RESTART_ERROR]: 'Failed to restart service',
  [ERROR_CODES.NOTIFICATION_ERROR]: 'Failed to send notification',
  
  [ERROR_CODES.PERMISSION_DENIED]: 'Permission denied',
  [ERROR_CODES.INSUFFICIENT_SCOPE]: 'Insufficient permissions',
  
  [ERROR_CODES.UNKNOWN_ERROR]: 'An unexpected error occurred'
} as const;

// ============================================================================
// Response Creation Functions
// ============================================================================

/**
 * Create a standardized success response
 */
export function createSuccessResponse<T>(data: T, requestId: string): MessageResponse<T> {
  return {
    success: true,
    data,
    requestId,
    timestamp: Date.now()
  };
}

/**
 * Create a standardized error response with enhanced error information
 */
export function createErrorResponse(
  code: string, 
  message: string, 
  requestId: string,
  details?: any
): MessageResponse {
  return {
    success: false,
    error: {
      code,
      message,
      details: details || null
    },
    requestId,
    timestamp: Date.now()
  };
}

/**
 * Create an error response from a standard error code
 */
export function createStandardErrorResponse(
  errorCode: keyof typeof ERROR_CODES,
  requestId: string,
  customMessage?: string,
  details?: any
): MessageResponse {
  const code = ERROR_CODES[errorCode];
  const message = customMessage || ERROR_MESSAGES[code] || ERROR_MESSAGES[ERROR_CODES.UNKNOWN_ERROR];
  
  return createErrorResponse(code, message, requestId, details);
}

/**
 * Create an error response from an exception/error object
 */
export function createErrorResponseFromError(
  error: Error | SecurityApiError | any,
  requestId: string,
  fallbackCode: string = ERROR_CODES.UNKNOWN_ERROR
): MessageResponse {
  if (error instanceof Error) {
    // Handle SecurityApiError with additional properties
    if ('code' in error && typeof error.code === 'string') {
      const securityError = error as SecurityApiError;
      return createErrorResponse(
        securityError.code,
        securityError.message,
        requestId,
        {
          status: securityError.status,
          details: securityError.details,
          timestamp: securityError.timestamp || Date.now()
        }
      );
    }
    
    // Handle standard Error objects
    return createErrorResponse(
      fallbackCode,
      error.message || 'An unexpected error occurred',
      requestId,
      {
        name: error.name,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      }
    );
  }
  
  // Handle non-Error objects
  const errorMessage = typeof error === 'string' ? error : 'An unexpected error occurred';
  return createErrorResponse(fallbackCode, errorMessage, requestId, { originalError: error });
}

// ============================================================================
// Response Validation and Formatting
// ============================================================================

/**
 * Validate that a response object has the correct structure
 */
export function validateMessageResponse(response: any): response is MessageResponse {
  return response &&
         typeof response === 'object' &&
         typeof response.success === 'boolean' &&
         typeof response.requestId === 'string' &&
         typeof response.timestamp === 'number' &&
         (response.success === true ? response.data !== undefined : response.error !== undefined);
}

/**
 * Sanitize response data to remove sensitive information
 */
export function sanitizeResponse(response: MessageResponse, sensitiveFields: string[] = []): MessageResponse {
  const defaultSensitiveFields = [
    'token', 'password', 'secret', 'key', 'authorization',
    'accessToken', 'refreshToken', 'clientSecret', 'apiKey'
  ];
  
  const allSensitiveFields = [...defaultSensitiveFields, ...sensitiveFields];
  
  const sanitized = JSON.parse(JSON.stringify(response));
  
  function maskSensitiveFields(obj: any): any {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => maskSensitiveFields(item));
    }
    
    const result: any = {};
    for (const [key, value] of Object.entries(obj)) {
      if (allSensitiveFields.some(field => key.toLowerCase().includes(field.toLowerCase()))) {
        result[key] = typeof value === 'string' && value.length > 0 
          ? `${value.substring(0, 4)}${'*'.repeat(Math.max(0, value.length - 4))}`
          : '[REDACTED]';
      } else {
        result[key] = maskSensitiveFields(value);
      }
    }
    return result;
  }
  
  if (sanitized.data) {
    sanitized.data = maskSensitiveFields(sanitized.data);
  }
  
  if (sanitized.error?.details) {
    sanitized.error.details = maskSensitiveFields(sanitized.error.details);
  }
  
  return sanitized;
}

/**
 * Format response for logging purposes
 */
export function formatResponseForLogging(response: MessageResponse): string {
  const sanitized = sanitizeResponse(response);
  const status = response.success ? '✅ SUCCESS' : '❌ ERROR';
  const requestInfo = `[${response.requestId}]`;
  
  if (response.success) {
    return `${status} ${requestInfo} - Data: ${JSON.stringify(sanitized.data)}`;
  } else {
    const error = response.error!;
    return `${status} ${requestInfo} - ${error.code}: ${error.message}${error.details ? ` | Details: ${JSON.stringify(error.details)}` : ''}`;
  }
}

// ============================================================================
// Authentication Error Helpers
// ============================================================================

/**
 * Check if an error response indicates authentication is required
 */
export function isAuthenticationError(response: MessageResponse): boolean {
  if (response.success) return false;
  
  const authErrorCodes = [
    ERROR_CODES.AUTH_REQUIRED,
    ERROR_CODES.TOKEN_EXPIRED,
    ERROR_CODES.AUTH_FAILED,
    ERROR_CODES.INVALID_CREDENTIALS
  ];
  
  return authErrorCodes.includes(response.error?.code as any);
}

/**
 * Create a standardized authentication required response
 */
export function createAuthRequiredResponse(requestId: string, reason?: string): MessageResponse {
  const message = reason || ERROR_MESSAGES[ERROR_CODES.AUTH_REQUIRED];
  return createErrorResponse(ERROR_CODES.AUTH_REQUIRED, message, requestId);
}

/**
 * Create a standardized token expired response
 */
export function createTokenExpiredResponse(requestId: string): MessageResponse {
  return createErrorResponse(
    ERROR_CODES.TOKEN_EXPIRED,
    ERROR_MESSAGES[ERROR_CODES.TOKEN_EXPIRED],
    requestId
  );
}

// ============================================================================
// Error Analysis and Reporting
// ============================================================================

/**
 * Analyze error response and determine severity
 */
export function analyzeErrorSeverity(response: MessageResponse): keyof typeof ERROR_SEVERITY {
  if (response.success) return ERROR_SEVERITY.LOW;
  
  const code = response.error?.code;
  
  switch (code) {
    case ERROR_CODES.INITIALIZATION_ERROR:
    case ERROR_CODES.CONFIGURATION_ERROR:
      return ERROR_SEVERITY.CRITICAL;
      
    case ERROR_CODES.AUTH_FAILED:
    case ERROR_CODES.SERVICE_UNAVAILABLE:
    case ERROR_CODES.STORAGE_ERROR:
      return ERROR_SEVERITY.HIGH;
      
    case ERROR_CODES.AUTH_REQUIRED:
    case ERROR_CODES.TOKEN_EXPIRED:
    case ERROR_CODES.VALIDATION_ERROR:
      return ERROR_SEVERITY.MEDIUM;
      
    default:
      return ERROR_SEVERITY.LOW;
  }
}

/**
 * Extract actionable information from error responses
 */
export function extractErrorActions(response: MessageResponse): {
  userAction?: string;
  developerAction?: string;
  retryable: boolean;
} {
  if (response.success) {
    return { retryable: false };
  }
  
  const code = response.error?.code;
  
  switch (code) {
    case ERROR_CODES.AUTH_REQUIRED:
    case ERROR_CODES.TOKEN_EXPIRED:
      return {
        userAction: 'Please login again to continue',
        retryable: true
      };
      
    case ERROR_CODES.NETWORK_ERROR:
    case ERROR_CODES.TIMEOUT_ERROR:
      return {
        userAction: 'Please check your internet connection and try again',
        retryable: true
      };
      
    case ERROR_CODES.RATE_LIMITED:
      return {
        userAction: 'Please wait a moment before trying again',
        retryable: true
      };
      
    case ERROR_CODES.CONFIGURATION_ERROR:
      return {
        userAction: 'Please check your extension settings',
        developerAction: 'Verify configuration parameters',
        retryable: false
      };
      
    case ERROR_CODES.PERMISSION_DENIED:
      return {
        userAction: 'You do not have permission to perform this action',
        retryable: false
      };
      
    default:
      return {
        userAction: 'Please try again or contact support if the problem persists',
        retryable: true
      };
  }
}

// ============================================================================
// Response Utility Factories
// ============================================================================

/**
 * Create a response utility factory for a specific request context
 */
export function createResponseFactory(requestId: string) {
  return {
    success: <T>(data: T) => createSuccessResponse(data, requestId),
    error: (code: string, message: string, details?: any) => createErrorResponse(code, message, requestId, details),
    standardError: (errorCode: keyof typeof ERROR_CODES, customMessage?: string, details?: any) => 
      createStandardErrorResponse(errorCode, requestId, customMessage, details),
    fromError: (error: Error | any, fallbackCode?: string) => 
      createErrorResponseFromError(error, requestId, fallbackCode),
    authRequired: (reason?: string) => createAuthRequiredResponse(requestId, reason),
    tokenExpired: () => createTokenExpiredResponse(requestId)
  };
}

// Export types and constants for external use
export type { MessageResponse, SecurityApiError, ErrorCode };
export type ErrorSeverity = keyof typeof ERROR_SEVERITY;

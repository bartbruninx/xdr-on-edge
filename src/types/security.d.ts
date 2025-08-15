/**
 * Microsoft Security API Types
 * Secure cross-browser extension types for Microsoft Security Center API integration
 */

import type { Browser } from 'webextension-polyfill';

// ============================================================================
// Authentication & Authorization Types
// ============================================================================

export interface OAuthConfig {
  clientId: string;
  tenantId: string; // REQUIRED: Must be a specific tenant GUID - multi-tenant authentication disabled for security
  scopes: string[];
  redirectUri: string;
}

export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  state: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn: number;
  expiresAt: number;
  scope: string;
  tokenType: 'Bearer';
}

export interface EncryptedTokenData {
  encryptedData: string;
  iv: string;
  salt: string;
  timestamp: number;
}

export interface ExtensionSettings {
  oauth: {
    clientId: string;
    tenantId: string;
    customScopes?: string[];
  };
  api: {
    timeout: number;
    retryAttempts: number;
    timeRangeDays: number;
  };
  ui: {
    theme: 'light' | 'dark' | 'auto';
    autoRefresh: boolean;
    refreshInterval: number; // minutes
    notifications: boolean;
    notifyOnNewAssignments: boolean;
    notifyOnHighSeverity: boolean;
    notifyOnMediumSeverity: boolean;
    notifyOnLowSeverity: boolean;
    notifyOnInformationalSeverity: boolean;
  };
  security: {
    autoRefreshInterval: number; // milliseconds
    notificationsEnabled: boolean;
    defaultIncidentFilters: {
      status: string[];
      severity: string[];
    };
  };
  debug?: {
    enabled: boolean;
  };
}

export interface ExtensionInfo {
  id: string;
  version: string;
  browser: string;
  manifestVersion: number;
  redirectUri: string;
}

export interface AuthenticationState {
  isAuthenticated: boolean;
  user?: {
    id: string;
    displayName: string;
    userPrincipalName: string;
    tenantId: string;
  };
  expiresAt?: number;
  scopes: string[];
}

// ============================================================================
// Microsoft Security API Data Types
// ============================================================================

export interface SecurityIncident {
  id: string;
  displayName: string; // Changed from incidentName to displayName
  description?: string;
  severity: 'informational' | 'low' | 'medium' | 'high';
  status: 'active' | 'resolved' | 'inProgress' | 'redirected'; // Added inProgress
  assignedTo?: string;
  classification?: 'unknown' | 'falsePositive' | 'truePositive';
  determination?: string;
  createdDateTime: string;
  lastUpdateDateTime: string;
  redirectIncidentId?: string;
  customTags?: string[]; // Changed from tags to customTags to match API
  systemTags?: string[]; // Added systemTags
  summary?: string; // Added summary
  incidentWebUrl?: string; // Added incident web URL
  tenantId?: string; // Added tenantId
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface IncidentFilters {
  status?: ('active' | 'resolved' | 'redirected' | 'inProgress')[];
  severity?: ('informational' | 'low' | 'medium' | 'high')[];
  assignedTo?: string;
  classification?: ('unknown' | 'falsePositive' | 'truePositive')[];
  createdDateTime?: {
    start?: string;
    end?: string;
  };
  lastUpdateDateTime?: {
    start?: string;
    end?: string;
  };
  $top?: number;
  $skip?: number;
  $orderby?: string;
  $count?: boolean;
  $select?: string; // Field selection for performance
  $filter?: string; // Custom OData filter support
}

// Enhanced incident data structures for dashboard
export interface IncidentDashboardData {
  incidentCounts: {
    total: number;
    assigned: number;
    active: number;
    inProgress: number;
    bySeverity: Record<string, number>;
  };
  recentIncidents: SecurityIncident[];
  assignedIncidents: SecurityIncident[];
  incidentsBySeverity: {
    high: SecurityIncident[];
    medium: SecurityIncident[];
    low: SecurityIncident[];
    informational: SecurityIncident[];
  };
  lastUpdated: number;
}

export interface OptimizedIncidentFilters extends IncidentFilters {
  // Performance-optimized query presets
  preset?: 'dashboard' | 'assigned' | 'severity-counts' | 'recent';
}

export interface TimeRange {
  start: string; // ISO 8601 format
  end: string;   // ISO 8601 format
}

export interface ApiResponse<T> {
  '@odata.context'?: string;
  '@odata.count'?: number;
  '@odata.nextLink'?: string;
  value: T[];
}

// ============================================================================
// Message Passing Types for Background Script Communication
// ============================================================================

export type MessageType = 
  | 'MS_SECURITY_AUTH'
  | 'MS_SECURITY_INCIDENTS'
  | 'MS_SECURITY_ALERTS'
  | 'MS_SECURITY_HUNT'
  | 'MS_SECURITY_STATUS'
  | 'MS_SECURITY_UPDATE_INCIDENT'
  | 'MS_SECURITY_UPDATE_ALERT'
  | 'MS_SECURITY_REFRESH_NOW'
  | 'SETTINGS_UPDATED'
  | 'IOC_SCAN_REQUEST';

export interface BaseMessage {
  type: MessageType;
  requestId: string;
  timestamp: number;
}

export interface AuthMessage extends BaseMessage {
  type: 'MS_SECURITY_AUTH';
  data: {
    action: 'login' | 'logout' | 'refresh' | 'check';
    tenantId?: string;
  };
}

export interface IncidentsMessage extends BaseMessage {
  type: 'MS_SECURITY_INCIDENTS';
  data: {
    filters?: IncidentFilters;
  };
}

export interface StatusMessage extends BaseMessage {
  type: 'MS_SECURITY_STATUS';
  data: {
    checkAuth: boolean;
  };
}

export interface UpdateIncidentMessage extends BaseMessage {
  type: 'MS_SECURITY_UPDATE_INCIDENT';
  data: {
    incidentId: string;
    update: Partial<SecurityIncident>;
  };
}
export interface SettingsMessage extends BaseMessage {
  type: 'SETTINGS_UPDATED';
  data: ExtensionSettings;
}

export interface RefreshMessage extends BaseMessage {
  type: 'MS_SECURITY_REFRESH_NOW';
  data: {};
}

export interface IOCMessage extends BaseMessage {
  type: 'IOC_SCAN_REQUEST';
  data: {
    tabId: number;
  };
}

export type SecurityMessage = 
  | AuthMessage
  | IncidentsMessage
  | StatusMessage
  | UpdateIncidentMessage
  | SettingsMessage
  | RefreshMessage
  | IOCMessage;

export interface MessageResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  requestId: string;
  timestamp: number;
}

// ============================================================================
// Error Types
// ============================================================================

export interface SecurityApiError extends Error {
  code: string;
  status?: number;
  details?: any;
  timestamp: number;
}

export type ErrorCode = 
  | 'AUTH_REQUIRED'
  | 'AUTH_FAILED'
  | 'TOKEN_EXPIRED'
  | 'TENANT_MISMATCH'
  | 'INSUFFICIENT_SCOPE'
  | 'RATE_LIMITED'
  | 'API_ERROR'
  | 'NETWORK_ERROR'
  | 'VALIDATION_ERROR'
  | 'ENCRYPTION_ERROR'
  | 'STORAGE_ERROR'
  | 'BROWSER_NOT_SUPPORTED';

// ============================================================================
// Configuration Types
// ============================================================================

export interface SecurityApiConfig {
  baseUrl: string;
  apiVersion: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  timeRangeDays: number;
  rateLimiting: {
    requestsPerMinute: number;
    burstLimit: number;
  };
}

export interface ExtensionConfig {
  oauth: OAuthConfig;
  api: SecurityApiConfig;
  security: {
    encryptionAlgorithm: 'AES-GCM';
    keyLength: 256;
    ivLength: 12;
    saltLength: 16;
    tokenRefreshThreshold: number; // seconds before expiry to refresh
  };
  audit: {
    enabled: boolean;
    maxLogEntries: number;
    sensitiveDataMask: boolean;
  };
  debug: {
    enabled: boolean;
  };
}

// ============================================================================
// Audit Logging Types
// ============================================================================

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  level: 'info' | 'warn' | 'error';
  category: 'auth' | 'api' | 'security' | 'user';
  action: string;
  userId?: string;
  sessionId: string;
  details: Record<string, any>;
  userAgent?: string;
  ipAddress?: string; // For content script context
}

// ============================================================================
// Cross-Browser Compatibility Types
// ============================================================================

export interface CrossBrowserIdentity {
  launchWebAuthFlow(options: {
    url: string;
    interactive: boolean;
  }): Promise<string>;
  
  getRedirectURL(path?: string): string;
}

export interface CrossBrowserStorage {
  local: {
    get(keys: string | string[] | null): Promise<Record<string, any>>;
    set(items: Record<string, any>): Promise<void>;
    remove(keys: string | string[]): Promise<void>;
    clear(): Promise<void>;
  };
  
  session?: {
    get(keys: string | string[] | null): Promise<Record<string, any>>;
    set(items: Record<string, any>): Promise<void>;
    remove(keys: string | string[]): Promise<void>;
    clear(): Promise<void>;
  };
}

export interface CrossBrowserRuntime {
  onMessage: {
    addListener(
      callback: (
        message: any,
        sender: any,
        sendResponse: (response?: any) => void
      ) => boolean | void | Promise<any>
    ): void;
  };
  
  sendMessage(message: any): Promise<any>;
  
  onInstalled: {
    addListener(callback: (details: { reason: string }) => void): void;
  };
  
  getManifest(): any;
  id: string;
}

// ============================================================================
// Browser Detection and Capabilities
// ============================================================================

export interface BrowserCapabilities {
  name: 'chrome' | 'firefox' | 'edge' | 'safari';
  version: string;
  manifestVersion: 2 | 3;
  supportsServiceWorker: boolean;
  supportsBackgroundPage: boolean;
  supportsIdentityAPI: boolean;
  supportsWebCrypto: boolean;
  maxStorageSize: number;
  redirectUriFormat: string;
}

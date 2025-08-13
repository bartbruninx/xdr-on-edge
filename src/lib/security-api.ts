/**
 * Microsoft Graph Security API Client
 * Secure background script API gateway for Microsoft Graph Security endpoints
 * Uses unified Microsoft Graph API instead of legacy Security API
 */

import type {
  SecurityIncident,
  SecurityAlert,
  AdvancedHuntingQuery,
  AdvancedHuntingResult,
  ApiResponse,
  IncidentFilters,
  AlertFilters,
  IncidentDashboardData,
  SecurityApiConfig,
  AuditLogEntry,
  SecurityApiError,
  ErrorCode
} from '../types/security.d.ts';
import { logger } from './audit-logger.js';

export class MicrosoftSecurityApiClient {
  private config: SecurityApiConfig;
  private requestQueue: Map<string, number> = new Map();
  private rateLimitResetTime: number = 0;
  private auditLog: AuditLogEntry[] = [];

  constructor(config: SecurityApiConfig) {
    this.config = config;
  }

  /**
   * Generate createdDateTime filter based on timeRangeDays setting
   */
  private generateTimeRangeFilter(): string {
    const daysAgo = this.config.timeRangeDays || 30;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysAgo);
    
    // Format as ISO 8601 string (e.g., "2021-08-13T08:43:35.5533333Z")
    const isoString = startDate.toISOString();
    
    return `createdDateTime ge ${isoString}`;
  }

  /**
   * Get security incidents with optional filtering
   */
  async getIncidents(accessToken: string, filters?: IncidentFilters): Promise<ApiResponse<SecurityIncident>> {
    const endpoint = '/security/incidents';
    const queryParams = this.buildIncidentQueryParams(filters);
    
    logger.debug(`getIncidents called with filters:`, JSON.stringify(filters, null, 2));
    logger.debug(`Built query parameters:`, JSON.stringify(queryParams, null, 2));
    
    return await this.makeApiRequest<ApiResponse<SecurityIncident>>(
      accessToken,
      'GET',
      endpoint,
      undefined,
      queryParams
    );
  }

  /**
   * Get active incidents with minimal fields for dashboard
   */
  async getActiveIncidents(accessToken: string, userEmail?: string): Promise<ApiResponse<SecurityIncident>> {
    const filters: IncidentFilters = {
      status: ['active'],
      $select: 'id,displayName,severity,status,assignedTo,createdDateTime,lastUpdateDateTime',
      $orderby: 'lastUpdateDateTime desc',
      $top: 50
    };
    
    if (userEmail) {
      filters.assignedTo = userEmail;
    }
    
    return await this.getIncidents(accessToken, filters);
  }

  /**
   * Get assigned incidents for current user
   * Temporarily remove assignedTo filter to debug 400 error
   */
  async getAssignedIncidents(accessToken: string, userEmail: string): Promise<ApiResponse<SecurityIncident>> {
    logger.debug(`getAssignedIncidents called with userEmail: ${userEmail}`);
    
    // NOTE: Microsoft Graph API has a maximum limit of 50 items for $top parameter
    // Temporarily get all active incidents and filter client-side to debug the 400 error
    const filters: IncidentFilters = {
      // assignedTo: userEmail, // Temporarily commented out to debug 400 error
      status: ['active'],
      $select: 'id,displayName,severity,status,assignedTo,createdDateTime,lastUpdateDateTime,classification,determination',
      $orderby: 'lastUpdateDateTime desc',
      $top: 50 // Maximum allowed by Microsoft Graph API
    };
    
    logger.debug('getAssignedIncidents filters:', JSON.stringify(filters, null, 2));
    
    const allIncidents = await this.getIncidents(accessToken, filters);
    
    // Filter client-side for now to see the actual assignedTo values
    if (allIncidents.value) {
      logger.debug('Sample assignedTo values from incidents:', 
        allIncidents.value.slice(0, 5).map(i => ({ id: i.id, assignedTo: i.assignedTo }))
      );
      
      // Filter client-side to find matches
      allIncidents.value = allIncidents.value.filter(incident => 
        incident.assignedTo === userEmail || 
        incident.assignedTo?.toLowerCase() === userEmail.toLowerCase()
      );
      
      logger.debug(`Filtered to ${allIncidents.value.length} assigned incidents for ${userEmail}`);
    }
    
    return allIncidents;
  }

  /**
   * Get incidents by severity with counts
   */
  async getIncidentsBySeverity(accessToken: string): Promise<{
    high: ApiResponse<SecurityIncident>;
    medium: ApiResponse<SecurityIncident>;
    low: ApiResponse<SecurityIncident>;
    informational: ApiResponse<SecurityIncident>;
  }> {
    const baseFilters: IncidentFilters = {
      status: ['active'],
      $select: 'id,displayName,severity,status,assignedTo,createdDateTime',
      $count: true,
      $top: 10
    };

    const [high, medium, low, informational] = await Promise.all([
      this.getIncidents(accessToken, { ...baseFilters, severity: ['high'] }),
      this.getIncidents(accessToken, { ...baseFilters, severity: ['medium'] }),
      this.getIncidents(accessToken, { ...baseFilters, severity: ['low'] }),
      this.getIncidents(accessToken, { ...baseFilters, severity: ['informational'] })
    ]);

    return { high, medium, low, informational };
  }

  /**
   * Get incident counts only (for dashboard summary)
   */
  async getIncidentCounts(accessToken: string, userEmail?: string): Promise<{
    total: number;
    assigned: number;
    active: number;
    inProgress: number;
    bySeverity: Record<string, number>;
  }> {
    const baseCountFilter = {
      $count: true,
      $top: 0, // Don't return data, just count
      $select: 'id' // Minimal field selection
    };

    // Build queries for different counts - separate assigned query from severity queries
    const totalActiveQuery = this.getIncidents(accessToken, {
      ...baseCountFilter,
      status: ['active']
    });

    const totalInProgressQuery = this.getIncidents(accessToken, {
      ...baseCountFilter,
      status: ['inProgress']
    });

    const assignedQuery = userEmail ? this.getIncidents(accessToken, {
      ...baseCountFilter,
      status: ['active', 'inProgress'],
      assignedTo: userEmail
    }) : null;

    // Severity queries (separate from others to avoid indexing confusion)
    const severityQueries = await Promise.all([
      this.getIncidents(accessToken, {
        ...baseCountFilter,
        status: ['active'],
        severity: ['high']
      }),
      this.getIncidents(accessToken, {
        ...baseCountFilter,
        status: ['active'],
        severity: ['medium']
      }),
      this.getIncidents(accessToken, {
        ...baseCountFilter,
        status: ['active'],
        severity: ['low']
      }),
      this.getIncidents(accessToken, {
        ...baseCountFilter,
        status: ['active'],
        severity: ['informational']
      })
    ]);

    const [totalActiveResult, totalInProgressResult, assignedResult] = await Promise.all([
      totalActiveQuery,
      totalInProgressQuery,
      assignedQuery
    ]);
    
    logger.debug('getIncidentCounts results:', {
      activeCount: (totalActiveResult as any)['@odata.count'],
      inProgressCount: (totalInProgressResult as any)['@odata.count'],
      assignedCount: assignedResult ? (assignedResult as any)['@odata.count'] : 0,
      severityCounts: {
        high: (severityQueries[0] as any)['@odata.count'],
        medium: (severityQueries[1] as any)['@odata.count'],
        low: (severityQueries[2] as any)['@odata.count'],
        informational: (severityQueries[3] as any)['@odata.count']
      }
    });
    
    const activeCount = (totalActiveResult as any)['@odata.count'] || 0;
    const inProgressCount = (totalInProgressResult as any)['@odata.count'] || 0;
    
    return {
      total: activeCount + inProgressCount, // Total is now active + inProgress
      assigned: assignedResult ? ((assignedResult as any)['@odata.count'] || 0) : 0,
      active: activeCount,
      inProgress: inProgressCount,
      bySeverity: {
        high: (severityQueries[0] as any)['@odata.count'] || 0,
        medium: (severityQueries[1] as any)['@odata.count'] || 0,
        low: (severityQueries[2] as any)['@odata.count'] || 0,
        informational: (severityQueries[3] as any)['@odata.count'] || 0
      }
    };
  }

  /**
   * Get comprehensive dashboard data
   */
  async getDashboardIncidentData(accessToken: string, userEmail?: string): Promise<IncidentDashboardData> {
    const [incidentCounts, incidentsBySeverity] = await Promise.all([
      this.getIncidentCounts(accessToken, userEmail),
      this.getIncidentsBySeverity(accessToken)
    ]);

    return {
      incidentCounts,
      recentIncidents: [], // No longer fetched in background polling
      assignedIncidents: [], // Only fetched on-demand when user visits the page
      incidentsBySeverity: {
        high: incidentsBySeverity.high.value || [],
        medium: incidentsBySeverity.medium.value || [],
        low: incidentsBySeverity.low.value || [],
        informational: incidentsBySeverity.informational.value || []
      },
      lastUpdated: Date.now()
    };
  }

  /**
   * Get a specific incident by ID
   */
  async getIncident(accessToken: string, incidentId: string): Promise<SecurityIncident> {
    const endpoint = `/security/incidents/${encodeURIComponent(incidentId)}`;
    
    return await this.makeApiRequest<SecurityIncident>(
      accessToken,
      'GET',
      endpoint
    );
  }

  /**
   * Update an incident
   */
  async updateIncident(
    accessToken: string, 
    incidentId: string, 
    update: Partial<SecurityIncident>
  ): Promise<SecurityIncident> {
    const endpoint = `/security/incidents/${encodeURIComponent(incidentId)}`;
    
    // Sanitize update data to only include allowed fields
    const allowedFields = ['status', 'assignedTo', 'classification', 'determination', 'tags'];
    const sanitizedUpdate = Object.keys(update)
      .filter(key => allowedFields.includes(key))
      .reduce((obj, key) => {
        obj[key] = update[key as keyof SecurityIncident];
        return obj;
      }, {} as any);

    return await this.makeApiRequest<SecurityIncident>(
      accessToken,
      'PATCH',
      endpoint,
      sanitizedUpdate
    );
  }

  /**
   * Get security alerts with optional filtering
   */
  async getAlerts(accessToken: string, filters?: AlertFilters): Promise<ApiResponse<SecurityAlert>> {
    const endpoint = '/security/alerts_v2';
    const queryParams = this.buildAlertQueryParams(filters);
    
    return await this.makeApiRequest<ApiResponse<SecurityAlert>>(
      accessToken,
      'GET',
      endpoint,
      undefined,
      queryParams
    );
  }

  /**
   * Get a specific alert by ID
   */
  async getAlert(accessToken: string, alertId: string): Promise<SecurityAlert> {
    const endpoint = `/security/alerts_v2/${encodeURIComponent(alertId)}`;
    
    return await this.makeApiRequest<SecurityAlert>(
      accessToken,
      'GET',
      endpoint
    );
  }

  /**
   * Update an alert
   */
  async updateAlert(
    accessToken: string, 
    alertId: string, 
    update: Partial<SecurityAlert>
  ): Promise<SecurityAlert> {
    const endpoint = `/security/alerts_v2/${encodeURIComponent(alertId)}`;
    
    // Sanitize update data to only include allowed fields
    const allowedFields = ['status', 'assignedTo', 'classification', 'determination'];
    const sanitizedUpdate = Object.keys(update)
      .filter(key => allowedFields.includes(key))
      .reduce((obj, key) => {
        obj[key] = update[key as keyof SecurityAlert];
        return obj;
      }, {} as any);

    return await this.makeApiRequest<SecurityAlert>(
      accessToken,
      'PATCH',
      endpoint,
      sanitizedUpdate
    );
  }

  /**
   * Run advanced hunting query
   */
  async runAdvancedHuntingQuery(
    accessToken: string, 
    query: AdvancedHuntingQuery
  ): Promise<AdvancedHuntingResult> {
    const endpoint = '/security/runHuntingQuery';
    
    // Validate and sanitize the query
    const sanitizedQuery = this.sanitizeHuntingQuery(query);
    
    return await this.makeApiRequest<AdvancedHuntingResult>(
      accessToken,
      'POST',
      endpoint,
      sanitizedQuery
    );
  }

  /**
   * Make authenticated API request with proper error handling and rate limiting
   */
  private async makeApiRequest<T>(
    accessToken: string,
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    endpoint: string,
    body?: any,
    queryParams?: Record<string, string>
  ): Promise<T> {
    // Check rate limiting
    await this.checkRateLimit();
    
    // Build URL
    let url = `${this.config.baseUrl}/${this.config.apiVersion}${endpoint}`;
    if (queryParams && Object.keys(queryParams).length > 0) {
      const searchParams = new URLSearchParams(queryParams);
      url += `?${searchParams.toString()}`;
    }

    // Add comprehensive debug logging
    logger.debug(`API Request Details:`, {
      method,
      endpoint,
      baseUrl: this.config.baseUrl,
      apiVersion: this.config.apiVersion,
      fullUrl: url,
      queryParams: queryParams || {},
      hasBody: !!body,
      bodyPreview: body ? JSON.stringify(body).substring(0, 200) : null,
      timestamp: new Date().toISOString()
    });

    // Prepare request options
    const requestOptions: RequestInit = {
      method,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'XDR-on-Edge-Extension/1.0.0',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      },
      signal: AbortSignal.timeout(this.config.timeout)
    };

    if (body && (method === 'POST' || method === 'PATCH' || method === 'PUT')) {
      requestOptions.body = JSON.stringify(body);
    }

    // Execute request with retries
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= this.config.retryAttempts; attempt++) {
      try {
        this.logRequest(method, endpoint, attempt);
        
        const response = await fetch(url, requestOptions);
        
        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : this.config.retryDelay * Math.pow(2, attempt);
          
          this.logRateLimit(waitTime);
          
          if (attempt < this.config.retryAttempts) {
            await this.sleep(waitTime);
            continue;
          } else {
            throw this.createError('RATE_LIMITED', 'API rate limit exceeded', { retryAfter });
          }
        }

        // Handle authentication errors
        if (response.status === 401) {
          throw this.createError('AUTH_REQUIRED', 'Authentication required or token expired');
        }

        if (response.status === 403) {
          throw this.createError('INSUFFICIENT_SCOPE', 'Insufficient permissions for this operation');
        }

        // Handle client errors (4xx)
        if (response.status >= 400 && response.status < 500) {
          const errorData = await response.json().catch(() => ({}));
          logger.debug(`API Client Error (${response.status}):`, {
            status: response.status,
            statusText: response.statusText,
            url: url,
            method: method,
            errorData: errorData,
            timestamp: new Date().toISOString()
          });
          throw this.createError('API_ERROR', `API error: ${response.status}`, {
            status: response.status,
            error: errorData
          });
        }

        // Handle server errors (5xx) with retry
        if (response.status >= 500) {
          const errorMessage = `Server error: ${response.status} ${response.statusText}`;
          
          if (attempt < this.config.retryAttempts) {
            lastError = new Error(errorMessage);
            await this.sleep(this.config.retryDelay * Math.pow(2, attempt));
            continue;
          } else {
            throw this.createError('API_ERROR', errorMessage, { status: response.status });
          }
        }

        // Success - parse response
        if (response.status === 204) {
          logger.debug(`API Success (204 No Content):`, {
            status: response.status,
            url: url,
            method: method,
            timestamp: new Date().toISOString()
          });
          return {} as T; // No content
        }

        const data = await response.json();
        logger.debug(`API Success (${response.status}):`, {
          status: response.status,
          url: url,
          method: method,
          dataKeys: Object.keys(data || {}),
          hasValue: !!data?.value,
          valueCount: data?.value?.length || 0,
          odataCount: data?.['@odata.count'],
          timestamp: new Date().toISOString()
        });
        
        this.logSuccess(method, endpoint, response.status);
        
        return data as T;
        
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry on authentication or validation errors
        if (error instanceof Error && 'code' in error) {
          const apiError = error as SecurityApiError;
          if (['AUTH_REQUIRED', 'INSUFFICIENT_SCOPE', 'VALIDATION_ERROR'].includes(apiError.code)) {
            throw error;
          }
        }
        
        // Don't retry on network timeout or abort - handle multiple timeout error types
        if (error instanceof Error) {
          // Handle AbortSignal timeout errors (DOMException with name 'TimeoutError')
          // Handle fetch timeout errors (Error with name 'TimeoutError')  
          // Handle manual abort errors (Error with name 'AbortError')
          // Handle timeout messages in error text
          const isTimeoutError = error.name === 'TimeoutError' || 
                                error.name === 'AbortError' ||
                                error.message.toLowerCase().includes('timeout') ||
                                error.message.toLowerCase().includes('request timeout') ||
                                (error instanceof DOMException && error.name === 'TimeoutError');
          
          if (isTimeoutError) {
            logger.warn(`Request timeout (attempt ${attempt + 1}/${this.config.retryAttempts + 1})`, {
              endpoint,
              method,
              attempt: attempt + 1,
              errorName: error.name,
              errorMessage: error.message
            });
            
            if (attempt < this.config.retryAttempts) {
              await this.sleep(this.config.retryDelay * Math.pow(2, attempt));
              continue;
            } else {
              throw this.createError('NETWORK_ERROR', 'Request timeout', { originalError: error.message });
            }
          }
        }
        
        // For other errors, retry with exponential backoff
        if (attempt < this.config.retryAttempts) {
          await this.sleep(this.config.retryDelay * Math.pow(2, attempt));
          continue;
        }
      }
    }
    
    // If we get here, all retries failed
    throw this.createError('NETWORK_ERROR', lastError?.message || 'Request failed after all retries', {
      attempts: this.config.retryAttempts + 1
    });
  }

  /**
   * Check and enforce rate limiting
   */
  private async checkRateLimit(): Promise<void> {
    const now = Date.now();
    const windowStart = now - 60000; // 1 minute window
    
    // Clean old requests
    for (const [timestamp] of this.requestQueue) {
      if (parseInt(timestamp) < windowStart) {
        this.requestQueue.delete(timestamp);
      }
    }
    
    // Check if we're at the limit
    if (this.requestQueue.size >= this.config.rateLimiting.requestsPerMinute) {
      const oldestRequest = Math.min(...Array.from(this.requestQueue.keys()).map(k => parseInt(k)));
      const waitTime = oldestRequest + 60000 - now;
      
      if (waitTime > 0) {
        logger.warn(`Rate limit reached, waiting ${waitTime}ms`);
        await this.sleep(waitTime);
      }
    }
    
    // Add current request
    this.requestQueue.set(now.toString(), now);
  }

  /**
   * Build query parameters for incident filtering
   */
  private buildIncidentQueryParams(filters?: IncidentFilters): Record<string, string> {
    const params: Record<string, string> = {};
    
    if (!filters) return params;
    
    // Handle custom $filter parameter (highest priority)
    if (filters.$filter) {
      params['$filter'] = filters.$filter;
    } else {
      // Build filter from individual properties
      const filterParts: string[] = [];
      
      // Add time range filter automatically for all incident queries except assignedTo
      if (!filters.assignedTo) {
        filterParts.push(this.generateTimeRangeFilter());
      }
      
      if (filters.status?.length) {
        filterParts.push(`status in (${filters.status.map(s => `'${s}'`).join(',')})`);
      }
      
      if (filters.severity?.length) {
        filterParts.push(`severity in (${filters.severity.map(s => `'${s}'`).join(',')})`);
      }
      
      if (filters.assignedTo) {
        filterParts.push(`assignedTo eq '${filters.assignedTo}'`);
      }
      
      if (filters.classification?.length) {
        filterParts.push(`classification in (${filters.classification.map(c => `'${c}'`).join(',')})`);
      }
      
      if (filters.createdDateTime?.start && filters.createdDateTime?.end) {
        filterParts.push(`createdDateTime ge ${filters.createdDateTime.start} and createdDateTime le ${filters.createdDateTime.end}`);
      }
      
      if (filterParts.length) {
        params['$filter'] = filterParts.join(' and ');
      }
    }
    
    // Field selection for performance (CRITICAL for large datasets)
    if (filters.$select) {
      params['$select'] = filters.$select;
    }
    
    // Sorting
    if (filters.$orderby) {
      params['$orderby'] = filters.$orderby;
    }
    
    // Pagination
    if (filters.$top) {
      params['$top'] = filters.$top.toString();
    }
    
    if (filters.$skip) {
      params['$skip'] = filters.$skip.toString();
    }
    
    // Count
    if (filters.$count) {
      params['$count'] = 'true';
    }
    
    return params;
  }

  /**
   * Build query parameters for alert filtering
   */
  private buildAlertQueryParams(filters?: AlertFilters): Record<string, string> {
    const params: Record<string, string> = {};
    
    if (!filters) return params;
    
    // Add filters
    if (filters.status?.length) {
      params['$filter'] = `status in (${filters.status.map(s => `'${s}'`).join(',')})`;
    }
    
    if (filters.severity?.length) {
      const severityFilter = `severity in (${filters.severity.map(s => `'${s}'`).join(',')})`;
      params['$filter'] = params['$filter'] ? `${params['$filter']} and ${severityFilter}` : severityFilter;
    }
    
    if (filters.category?.length) {
      const categoryFilter = `category in (${filters.category.map(c => `'${c}'`).join(',')})`;
      params['$filter'] = params['$filter'] ? `${params['$filter']} and ${categoryFilter}` : categoryFilter;
    }
    
    if (filters.assignedTo) {
      const assignedFilter = `assignedTo eq '${filters.assignedTo}'`;
      params['$filter'] = params['$filter'] ? `${params['$filter']} and ${assignedFilter}` : assignedFilter;
    }
    
    // Add pagination
    if (filters.$top) {
      params['$top'] = filters.$top.toString();
    }
    
    if (filters.$skip) {
      params['$skip'] = filters.$skip.toString();
    }
    
    if (filters.$orderby) {
      params['$orderby'] = filters.$orderby;
    }
    
    return params;
  }

  /**
   * Sanitize and validate hunting query
   */
  private sanitizeHuntingQuery(query: AdvancedHuntingQuery): AdvancedHuntingQuery {
    // Basic validation
    if (!query.query || typeof query.query !== 'string') {
      throw this.createError('VALIDATION_ERROR', 'Invalid query string');
    }
    
    // Remove potentially dangerous operations
    const dangerousPatterns = [
      /\bexternaldata\b/i,
      /\binvoke\b/i,
      /\beval\b/i,
      /\bexecute\b/i
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(query.query)) {
        throw this.createError('VALIDATION_ERROR', 'Query contains potentially dangerous operations');
      }
    }
    
    // Limit query length
    if (query.query.length > 10000) {
      throw this.createError('VALIDATION_ERROR', 'Query is too long (max 10,000 characters)');
    }
    
    // Validate timespan format if provided
    if (query.timespan) {
      const timespanRegex = /^P(\d+Y)?(\d+M)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$/;
      if (!timespanRegex.test(query.timespan)) {
        throw this.createError('VALIDATION_ERROR', 'Invalid timespan format (must be ISO 8601 duration)');
      }
    }
    
    return {
      query: query.query.trim(),
      timespan: query.timespan
    };
  }

  /**
   * Logging methods for audit trail
   */
  private logRequest(method: string, endpoint: string, attempt: number): void {
    this.addAuditLog('info', 'api', 'request', {
      method,
      endpoint,
      attempt,
      timestamp: Date.now()
    });
  }

  private logSuccess(method: string, endpoint: string, status: number): void {
    this.addAuditLog('info', 'api', 'success', {
      method,
      endpoint,
      status,
      timestamp: Date.now()
    });
  }

  private logRateLimit(waitTime: number): void {
    this.addAuditLog('warn', 'api', 'rate_limit', {
      waitTime,
      timestamp: Date.now()
    });
  }

  private addAuditLog(level: AuditLogEntry['level'], category: AuditLogEntry['category'], action: string, details: Record<string, any>): void {
    const logEntry: AuditLogEntry = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      level,
      category,
      action,
      sessionId: 'background_session', // Could be enhanced with actual session tracking
      details,
      userAgent: navigator.userAgent
    };
    
    this.auditLog.push(logEntry);
    
    // Keep only last 1000 entries
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Get audit log entries
   */
  getAuditLog(): AuditLogEntry[] {
    return [...this.auditLog]; // Return copy
  }

  /**
   * Clear audit log
   */
  clearAuditLog(): void {
    this.auditLog = [];
  }

  /**
   * Utility: Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Create a standardized error
   */
  private createError(code: ErrorCode, message: string, details?: any): SecurityApiError {
    const error = new Error(message) as SecurityApiError;
    error.code = code;
    error.details = details;
    error.timestamp = Date.now();
    return error;
  }
}

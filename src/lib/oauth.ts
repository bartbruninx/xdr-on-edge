/**
 * Cross-Browser OAuth Authentication Service
 * Implements OAuth 2.0 with PKCE for Microsoft Security API access
 */

import browser from 'webextension-polyfill';
import type { 
  OAuthConfig, 
  PKCEParams, 
  TokenSet, 
  AuthenticationState,
  BrowserCapabilities,
  ErrorCode,
  SecurityApiError
} from '../types/security.d.ts';
import { encryptionService, EncryptionService } from './encryption.js';
import { logger } from './audit-logger.js';
import { createSecurityAlertNotification } from './notifications.js';

export class OAuthService {
  private config: OAuthConfig;
  private browserCapabilities: BrowserCapabilities;
  private currentPKCE: PKCEParams | null = null;

  constructor(config: OAuthConfig) {
    // SECURITY: Validate single-tenant configuration on construction
    if (!config.tenantId || 
        config.tenantId === 'common' || 
        config.tenantId === 'organizations' || 
        config.tenantId === 'consumers') {
      throw new Error('Single-tenant authentication required: Multi-tenant configurations are disabled for security. Please configure a specific tenant GUID.');
    }
    
    // Validate tenant ID is a proper GUID format
    const tenantIdGuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!tenantIdGuidRegex.test(config.tenantId)) {
      throw new Error('Invalid tenant ID format: Must be a valid GUID.');
    }
    
    this.config = config;
    this.browserCapabilities = this.detectBrowserCapabilities();
    
    logger.info('OAuth service initialized with validated single-tenant configuration', {
      tenantId: config.tenantId,
      clientId: config.clientId.substring(0, 8) + '...' // Log partial client ID for debugging
    });
  }

  /**
   * Detect browser capabilities for OAuth flow
   */
  private detectBrowserCapabilities(): BrowserCapabilities {
    const userAgent = navigator.userAgent.toLowerCase();
    const manifest = browser.runtime.getManifest();
    
    let browserName: BrowserCapabilities['name'] = 'chrome';
    if (userAgent.includes('firefox')) {
      browserName = 'firefox';
    } else if (userAgent.includes('edge')) {
      browserName = 'edge';
    } else if (userAgent.includes('safari')) {
      browserName = 'safari';
    }

    const manifestVersion = manifest.manifest_version as 2 | 3;
    // Use Mozilla best practices: browser.identity.getRedirectURL() for Firefox
    const redirectUriFormat = browserName === 'firefox' 
      ? browser.identity.getRedirectURL()
      : `https://${browser.runtime.id}.chromiumapp.org/`;

    return {
      name: browserName,
      version: this.getBrowserVersion(userAgent),
      manifestVersion,
      supportsServiceWorker: manifestVersion === 3,
      supportsBackgroundPage: true,
      supportsIdentityAPI: typeof browser.identity !== 'undefined',
      supportsWebCrypto: typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined',
      maxStorageSize: browserName === 'firefox' ? 5 * 1024 * 1024 : 10 * 1024 * 1024, // 5MB Firefox, 10MB Chrome
      redirectUriFormat
    };
  }

  /**
   * Extract browser version from user agent
   */
  private getBrowserVersion(userAgent: string): string {
    const patterns = {
      firefox: /firefox\/(\d+\.\d+)/i,
      chrome: /chrome\/(\d+\.\d+)/i,
      edge: /edge\/(\d+\.\d+)/i,
      safari: /safari\/(\d+\.\d+)/i
    };

    for (const [browser, pattern] of Object.entries(patterns)) {
      const match = userAgent.match(pattern);
      if (match) {
        return match[1];
      }
    }
    return 'unknown';
  }

  /**
   * Start the OAuth authentication flow
   */
  async authenticate(): Promise<AuthenticationState> {
    try {
      if (!this.browserCapabilities.supportsIdentityAPI) {
        throw this.createError('BROWSER_NOT_SUPPORTED', 'Browser does not support identity API');
      }

      // Generate PKCE parameters
      this.currentPKCE = await this.generatePKCEParams();
      
      // Build authorization URL
      const authUrl = this.buildAuthorizationUrl(this.currentPKCE);
      
      logger.debug('Starting OAuth flow with URL:', authUrl.substring(0, 100) + '...');
      
      // Launch web auth flow
      const redirectUrl = await browser.identity.launchWebAuthFlow({
        url: authUrl,
        interactive: true
      });

      if (!redirectUrl) {
        throw this.createError('AUTH_FAILED', 'No redirect URL received from auth flow');
      }

      logger.debug('Auth flow completed, processing redirect URL');
      
      // Extract authorization code from redirect URL
      const authCode = this.extractAuthorizationCode(redirectUrl);
      
      // Exchange authorization code for tokens
      const tokenSet = await this.exchangeCodeForTokens(authCode, this.currentPKCE);
      
      // Store tokens securely
      await this.storeTokens(tokenSet);
      
      // Get user info and build auth state
      const authState = await this.buildAuthenticationState(tokenSet);
      
      logger.info('Authentication completed successfully');
      return authState;
      
    } catch (error) {
      logger.error('Authentication failed:', error);
      await this.clearStoredTokens();
      
      if (error instanceof Error && 'code' in error) {
        throw error;
      }
      
      throw this.createError('AUTH_FAILED', error instanceof Error ? error.message : 'Unknown authentication error');
    } finally {
      // Clear PKCE parameters
      this.currentPKCE = null;
    }
  }

  /**
   * Check current authentication status
   */
  async getAuthenticationState(): Promise<AuthenticationState> {
    try {
      const tokens = await this.getStoredTokens();
      
      if (!tokens) {
        return {
          isAuthenticated: false,
          scopes: []
        };
      }

      // Check if token is expired
      if (this.isTokenExpired(tokens)) {
        logger.debug('Access token expired, attempting refresh');
        
        if (tokens.refreshToken) {
          try {
            const newTokens = await this.refreshAccessToken(tokens.refreshToken);
            await this.storeTokens(newTokens);
            return await this.buildAuthenticationState(newTokens);
          } catch (error) {
            logger.error('Token refresh failed:', error);
            await this.clearStoredTokens();
            return {
              isAuthenticated: false,
              scopes: []
            };
          }
        } else {
          logger.warn('No refresh token available, clearing stored tokens');
          await this.clearStoredTokens();
          return {
            isAuthenticated: false,
            scopes: []
          };
        }
      }

      return await this.buildAuthenticationState(tokens);
      
    } catch (error) {
      logger.error('Error checking authentication state:', error);
      return {
        isAuthenticated: false,
        scopes: []
      };
    }
  }

  /**
   * Refresh the access token using refresh token
   */
  async refreshTokens(): Promise<AuthenticationState> {
    try {
      const currentTokens = await this.getStoredTokens();
      
      if (!currentTokens?.refreshToken) {
        throw this.createError('AUTH_REQUIRED', 'No refresh token available');
      }

      const newTokens = await this.refreshAccessToken(currentTokens.refreshToken);
      await this.storeTokens(newTokens);
      
      return await this.buildAuthenticationState(newTokens);
      
    } catch (error) {
      logger.error('Token refresh failed:', error);
      await this.clearStoredTokens();
      throw error;
    }
  }

  /**
   * Logout and clear all stored tokens
   */
  async logout(): Promise<void> {
    try {
      const tokens = await this.getStoredTokens();
      
      if (tokens?.accessToken) {
        // Attempt to revoke tokens at Microsoft
        try {
          await this.revokeTokens(tokens);
        } catch (error) {
          logger.warn('Failed to revoke tokens at provider:', { error: error instanceof Error ? error.message : String(error) });
        }
      }
      
      await this.clearStoredTokens();
      encryptionService.clearSessionKey();
      
      logger.info('Logout completed successfully');
      
    } catch (error) {
      logger.error('Error during logout:', error);
      // Still clear local tokens even if remote revocation fails
      await this.clearStoredTokens();
      encryptionService.clearSessionKey();
    }
  }

  /**
   * Get a valid access token (refresh if needed)
   */
  async getValidAccessToken(): Promise<string> {
    try {
      // First check authentication state (this will auto-refresh if needed)
      const authState = await this.getAuthenticationState();
      
      if (!authState.isAuthenticated) {
        throw this.createError('AUTH_REQUIRED', 'User is not authenticated');
      }

      const tokens = await this.getStoredTokens();
      if (!tokens?.accessToken) {
        throw this.createError('AUTH_REQUIRED', 'No access token available');
      }

      // Double-check token expiry with a small buffer (30 seconds)
      if (this.isTokenExpired(tokens, 30)) {
        logger.debug('Access token near expiry, refreshing preemptively');
        
        if (tokens.refreshToken) {
          try {
            const newTokens = await this.refreshAccessToken(tokens.refreshToken);
            await this.storeTokens(newTokens);
            return newTokens.accessToken;
          } catch (error) {
            logger.error('Preemptive token refresh failed:', error);
            // Clear invalid tokens and throw auth required
            await this.clearStoredTokens();
            throw this.createError('TOKEN_EXPIRED', 'Token refresh failed - re-authentication required');
          }
        } else {
          logger.warn('No refresh token available for preemptive refresh');
          await this.clearStoredTokens();
          throw this.createError('TOKEN_EXPIRED', 'No refresh token available - re-authentication required');
        }
      }

      return tokens.accessToken;
      
    } catch (error) {
      // If it's already our custom error, re-throw it
      if (error instanceof Error && 'code' in error) {
        throw error;
      }
      
      // For unexpected errors, clear tokens and require re-auth
      logger.error('Unexpected error in getValidAccessToken:', error);
      await this.clearStoredTokens();
      throw this.createError('AUTH_REQUIRED', 'Authentication state corrupted - re-authentication required');
    }
  }

  /**
   * Generate PKCE parameters for OAuth flow
   */
  private async generatePKCEParams(): Promise<PKCEParams> {
    const codeVerifier = EncryptionService.generateCodeVerifier();
    const codeChallenge = await EncryptionService.generateCodeChallenge(codeVerifier);
    const state = EncryptionService.generateState();

    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
      state
    };
  }

  /**
   * Build the authorization URL
   */
  private buildAuthorizationUrl(pkce: PKCEParams): string {
    const baseUrl = `https://login.microsoftonline.com/${this.config.tenantId || 'common'}/oauth2/v2.0/authorize`;
    
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      response_type: 'code',
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      state: pkce.state,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      response_mode: 'query',
      prompt: 'select_account'
    });

    return `${baseUrl}?${params.toString()}`;
  }

  /**
   * Extract authorization code from redirect URL
   */
  private extractAuthorizationCode(redirectUrl: string): string {
    const url = new URL(redirectUrl);
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    const state = url.searchParams.get('state');

    if (error) {
      const errorDescription = url.searchParams.get('error_description') || 'Unknown OAuth error';
      throw this.createError('AUTH_FAILED', `OAuth error: ${error} - ${errorDescription}`);
    }

    if (!code) {
      throw this.createError('AUTH_FAILED', 'No authorization code received');
    }

    if (!state || (this.currentPKCE && state !== this.currentPKCE.state)) {
      throw this.createError('AUTH_FAILED', 'Invalid state parameter');
    }

    return code;
  }

  /**
   * Exchange authorization code for tokens
   */
  private async exchangeCodeForTokens(authCode: string, pkce: PKCEParams): Promise<TokenSet> {
    const tokenUrl = `https://login.microsoftonline.com/${this.config.tenantId || 'common'}/oauth2/v2.0/token`;
    
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: this.config.redirectUri,
      code_verifier: pkce.codeVerifier
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: body.toString()
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw this.createError('AUTH_FAILED', `Token exchange failed: ${errorData.error_description || response.statusText}`);
    }

    const tokenData = await response.json();
    
    return {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      idToken: tokenData.id_token,
      expiresIn: tokenData.expires_in,
      expiresAt: Date.now() + (tokenData.expires_in * 1000),
      scope: tokenData.scope || this.config.scopes.join(' '),
      tokenType: 'Bearer'
    };
  }

  /**
   * Refresh access token using refresh token
   * Updated for proper Microsoft Entra ID token refresh flow
   */
  private async refreshAccessToken(refreshToken: string): Promise<TokenSet> {
    try {
      logger.debug('Starting token refresh process');
      
      // Use the correct Microsoft Entra ID token endpoint
      const tokenUrl = `https://login.microsoftonline.com/${this.config.tenantId || 'common'}/oauth2/v2.0/token`;
      
      // Prepare the request body according to Microsoft Entra ID requirements
      const scopes = this.config.scopes.join(' ');
      // Ensure offline_access is included for refresh token capability
      const refreshScopes = scopes.includes('offline_access') ? scopes : `${scopes} offline_access`;
      
      const requestBody = new URLSearchParams({
        client_id: this.config.clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: refreshScopes
      });

      logger.debug('Making token refresh request to:', tokenUrl);
      
      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'User-Agent': `XDR-Extension/${browser.runtime.getManifest().version}`
        },
        body: requestBody.toString()
      });

      // Get response text first for better error debugging
      const responseText = await response.text();
      
      if (!response.ok) {
        logger.error('Token refresh failed with status:', { status: response.status, statusText: response.statusText });
        logger.error('Response body:', { responseText });
        
        let errorData;
        try {
          errorData = JSON.parse(responseText);
        } catch {
          errorData = { error: 'parse_error', error_description: responseText };
        }
        
        // Handle specific Microsoft Entra ID errors
        const errorCode = errorData.error;
        const errorDescription = errorData.error_description || 'Unknown error';
        
        switch (errorCode) {
          case 'invalid_grant':
            throw this.createError('TOKEN_EXPIRED', 'Refresh token has expired or been revoked - re-authentication required');
          case 'invalid_client':
            throw this.createError('AUTH_FAILED', 'Invalid client configuration - check client ID and tenant ID');
          case 'unauthorized_client':
            throw this.createError('AUTH_FAILED', 'Client not authorized for refresh token grant');
          case 'invalid_scope':
            throw this.createError('VALIDATION_ERROR', 'Invalid or unauthorized scope requested');
          default:
            throw this.createError('API_ERROR', `Token refresh failed: ${errorDescription} (${errorCode})`);
        }
      }

      let tokenData;
      try {
        tokenData = JSON.parse(responseText);
      } catch (parseError) {
        logger.error('Failed to parse token response:', parseError);
        throw this.createError('API_ERROR', 'Invalid response format from token endpoint');
      }

      // Validate required fields in response
      if (!tokenData.access_token) {
        logger.error('Token response missing access_token:', tokenData);
        throw this.createError('API_ERROR', 'Response missing access token');
      }

      if (!tokenData.expires_in) {
        logger.warn('Token response missing expires_in, defaulting to 3600 seconds');
        tokenData.expires_in = 3600; // Default to 1 hour
      }

      // Calculate expiration time with buffer
      const expiresIn = parseInt(tokenData.expires_in, 10);
      const expiresAt = Date.now() + (expiresIn * 1000);
      
      logger.debug('Token refresh successful, expires in:', expiresIn, 'seconds');
      
      const newTokenSet: TokenSet = {
        accessToken: tokenData.access_token,
        // Microsoft may or may not return a new refresh token
        refreshToken: tokenData.refresh_token || refreshToken,
        idToken: tokenData.id_token || undefined,
        expiresIn: expiresIn,
        expiresAt: expiresAt,
        scope: tokenData.scope || this.config.scopes.join(' '),
        tokenType: tokenData.token_type || 'Bearer'
      };

      // Validate the new token set
      if (!this.isValidTokenSet(newTokenSet)) {
        throw this.createError('VALIDATION_ERROR', 'Invalid token set received from refresh');
      }

      return newTokenSet;
      
    } catch (error) {
      // If it's already our custom error, re-throw it
      if (error instanceof Error && 'code' in error) {
        throw error;
      }
      
      // Handle network errors
      if (error instanceof TypeError && error.message.includes('fetch')) {
        logger.error('Network error during token refresh:', error);
        throw this.createError('NETWORK_ERROR', 'Unable to connect to Microsoft authentication service - check your internet connection');
      }
      
      // Handle other unexpected errors
      logger.error('Unexpected error during token refresh:', error);
      throw this.createError('API_ERROR', `Unexpected error during token refresh: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Revoke tokens at Microsoft
   */
  private async revokeTokens(tokens: TokenSet): Promise<void> {
    const revokeUrl = `https://login.microsoftonline.com/${this.config.tenantId || 'common'}/oauth2/v2.0/logout`;
    
    try {
      // Microsoft doesn't have a standard revoke endpoint, so we'll just log out
      const logoutUrl = `${revokeUrl}?post_logout_redirect_uri=${encodeURIComponent(this.config.redirectUri)}`;
      
      await fetch(logoutUrl, {
        method: 'GET',
        credentials: 'include'
      });
    } catch (error) {
      logger.warn('Token revocation may have failed:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  /**
   * Check if token is expired or expires soon
   */
  private isTokenExpired(tokens: TokenSet, bufferSeconds: number = 300): boolean {
    return Date.now() >= (tokens.expiresAt - (bufferSeconds * 1000));
  }

  /**
   * Store tokens securely in browser storage
   */
  private async storeTokens(tokens: TokenSet): Promise<void> {
    try {
      const encryptedTokens = await encryptionService.encrypt(JSON.stringify(tokens));
      
      await browser.storage.local.set({
        'ms_security_tokens': encryptedTokens,
        'ms_security_auth_timestamp': Date.now()
      });
      
    } catch (error) {
      logger.error('Failed to store tokens:', error);
      throw this.createError('STORAGE_ERROR', 'Failed to store authentication tokens');
    }
  }

  /**
   * Retrieve tokens from secure storage
   */
  private async getStoredTokens(): Promise<TokenSet | null> {
    try {
      const result = await browser.storage.local.get({ ms_security_tokens: null });
      
      if (!result.ms_security_tokens) {
        return null;
      }

      // Validate that we have encrypted token data
      const encryptedTokens = result.ms_security_tokens;
      if (!this.isValidEncryptedTokenData(encryptedTokens)) {
        logger.warn('Invalid encrypted token data format, clearing storage');
        await this.clearStoredTokens();
        return null;
      }

      const decryptedData = await encryptionService.decrypt(encryptedTokens);
      const tokens = JSON.parse(decryptedData) as TokenSet;
      
      // Validate token structure
      if (!this.isValidTokenSet(tokens)) {
        logger.warn('Invalid token structure, clearing storage');
        await this.clearStoredTokens();
        return null;
      }
      
      return tokens;
      
    } catch (error) {
      logger.error('Failed to retrieve tokens:', error);
      
      // Provide specific error messages for common issues
      if (error instanceof Error) {
        if (error.message.includes('decrypt')) {
          logger.debug('Token decryption failed - likely due to extension reload or browser restart');
          logger.debug('This is normal for development extensions. User will need to re-authenticate.');
        } else if (error.message.includes('JSON')) {
          logger.warn('Token data corrupted - clearing storage');
        }
      }
      
      // Clear corrupted data
      await this.clearStoredTokens();
      return null;
    }
  }

  /**
   * Validate token set structure
   */
  private isValidTokenSet(tokens: any): tokens is TokenSet {
    return tokens && 
           typeof tokens === 'object' && 
           typeof tokens.accessToken === 'string' && 
           typeof tokens.tokenType === 'string' && 
           typeof tokens.expiresAt === 'number' && 
           typeof tokens.scope === 'string' &&
           tokens.accessToken.length > 0;
  }

  /**
   * Type guard to validate encrypted token data
   */
  private isValidEncryptedTokenData(data: any): data is import('../types/security.d.ts').EncryptedTokenData {
    return data && 
           typeof data === 'object' && 
           typeof data.encryptedData === 'string' && 
           typeof data.iv === 'string' && 
           typeof data.salt === 'string' && 
           typeof data.timestamp === 'number';
  }

  /**
   * Clear all stored tokens
   */
  private async clearStoredTokens(): Promise<void> {
    try {
      await browser.storage.local.remove([
        'ms_security_tokens',
        'ms_security_auth_timestamp',
        'ms_security_user_info'
      ]);
    } catch (error) {
      logger.error('Failed to clear stored tokens:', error);
    }
  }

  /**
   * Build authentication state from tokens
   */
  private async buildAuthenticationState(tokens: TokenSet): Promise<AuthenticationState> {
    try {
      // Parse ID token to get user info (if available)
      let userInfo: AuthenticationState['user'] = undefined;
      if (tokens.idToken) {
        try {
          const payload = this.parseJWT(tokens.idToken);
          
          // SECURITY: Enforce single-tenant only authentication
          const receivedTenantId = payload.tid;
          if (!receivedTenantId) {
            logger.error('No tenant ID found in ID token - invalid authentication response');
            await this.clearStoredTokens();
            throw this.createError('TENANT_MISMATCH', 'Authentication failed: No tenant ID in response');
          }

          // Reject multi-tenant configurations entirely
          if (!this.config.tenantId || this.config.tenantId === 'common' || this.config.tenantId === 'organizations') {
            const errorMessage = 'Authentication failed: Multi-tenant authentication is not permitted for security reasons. Please configure a specific tenant ID.';
            
            logger.error('Invalid tenant configuration - multi-tenant authentication blocked', {
              configuredTenantId: this.config.tenantId || 'undefined'
            });
            
            try {
              await createSecurityAlertNotification(
                'Security Error: Invalid Configuration',
                'Multi-tenant authentication is disabled for security. Please contact your administrator to configure a specific tenant ID.',
                2 // High priority
              );
            } catch (notificationError) {
              logger.error('Failed to show configuration error notification', notificationError);
            }
            
            await this.clearStoredTokens();
            throw this.createError('TENANT_MISMATCH', errorMessage);
          }

          // Validate against configured single tenant
          if (receivedTenantId !== this.config.tenantId) {
            const errorMessage = `Authentication failed: User authenticated from unauthorized tenant '${receivedTenantId}'. Expected tenant: '${this.config.tenantId}'.`;
            
            logger.error('Tenant ID mismatch detected - unauthorized tenant access attempt', {
              expected: this.config.tenantId,
              received: receivedTenantId,
              userPrincipalName: payload.preferred_username || payload.upn || 'unknown'
            });
            
            try {
              await createSecurityAlertNotification(
                'Security Alert: Unauthorized Tenant Access',
                `Authentication blocked from unauthorized tenant. Expected: ${this.config.tenantId}, Received: ${receivedTenantId}`,
                2 // High priority
              );
            } catch (notificationError) {
              logger.error('Failed to show security alert notification', notificationError);
            }
            
            await this.clearStoredTokens();
            throw this.createError('TENANT_MISMATCH', errorMessage);
          }
          
          logger.info('Single-tenant authentication validation successful', {
            tenantId: receivedTenantId,
            userPrincipalName: payload.preferred_username || payload.upn || 'unknown'
          });
          
          userInfo = {
            id: payload.oid || payload.sub || 'unknown',
            displayName: payload.name || 'Unknown User',
            userPrincipalName: payload.preferred_username || payload.upn || 'unknown@unknown.com',
            tenantId: receivedTenantId || 'unknown'
          };
        } catch (error) {
          // Re-throw our custom security errors
          if (error instanceof Error && 'code' in error && (error as any).code === 'TENANT_MISMATCH') {
            throw error;
          }
          
          logger.warn('Failed to parse ID token:', { error: error instanceof Error ? error.message : String(error) });
        }
      }

      return {
        isAuthenticated: true,
        user: userInfo,
        expiresAt: tokens.expiresAt,
        scopes: tokens.scope.split(' ').filter((s: string) => s.length > 0)
      };
      
    } catch (error) {
      // Re-throw our custom security errors
      if (error instanceof Error && 'code' in error && (error as any).code === 'TENANT_MISMATCH') {
        throw error;
      }
      
      logger.error('Failed to build authentication state:', error);
      return {
        isAuthenticated: false,
        scopes: []
      };
    }
  }

  /**
   * Parse JWT token payload
   */
  private parseJWT(token: string): any {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      
      return JSON.parse(jsonPayload);
    } catch (error) {
      throw new Error('Invalid JWT token');
    }
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

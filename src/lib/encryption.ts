/**
 * Secure Encryption Utilities for Token Storage
 * Uses Web Crypto API for AES-GCM encryption/decryption
 */

import browser from 'webextension-polyfill';
import type { AuditLogEntry, EncryptedTokenData } from '../types/security.d.ts';
import { logger } from './audit-logger.js';

// ============================================================================

export class EncryptionService {
  private static readonly ALGORITHM = 'AES-GCM';
  private static readonly KEY_LENGTH = 256;
  private static readonly IV_LENGTH = 12;
  private static readonly SALT_LENGTH = 16;
  private static readonly ITERATIONS = 100000;

  private sessionKey: CryptoKey | null = null;
  private sessionSalt: Uint8Array | null = null;

  /**
   * Generate a new session key for encryption
   * This key is generated per browser session and never stored
   */
  async generateSessionKey(): Promise<void> {
    try {
      // Generate a random salt for key derivation
      this.sessionSalt = crypto.getRandomValues(new Uint8Array(EncryptionService.SALT_LENGTH));
      
      // Create a base key from random data + browser-specific entropy
      const entropy = await this.getBrowserEntropy();
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        entropy,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
      );

      // Derive the actual encryption key
      this.sessionKey = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: this.sessionSalt,
          iterations: EncryptionService.ITERATIONS,
          hash: 'SHA-256'
        },
        keyMaterial,
        {
          name: EncryptionService.ALGORITHM,
          length: EncryptionService.KEY_LENGTH
        },
        false,
        ['encrypt', 'decrypt']
      );
    } catch (error) {
      logger.error('Failed to generate session key', error);
      throw new Error('Encryption key generation failed');
    }
  }

  /**
   * Get browser-specific entropy for key derivation
   * This creates deterministic entropy that will be the same across browser sessions
   */
  private async getBrowserEntropy(): Promise<Uint8Array> {
    try {
      // Use deterministic browser-specific data for consistent key derivation
      const userAgent = navigator.userAgent;
      const extensionId = typeof browser !== 'undefined' && browser.runtime ? browser.runtime.id : 'fallback';
      const language = navigator.language || 'en-US';
      const platform = navigator.platform || 'unknown';
      
      // Combine deterministic browser data (no timestamp!)
      const combined = `${userAgent}:${extensionId}:${language}:${platform}:xdr-encryption-v1`;
      
      const encoder = new TextEncoder();
      const combinedBytes = encoder.encode(combined);
      
      // Hash the combined data to create deterministic entropy
      const hashBuffer = await crypto.subtle.digest('SHA-256', combinedBytes);
      return new Uint8Array(hashBuffer);
    } catch (error) {
      logger.warn('Could not create browser entropy, using fallback', { error: error instanceof Error ? error.message : 'Unknown error' });
      
      // Fallback to a deterministic but secure pattern
      const fallback = 'xdr-fallback-entropy-key-v1';
      const encoder = new TextEncoder();
      const fallbackBytes = encoder.encode(fallback);
      const hashBuffer = await crypto.subtle.digest('SHA-256', fallbackBytes);
      return new Uint8Array(hashBuffer);
    }
  }

  /**
   * Encrypt sensitive data (like tokens)
   */
  async encrypt(data: string): Promise<EncryptedTokenData> {
    if (!this.sessionKey || !this.sessionSalt) {
      await this.generateSessionKey();
    }

    if (!this.sessionKey || !this.sessionSalt) {
      throw new Error('Encryption key not available');
    }

    try {
      // Generate a unique IV for this encryption
      const iv = crypto.getRandomValues(new Uint8Array(EncryptionService.IV_LENGTH));
      
      // Encode the data
      const encoder = new TextEncoder();
      const dataBytes = encoder.encode(data);
      
      // Encrypt
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: EncryptionService.ALGORITHM,
          iv: iv
        },
        this.sessionKey,
        dataBytes
      );
      
      // Convert to base64 for storage
      const encryptedArray = new Uint8Array(encryptedBuffer);
      const encryptedData = this.arrayBufferToBase64(encryptedArray);
      const ivBase64 = this.arrayBufferToBase64(iv);
      const saltBase64 = this.arrayBufferToBase64(this.sessionSalt);
      
      return {
        encryptedData,
        iv: ivBase64,
        salt: saltBase64,
        timestamp: Date.now()
      };
    } catch (error) {
      logger.error('Encryption failed', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypt sensitive data
   */
  async decrypt(encryptedData: EncryptedTokenData): Promise<string> {
    try {
      // Always reconstruct the key using the stored salt for consistent decryption
      const storedSalt = this.base64ToArrayBuffer(encryptedData.salt);
      if (storedSalt.byteLength !== EncryptionService.SALT_LENGTH) {
        throw new Error('Invalid encryption salt length');
      }

      // Use the stored salt to recreate the exact same key that was used for encryption
      const entropy = await this.getBrowserEntropy();
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        entropy,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
      );

      const decryptionKey = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new Uint8Array(storedSalt),
          iterations: EncryptionService.ITERATIONS,
          hash: 'SHA-256'
        },
        keyMaterial,
        {
          name: EncryptionService.ALGORITHM,
          length: EncryptionService.KEY_LENGTH
        },
        false,
        ['encrypt', 'decrypt']
      );

      // Convert from base64
      const encrypted = this.base64ToArrayBuffer(encryptedData.encryptedData);
      const iv = this.base64ToArrayBuffer(encryptedData.iv);
      
      // Decrypt
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: EncryptionService.ALGORITHM,
          iv: iv
        },
        decryptionKey,
        encrypted
      );
      
      // Decode the result
      const decoder = new TextDecoder();
      return decoder.decode(decryptedBuffer);
    } catch (error) {
      logger.error('Decryption failed', error);
      throw new Error('Failed to decrypt data - tokens may be corrupted or from a different browser session');
    }
  }

  /**
   * Check if encrypted data is still valid (not too old)
   */
  isDataValid(encryptedData: EncryptedTokenData, maxAgeMs: number = 24 * 60 * 60 * 1000): boolean {
    const age = Date.now() - encryptedData.timestamp;
    return age <= maxAgeMs;
  }

  /**
   * Securely clear the session key
   */
  clearSessionKey(): void {
    this.sessionKey = null;
    this.sessionSalt = null;
  }

  /**
   * Utility: Convert ArrayBuffer to base64
   */
  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Utility: Convert base64 to ArrayBuffer
   */
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      view[i] = binary.charCodeAt(i);
    }
    return buffer;
  }

  /**
   * Generate a secure random string for PKCE code verifier
   */
  static generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, Array.from(array)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate PKCE code challenge from verifier
   */
  static async generateCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate a secure random state parameter
   */
  static generateState(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, Array.from(array)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}

/**
 * Singleton instance for the encryption service
 */
export const encryptionService = new EncryptionService();

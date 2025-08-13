/**
 * IOC Scanner Module for XDR on Edge
 * This module extracts IOCs (DNS, IP, URL, Email, SHA1, SHA256) from web page content
 * 
 * Uses advanced pattern matching and filtering to minimize false positives
 */

import browser from 'webextension-polyfill';
import { logger } from './audit-logger.js';

// ============================================================================
// Types and Interfaces
// ============================================================================

export interface IOCResults {
  urls: string[];
  ips: string[];
  domains: string[];
  files: string[];
  emails: string[];
  md5Hashes: string[];
  sha1Hashes: string[];
  sha256Hashes: string[];
  extractionTime: number;
  pageUrl: string;
  pageTitle: string;
  totalIOCs: number;
}

export interface IOCScanRequest {
  tabId: number;
  requestId: string;
  timestamp: number;
}

export interface IOCScanResponse {
  success: boolean;
  data?: IOCResults;
  error?: {
    message: string;
    code?: string;
  };
}

// ============================================================================
// Regular Expressions for IOC Detection
// ============================================================================

export const IOC_PATTERNS = {
  // IPv4 addresses (excluding private ranges for noise reduction)
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  
  // Defanged IPv4 addresses with [.] notation
  defangedIpv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  
  // Domain names (basic pattern)
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  
  // Defanged domain names with [.] notation
  defangedDomain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\])+[a-zA-Z]{2,}\b/g,
  
  // Email addresses (basic pattern)
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  
  // Defanged email addresses with [.] notation
  defangedEmail: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*\[\.\][a-zA-Z0-9.-]*[a-zA-Z]{2,}\b/g,
  
  // File references with common extensions
  file: /\b[a-zA-Z0-9][\w\-\.]*\.(?:exe|dll|bat|cmd|ps1|sh|py|js|vbs|scr|pif|jar|zip|rar|7z|tar|gz|pdf|doc|docx|xls|xlsx|ppt|pptx|rtf|txt|log|cfg|ini|xml|json|csv|sql|bak|tmp|iso|img|vhd|vmdk|ova|msi|deb|rpm|dmg|pkg|app|bin|dat|db|sqlite|accdb|mdb|pst|ost|eml|msg|vcf|p12|pfx|cer|crt|key|pem|pub|ppk|asc|sig|torrent|lnk|url|contact|gadget|theme|deskthemepack|themepack|library-ms|searchconnector-ms|website|webloc|desktop|directory|service|socket|fifo|device|mount|swap|core|dump|crash|dmp|hdmp|mdmp|wer|evt|evtx|reg|pol|adm|admx|adml|msc|mof|inf|cat|sys|drv|fon|ttf|otf|eot|woff|woff2|svg|ico|cur|ani|bmp|gif|jpg|jpeg|png|tiff|tif|webp|psd|ai|eps|cdr|sketch|fig|dwg|dxf|3ds|obj|fbx|dae|blend|ma|mb|max|c4d|lwo|lws|x3d|wrl|ply|stl|off|iges|step|stp|sat|brep|nurbs|mesh|raw|yuv|braw|r3d|mov|mp4|avi|mkv|webm|wmv|flv|f4v|m4v|3gp|3g2|asf|rm|rmvb|vob|ts|m2ts|mts|ogv|dv|m1v|m2v|mpv|mp2|mpe|mpeg|mpg|qt|swf|fla|as|asc|actionscript|wav|mp3|ogg|flac|aac|wma|m4a|opus|amr|au|aiff|aif|aifc|caf|ac3|dts|tta|tak|ape|wv|mka|ra|ram|mid|midi|kar|rmi|xmf|s3m|it|xm|mod|669|mtm|ult|wow|oct|med|far|ult|669|psm|ptm|stm|nst|wow|oct|med|far)\b/gi,
  
  // URLs (http/https/ftp)
  url: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`\[\]]+/gi,
  
  // Defanged URLs with [.] notation
  defangedUrl: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`]*\[\.\][^\s<>"{}|\\^`\[\]]*/gi,
  
  // MD5 hashes (32 hex characters)
  md5: /\b[a-fA-F0-9]{32}\b/g,
  
  // SHA1 hashes (40 hex characters)
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  
  // SHA256 hashes (64 hex characters)
  sha256: /\b[a-fA-F0-9]{64}\b/g
};

/**
 * Normalize defanged IOCs by removing bracket notation
 */
export function normalizeDefangedIOC(ioc: string): string {
  return ioc.replace(/\[\.\]/g, '.');
}

// Common file extensions for validation
const FILE_EXTENSIONS = new Set([
  // Executables and scripts
  'exe', 'dll', 'bat', 'cmd', 'ps1', 'sh', 'py', 'js', 'vbs', 'scr', 'pif', 'jar',
  // Archives
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'lzma', 'cab', 'ace', 'arj', 'lha', 'lzh',
  // Documents
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'log', 'cfg', 'ini',
  // Data formats
  'xml', 'json', 'csv', 'sql', 'bak', 'tmp', 'dat', 'db', 'sqlite', 'accdb', 'mdb',
  // Disk images
  'iso', 'img', 'vhd', 'vmdk', 'ova', 'qcow2', 'vdi', 'vbox',
  // Installers
  'msi', 'deb', 'rpm', 'dmg', 'pkg', 'app', 'snap', 'flatpak', 'appimage',
  // Email and communication
  'pst', 'ost', 'eml', 'msg', 'vcf', 'ics',
  // Security and certificates
  'p12', 'pfx', 'cer', 'crt', 'key', 'pem', 'pub', 'ppk', 'asc', 'sig',
  // Media files
  'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'mp3', 'wav', 'flac', 'ogg',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg', 'webp', 'ico',
  // System files
  'sys', 'drv', 'reg', 'pol', 'evt', 'evtx', 'dmp', 'crash', 'core'
]);

// Common top-level domains that should NOT be considered file extensions
const TOP_LEVEL_DOMAINS = new Set([
  // Generic TLDs
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro',
  'museum', 'coop', 'aero', 'asia', 'cat', 'jobs', 'mobi', 'tel', 'travel',
  // Country code TLDs (common ones)
  'uk', 'de', 'fr', 'it', 'es', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk', 'fi',
  'pl', 'cz', 'hu', 'pt', 'gr', 'ie', 'lu', 'bg', 'ro', 'hr', 'si', 'sk', 'mt',
  'cy', 'ee', 'lv', 'lt', 'us', 'ca', 'mx', 'br', 'ar', 'co', 've', 'pe', 'cl',
  'au', 'nz', 'jp', 'kr', 'cn', 'hk', 'tw', 'sg', 'my', 'th', 'ph', 'vn', 'in',
  'pk', 'bd', 'lk', 'np', 'mm', 'kh', 'la', 'mn', 'kg', 'kz', 'uz', 'tj', 'tm',
  'af', 'ir', 'iq', 'il', 'jo', 'lb', 'sy', 'tr', 'ge', 'am', 'az', 'ru', 'ua',
  'by', 'md', 'rs', 'ba', 'mk', 'al', 'me', 'xk', 'za', 'ng', 'ke', 'gh', 'tz',
  'ug', 'rw', 'bi', 'mw', 'zm', 'zw', 'bw', 'na', 'sz', 'ls', 'mg', 'mu', 'sc',
  'eg', 'ly', 'tn', 'dz', 'ma', 'sd', 'et', 'er', 'dj', 'so', 'km', 'td', 'cf',
  'cm', 'gq', 'ga', 'cg', 'cd', 'ao', 'st', 'gw', 'gn', 'sl', 'lr', 'ci', 'bf',
  'ml', 'ne', 'sn', 'gm', 'mr', 'cv', 'mz', 'mv', 'bt', 'fj', 'pg', 'vu', 'nc',
  'pf', 'ws', 'to', 'tv', 'ki', 'nr', 'pw', 'mh', 'fm', 'ck', 'nu', 'tk'
]);

// ============================================================================
// Private IP Range Detection
// ============================================================================

/**
 * Check if an IP address is in a private range
 */
export function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => isNaN(part) || part < 0 || part > 255)) {
    return true; // Invalid IP, treat as private
  }
  
  const [a, b, c, d] = parts;
  
  // Private ranges:
  // 10.0.0.0/8
  if (a === 10) return true;
  
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  
  // Loopback 127.0.0.0/8
  if (a === 127) return true;
  
  // Link-local 169.254.0.0/16
  if (a === 169 && b === 254) return true;
  
  return false;
}

// ============================================================================
// IOC Detection Utility Functions
// ============================================================================

/**
 * Detect the IOC type from a single input string
 */
export function detectIOCType(input: string): string | null {
  const trimmed = input.trim();
  
  // Test each pattern type
  const patterns = [
    { type: 'md5Hashes', pattern: IOC_PATTERNS.md5 },
    { type: 'sha1Hashes', pattern: IOC_PATTERNS.sha1 },
    { type: 'sha256Hashes', pattern: IOC_PATTERNS.sha256 },
    { type: 'urls', pattern: IOC_PATTERNS.url },
    { type: 'urls', pattern: IOC_PATTERNS.defangedUrl },
    { type: 'emails', pattern: IOC_PATTERNS.email },
    { type: 'emails', pattern: IOC_PATTERNS.defangedEmail },
    { type: 'files', pattern: IOC_PATTERNS.file },
    { type: 'ips', pattern: IOC_PATTERNS.ipv4 },
    { type: 'ips', pattern: IOC_PATTERNS.defangedIpv4 },
    { type: 'domains', pattern: IOC_PATTERNS.domain },
    { type: 'domains', pattern: IOC_PATTERNS.defangedDomain }
  ];
  
  for (const { type, pattern } of patterns) {
    pattern.lastIndex = 0; // Reset regex state
    const match = pattern.exec(trimmed);
    if (match && match[0] === trimmed) {
      // For IPs, check if it's private (skip private IPs for domains)
      if (type === 'ips') {
        const normalized = normalizeDefangedIOC(trimmed);
        if (isPrivateIP(normalized)) {
          continue; // Skip private IPs
        }
      }
      return type;
    }
  }
  
  return null;
}

/**
 * Parse multiple IOCs from a text input and return them categorized by type
 */
export function parseIOCsFromText(text: string): Record<string, string[]> {
  const result: Record<string, string[]> = {
    urls: [],
    ips: [],
    domains: [],
    files: [],
    emails: [],
    md5Hashes: [],
    sha1Hashes: [],
    sha256Hashes: []
  };
  
  const lines = text.split(/\r?\n/);
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    
    const type = detectIOCType(trimmed);
    if (type && result[type]) {
      const normalized = normalizeDefangedIOC(trimmed);
      if (!result[type].includes(normalized)) {
        result[type].push(normalized);
      }
    }
  }
  
  return result;
}

// ============================================================================
// IOC Scanner Class
// ============================================================================

export class IOCScanner {
  /**
   * Scan the active tab for IOCs
   */
  static async scanActiveTab(): Promise<IOCScanResponse> {
    try {
      logger.debug('Starting IOC scan of active tab');
      
      // Get the active tab
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (!tabs.length) {
        throw new Error('No active tab found');
      }
      
      const activeTab = tabs[0];
      if (!activeTab.id) {
        throw new Error('Active tab has no ID');
      }
      
      logger.debug('Active tab found', { 
        tabId: activeTab.id, 
        url: activeTab.url, 
        title: activeTab.title 
      });
      
      // Check if we can inject into this tab
      if (!activeTab.url || 
          activeTab.url.startsWith('chrome://') || 
          activeTab.url.startsWith('chrome-extension://') ||
          activeTab.url.startsWith('moz-extension://') ||
          activeTab.url.startsWith('edge://') ||
          activeTab.url.startsWith('about:')) {
        throw new Error('Cannot scan system pages or extension pages');
      }
      
      // Execute the content script to extract IOCs
      const results = await browser.scripting.executeScript({
        target: { tabId: activeTab.id },
        func: () => {
          // This is the actual function that will be executed in the tab context
          const patterns = {
            ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
            defangedIpv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\]){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
            domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
            defangedDomain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\])+[a-zA-Z]{2,}\b/g,
            email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
            defangedEmail: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*\[\.\][a-zA-Z0-9.-]*[a-zA-Z]{2,}\b/g,
            file: /\b[a-zA-Z0-9][\w\-\.]*\.(?:exe|dll|bat|cmd|ps1|sh|py|js|vbs|scr|pif|jar|zip|rar|7z|tar|gz|pdf|doc|docx|xls|xlsx|ppt|pptx|rtf|txt|log|cfg|ini|xml|json|csv|sql|bak|tmp|iso|img|vhd|vmdk|ova|msi|deb|rpm|dmg|pkg|app|bin|dat|db|sqlite|accdb|mdb|pst|ost|eml|msg|vcf|p12|pfx|cer|crt|key|pem|pub|ppk|asc|sig|torrent|lnk|url|contact|gadget|theme|deskthemepack|themepack|library-ms|searchconnector-ms|website|webloc|desktop|directory|service|socket|fifo|device|mount|swap|core|dump|crash|dmp|hdmp|mdmp|wer|evt|evtx|reg|pol|adm|admx|adml|msc|mof|inf|cat|sys|drv|fon|ttf|otf|eot|woff|woff2|svg|ico|cur|ani|bmp|gif|jpg|jpeg|png|tiff|tif|webp|psd|ai|eps|cdr|sketch|fig|dwg|dxf|3ds|obj|fbx|dae|blend|ma|mb|max|c4d|lwo|lws|x3d|wrl|ply|stl|off|iges|step|stp|sat|brep|nurbs|mesh|raw|yuv|braw|r3d|mov|mp4|avi|mkv|webm|wmv|flv|f4v|m4v|3gp|3g2|asf|rm|rmvb|vob|ts|m2ts|mts|ogv|dv|m1v|m2v|mpv|mp2|mpe|mpeg|mpg|qt|swf|fla|as|asc|actionscript|wav|mp3|ogg|flac|aac|wma|m4a|opus|amr|au|aiff|aif|aifc|caf|ac3|dts|tta|tak|ape|wv|mka|ra|ram|mid|midi|kar|rmi|xmf|s3m|it|xm|mod|669|mtm|ult|wow|oct|med|far|ult|669|psm|ptm|stm|nst|wow|oct|med|far)\b/gi,
            url: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`\[\]]+/gi,
            defangedUrl: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`]*\[\.\][^\s<>"{}|\\^`\[\]]*/gi,
            md5: /\b[a-fA-F0-9]{32}\b/g,
            sha1: /\b[a-fA-F0-9]{40}\b/g,
            sha256: /\b[a-fA-F0-9]{64}\b/g
          };
          
          function normalizeDefangedIOC(ioc: string): string {
            return ioc.replace(/\[\.\]/g, '.');
          }
          
          const fileExtensions = new Set([
            'exe', 'dll', 'bat', 'cmd', 'ps1', 'sh', 'py', 'js', 'vbs', 'scr', 'pif', 'jar',
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'lzma', 'cab', 'ace', 'arj', 'lha', 'lzh',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'log', 'cfg', 'ini',
            'xml', 'json', 'csv', 'sql', 'bak', 'tmp', 'dat', 'db', 'sqlite', 'accdb', 'mdb',
            'iso', 'img', 'vhd', 'vmdk', 'ova', 'qcow2', 'vdi', 'vbox',
            'msi', 'deb', 'rpm', 'dmg', 'pkg', 'app', 'snap', 'flatpak', 'appimage',
            'pst', 'ost', 'eml', 'msg', 'vcf', 'ics',
            'p12', 'pfx', 'cer', 'crt', 'key', 'pem', 'pub', 'ppk', 'asc', 'sig',
            'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'mp3', 'wav', 'flac', 'ogg',
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg', 'webp', 'ico',
            'sys', 'drv', 'reg', 'pol', 'evt', 'evtx', 'dmp', 'crash', 'core'
          ]);
          
          const topLevelDomains = new Set([
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro',
            'museum', 'coop', 'aero', 'asia', 'cat', 'jobs', 'mobi', 'tel', 'travel',
            'uk', 'de', 'fr', 'it', 'es', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk', 'fi',
            'pl', 'cz', 'hu', 'pt', 'gr', 'ie', 'lu', 'bg', 'ro', 'hr', 'si', 'sk', 'mt',
            'cy', 'ee', 'lv', 'lt', 'us', 'ca', 'mx', 'br', 'ar', 'co', 've', 'pe', 'cl',
            'au', 'nz', 'jp', 'kr', 'cn', 'hk', 'tw', 'sg', 'my', 'th', 'ph', 'vn', 'in',
            'pk', 'bd', 'lk', 'np', 'mm', 'kh', 'la', 'mn', 'kg', 'kz', 'uz', 'tj', 'tm',
            'af', 'ir', 'iq', 'il', 'jo', 'lb', 'sy', 'tr', 'ge', 'am', 'az', 'ru', 'ua',
            'by', 'md', 'rs', 'ba', 'mk', 'al', 'me', 'xk', 'za', 'ng', 'ke', 'gh', 'tz',
            'ug', 'rw', 'bi', 'mw', 'zm', 'zw', 'bw', 'na', 'sz', 'ls', 'mg', 'mu', 'sc',
            'eg', 'ly', 'tn', 'dz', 'ma', 'sd', 'et', 'er', 'dj', 'so', 'km', 'td', 'cf',
            'cm', 'gq', 'ga', 'cg', 'cd', 'ao', 'st', 'gw', 'gn', 'sl', 'lr', 'ci', 'bf',
            'ml', 'ne', 'sn', 'gm', 'mr', 'cv', 'mz', 'mv', 'bt', 'fj', 'pg', 'vu', 'nc',
            'pf', 'ws', 'to', 'tv', 'ki', 'nr', 'pw', 'mh', 'fm', 'ck', 'nu', 'tk'
          ]);
          
          function isFileExtension(text: string): boolean {
            const lastDot = text.lastIndexOf('.');
            if (lastDot === -1) return false;
            const extension = text.substring(lastDot + 1).toLowerCase();
            
            // If it's a known TLD, it's definitely not a file
            if (topLevelDomains.has(extension)) {
              return false;
            }
            
            // Check if it's a known file extension
            return fileExtensions.has(extension);
          }
          
          function isPrivateIP(ip: string): boolean {
            const parts = ip.split('.').map(Number);
            if (parts.length !== 4 || parts.some(part => isNaN(part) || part < 0 || part > 255)) {
              return true;
            }
            
            const [a, b, c, d] = parts;
            
            if (a === 10) return true;
            if (a === 172 && b >= 16 && b <= 31) return true;
            if (a === 192 && b === 168) return true;
            if (a === 127) return true;
            if (a === 169 && b === 254) return true;
            
            return false;
          }
          
          function getVisibleTextContent(): string {
            // Only get text content that is actually visible to the user for reading
            const walker = document.createTreeWalker(
              document.body || document.documentElement,
              NodeFilter.SHOW_TEXT,
              {
                acceptNode: function(node) {
                  const parent = node.parentElement;
                  if (!parent) return NodeFilter.FILTER_REJECT;
                  
                  // Skip script, style, noscript tags and hidden elements
                  const tagName = parent.tagName.toLowerCase();
                  if (['script', 'style', 'noscript', 'meta', 'head', 'title'].includes(tagName)) {
                    return NodeFilter.FILTER_REJECT;
                  }
                  
                  // Skip interactive elements that are UI controls, not content
                  if (['button', 'input', 'select', 'textarea', 'a', 'nav', 'menu'].includes(tagName)) {
                    return NodeFilter.FILTER_REJECT;
                  }
                  
                  // Skip elements with interactive roles
                  const role = parent.getAttribute('role');
                  if (role && ['button', 'link', 'menuitem', 'tab', 'option'].includes(role)) {
                    return NodeFilter.FILTER_REJECT;
                  }
                  
                  // Skip hidden elements
                  const computedStyle = window.getComputedStyle(parent);
                  if (computedStyle.display === 'none' || 
                      computedStyle.visibility === 'hidden' ||
                      computedStyle.opacity === '0') {
                    return NodeFilter.FILTER_REJECT;
                  }
                  
                  // Skip elements that are off-screen or have zero dimensions
                  const rect = parent.getBoundingClientRect();
                  if (rect.width === 0 || rect.height === 0) {
                    return NodeFilter.FILTER_REJECT;
                  }
                  
                  return NodeFilter.FILTER_ACCEPT;
                }
              }
            );
            
            let visibleText = '';
            let node;
            while (node = walker.nextNode()) {
              const textContent = node.textContent?.trim();
              if (textContent) {
                visibleText += textContent + ' ';
              }
            }
            
            return visibleText;
          }
          
          function extractIOCs() {
            const startTime = performance.now();
            
            // Get only visible text content that users can actually see
            const visibleContent = getVisibleTextContent();
            
            // Extract URLs (normal and defanged)
            const normalUrls = (visibleContent.match(patterns.url) || []).map(url => url.trim());
            const defangedUrls = (visibleContent.match(patterns.defangedUrl) || []).map(url => normalizeDefangedIOC(url.trim()));
            const urls = [...new Set([...normalUrls, ...defangedUrls])];
            
            // Extract IPs (normal and defanged)
            const normalIps = (visibleContent.match(patterns.ipv4) || [])
              .filter(ip => !isPrivateIP(ip.trim()))
              .map(ip => ip.trim());
            const defangedIps = (visibleContent.match(patterns.defangedIpv4) || [])
              .map(ip => normalizeDefangedIOC(ip))
              .filter(ip => !isPrivateIP(ip.trim()))
              .map(ip => ip.trim());
            const ips = [...new Set([...normalIps, ...defangedIps])];
            
            // Extract potential domains and files (normal and defanged)
            const normalDomainMatches = (visibleContent.match(patterns.domain) || []).map(item => item.toLowerCase().trim());
            const defangedDomainMatches = (visibleContent.match(patterns.defangedDomain) || [])
              .map(item => normalizeDefangedIOC(item.toLowerCase().trim()));
            const potentialDomains = [...new Set([...normalDomainMatches, ...defangedDomainMatches])];
            
            // Separate files from domains
            const files = potentialDomains.filter(item => isFileExtension(item));
            const domains = potentialDomains.filter(item => 
              !isFileExtension(item) && 
              item.includes('.') && 
              !item.match(/^\d+\.\d+\.\d+\.\d+$/) && // Not an IP
              item.length >= 4 && 
              !item.includes(' ')
            );
            
            // Extract emails (normal and defanged)
            const normalEmails = (visibleContent.match(patterns.email) || []).map(email => email.toLowerCase().trim());
            const defangedEmails = (visibleContent.match(patterns.defangedEmail) || [])
              .map(email => normalizeDefangedIOC(email.toLowerCase().trim()));
            const emails = [...new Set([...normalEmails, ...defangedEmails])];
            
            // Extract hashes (these are not typically defanged)
            const md5Hashes = [...new Set((visibleContent.match(patterns.md5) || []).map(hash => hash.toLowerCase()))];
            const sha1Hashes = [...new Set((visibleContent.match(patterns.sha1) || []).map(hash => hash.toLowerCase()))];
            const sha256Hashes = [...new Set((visibleContent.match(patterns.sha256) || []).map(hash => hash.toLowerCase()))];
            
            const endTime = performance.now();
            
            return {
              urls,
              ips,
              domains,
              files,
              emails,
              md5Hashes,
              sha1Hashes,
              sha256Hashes,
              extractionTime: Math.round(endTime - startTime),
              pageUrl: window.location.href,
              pageTitle: document.title || 'Unknown',
              totalIOCs: urls.length + ips.length + domains.length + files.length + emails.length + md5Hashes.length + sha1Hashes.length + sha256Hashes.length
            };
          }
          
          return extractIOCs();
        }
      });
      
      if (!results || !results[0]) {
        throw new Error('Failed to execute content script');
      }
      
      const contentScriptResult = results[0].result as any;
      
      // Map content script result to IOCResults format
      const iocData: IOCResults = {
        urls: contentScriptResult.urls || [],
        ips: contentScriptResult.ips || [],
        domains: contentScriptResult.domains || [],
        files: contentScriptResult.files || [],
        emails: contentScriptResult.emails || [],
        md5Hashes: contentScriptResult.md5Hashes || [],
        sha1Hashes: contentScriptResult.sha1Hashes || [],
        sha256Hashes: contentScriptResult.sha256Hashes || [],
        pageUrl: contentScriptResult.pageUrl || '',
        pageTitle: contentScriptResult.pageTitle || '',
        totalIOCs: contentScriptResult.totalIOCs || 0,
        extractionTime: contentScriptResult.extractionTime || 0
      };
      
      logger.info('IOC scan completed successfully', {
        pageUrl: iocData.pageUrl,
        totalIOCs: iocData.totalIOCs,
        extractionTime: iocData.extractionTime,
        breakdown: {
          urls: iocData.urls.length,
          ips: iocData.ips.length,
          domains: iocData.domains.length,
          files: iocData.files.length,
          emails: iocData.emails.length,
          md5: iocData.md5Hashes.length,
          sha1: iocData.sha1Hashes.length,
          sha256: iocData.sha256Hashes.length
        }
      });
      
      return {
        success: true,
        data: iocData
      };
      
    } catch (error) {
      logger.error('IOC scan failed', error);
      
      return {
        success: false,
        error: {
          message: error instanceof Error ? error.message : 'Unknown error during IOC scan',
          code: 'IOC_SCAN_FAILED'
        }
      };
    }
  }
  
  /**
   * Validate IOC data quality and filter false positives
   */
  static validateIOCs(iocs: IOCResults): IOCResults {
    // Don't spread the original iocs to avoid preserving stale totalIOCs
    const validated: IOCResults = {
      pageUrl: iocs.pageUrl,
      pageTitle: iocs.pageTitle,
      extractionTime: iocs.extractionTime,
      urls: [],
      ips: [],
      domains: [],
      files: [],
      emails: [],
      md5Hashes: [],
      sha1Hashes: [],
      sha256Hashes: [],
      totalIOCs: 0 // Will be recalculated at the end
    };

    // Filter URLs - remove common false positives
    validated.urls = iocs.urls.filter(url => {
      try {
        const urlObj = new URL(url);
        // Filter out data URLs, javascript URLs, etc.
        return ['http:', 'https:', 'ftp:'].includes(urlObj.protocol);
      } catch {
        return false;
      }
    });

    // Filter IPs - already filtered for private IPs in extraction
    validated.ips = iocs.ips.filter(ip => {
      const parts = ip.split('.');
      return parts.length === 4 && parts.every(part => {
        const num = parseInt(part, 10);
        return !isNaN(num) && num >= 0 && num <= 255;
      });
    });

    // Filter domains - remove obvious false positives and file extensions
    validated.domains = iocs.domains.filter(domain => {
      const lastDot = domain.lastIndexOf('.');
      if (lastDot !== -1) {
        const extension = domain.substring(lastDot + 1).toLowerCase();
        // Skip if it's a known file extension (but not a TLD)
        if (FILE_EXTENSIONS.has(extension) && !TOP_LEVEL_DOMAINS.has(extension)) {
          return false;
        }
      }
      
      // Remove domains that are too short or contain invalid characters
      return domain.length >= 4 && 
             domain.includes('.') && 
             !domain.includes(' ') &&
             domain.split('.').length >= 2; // At least one dot
    });    // Filter files - validate they have proper file extensions and are not TLDs
    validated.files = iocs.files.filter(file => {
      const lastDot = file.lastIndexOf('.');
      if (lastDot === -1) return false;
      
      const extension = file.substring(lastDot + 1).toLowerCase();
      const fileName = file.substring(0, lastDot);
      
      // Must be a known file extension but NOT a TLD
      return FILE_EXTENSIONS.has(extension) && 
             !TOP_LEVEL_DOMAINS.has(extension) &&
             fileName.length > 0 && 
             !file.includes(' ') &&
             file.length >= 3; // Minimum reasonable file name length
    });
    
    // Filter emails - validate they have proper email format
    validated.emails = iocs.emails.filter(email => {
      // Basic email validation
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      const parts = email.split('@');
      
      return emailRegex.test(email) && 
             parts.length === 2 &&
             parts[0].length > 0 && 
             parts[1].length > 0 &&
             parts[1].includes('.') &&
             !email.includes(' ') &&
             email.length >= 5; // Minimum reasonable email length (a@b.co)
    });
    
    // Hashes are already validated by regex pattern length
    validated.md5Hashes = iocs.md5Hashes;
    validated.sha1Hashes = iocs.sha1Hashes;
    validated.sha256Hashes = iocs.sha256Hashes;
    
    // Recalculate total
    validated.totalIOCs = validated.urls.length + validated.ips.length + 
                         validated.domains.length + validated.files.length +
                         validated.emails.length +
                         validated.md5Hashes.length + validated.sha1Hashes.length + validated.sha256Hashes.length;

    return validated;
  }
}

// ============================================================================
// Message Handler Integration
// ============================================================================

/**
 * Store scan results for persistence across sessions
 */
async function storeScanResults(results: IOCResults): Promise<void> {
  try {
    await browser.storage.local.set({
      'scanWebsite_results': results
    });
    logger.debug('IOC scan results stored for persistence', { 
      totalIOCs: results.totalIOCs,
      pageTitle: results.pageTitle 
    });
  } catch (error) {
    logger.error('Failed to store scan results', error);
  }
}

/**
 * Handle IOC scan requests from the popup/options page
 */
export async function handleIOCScanRequest(
  request: IOCScanRequest,
  logAuditEvent: (level: 'info' | 'warn' | 'error', category: 'auth' | 'api' | 'security' | 'user', action: string, details: Record<string, any>) => void
): Promise<IOCScanResponse> {
  try {
    logger.debug('Processing IOC scan request', { requestId: request.requestId });
    
    // Log audit event for scan initiation
    logAuditEvent('info', 'security', 'ioc_scan_initiated', {
      requestId: request.requestId,
      timestamp: request.timestamp,
      tabId: request.tabId
    });
    
    // Perform the scan
    const scanResult = await IOCScanner.scanActiveTab();
    
    if (scanResult.success && scanResult.data) {
      // Validate and filter IOCs
      const validatedIOCs = IOCScanner.validateIOCs(scanResult.data);
      
      // Log successful scan
      logAuditEvent('info', 'security', 'ioc_scan_completed', {
        requestId: request.requestId,
        pageUrl: validatedIOCs.pageUrl,
        totalIOCs: validatedIOCs.totalIOCs,
        extractionTime: validatedIOCs.extractionTime,
        iocBreakdown: {
          urls: validatedIOCs.urls.length,
          ips: validatedIOCs.ips.length,
          domains: validatedIOCs.domains.length,
          files: validatedIOCs.files.length,
          emails: validatedIOCs.emails.length,
          sha1: validatedIOCs.sha1Hashes.length,
          sha256: validatedIOCs.sha256Hashes.length
        }
      });
      
      // Store the scan results for persistence
      await storeScanResults(validatedIOCs);
      
      return {
        success: true,
        data: validatedIOCs
      };
    } else {
      // Log failed scan
      logAuditEvent('error', 'security', 'ioc_scan_failed', {
        requestId: request.requestId,
        error: scanResult.error?.message || 'Unknown error'
      });
      
      return scanResult;
    }
    
  } catch (error) {
    logger.error('Error handling IOC scan request', error);
    
    logAuditEvent('error', 'security', 'ioc_scan_error', {
      requestId: request.requestId,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    
    return {
      success: false,
      error: {
        message: error instanceof Error ? error.message : 'Unknown error',
        code: 'IOC_SCAN_REQUEST_FAILED'
      }
    };
  }
}

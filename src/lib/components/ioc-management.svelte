<!--
  IOC Management Module
  Website scanning and manual IOC management interface for threat hunting
  Based on ScanWebsite.svelte
-->

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { Button, Accordion } from 'bits-ui';
  import { AlertCircle, ScanSearch, Shield, Copy, Trash2 } from 'lucide-svelte';
  import { logger } from '../audit-logger.js';
  import browser from 'webextension-polyfill';
  import type { IOCResults } from '../ioc-scanner.js';
  import { detectIOCType, normalizeDefangedIOC } from '../ioc-scanner.js';
  import { getDefaultSettings, mergeWithDefaults, type SettingsSchema } from '../default-settings.js';

  // Props
  let { 
    isAuthenticated = false,
    onNavigateToHunt = () => {}
  }: { 
    isAuthenticated?: boolean;
    onNavigateToHunt?: (iocs: any) => void;
  } = $props();

  // State management
  let isScanning = $state(false);
  let error = $state('');
  let scanResults = $state<IOCResults | null>(null);
  let showResults = $state(false);
  let isLoadingPersistence = $state(true);

  // Settings for KQL templates
  let settings: SettingsSchema | null = $state(null);
  let settingsLoaded = $state(false);

  // Smart IOC input state
  let smartIOCInput = $state('');
  let detectedType = $state<string>('');

  // IOC type display names
  const iocTypeDisplayNames = {
    domains: 'Domain',
    ips: 'IP Address', 
    urls: 'URL',
    sha256Hashes: 'SHA256 Hash',
    sha1Hashes: 'SHA1 Hash',
    md5Hashes: 'MD5 Hash',
    emails: 'Email',
    files: 'File'
  };

  // Storage key for persistence
  const SCAN_RESULTS_KEY = 'scanWebsite_results';
  const SCAN_STATE_KEY = 'scanWebsite_state';

  // Functions
  async function loadSettings() {
    try {
      const result = await browser.storage.local.get({ xdr_settings: null });
      if (result.xdr_settings) {
        settings = mergeWithDefaults(result.xdr_settings);
      } else {
        settings = getDefaultSettings();
      }
      settingsLoaded = true;
    } catch (err) {
      logger.error('Failed to load settings', { error: err instanceof Error ? err.message : 'Unknown error' });
      settings = getDefaultSettings();
      settingsLoaded = true;
    }
  }

  // Load persisted scan results
  async function loadPersistedResults() {
    try {
      const result = await browser.storage.local.get(SCAN_RESULTS_KEY);
      
      if (result[SCAN_RESULTS_KEY]) {
        const loadedResults = result[SCAN_RESULTS_KEY] as IOCResults;
        
        // Helper function to convert object-with-numeric-keys to array
        const objectToArray = (obj: any): string[] => {
          if (Array.isArray(obj)) return obj;
          if (obj && typeof obj === 'object') {
            // Convert object with numeric keys to array
            const keys = Object.keys(obj).map(k => parseInt(k)).filter(k => !isNaN(k)).sort((a, b) => a - b);
            return keys.map(k => obj[k.toString()]).filter(item => typeof item === 'string');
          }
          return [];
        };
        
        // Ensure all arrays exist and are properly initialized
        scanResults = {
          pageUrl: loadedResults.pageUrl || '',
          pageTitle: loadedResults.pageTitle || '',
          extractionTime: loadedResults.extractionTime || 0,
          totalIOCs: loadedResults.totalIOCs || 0,
          urls: objectToArray(loadedResults.urls),
          ips: objectToArray(loadedResults.ips),
          domains: objectToArray(loadedResults.domains),
          files: objectToArray(loadedResults.files),
          emails: objectToArray(loadedResults.emails),
          md5Hashes: objectToArray(loadedResults.md5Hashes),
          sha1Hashes: objectToArray(loadedResults.sha1Hashes),
          sha256Hashes: objectToArray(loadedResults.sha256Hashes)
        };
        
        // Only show results if we actually have IOCs
        if (scanResults.totalIOCs > 0) {
          showResults = true;
          logger.debug('Loaded persisted scan results', { 
            totalIOCs: scanResults.totalIOCs,
            pageTitle: scanResults.pageTitle 
          });
        }
      }
    } catch (err) {
      logger.error('Failed to load persisted scan results', { error: err instanceof Error ? err.message : 'Unknown error' });
    } finally {
      isLoadingPersistence = false;
    }
  }

  // Save scan results to storage
  async function saveResults() {
    try {
      if (scanResults) {
        await browser.storage.local.set({
          [SCAN_RESULTS_KEY]: scanResults
        });
        logger.debug('Saved scan results to storage', { totalIOCs: scanResults.totalIOCs });
      }
    } catch (err) {
      logger.error('Failed to save scan results', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  // Clear persisted results
  async function clearPersistedResults() {
    try {
      await browser.storage.local.remove(SCAN_RESULTS_KEY);
      logger.debug('Cleared persisted scan results');
    } catch (err) {
      logger.error('Failed to clear persisted results', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  // Reset scan state - clear all results and UI state
  async function resetScan() {
    scanResults = null;
    showResults = false;
    error = '';
    await clearPersistedResults();
    logger.debug('Scan state reset and persisted data cleared');
  }
  async function saveStateToStorage() {
    try {
      // Debug: Log what we're about to save
      logger.debug('Saving scan results to storage', {
        totalIOCs: scanResults?.totalIOCs,
        urls: scanResults?.urls?.length,
        ips: scanResults?.ips?.length,
        domains: scanResults?.domains?.length,
        files: scanResults?.files?.length,
        emails: scanResults?.emails?.length,
        md5Hashes: scanResults?.md5Hashes?.length,
        sha1Hashes: scanResults?.sha1Hashes?.length,
        sha256Hashes: scanResults?.sha256Hashes?.length,
        pageTitle: scanResults?.pageTitle
      });

      await browser.storage.local.set({
        [SCAN_RESULTS_KEY]: scanResults,
        [SCAN_STATE_KEY]: {
          showResults
        }
      });
      
      logger.debug('Successfully saved scan results to storage');
    } catch (err) {
      logger.error('Failed to save state to storage', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  // Clear persisted state
  async function clearPersistedState() {
    try {
      await browser.storage.local.remove([SCAN_RESULTS_KEY, SCAN_STATE_KEY]);
      logger.debug('Cleared persisted scan state');
    } catch (err) {
      logger.error('Failed to clear persisted state', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  // Start a new scan while keeping results in storage until scan completes
  async function scanAgain() {
    if (isScanning) return;
    
    isScanning = true;
    error = '';
    // Don't clear scanResults or showResults - keep them visible during scan
    
    try {
      logger.debug('Website scan again initiated');
      
      // Get the active tab
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (!tabs.length || !tabs[0].id) {
        throw new Error('No active tab found');
      }
      
      const activeTab = tabs[0];
      
      // Send IOC scan request to background script
      const response = await browser.runtime.sendMessage({
        type: 'IOC_SCAN_REQUEST',
        requestId: `ioc-scan-${Date.now()}`,
        timestamp: Date.now(),
        data: {
          tabId: activeTab.id
        }
      }) as { success: boolean; data?: IOCResults; error?: { message?: string } };
      
      if (response.success && response.data) {
        scanResults = response.data;
        showResults = true;
        await saveResults(); // Persist the results
        logger.debug('Website scan again completed successfully', { 
          totalIOCs: response.data.totalIOCs,
          pageUrl: response.data.pageUrl
        });
      } else {
        throw new Error(response.error?.message || 'Scan failed');
      }
      
    } catch (err) {
      error = err instanceof Error ? err.message : 'Scan failed';
      logger.error('Website scan again failed:', err);
    } finally {
      isScanning = false;
    }
  }

  // Initial scan that clears results first
  async function initialScan() {
    if (isScanning) return;
    
    isScanning = true;
    error = '';
    scanResults = null;
    showResults = false;
    
    try {
      logger.debug('Initial website scan initiated');
      
      // Get the active tab
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (!tabs.length || !tabs[0].id) {
        throw new Error('No active tab found');
      }
      
      const activeTab = tabs[0];
      
      // Send IOC scan request to background script
      const response = await browser.runtime.sendMessage({
        type: 'IOC_SCAN_REQUEST',
        requestId: `ioc-scan-${Date.now()}`,
        timestamp: Date.now(),
        data: {
          tabId: activeTab.id
        }
      }) as { success: boolean; data?: IOCResults; error?: { message?: string } };
      
      if (response.success && response.data) {
        scanResults = response.data;
        showResults = true;
        await saveResults(); // Persist the results
        logger.debug('Initial website scan completed successfully', { 
          totalIOCs: response.data.totalIOCs,
          pageUrl: response.data.pageUrl
        });
      } else {
        throw new Error(response.error?.message || 'Scan failed');
      }
      
    } catch (err) {
      error = err instanceof Error ? err.message : 'Scan failed';
      logger.error('Initial website scan failed:', err);
    } finally {
      isScanning = false;
    }
  }
  
  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      logger.debug('Copied to clipboard', { textLength: text.length });
    } catch (err) {
      logger.warn('Failed to copy to clipboard', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  async function copyIOCTypeToClipboard(iocType: string, iocs: string[]) {
    if (iocs.length === 0) return;
    
    const text = iocs.join('\n');
    await copyToClipboard(text);
    logger.debug(`Copied ${iocType} IOCs to clipboard`, { count: iocs.length });
  }

  async function copyAllIOCs() {
    if (!scanResults) return;
    
    const allIOCs: string[] = [];
    
    if (scanResults.urls.length > 0) {
      allIOCs.push('=== URLs ===', ...scanResults.urls, '');
    }
    if (scanResults.ips.length > 0) {
      allIOCs.push('=== IP Addresses ===', ...scanResults.ips, '');
    }
    if (scanResults.domains.length > 0) {
      allIOCs.push('=== Domains ===', ...scanResults.domains, '');
    }
    if (scanResults.files.length > 0) {
      allIOCs.push('=== Files ===', ...scanResults.files, '');
    }
    if (scanResults.emails.length > 0) {
      allIOCs.push('=== Email Addresses ===', ...scanResults.emails, '');
    }
    if (scanResults.md5Hashes.length > 0) {
      allIOCs.push('=== MD5 Hashes ===', ...scanResults.md5Hashes, '');
    }
    if (scanResults.sha1Hashes.length > 0) {
      allIOCs.push('=== SHA1 Hashes ===', ...scanResults.sha1Hashes, '');
    }
    if (scanResults.sha256Hashes.length > 0) {
      allIOCs.push('=== SHA256 Hashes ===', ...scanResults.sha256Hashes, '');
    }
    
    const text = allIOCs.join('\n').trim();
    await copyToClipboard(text);
    logger.debug('Copied all IOCs to clipboard', { totalCount: scanResults.totalIOCs });
  }

  // Navigation function to threat hunt
  function navigateToThreatHunt() {
    if (!scanResults || scanResults.totalIOCs === 0) {
      logger.warn('No IOCs available for threat hunting');
      return;
    }

    // Prepare IOCs for threat hunt
    const iocs = {
      urls: scanResults.urls,
      ips: scanResults.ips,
      domains: scanResults.domains,
      sha256Hashes: scanResults.sha256Hashes,
      sha1Hashes: scanResults.sha1Hashes,
      md5Hashes: scanResults.md5Hashes,
      emails: scanResults.emails,
      files: scanResults.files
    };

    onNavigateToHunt(iocs);
    logger.debug('Navigated to threat hunt with IOCs', { 
      totalIOCs: scanResults.totalIOCs,
      iocCounts: {
        domains: scanResults.domains.length,
        ips: scanResults.ips.length,
        urls: scanResults.urls.length,
        sha256: scanResults.sha256Hashes.length,
        sha1: scanResults.sha1Hashes.length,
        md5: scanResults.md5Hashes.length,
        emails: scanResults.emails.length,
        files: scanResults.files.length
      }
    });
  }

  // Smart IOC input functions
  function addManualIOC() {
    if (!smartIOCInput.trim()) {
      error = 'IOC value is required';
      return;
    }

    const iocValue = smartIOCInput.trim();
    const detectedIOCType = detectIOCType(iocValue);
    
    if (!detectedIOCType) {
      error = 'Unable to detect IOC type. Please check the format.';
      return;
    }

    const normalizedIOC = normalizeDefangedIOC(iocValue);
    
    // Add to scan results
    if (!scanResults) {
      scanResults = {
        urls: [],
        ips: [],
        domains: [],
        files: [],
        emails: [],
        md5Hashes: [],
        sha1Hashes: [],
        sha256Hashes: [],
        totalIOCs: 0,
        extractionTime: Date.now(),
        pageUrl: 'manual-entry',
        pageTitle: 'Manual Entry'
      };
    }

    // Add to appropriate array if not already present
    const iocArray = scanResults![detectedIOCType as keyof IOCResults] as string[];
    if (!iocArray.includes(normalizedIOC)) {
      iocArray.push(normalizedIOC);
      scanResults!.totalIOCs = Object.values(scanResults!)
        .filter(value => Array.isArray(value))
        .reduce((total, arr) => total + arr.length, 0);
      
      // Save results and clear input
      saveResults();
      smartIOCInput = '';
      error = '';
      showResults = true; // Show results interface when IOC is added
      
      logger.debug('Added manual IOC', { type: detectedIOCType, value: normalizedIOC });
    } else {
      error = 'IOC already exists';
    }
  }

  // Delete individual IOC function
  function deleteIOC(iocType: keyof IOCResults, iocValue: string) {
    if (!scanResults) return;
    
    const iocArray = scanResults[iocType] as string[];
    const index = iocArray.indexOf(iocValue);
    
    if (index > -1) {
      iocArray.splice(index, 1);
      scanResults.totalIOCs = Object.values(scanResults)
        .filter(value => Array.isArray(value))
        .reduce((total, arr) => total + arr.length, 0);
      
      // Save updated results
      saveResults();
      
      logger.debug('Deleted IOC', { type: iocType, value: iocValue });
    }
  }

  // Auto-detect IOC type as user types
  $effect(() => {
    if (smartIOCInput.trim()) {
      const detectedIOCType = detectIOCType(smartIOCInput.trim());
      if (detectedIOCType) {
        detectedType = detectedIOCType;
      } else {
        detectedType = '';
      }
    } else {
      detectedType = '';
    }
  });

  onMount(async () => {
    logger.debug('IOCManagement component mounted');
    await loadSettings();
    await loadPersistedResults();
  });

  onDestroy(() => {
    logger.debug('IOCManagement component destroyed');
  });
</script>

<div class="rounded-lg border bg-card text-card-foreground shadow-sm">
  <div class="p-6 border-b">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-semibold leading-none tracking-tight flex items-center gap-2">
          <ScanSearch class="w-5 h-5" />
          Indicators
        </h3>
        {#if scanResults}
          <p class="text-xs text-muted-foreground mt-2">
            Scanned: {scanResults.pageTitle}
          </p>
        {/if}
      </div>
    </div>
  </div>

  <div class="p-6">
    {#if !isAuthenticated}
      <div class="text-center py-4">
        <Shield class="w-6 h-6 text-muted-foreground mx-auto mb-3" />
        <p class="text-xs text-muted-foreground">
          Authentication required to use website scanner
        </p>
      </div>
    {:else if error}
      <div class="rounded-lg border border-destructive bg-destructive/5 p-4 mb-6">
        <div class="flex items-center gap-3">
          <AlertCircle class="w-5 h-5 text-destructive" />
          <div>
            <p class="font-medium text-destructive">Scan Error</p>
            <p class="text-sm text-destructive/80">{error}</p>
          </div>
        </div>
      </div>
    {:else if isLoadingPersistence}
      <!-- Loading persistence data -->
      <div class="text-center py-4">
        <div class="animate-spin w-4 h-4 border-2 border-primary border-t-transparent rounded-full mx-auto mb-3"></div>
        <p class="text-xs text-muted-foreground">Loading scan data...</p>
      </div>
    {/if}
    
    {#if !isLoadingPersistence && !showResults}
      <!-- Ultra Compact Scan Interface -->
      <div class="text-center py-4">
        <ScanSearch class="w-6 h-6 text-muted-foreground mx-auto mb-3" />
        
        <h3 class="text-sm font-semibold mb-1">IOC Management</h3>
        <p class="text-xs text-muted-foreground mb-4 max-w-md mx-auto">
          Scan for indicators or add manually
        </p>
        
        <!-- Scan Button (Primary Option) -->
        <div class="mb-4">
          <Button.Root 
            disabled={isScanning}
            onclick={initialScan}
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-4 text-xs font-semibold active:scale-[0.98] active:transition-all"
          >
            {isScanning ? 'Scanning...' : 'Scan Current Tab'}
          </Button.Root>
        </div>

        <!-- Divider -->
        <div class="flex items-center gap-4 mb-4 max-w-md mx-auto">
          <div class="flex-1 h-px bg-border"></div>
          <span class="text-xs text-muted-foreground">OR</span>
          <div class="flex-1 h-px bg-border"></div>
        </div>

        <!-- Smart IOC Input (Alternative Option) -->
        <div class="max-w-md mx-auto">
          <div class="mb-2">
            <input
              type="text"
              bind:value={smartIOCInput}
              placeholder="Enter IOC manually (press Enter to add)"
              class="w-full rounded-md border border-input bg-background px-2 py-1 text-xs text-center"
              onkeydown={(e) => e.key === 'Enter' && addManualIOC()}
            />
          </div>
          {#if detectedType}
            <div class="text-center mt-1">
              <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-primary/10 text-primary">
                <ScanSearch class="w-3 h-3" />
                Detected: {iocTypeDisplayNames[detectedType as keyof typeof iocTypeDisplayNames] || detectedType}
              </span>
            </div>
          {:else if smartIOCInput.trim()}
            <div class="text-center mt-1">
              <span class="text-xs text-muted-foreground">Type an IOC to see auto-detection</span>
            </div>
          {/if}
        </div>
      </div>
    {:else if !isLoadingPersistence && scanResults && scanResults.totalIOCs > 0}
      <!-- Scan Results -->
      <div class="space-y-4">
        <!-- Header with Actions -->
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <h4 class="text-sm font-semibold">IOCs Found:</h4>
            <span class="inline-flex items-center rounded-full bg-primary px-2.5 py-0.5 text-xs font-semibold text-primary-foreground">
              {scanResults.totalIOCs}
            </span>
          </div>
          
          <div class="flex items-center gap-2">
            <!-- Copy All Button -->
            <Button.Root 
              class="rounded-full border border-input bg-background shadow-mini hover:bg-accent hover:text-accent-foreground inline-flex h-8 items-center justify-center px-3 text-xs font-medium active:scale-[0.98] active:transition-all"
              onclick={copyAllIOCs}
              disabled={scanResults.totalIOCs === 0}
            >
              Copy All
            </Button.Root>
          </div>
        </div>

        <!-- Compact Smart IOC Input -->
        <div class="border-t pt-4">
          <div class="mb-2">
            <input
              type="text"
              bind:value={smartIOCInput}
              placeholder="Add IOC manually (press Enter to add)"
              class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              onkeydown={(e) => e.key === 'Enter' && addManualIOC()}
            />
          </div>
          {#if detectedType}
            <div class="text-center mt-2">
              <span class="inline-flex items-center gap-2 px-2 py-1 rounded text-xs font-medium bg-primary/10 text-primary">
                <ScanSearch class="w-3 h-3" />
                Detected: {iocTypeDisplayNames[detectedType as keyof typeof iocTypeDisplayNames] || detectedType}
              </span>
            </div>
          {/if}
        </div>

        <!-- IOC Types Accordion -->
        {#if scanResults.totalIOCs > 0}
          <Accordion.Root type="single" class="divide-y divide-gray-300">
            <!-- URLs -->
            {#if scanResults.urls && scanResults.urls.length > 0}
              <Accordion.Item value="urls" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">URLs</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.urls.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('URLs', scanResults.urls); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.urls as url}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono break-all flex-1 mr-2">{url}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(url)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('urls', url)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- IP Addresses -->
            {#if scanResults.ips.length > 0}
              <Accordion.Item value="ips" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">IP Addresses</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.ips.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('IP Addresses', scanResults.ips); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.ips as ip}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono flex-1 mr-2">{ip}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(ip)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('ips', ip)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- Domains -->
            {#if scanResults.domains.length > 0}
              <Accordion.Item value="domains" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">Domains</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.domains.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('Domains', scanResults.domains); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.domains as domain}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono flex-1 mr-2">{domain}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(domain)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('domains', domain)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- Files -->
            {#if scanResults.files.length > 0}
              <Accordion.Item value="files" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">Files</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.files.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('Files', scanResults.files); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.files as file}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono break-all flex-1 mr-2">{file}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(file)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('files', file)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- Email Addresses -->
            {#if scanResults.emails.length > 0}
              <Accordion.Item value="emails" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">Email Addresses</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.emails.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('Email Addresses', scanResults.emails); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.emails as email}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono flex-1 mr-2">{email}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(email)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('emails', email)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- MD5 Hashes -->
            {#if scanResults.md5Hashes.length > 0}
              <Accordion.Item value="md5" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">MD5 Hashes</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.md5Hashes.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('MD5 Hashes', scanResults.md5Hashes); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.md5Hashes as hash}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono break-all flex-1 mr-2">{hash}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(hash)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('md5Hashes', hash)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- SHA1 Hashes -->
            {#if scanResults.sha1Hashes.length > 0}
              <Accordion.Item value="sha1" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">SHA1 Hashes</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.sha1Hashes.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('SHA1 Hashes', scanResults.sha1Hashes); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.sha1Hashes as hash}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono break-all flex-1 mr-2">{hash}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(hash)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('sha1Hashes', hash)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}

            <!-- SHA256 Hashes -->
            {#if scanResults.sha256Hashes.length > 0}
              <Accordion.Item value="sha256" class="border-0 group">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                    <div class="flex items-center gap-2 flex-1 min-w-0">
                      <div class="flex-1 min-w-0">
                        <h5 class="font-medium text-sm">SHA256 Hashes</h5>
                      </div>
                      <span class="inline-flex items-center justify-center rounded-full bg-white border text-black text-xs font-medium px-2 py-1 shrink-0">
                        {scanResults.sha256Hashes.length}
                      </span>
                      <Button.Root 
                        class="h-6 w-6 p-0 rounded hover:bg-background ml-2 shrink-0"
                        onclick={(e: Event) => { e.stopPropagation(); scanResults && copyIOCTypeToClipboard('SHA256 Hashes', scanResults.sha256Hashes); }}
                      >
                        <Copy class="w-3 h-3" />
                      </Button.Root>
                    </div>
                    <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                      <span class="transition-transform duration-200">▼</span>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                <Accordion.Content class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs">
                  <div class="pb-3 max-h-48 overflow-y-auto">
                    <div class="space-y-1 pt-1">
                      {#each scanResults.sha256Hashes as hash}
                        <div class="flex items-center gap-2 p-2 rounded bg-muted/50">
                          <span class="text-xs font-mono break-all flex-1 mr-2">{hash}</span>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => copyToClipboard(hash)}
                          >
                            <Copy class="w-2.5 h-2.5" />
                          </Button.Root>
                          <Button.Root 
                            class="h-5 w-5 p-0 rounded hover:bg-background shrink-0"
                            onclick={() => deleteIOC('sha256Hashes', hash)}
                          >
                            <Trash2 class="w-2.5 h-2.5" />
                          </Button.Root>
                        </div>
                      {/each}
                    </div>
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/if}
          </Accordion.Root>
        {:else}
          <!-- No IOCs Found -->
          <div class="text-center py-8">
            <ScanSearch class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p class="text-sm text-muted-foreground mb-2">No IOCs found on this page</p>
            <p class="text-xs text-muted-foreground">
              The page may not contain any indicators of compromise, or they may be in a format not detected by the scanner.
            </p>
          </div>
        {/if}

        <!-- Actions -->
        <div class="flex items-center justify-center gap-2 pt-4 border-t">
          <Button.Root 
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
            onclick={scanAgain}
            disabled={isScanning}
          >
            {#if isScanning}
              Scanning...
            {:else}
              Scan Again
            {/if}
          </Button.Root>
          
          <Button.Root 
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
            onclick={navigateToThreatHunt}
            title="Open threat hunting interface with discovered IOCs"
          >
            Hunt
          </Button.Root>
          
          <Button.Root 
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
            onclick={resetScan}
          >
            Clear Results
          </Button.Root>
        </div>
      </div>
    {:else if !isLoadingPersistence && showResults && (!scanResults || scanResults.totalIOCs === 0)}
      <!-- No results state -->
      <div class="text-center py-8">
        <ScanSearch class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <h4 class="text-lg font-medium mb-2">No IOCs Found</h4>
        <p class="text-sm text-muted-foreground mb-6">
          The scan completed but no indicators of compromise were detected
        </p>
        <Button.Root 
          onclick={resetScan}
          class="bg-black text-white hover:bg-gray-800 focus:bg-gray-800"
        >
          Scan Again
        </Button.Root>
      </div>
    {/if}
  </div>
</div>
<!--
  ThreatHunt Module
  KQL template selection and execution interface for threat hunting
-->

<script lang="ts">
  import { onMount } from 'svelte';
  import { Button, Accordion } from 'bits-ui';
  import { AlertCircle, Shield, Target } from 'lucide-svelte';
  import { logger } from '../audit-logger.js';
  import browser from 'webextension-polyfill';
  import { getDefaultSettings, mergeWithDefaults, type SettingsSchema, type IOCTemplateCollection } from '../default-settings.js';
  import type { IOCResults } from '../ioc-scanner.js';
  // Import pako for gzip compression (no workers needed)
  import * as pako from 'pako';

  // Props - IOCs can be passed in from IOC Management page
  let { 
    isAuthenticated = false,
    initialIOCs = null 
  }: { 
    isAuthenticated?: boolean;
    initialIOCs?: any;
  } = $props();

  // State management
  let error = $state('');
  let settings: SettingsSchema | null = $state(null);
  let settingsLoaded = $state(false);
  let isExecuting = $state(false);
  let isLoadingPersistence = $state(true);

  // Storage key for persistence
  const THREAT_HUNT_KEY = 'threatHunt_data';

  // IOCs from external source (read-only)
  let availableIOCs = $state({
    urls: [] as string[],
    ips: [] as string[],
    domains: [] as string[],
    sha256Hashes: [] as string[],
    sha1Hashes: [] as string[],
    md5Hashes: [] as string[],
    emails: [] as string[],
    files: [] as string[]
  });

  // Template selection state - tracks which templates are selected for each IOC type
  let selectedTemplates = $state<Record<keyof IOCTemplateCollection, Set<string>>>({
    urls: new Set<string>(),
    ips: new Set<string>(),
    domains: new Set<string>(),
    sha256Hashes: new Set<string>(),
    sha1Hashes: new Set<string>(),
    md5Hashes: new Set<string>(),
    emails: new Set<string>(),
    files: new Set<string>()
  });

  // IOC type display names
  const iocTypeDisplayNames = {
    domains: 'Domains',
    ips: 'IP Addresses', 
    urls: 'URLs',
    sha256Hashes: 'SHA256 Hashes',
    sha1Hashes: 'SHA1 Hashes',
    md5Hashes: 'MD5 Hashes',
    emails: 'Email Addresses',
    files: 'Files'
  };

  // Auto-load IOCs from external source when provided (only once on mount)
  let initialIOCsProcessed = false;
  $effect(() => {
    if (initialIOCs && !initialIOCsProcessed) {
      availableIOCs = { ...initialIOCs };
      initialIOCsProcessed = true;
      logger.info('ThreatHunt loaded external IOCs:', availableIOCs);
    }
  });

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

  // Persistence functions
  async function loadPersistedData() {
    try {
      // Load both threat hunt template selections AND IOC data if no initialIOCs provided
      const keys = [THREAT_HUNT_KEY];
      if (!initialIOCs) {
        keys.push('scanWebsite_results'); // IOC Management storage key
      }
      
      const result = await browser.storage.local.get(keys);
      
      // Load template selections
      if (result[THREAT_HUNT_KEY]) {
        const persistedData = result[THREAT_HUNT_KEY] as {
          selectedTemplates: Record<keyof IOCTemplateCollection, string[]>;
        };
        
        // Restore selectedTemplates from arrays back to Sets
        if (persistedData.selectedTemplates) {
          Object.entries(persistedData.selectedTemplates).forEach(([type, templates]) => {
            const typedType = type as keyof IOCTemplateCollection;
            if (Array.isArray(templates)) {
              selectedTemplates[typedType] = new Set(templates);
            }
          });
        }
        
        logger.debug('Loaded persisted threat hunt template selections', { 
          templateCounts: Object.fromEntries(
            Object.entries(selectedTemplates).map(([type, set]) => [type, set.size])
          )
        });
      }
      
      // Load IOC data if no initialIOCs were provided
      if (!initialIOCs && result['scanWebsite_results']) {
        const loadedResults = result['scanWebsite_results'] as IOCResults;
        
        // Helper function to convert object-with-numeric-keys to array (same as IOC Management)
        const objectToArray = (obj: any): string[] => {
          if (Array.isArray(obj)) return obj;
          if (obj && typeof obj === 'object') {
            // Convert object with numeric keys to array
            const keys = Object.keys(obj).map(k => parseInt(k)).filter(k => !isNaN(k)).sort((a, b) => a - b);
            return keys.map(k => obj[k.toString()]).filter(item => typeof item === 'string');
          }
          return [];
        };
        
        // Load IOCs from persisted scan results
        if (loadedResults) {
          availableIOCs = {
            urls: objectToArray(loadedResults.urls),
            ips: objectToArray(loadedResults.ips),
            domains: objectToArray(loadedResults.domains),
            sha256Hashes: objectToArray(loadedResults.sha256Hashes),
            sha1Hashes: objectToArray(loadedResults.sha1Hashes),
            md5Hashes: objectToArray(loadedResults.md5Hashes),
            emails: objectToArray(loadedResults.emails),
            files: objectToArray(loadedResults.files)
          };
          
          const totalIOCs = Object.values(availableIOCs).reduce((total, iocs) => total + iocs.length, 0);
          
          if (totalIOCs > 0) {
            logger.debug('Loaded persisted IOCs from IOC Management', { 
              totalIOCs,
              iocCounts: Object.fromEntries(
                Object.entries(availableIOCs).map(([type, iocs]) => [type, iocs.length])
              )
            });
          }
        }
      }
    } catch (err) {
      logger.error('Failed to load persisted threat hunt data', { error: err instanceof Error ? err.message : 'Unknown error' });
    } finally {
      isLoadingPersistence = false;
    }
  }

  async function savePersistedData() {
    try {
      // Convert Sets back to arrays for storage
      const dataToStore = {
        selectedTemplates: Object.fromEntries(
          Object.entries(selectedTemplates).map(([type, set]) => [type, Array.from(set)])
        )
      };
      
      await browser.storage.local.set({
        [THREAT_HUNT_KEY]: dataToStore
      });
      
      logger.debug('Saved threat hunt template selections to persistence', { 
        totalSelections: getTotalTemplateCount() 
      });
    } catch (err) {
      logger.error('Failed to save threat hunt data', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  async function clearPersistedData() {
    try {
      await browser.storage.local.remove(THREAT_HUNT_KEY);
      logger.debug('Cleared persisted threat hunt data');
    } catch (err) {
      logger.error('Failed to clear persisted threat hunt data', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  // Template selection functions
  function toggleTemplate(type: keyof IOCTemplateCollection, templateId: string) {
    if (selectedTemplates[type].has(templateId)) {
      selectedTemplates[type].delete(templateId);
    } else {
      selectedTemplates[type].add(templateId);
    }
    selectedTemplates = { ...selectedTemplates }; // Trigger reactivity
    
    // Auto-save after template selection change
    savePersistedData();
    
    logger.debug('Toggled template selection', { type, templateId, isSelected: selectedTemplates[type].has(templateId) });
  }

  function selectAllTemplatesForType(type: keyof IOCTemplateCollection) {
    if (!settings) return;
    
    const templates = settings.kql.templates[type];
    templates.forEach(template => {
      selectedTemplates[type].add(template.id);
    });
    selectedTemplates = { ...selectedTemplates }; // Trigger reactivity
    
    // Auto-save after selection change
    savePersistedData();
    
    logger.debug('Selected all templates for type', { type, count: templates.length });
  }

  function clearAllTemplatesForType(type: keyof IOCTemplateCollection) {
    selectedTemplates[type].clear();
    selectedTemplates = { ...selectedTemplates }; // Trigger reactivity
    
    // Auto-save after clearing
    savePersistedData();
    
    logger.debug('Cleared all templates for type', { type });
  }

  function clearAllTemplates() {
    Object.keys(selectedTemplates).forEach(type => {
      selectedTemplates[type as keyof IOCTemplateCollection].clear();
    });
    selectedTemplates = { ...selectedTemplates }; // Trigger reactivity
    
    // Auto-save after clearing and also clear persisted data
    clearPersistedData();
    
    logger.debug('Cleared all template selections');
  }

  function getTotalTemplateCount(): number {
    return Object.values(selectedTemplates).reduce((total, set) => total + set.size, 0);
  }

  function getSelectedTemplatesForType(type: keyof IOCTemplateCollection): string[] {
    return Array.from(selectedTemplates[type]);
  }

  function generateKQLQuery(): string {
    if (!settings) {
      return "// Settings not loaded\nDeviceNetworkEvents | limit 10";
    }

    const kqlParts: string[] = [];

    Object.entries(selectedTemplates).forEach(([type, templateIds]) => {
      if (templateIds.size > 0) {
        const typedType = type as keyof IOCTemplateCollection;
        const typeIOCs = availableIOCs[typedType];
        
        if (typeIOCs.length === 0) {
          // Add comment if no IOCs available for this type
          kqlParts.push(`// ${iocTypeDisplayNames[typedType]}: No IOCs available for selected templates`);
          return;
        }
        
        templateIds.forEach(templateId => {
          const template = settings!.kql.templates[typedType].find(t => t.id === templateId);
          
          if (template) {
            // Determine the correct format based on the template syntax
            let iocReplacement: string;
            
            if (template.query.includes('dynamic($PLACEHOLDER$)')) {
              // For dynamic(), use JSON array format
              iocReplacement = `[${typeIOCs.map(ioc => `"${ioc}"`).join(', ')}]`;
            } else if (template.query.includes('has_any($PLACEHOLDER$)')) {
              // For has_any(), use comma-separated values without additional parentheses
              iocReplacement = typeIOCs.map(ioc => `"${ioc}"`).join(', ');
            } else if (template.query.includes('in ($PLACEHOLDER$)')) {
              // For in (), use comma-separated values without additional parentheses
              iocReplacement = typeIOCs.map(ioc => `"${ioc}"`).join(', ');
            } else {
              // Default fallback - use comma-separated values in parentheses
              iocReplacement = `(${typeIOCs.map(ioc => `"${ioc}"`).join(', ')})`;
            }
            
            const kql = template.query.replace(/\$PLACEHOLDER\$/g, iocReplacement);
            kqlParts.push(`// ${iocTypeDisplayNames[typedType]} Hunt using template: ${template.name}`);
            kqlParts.push(kql);
            kqlParts.push('');
          }
        });
      }
    });

    if (kqlParts.length === 0) {
      if (getTotalTemplateCount() === 0) {
        return "// No templates selected\n// Please select KQL templates to generate hunt queries\nDeviceNetworkEvents | limit 10";
      } else {
        return "// Templates selected but no IOCs provided\n// Please provide IOCs through IOC Management first\nDeviceNetworkEvents | limit 10";
      }
    }

    // Handle multiple queries with proper UNION syntax
    const queries = kqlParts.filter(part => !part.startsWith('//') && part.trim() !== '');
    if (queries.length > 1) {
      // First query stays as-is, subsequent queries are wrapped in parentheses
      let unionQuery = queries[0]; // First query without parentheses
      
      // Add union clauses for remaining queries
      for (let i = 1; i < queries.length; i++) {
        if (i === 1) {
          unionQuery += '\n| union (';
        } else {
          unionQuery += '), (';
        }
        
        // Add the query with proper indentation
        const queryLines = queries[i].split('\n');
        unionQuery += '\n    ' + queryLines.join('\n    ');
        unionQuery += '\n';
      }
      
      // Close the final parenthesis
      if (queries.length > 1) {
        unionQuery += ')';
      }
      
      return unionQuery;
    }
    
    return kqlParts.join('\n');
  }

  /**
   * Encode a KQL query using the EXACT format from the working example
   * The working example uses UTF-16 encoding with null bytes between characters
   */
  async function encodeKQLQuery(kqlQuery: string): Promise<string> {
    logger.debug('Encoding KQL query using UTF-16 format', { originalLength: kqlQuery.length });
    
    try {
      // STEP 1: Minimal query cleaning to match working example
      let cleanQuery = kqlQuery
        .replace(/\u2028/g, ' ')    // Remove Unicode Line Separator
        .replace(/\u2029/g, ' ')    // Remove Unicode Paragraph Separator
        .replace(/\r\n/g, '\n')     // Normalize Windows line endings
        .replace(/\r/g, '\n')       // Normalize Mac line endings
        .trim();                    // Remove only leading/trailing whitespace
      
      // STEP 2: Convert to UTF-16-like format with null bytes (like the working example)
      // The working example has null bytes between every character, suggesting UTF-16 little-endian encoding
      const utf16Bytes = new Uint8Array(cleanQuery.length * 2);
      for (let i = 0; i < cleanQuery.length; i++) {
        const charCode = cleanQuery.charCodeAt(i);
        utf16Bytes[i * 2] = charCode & 0xFF;      // Low byte
        utf16Bytes[i * 2 + 1] = (charCode >> 8) & 0xFF; // High byte (usually 0 for ASCII)
      }
      
      // STEP 3: Gzip compression using pako (synchronous, no workers needed)
      const compressedData = pako.gzip(utf16Bytes);
      
      // STEP 4: Convert to Base64 using the working example approach
      let standardBase64: string;
      try {
        // Use proper binary string conversion (safer for large data)
        let binaryString = '';
        for (let i = 0; i < compressedData.length; i++) {
          binaryString += String.fromCharCode(compressedData[i]);
        }
        standardBase64 = btoa(binaryString);
      } catch (err) {
        logger.warn('Primary binary conversion failed, trying alternative method', { error: err instanceof Error ? err.message : 'Unknown error' });
        // Fallback using chunks to avoid call stack limits
        try {
          const chunks: string[] = [];
          const chunkSize = 8192; // Process in smaller chunks
          for (let i = 0; i < compressedData.length; i += chunkSize) {
            const chunk = compressedData.slice(i, i + chunkSize);
            chunks.push(String.fromCharCode(...chunk));
          }
          standardBase64 = btoa(chunks.join(''));
        } catch (err2) {
          logger.error('All binary conversion methods failed', { error: err2 instanceof Error ? err2.message : 'Unknown error' });
          throw new Error('Failed to convert binary data to Base64');
        }
      }
      
      // STEP 5: Convert to URL-safe Base64 (exactly like the working example)
      const urlSafeBase64 = standardBase64
        .replace(/\+/g, '-')    // + becomes -
        .replace(/\//g, '_')    // / becomes _
        .replace(/=+$/, '');    // Remove all trailing = padding
      
      logger.debug('Successfully encoded KQL query with UTF-16 format', { 
        originalLength: kqlQuery.length,
        cleanedLength: cleanQuery.length,
        utf16Length: utf16Bytes.length,
        compressedLength: compressedData.length,
        encodedLength: urlSafeBase64.length,
        isUrlSafe: !urlSafeBase64.includes('+') && !urlSafeBase64.includes('/') && !urlSafeBase64.includes('='),
        startsWithGzipMagic: urlSafeBase64.startsWith('H4sIA')
      });
      
      return urlSafeBase64;
      
    } catch (err) {
      logger.error('Failed to encode KQL query', { error: err instanceof Error ? err.message : 'Unknown error' });
      
      // Fallback: simple encoding
      logger.debug('Using fallback encoding method');
      const fallback = btoa(unescape(encodeURIComponent(kqlQuery)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      return fallback;
    }
  }

  async function copyKQLToClipboard() {
    try {
      const kqlQuery = generateKQLQuery();
      await navigator.clipboard.writeText(kqlQuery);
      logger.debug('Copied KQL query to clipboard', { queryLength: kqlQuery.length });
    } catch (err) {
      logger.warn('Failed to copy KQL to clipboard', { error: err instanceof Error ? err.message : 'Unknown error' });
    }
  }

  async function executeHunt() {
    if (getTotalTemplateCount() === 0) {
      error = 'No templates selected for hunting';
      return;
    }

    // Check if we have any IOCs available
    const totalIOCs = Object.values(availableIOCs).reduce((total, iocs) => total + iocs.length, 0);
    if (totalIOCs === 0) {
      error = 'No IOCs available for hunting. Please use IOC Management to add IOCs first.';
      return;
    }

    isExecuting = true;
    error = '';

    try {
      const kqlQuery = generateKQLQuery();
      const encodedQuery = await encodeKQLQuery(kqlQuery);
      const uriEncodedQuery = encodeURIComponent(encodedQuery);
      
      // Build the hunting URL
      const huntingUrl = `https://security.microsoft.com/hunting?timeRangeId=month&query=${uriEncodedQuery}&runQuery=true&tid=&goHunt=1`;
      
      // Open in new tab
      await browser.tabs.create({
        url: huntingUrl,
        active: true
      });
      
      logger.debug('Executed threat hunt', { 
        selectedTemplates: getTotalTemplateCount(),
        availableIOCs: totalIOCs,
        templateCounts: Object.fromEntries(
          Object.entries(selectedTemplates).map(([type, set]) => [type, set.size])
        ),
        iocCounts: Object.fromEntries(
          Object.entries(availableIOCs).map(([type, iocs]) => [type, iocs.length])
        )
      });
      
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to execute hunt';
      logger.error('Failed to execute hunt', { error: err instanceof Error ? err.message : 'Unknown error' });
    } finally {
      isExecuting = false;
    }
  }

  // Initialize component
  onMount(async () => {
    logger.debug('ThreatHunt component mounted');
    
    // Load settings first
    await loadSettings();
    
    // Load persisted data (templates + IOCs if no initialIOCs)
    await loadPersistedData();
    
    // If initial IOCs were passed in (from IOC Management), override persisted IOCs
    if (initialIOCs) {
      availableIOCs = { ...initialIOCs };
      logger.debug('Loaded IOCs from external source (overriding persisted)', { 
        totalIOCs: Object.values(availableIOCs).reduce((total, iocs) => total + iocs.length, 0),
        iocCounts: Object.fromEntries(
          Object.entries(availableIOCs).map(([type, iocs]) => [type, iocs.length])
        )
      });
    } else {
      // Log what we loaded from persistence
      const totalIOCs = Object.values(availableIOCs).reduce((total, iocs) => total + iocs.length, 0);
      if (totalIOCs > 0) {
        logger.debug('Using persisted IOCs from storage', { 
          totalIOCs,
          iocCounts: Object.fromEntries(
            Object.entries(availableIOCs).map(([type, iocs]) => [type, iocs.length])
          )
        });
      } else {
        logger.debug('No IOCs available (neither from external source nor persistence)');
      }
    }
    
    // Mark loading as complete
    isLoadingPersistence = false;
  });
</script>

<div class="rounded-lg border bg-card text-card-foreground shadow-sm">
  <!-- Header -->
  <div class="p-6 border-b">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-semibold leading-none tracking-tight flex items-center gap-2">
          <Target class="w-5 h-5" />
          KQL Template Selection
        </h3>
        <p class="text-sm text-muted-foreground mt-1">
          Select KQL templates to generate threat hunting queries
        </p>
      </div>
    </div>
  </div>

  <div class="p-6">
    {#if !isAuthenticated}
      <div class="text-center py-8">
        <Shield class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <p class="text-sm text-muted-foreground">
          Authentication required to use threat hunting
        </p>
      </div>
    {:else if !settingsLoaded}
      <div class="text-center py-8">
        <div class="w-8 h-8 mx-auto mb-4 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
        <p class="text-sm text-muted-foreground">
          Loading settings...
        </p>
      </div>
    {:else if isLoadingPersistence}
      <div class="text-center py-8">
        <div class="w-8 h-8 mx-auto mb-4 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
        <p class="text-sm text-muted-foreground">
          Loading threat hunt data...
        </p>
      </div>
    {:else}
      {#if error}
        <div class="rounded-lg border border-destructive bg-destructive/5 p-4 mb-6">
          <div class="flex items-center gap-3">
            <AlertCircle class="w-5 h-5 text-destructive" />
            <div>
              <p class="font-medium text-destructive">Error</p>
              <p class="text-sm text-destructive/80">{error}</p>
            </div>
          </div>
        </div>
      {/if}

      <!-- Only show content if IOCs are available -->
      {#if Object.values(availableIOCs).some(iocs => iocs.length > 0)}

      <!-- Template Selection Accordion -->
      <div class="space-y-4 mb-6">
        <Accordion.Root type="multiple" class="divide-y divide-gray-300">
          {#each Object.entries(iocTypeDisplayNames) as [type, displayName]}
            {@const typedType = type as keyof IOCTemplateCollection}
            {@const templates = settings?.kql?.templates?.[typedType] || []}
            {@const availableCount = availableIOCs[typedType].length}
            {@const selectedCount = selectedTemplates[typedType].size}
            
            {#if availableCount > 0}
              <Accordion.Item value={type} class="border-0">
              <Accordion.Header>
                <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                  <div class="flex items-center gap-2 flex-1 min-w-0">
                    <div class="flex-1 min-w-0">
                      <h5 class="font-medium text-sm">{displayName} Templates</h5>
                      <p class="text-xs text-muted-foreground">
                        {availableCount} {displayName.toLowerCase()} available
                      </p>
                    </div>
                    <span class="inline-flex items-center justify-center rounded-full bg-primary text-primary-foreground text-xs font-medium px-2 py-1 shrink-0">
                      {selectedCount}
                    </span>
                  </div>
                  <div class="shrink-0 ml-2">
                    <span class="transition-transform duration-200">▼</span>
                  </div>
                </Accordion.Trigger>
              </Accordion.Header>
              <Accordion.Content class="pb-4 data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden">
                <div class="space-y-4 pt-4">
                  {#if templates.length > 0}
                    <div class="flex gap-2 mb-3">
                      <Button.Root
                        onclick={() => selectAllTemplatesForType(typedType)}
                        class="text-xs px-2 py-1 h-7 border border-input bg-background hover:bg-accent hover:text-accent-foreground"
                      >
                        Select All
                      </Button.Root>
                      <Button.Root
                        onclick={() => clearAllTemplatesForType(typedType)}
                        class="text-xs px-2 py-1 h-7 border border-input bg-background hover:bg-accent hover:text-accent-foreground"
                      >
                        Clear All
                      </Button.Root>
                    </div>
                    
                    <div class="space-y-2">
                      {#each templates as template}
                        <label class="flex items-start gap-3 p-3 rounded-lg border cursor-pointer hover:bg-muted/50 transition-colors {selectedTemplates[typedType].has(template.id) ? 'bg-primary/5 border-primary' : ''}">
                          <input
                            type="checkbox"
                            checked={selectedTemplates[typedType].has(template.id)}
                            onchange={() => toggleTemplate(typedType, template.id)}
                            class="mt-0.5"
                          />
                          <div class="flex-1 min-w-0">
                            <div class="font-medium text-sm">{template.name}</div>
                            <div class="text-xs text-muted-foreground mt-1">{template.query.substring(0, 100)}...</div>
                            {#if availableCount === 0}
                              <div class="text-xs text-orange-600 mt-1">⚠️ No {displayName.toLowerCase()} available</div>
                            {/if}
                          </div>
                        </label>
                      {/each}
                    </div>
                  {:else}
                    <div class="text-center py-4 text-muted-foreground text-sm">
                      No {displayName.toLowerCase()} templates configured
                    </div>
                  {/if}
                </div>
              </Accordion.Content>
            </Accordion.Item>
            {/if}
          {/each}
        </Accordion.Root>
      </div>

        <!-- Actions -->
        <div class="flex items-center justify-center gap-2 pt-4 border-t">
          <Button.Root
            onclick={copyKQLToClipboard}
            disabled={getTotalTemplateCount() === 0}
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
          >
            Copy KQL
          </Button.Root>
          
          <Button.Root
            onclick={executeHunt}
            disabled={getTotalTemplateCount() === 0 || isExecuting}
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
          >
            {#if isExecuting}
              Executing...
            {:else}
              Hunt
            {/if}
          </Button.Root>
          
          <Button.Root
            onclick={clearAllTemplates}
            disabled={getTotalTemplateCount() === 0}
            class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
          >
            Clear All
          </Button.Root>
        </div>
      {:else}
        <!-- No IOCs available state -->
        <div class="text-center py-8">
          <Target class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <h4 class="text-lg font-medium mb-2">No IOCs Available</h4>
          <p class="text-sm text-muted-foreground mb-6">
            No indicators of compromise are available for threat hunting. Use IOC Management to scan websites or add IOCs manually.
          </p>
        </div>
      {/if}
    {/if}
  </div>
</div>

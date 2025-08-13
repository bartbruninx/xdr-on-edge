<!--
  Modular Security Dashboard
  Clean authentication interface for the security platform
-->

<script lang="ts">
  import { onMount } from 'svelte';
  import { Button, Menubar } from 'bits-ui';
  import { AlertCircle, Shield, Settings } from 'lucide-svelte';
  import browser from 'webextension-polyfill';
  import { msSecurityClient } from '../security-client.js';
  import { logger } from '../audit-logger.js';
  import Options from './Options.svelte';
  import Incidents from './Incidents.svelte';
  import AssignedIncidents from './AssignedIncidents.svelte';
  import IOCManagement from './ioc-management.svelte';
  import ThreatHunt from './ThreatHunt.svelte';

  // State management
  let isAuthenticated = $state(false);
  let isLoading = $state(false);
  let error = $state('');
  let authState = $state<any>(null);
  let currentView = $state<'incidents' | 'assigned' | 'scan' | 'hunt' | 'settings'>('incidents');
  let threatHuntIOCs = $state<any>(null);

  // Functions
  function handleIncidentsNavigation() {
    currentView = 'incidents';
  }

  function handleAssignedIncidentsNavigation() {
    currentView = 'assigned';
  }

  function handleScanNavigation() {
    currentView = 'scan';
  }

  function handleThreatHuntNavigation(iocs = null) {
    threatHuntIOCs = iocs;
    currentView = 'hunt';
  }

  function handleSettings() {
    // Open settings in a new tab instead of navigating within the popup
    browser.runtime.openOptionsPage().catch((error) => {
      // Fallback: try to open with tabs.create
      browser.tabs.create({ 
        url: browser.runtime.getURL('options.html') 
      }).catch((fallbackError) => {
        logger.error('Fallback failed', fallbackError);
        // Final fallback: navigate within popup (original behavior)
        currentView = 'settings';
      });
    });
  }

  async function handleLogin() {
    if (isLoading) return;
    
    isLoading = true;
    error = '';
    
    try {
      // Get stored settings for tenant ID
      let tenantId: string | undefined;
      try {
        const storedSettings = await browser.storage.local.get({ xdr_settings: null });
        if (storedSettings.xdr_settings && (storedSettings.xdr_settings as any)?.oauth?.tenantId) {
          tenantId = (storedSettings.xdr_settings as any).oauth.tenantId;
        }
      } catch (settingsError) {
        logger.debug('No stored settings found, using default tenant');
      }

      // Initiate authentication via security client
      const response = await msSecurityClient.login(tenantId);
      
      if (response.success && response.data) {
        isAuthenticated = response.data.isAuthenticated;
        authState = response.data;
        
        // Trigger initial data hydration for first-time login
        try {
          await browser.runtime.sendMessage({
            type: 'MS_SECURITY_REFRESH_NOW',
            requestId: `initial-hydration-${Date.now()}`,
            timestamp: Date.now(),
            data: {}
          });
        } catch (hydrationError) {
          logger.warn('Failed to trigger initial data hydration', { error: hydrationError instanceof Error ? hydrationError.message : 'Unknown error' });
        }
      } else {
        const errorMsg = msSecurityClient.getErrorMessage(response);
        error = errorMsg;
        logger.error('Authentication failed', { errorMsg });
        isAuthenticated = false;
      }
    } catch (err) {
      error = 'Authentication failed';
      logger.error('Authentication error', err);
      isAuthenticated = false;
    } finally {
      isLoading = false;
    }
  }

  async function checkAuthenticationStatus() {
    try {
      const response = await msSecurityClient.getAuthStatus();
      if (response.success && response.data) {
        isAuthenticated = response.data.isAuthenticated;
        authState = response.data;
      } else {
        isAuthenticated = false;
        authState = null;
      }
    } catch (err) {
      logger.error('Failed to check authentication status', err);
      isAuthenticated = false;
      authState = null;
    }
  }

  onMount(() => {
    // Check authentication status on mount
    checkAuthenticationStatus();
  });
</script>

<div class="container max-w-7xl mx-auto p-6 space-y-6">
  <!-- Header -->
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-3xl font-bold tracking-tight">XDRonEdge</h1>
    </div>
    <div class="flex items-center gap-4">
      {#if !isAuthenticated}
        <span class="inline-flex items-center rounded-full bg-secondary px-2.5 py-0.5 text-xs font-medium text-secondary-foreground">
          <div class="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
          Offline
        </span>
      {:else}
        <span class="inline-flex items-center rounded-full bg-secondary px-2.5 py-0.5 text-xs font-medium text-secondary-foreground">
          <div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
          Online
        </span>
      {/if}
      <Button.Root 
        class="rounded-full shadow-mini hover:bg-black/25 inline-flex items-center justify-center active:scale-[0.98] active:transition-all"
        onclick={handleSettings}
      >
        <Settings class="w-4 h-4" />
      </Button.Root>
    </div>
  </div>

  {#if error}
    <div class="rounded-lg border border-destructive bg-card text-card-foreground shadow-sm p-4">
      <div class="flex items-center gap-3">
        <AlertCircle class="w-5 h-5 text-destructive" />
        <div>
          <p class="font-medium text-destructive">Error</p>
          <p class="text-sm text-destructive/80">{error}</p>
        </div>
      </div>
    </div>
  {/if}

  {#if !isAuthenticated}
    <!-- Authentication Required -->
    <div class="max-w-md mx-auto rounded-lg border bg-card text-card-foreground shadow-sm">
      <div class="p-6 text-center">
        <div class="flex items-center justify-center gap-2 mb-2">
          <Shield class="w-6 h-6" />
          <h3 class="text-lg font-semibold leading-none tracking-tight">Authentication Required</h3>
        </div>
        <p class="text-sm text-muted-foreground mb-6">
          Connect to your security platform to view dashboard data
        </p>
        <Button.Root 
          class="w-full rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
          onclick={handleLogin}
          disabled={isLoading} 
        >
          {#if isLoading}
            <div class="w-4 h-4 mr-2 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent"></div>
          {:else}
            <Shield class="w-4 h-4 mr-2" />
          {/if}
          {isLoading ? 'Connecting...' : 'Connect to Platform'}
        </Button.Root>
      </div>
    </div>
  {:else}
    <!-- Navigation Menubar -->
    <Menubar.Root class="flex h-10 items-center gap-1 rounded-lg bg-card px-2 shadow-sm">
      <Menubar.Menu>
        <Menubar.Trigger class="hover:bg-gray-100 dark:hover:bg-gray-700 data-[state=open]:bg-gray-100 dark:data-[state=open]:bg-gray-700 inline-flex h-8 cursor-default items-center justify-center rounded-sm px-3 text-xs font-medium focus-visible:outline-none">
          Incidents
        </Menubar.Trigger>
        <Menubar.Portal>
          <Menubar.Content class="z-50 min-w-[160px] rounded-md border border-border bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 px-1 py-1.5 shadow-lg" align="start" sideOffset={3}>
            <Menubar.Item 
              class="hover:bg-gray-100 dark:hover:bg-gray-700 focus:bg-gray-100 dark:focus:bg-gray-700 relative flex h-8 cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-xs font-medium outline-none"
              onSelect={handleIncidentsNavigation}
            >
              Stats
            </Menubar.Item>
            <Menubar.Item 
              class="hover:bg-gray-100 dark:hover:bg-gray-700 focus:bg-gray-100 dark:focus:bg-gray-700 relative flex h-8 cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-xs font-medium outline-none"
              onSelect={handleAssignedIncidentsNavigation}
            >
              Assigned
            </Menubar.Item>
          </Menubar.Content>
        </Menubar.Portal>
      </Menubar.Menu>
      <Menubar.Menu>
        <Menubar.Trigger class="hover:bg-gray-100 dark:hover:bg-gray-700 data-[state=open]:bg-gray-100 dark:data-[state=open]:bg-gray-700 inline-flex h-8 cursor-default items-center justify-center rounded-sm px-3 text-xs font-medium focus-visible:outline-none">
          Ops
        </Menubar.Trigger>
        <Menubar.Portal>
          <Menubar.Content class="z-50 min-w-[160px] rounded-md border border-border bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 px-1 py-1.5 shadow-lg" align="start" sideOffset={3}>
            <Menubar.Item 
              class="hover:bg-gray-100 dark:hover:bg-gray-700 focus:bg-gray-100 dark:focus:bg-gray-700 relative flex h-8 cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-xs font-medium outline-none"
              onSelect={handleScanNavigation}
            >
              IoC
            </Menubar.Item>
            <Menubar.Item 
              class="hover:bg-gray-100 dark:hover:bg-gray-700 focus:bg-gray-100 dark:focus:bg-gray-700 relative flex h-8 cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-xs font-medium outline-none"
              onSelect={() => handleThreatHuntNavigation()}
            >
              Hunt
            </Menubar.Item>
          </Menubar.Content>
        </Menubar.Portal>
      </Menubar.Menu>
    </Menubar.Root>

    <!-- Modular Components -->
    <div class="space-y-6">
      {#if currentView === 'incidents'}
        <Incidents {isAuthenticated} />
      {:else if currentView === 'assigned'}
        <AssignedIncidents {isAuthenticated} />
      {:else if currentView === 'scan'}
        <IOCManagement {isAuthenticated} onNavigateToHunt={handleThreatHuntNavigation} />
      {:else if currentView === 'hunt'}
        <ThreatHunt {isAuthenticated} initialIOCs={threatHuntIOCs} />
      {:else if currentView === 'settings'}
        <Options />
      {/if}
    </div>
  {/if}
</div>

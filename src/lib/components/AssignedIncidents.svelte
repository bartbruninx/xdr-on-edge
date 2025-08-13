<!--
  Assigned Incidents Module
  Displays detailed view of incidents assigned to the current user
  Uses same UX design elements as the main incidents page
-->

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { Button, Accordion } from 'bits-ui';
  import { AlertCircle, RefreshCw, Activity, User, Clock, Shield, ExternalLink } from 'lucide-svelte';
  import { msSecurityClient } from '../security-client.js';
  import { getStorageManager } from '../storage-manager.js';
  import { logger } from '../audit-logger.js';
  import browser from 'webextension-polyfill';
  import type { IncidentDashboardData, SecurityIncident } from '../../types/security.d.ts';

  // Props
  let { isAuthenticated = false }: { isAuthenticated?: boolean } = $props();

  // State management
  let assignedIncidents = $state<SecurityIncident[]>([]);
  let isLoading = $state(false);
  let isRefreshing = $state(false);
  let error = $state('');
  let lastUpdated = $state<Date | null>(null);
  let currentUserEmail = $state<string>('');
  let autoRefreshInterval = $state<ReturnType<typeof setInterval> | null>(null);
  let settings = $state<any>(null);
  let hasLoadedOnce = $state(false); // Track if we've loaded data at least once
  let cacheExpiredMinutes = 15; // Cache expiry time in minutes

  const storageManager = getStorageManager();

  // Clear cache when authentication state changes
  $effect(() => {
    if (!isAuthenticated) {
      // Clear cache and data when user is not authenticated
      clearAssignedIncidentsCache();
      assignedIncidents = [];
      lastUpdated = null;
      currentUserEmail = '';
      error = '';
      hasLoadedOnce = false;
    }
  });

  // Functions
  async function loadSettings() {
    try {
      const result = await browser.storage.local.get({ xdr_settings: null });
      if (result.xdr_settings) {
        settings = result.xdr_settings;
        // Set up auto-refresh after settings are loaded
        setupAutoRefresh();
      } else {
        settings = null;
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async function loadAssignedIncidentsFromStorage() {
    try {
      // Try to load from cache first (with configurable TTL)
      const cachedData = await storageManager.getCache<{
        incidents: SecurityIncident[];
        lastUpdated: string;
        userEmail: string;
      }>('assigned_incidents');
      
      if (cachedData) {
        logger.debug('Loading assigned incidents from cache');
        assignedIncidents = cachedData.incidents || [];
        lastUpdated = cachedData.lastUpdated ? new Date(cachedData.lastUpdated) : null;
        currentUserEmail = cachedData.userEmail || '';
        
        // Mark that we have loaded data
        hasLoadedOnce = true;
        return true; // Successfully loaded from cache
      }
    } catch (error) {
      logger.error('Failed to load assigned incidents from cache:', error);
    }
    
    return false; // No cached data available
  }

  // Check if cached data is still fresh (not expired)
  function isCacheStale(): boolean {
    if (!lastUpdated) return true;
    
    const now = new Date();
    const diffInMinutes = (now.getTime() - lastUpdated.getTime()) / (1000 * 60);
    return diffInMinutes > cacheExpiredMinutes;
  }

  // Check if we should load fresh data
  function shouldLoadFreshData(): boolean {
    // Load fresh data if:
    // 1. It's the first visit (hasLoadedOnce is false)
    // 2. OR cache is stale (older than cacheExpiredMinutes)
    return !hasLoadedOnce || isCacheStale();
  }

  async function saveAssignedIncidentsToStorage() {
    try {
      const dataToCache = {
        incidents: assignedIncidents,
        lastUpdated: lastUpdated?.toISOString(),
        userEmail: currentUserEmail
      };
      
      // Cache for longer duration since we're controlling refresh manually
      await storageManager.setCache('assigned_incidents', dataToCache, 60);
      logger.debug('Assigned incidents saved to cache');
    } catch (error) {
      logger.error('Failed to save assigned incidents to cache:', error);
    }
  }

  async function clearAssignedIncidentsCache() {
    try {
      await storageManager.remove('cache_assigned_incidents');
      logger.debug('Assigned incidents cache cleared');
    } catch (error) {
      logger.error('Failed to clear assigned incidents cache:', error);
    }
  }

  async function refreshAssignedIncidents() {
    if (!isAuthenticated) {
      error = 'Please authenticate first';
      return;
    }

    isLoading = true;
    error = '';

    try {
      // Get current auth state to get user email
      const authResponse = await msSecurityClient.getAuthStatus();
      
      if (!authResponse.success || !authResponse.data?.isAuthenticated) {
        throw new Error('User not authenticated');
      }
      
      const authState = authResponse.data;
      if (!authState?.user?.userPrincipalName) {
        throw new Error('User email not found in auth state');
      }
      
      currentUserEmail = authState.user.userPrincipalName;

      // Use the security client to get incidents assigned to current user
      // This goes through the background script properly
      const incidentsResponse = await msSecurityClient.getIncidents({
        status: ['active', 'inProgress'],
        assignedTo: currentUserEmail,
        $select: 'id,displayName,severity,status,assignedTo,createdDateTime,lastUpdateDateTime,classification,determination,incidentWebUrl',
        $orderby: 'lastUpdateDateTime desc',
        $top: 50
      });

      if (incidentsResponse.success && incidentsResponse.data?.value) {
        assignedIncidents = incidentsResponse.data.value;
        lastUpdated = new Date();
        hasLoadedOnce = true;
        
        // Save to cache after successful fetch
        await saveAssignedIncidentsToStorage();
      } else {
        assignedIncidents = [];
        lastUpdated = new Date();
        hasLoadedOnce = true;
        
        // Save empty result to cache as well
        await saveAssignedIncidentsToStorage();
      }

    } catch (err) {
      console.error('Failed to refresh assigned incidents:', err);
      error = `Failed to refresh: ${err instanceof Error ? err.message : String(err)}`;
    } finally {
      isLoading = false;
    }
  }

  async function manualRefresh() {
    if (!isAuthenticated || isRefreshing) {
      return;
    }

    isRefreshing = true;
    error = '';

    try {
      // Get current auth state to get user email
      const authResponse = await msSecurityClient.getAuthStatus();
      
      if (!authResponse.success || !authResponse.data?.isAuthenticated) {
        throw new Error('User not authenticated');
      }
      
      const authState = authResponse.data;
      if (!authState?.user?.userPrincipalName) {
        throw new Error('User email not found in auth state');
      }
      
      currentUserEmail = authState.user.userPrincipalName;

      // Always fetch fresh data on manual refresh
      const incidentsResponse = await msSecurityClient.getIncidents({
        status: ['active', 'inProgress'],
        assignedTo: currentUserEmail,
        $select: 'id,displayName,severity,status,assignedTo,createdDateTime,lastUpdateDateTime,classification,determination,incidentWebUrl',
        $orderby: 'lastUpdateDateTime desc',
        $top: 50
      });

      if (incidentsResponse.success && incidentsResponse.data?.value) {
        assignedIncidents = incidentsResponse.data.value;
        lastUpdated = new Date();
        hasLoadedOnce = true;
        
        // Save to cache after successful manual refresh
        await saveAssignedIncidentsToStorage();
      } else {
        assignedIncidents = [];
        lastUpdated = new Date();
        hasLoadedOnce = true;
        
        // Save empty result to cache as well
        await saveAssignedIncidentsToStorage();
      }

    } catch (err) {
      console.error('Failed to refresh assigned incidents:', err);
      error = `Failed to refresh: ${err instanceof Error ? err.message : String(err)}`;
    } finally {
      isRefreshing = false;
    }
  }

  function setupAutoRefresh() {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }

    // Disable auto-refresh for assigned incidents since we're using smart caching
    // Users can manually refresh when they want fresh data
    logger.debug('Auto-refresh disabled for assigned incidents - using smart caching instead');
  }

  function formatDate(dateString: string): string {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return 'Invalid date';
    }
  }

  function getSeverityColor(severity: string): string {
    switch (severity?.toLowerCase()) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-orange-500';
      case 'low': return 'bg-yellow-500';
      case 'informational': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  }

  function getStatusColor(status: string): string {
    switch (status?.toLowerCase()) {
      case 'active': return 'text-green-600 bg-green-50';
      case 'resolved': return 'text-gray-600 bg-gray-50';
      case 'inprogress': return 'text-blue-600 bg-blue-50';
      case 'redirected': return 'text-purple-600 bg-purple-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  }

  function getStatusBadge(status: string): string {
    switch (status?.toLowerCase()) {
      case 'active': return 'A';
      case 'inprogress': return 'I-P';
      case 'resolved': return 'R';
      case 'redirected': return 'RD';
      default: return '?';
    }
  }

  function openIncidentUrl(url: string | undefined) {
    if (url) {
      window.open(url, '_blank');
    }
  }

  // Storage listener for real-time updates (disabled for assigned incidents)
  function setupStorageListener() {
    // No longer needed since assigned incidents are fetched on-demand
  }

  // Lifecycle
  onMount(async () => {
    await loadSettings();
    
    // Always try to load from cache first
    const hasCachedData = await loadAssignedIncidentsFromStorage();
    
    // Smart loading logic:
    // 1. If user is authenticated AND we should load fresh data, fetch it
    // 2. Otherwise, rely on cached data
    if (isAuthenticated && shouldLoadFreshData()) {
      logger.debug('Loading fresh assigned incidents data', { 
        firstVisit: !hasLoadedOnce, 
        cacheStale: isCacheStale(),
        lastUpdated: lastUpdated?.toISOString()
      });
      await refreshAssignedIncidents();
    } else if (hasCachedData) {
      logger.debug('Using cached assigned incidents data', { 
        cacheAge: lastUpdated ? Math.round((new Date().getTime() - lastUpdated.getTime()) / (1000 * 60)) : 0,
        incidents: assignedIncidents.length
      });
    }
    
    setupStorageListener();
  });

  onDestroy(() => {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
    }
    // No storage listener to remove since we don't use background polling
  });
</script>

<!-- Component Template -->
<div class="rounded-lg border bg-card text-card-foreground shadow-sm">
  <div class="p-6 border-b">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-semibold leading-none tracking-tight flex items-center gap-2">
          <User class="w-5 h-5" />
          Assigned Incidents
        </h3>
      </div>
      <div class="flex items-center gap-2">
        <Button.Root 
          class="rounded-full shadow-mini hover:bg-black/25 inline-flex items-center justify-center active:scale-[0.98] active:transition-all"
          onclick={manualRefresh}
          disabled={!isAuthenticated || isRefreshing}
        >
          <RefreshCw class={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
        </Button.Root>
      </div>
    </div>
    {#if lastUpdated}
      <p class="text-xs text-muted-foreground mt-2">
        Last updated: {lastUpdated.toLocaleTimeString()}
      </p>
    {/if}
  </div>

  <div class="p-6">
    {#if !isAuthenticated}
      <div class="text-center py-8">
        <User class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <p class="text-sm text-muted-foreground">
          Authentication required to view assigned incidents
        </p>
      </div>
    {:else if error}
      <div class="rounded-lg border border-destructive bg-destructive/5 p-4">
        <div class="flex items-center gap-3">
          <AlertCircle class="w-5 h-5 text-destructive" />
          <div>
            <p class="font-medium text-destructive">Error Loading Assigned Incidents</p>
            <p class="text-sm text-destructive/80">{error}</p>
          </div>
        </div>
      </div>
    {:else if isLoading && assignedIncidents.length === 0}
      <div class="text-center py-8">
        <div class="w-8 h-8 mx-auto animate-spin rounded-full border-2 border-primary border-t-transparent mb-4"></div>
        <p class="text-sm text-muted-foreground">Loading assigned incidents...</p>
      </div>
    {:else if assignedIncidents.length > 0}
      <!-- Assigned Incidents Accordion -->
      <div class="space-y-0">
        <Accordion.Root type="single" class="divide-y divide-gray-300">
          {#each assignedIncidents as incident, index}
            <Accordion.Item value={`incident-${index}`} class="border-0 group">
              <Accordion.Header>
                <Accordion.Trigger class="w-full flex items-center justify-between py-3 text-left hover:bg-muted/50 transition-all [&[data-state=open]>div:last-child>span]:rotate-180">
                  <div class="flex items-center gap-2 flex-1 min-w-0">
                    <div class="w-2 h-2 rounded-full {getSeverityColor(incident.severity)} shrink-0"></div>
                    <div class="flex-1 min-w-0">
                      <h5 class="font-medium text-xs break-words pr-2">{incident.displayName || 'Unnamed Incident'}</h5>
                    </div>
                    <span class="inline-flex items-center justify-center w-6 h-5 rounded-full text-xs font-medium {getStatusColor(incident.status)} shrink-0">
                      {getStatusBadge(incident.status)}
                    </span>
                  </div>
                  <div class="text-xs text-muted-foreground ml-2 shrink-0 hover:bg-muted inline-flex size-6 items-center justify-center rounded transition-all">
                    <span class="transition-transform duration-200">▼</span>
                  </div>
                </Accordion.Trigger>
              </Accordion.Header>
              <Accordion.Content
                class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-xs"
              >
                <div class="pb-3">
                  <div class="space-y-1 pt-1">
                    <!-- Incident Details -->
                    <div class="grid gap-1 text-xs">
                      <div class="flex items-start gap-2">
                        <span class="text-muted-foreground w-20 shrink-0">Severity:</span>
                        <div class="flex items-center gap-1 min-w-0">
                          <div class="w-1 h-1 rounded-full {getSeverityColor(incident.severity)}"></div>
                          <span class="capitalize">{incident.severity}</span>
                        </div>
                      </div>
                      
                      <div class="flex items-start gap-2">
                        <span class="text-muted-foreground w-20 shrink-0">Created:</span>
                        <span class="min-w-0">{formatDate(incident.createdDateTime)}</span>
                      </div>
                      
                      {#if incident.lastUpdateDateTime}
                        <div class="flex items-start gap-2">
                          <span class="text-muted-foreground w-20 shrink-0">Updated:</span>
                          <span class="min-w-0">{formatDate(incident.lastUpdateDateTime)}</span>
                        </div>
                      {/if}
                      
                      {#if incident.classification}
                        <div class="flex items-start gap-2">
                          <span class="text-muted-foreground w-20 shrink-0">Classification:</span>
                          <span class="min-w-0 break-words">{incident.classification}</span>
                        </div>
                      {/if}
                      
                      {#if incident.determination}
                        <div class="flex items-start gap-2">
                          <span class="text-muted-foreground w-20 shrink-0">Determination:</span>
                          <span class="min-w-0 break-words">{incident.determination}</span>
                        </div>
                      {/if}
                    </div>
                    
                    <!-- Action Button -->
                    {#if incident.incidentWebUrl}
                      <div class="pt-1 flex justify-center">
                        <Button.Root 
                          onclick={() => openIncidentUrl(incident.incidentWebUrl)}
                          class="inline-flex items-center gap-1 h-6 px-2 border border-input bg-background hover:bg-accent hover:text-accent-foreground text-xs transition-all"
                        >
                          <ExternalLink class="h-2.5 w-2.5" />
                          Go to Incident
                        </Button.Root>
                      </div>
                    {/if}
                  </div>
                </div>
              </Accordion.Content>
            </Accordion.Item>
          {/each}
        </Accordion.Root>
      </div>
    {:else}
      <!-- No assigned incidents -->
      <div class="text-center py-8">
        <User class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <p class="text-sm text-muted-foreground mb-2">No incidents assigned to you</p>
        <p class="text-xs text-muted-foreground">
          {#if currentUserEmail}
            No active incidents found for {currentUserEmail}
          {:else}
            Data will be loaded when you refresh
          {/if}
        </p>
      </div>
    {/if}
  </div>
</div>

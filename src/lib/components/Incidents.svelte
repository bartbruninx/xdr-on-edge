<!--
  Incidents Module
  Displays incident counts and dashboard data from stored background data
  Background job fetches and stores all data, UI displays stored data
-->

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { Button } from 'bits-ui';
  import { AlertCircle, RefreshCw, Shield, TrendingUp } from 'lucide-svelte';
  import { msSecurityClient } from '../security-client.js';
  import { getStorageManager } from '../storage-manager.js';
  import browser from 'webextension-polyfill';
  import type { IncidentDashboardData } from '../../types/security.d.ts';
  import { logger } from '../audit-logger.js';

  // Props
  let { isAuthenticated = false }: { isAuthenticated?: boolean } = $props();

  // State management - enhanced for dashboard data
  let dashboardData = $state<IncidentDashboardData | null>(null);
  let activeView = $state<'dashboard' | 'assigned' | 'severity'>('dashboard');
  let isLoading = $state(false);
  let isRefreshing = $state(false);
  let error = $state('');
  let lastUpdated = $state<Date | null>(null);
  let currentUserEmail = $state<string>('');
  let autoRefreshInterval = $state<ReturnType<typeof setInterval> | null>(null);
  let settings = $state<any>(null);
  let isInitialLoad = $state(true);
  let storageListener: any = null;

  const storageManager = getStorageManager();

  // Functions
  async function loadSettings() {
    try {
      const result = await browser.storage.local.get({ xdr_settings: null });
      if (result.xdr_settings) {
        settings = result.xdr_settings;
      } else {
        settings = null;
      }
    } catch (error) {
      logger.error('Failed to load settings:', error);
    }
  }

  function setupAutoRefresh() {

    
    // Clear existing interval
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }

    // Remove existing storage listener if any
    if (storageListener) {
      browser.storage.onChanged.removeListener(storageListener);
      storageListener = null;
    }

    // If auto refresh is enabled, the background script will handle it
    // We just need to listen for storage changes for background updates
    if (settings?.ui?.autoRefresh && 
        settings?.ui?.refreshInterval && 
        isAuthenticated && 
        !isLoading) {
      
      // Set up a listener for background updates
      storageListener = (changes: any, area: string) => {
        if (area === 'local' && (changes.incident_dashboard_data || changes.lastKnownCounts)) {
          loadBackgroundData();
        }
      };
      browser.storage.onChanged.addListener(storageListener);
    } else {
      logger.debug('Auto refresh not set up - conditions not met');
    }
  }

  async function loadBackgroundData() {
    // Updated to use the new comprehensive dashboard data
    await loadDashboardData();
  }

  async function loadDashboardData() {
    if (!isAuthenticated) return;
    
    isLoading = true;
    error = '';
    
    try {
      // Load comprehensive dashboard data from storage (set by background script)
      const storedDashboardData = await storageManager.getIncidentDashboardData();
      
      if (storedDashboardData) {
        dashboardData = storedDashboardData;
        lastUpdated = new Date(storedDashboardData.lastUpdated);
      } else {
        // Fallback to legacy storage structure for backward compatibility
        const result = await browser.storage.local.get({ lastKnownCounts: null });
        const lastKnownCounts = result.lastKnownCounts as any;
        
        if (lastKnownCounts) {
          // Create minimal dashboard data from legacy format
          dashboardData = {
            incidentCounts: {
              total: lastKnownCounts.incidents || 0,
              assigned: lastKnownCounts.incidents || 0,
              active: lastKnownCounts.alerts || 0,
              inProgress: 0, // Legacy data doesn't have inProgress
              bySeverity: {
                high: 0,
                medium: 0,
                low: 0,
                informational: 0
              }
            },
            recentIncidents: [], // Empty for legacy fallback
            assignedIncidents: [], // Empty for legacy fallback
            incidentsBySeverity: {
              high: [],
              medium: [],
              low: [],
              informational: []
            },
            lastUpdated: lastKnownCounts.lastUpdated || Date.now()
          };
          
          lastUpdated = new Date(lastKnownCounts.lastUpdated || Date.now());
        } else {
          dashboardData = null;
        }
      }
      
      // Check if data is stale and trigger refresh if needed
      const isDataFresh = await storageManager.isIncidentDashboardDataFresh(5); // 5 minutes
      if (!isDataFresh && settings?.ui?.autoRefresh) {
        // Trigger manual refresh by sending message to background
        browser.runtime.sendMessage({ type: 'MS_SECURITY_REFRESH_NOW' })
          .then(() => logger.debug('Background refresh triggered'))
          .catch((error) => logger.warn('Failed to trigger background refresh:', { error: error instanceof Error ? error.message : String(error) }));
      }
      
    } catch (err) {
      error = `Failed to load incident data: ${err instanceof Error ? err.message : 'Unknown error'}`;
      logger.error('Error loading dashboard data:', err);
    } finally {
      isLoading = false;
      isInitialLoad = false;
    }
  }

  onMount(async () => {
    await loadSettings();
    
    if (isAuthenticated) {
      // Load comprehensive dashboard data from background storage
      await loadDashboardData();
      // Set up auto refresh only after initial load is complete
      setupAutoRefresh();
    }
  });

  onDestroy(() => {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
    }
    if (storageListener) {
      browser.storage.onChanged.removeListener(storageListener);
    }
  });

  // Reactive: load dashboard data when authentication status changes
  $effect(() => {
    if (isAuthenticated && settings) {
      loadDashboardData().then(async () => {
        // If no data was loaded from storage, trigger background refresh
        if (!dashboardData || (!dashboardData.incidentCounts.active && !dashboardData.incidentCounts.inProgress && !dashboardData.incidentCounts.assigned && !lastUpdated)) {

          try {
            await browser.runtime.sendMessage({
              type: 'MS_SECURITY_REFRESH_NOW',
              requestId: `initial-load-${Date.now()}`,
              timestamp: Date.now(),
              data: {}
            });
            // Wait for background to complete, then reload
            setTimeout(() => {
              loadDashboardData();
            }, 2000);
          } catch (error) {
            logger.warn('Failed to trigger initial background refresh:', { error: error instanceof Error ? error.message : String(error) });
          }
        }
        
        // Set up auto refresh after data load attempt
        setupAutoRefresh();
      });
    } else {
      dashboardData = null;
      currentUserEmail = '';
      error = '';
      lastUpdated = null;
      isInitialLoad = true;
      if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
      }
    }
  });
</script>

<div class="rounded-lg border bg-card text-card-foreground shadow-sm">
  <div class="p-6 border-b">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-semibold leading-none tracking-tight flex items-center gap-2">
          <AlertCircle class="w-5 h-5" />
          Security Incidents
        </h3>
      </div>
      <Button.Root 
        class="rounded-full shadow-mini hover:bg-black/25 inline-flex items-center justify-center active:scale-[0.98] active:transition-all"
        onclick={async () => {
          if (isRefreshing) return;
          
          isRefreshing = true;
          error = '';
          
          try {
            logger.debug('Manual refresh triggered');
            // Trigger background refresh
            const response = await browser.runtime.sendMessage({
              type: 'MS_SECURITY_REFRESH_NOW',
              requestId: `manual-refresh-${Date.now()}`,
              timestamp: Date.now(),
              data: {}
            }) as { success: boolean; error?: { message?: string } };
            
            if (response.success) {
              // Wait a moment for the storage to be updated, then reload
              setTimeout(async () => {
                await loadDashboardData();
                isRefreshing = false;
              }, 1500);
            } else {
              error = `Refresh failed: ${response.error?.message || 'Unknown error'}`;
              isRefreshing = false;
            }
          } catch (error) {
            logger.error('Failed to trigger background refresh:', error);
            error = 'Failed to trigger refresh';
            // Fallback to loading from storage
            await loadDashboardData();
            isRefreshing = false;
          }
        }}
        disabled={!isAuthenticated || isRefreshing}
      >
        <RefreshCw class={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
      </Button.Root>
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
        <AlertCircle class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <p class="text-sm text-muted-foreground">
          Authentication required to view incident counts
        </p>
      </div>
    {:else if error}
      <div class="rounded-lg border border-destructive bg-destructive/5 p-4">
        <div class="flex items-center gap-3">
          <AlertCircle class="w-5 h-5 text-destructive" />
          <div>
            <p class="font-medium text-destructive">Error Loading Incident Counts</p>
            <p class="text-sm text-destructive/80">{error}</p>
          </div>
        </div>
      </div>
    {:else if isLoading && !dashboardData}
      <div class="text-center py-8">
        <div class="w-8 h-8 mx-auto animate-spin rounded-full border-2 border-primary border-t-transparent mb-4"></div>
        <p class="text-sm text-muted-foreground">Loading incident counts...</p>
      </div>
    {:else}
      <!-- Dashboard Data Cards -->
      {#if dashboardData}
        <div class="space-y-6">
          <!-- Overview Cards -->
          <div class="grid gap-4 grid-cols-3">
            <!-- Active Incidents Count -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-4 text-center">
                <div class="text-2xl font-bold">{dashboardData.incidentCounts.active}</div>
                <h4 class="text-xs font-medium text-muted-foreground mt-1">Active</h4>
              </div>
            </div>

            <!-- In Progress Incidents Count -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-4 text-center">
                <div class="text-2xl font-bold">{dashboardData.incidentCounts.inProgress}</div>
                <h4 class="text-xs font-medium text-muted-foreground mt-1">In Progress</h4>
              </div>
            </div>

            <!-- Assigned Incidents Count -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-4 text-center">
                <div class="text-2xl font-bold">{dashboardData.incidentCounts.assigned}</div>
                <h4 class="text-xs font-medium text-muted-foreground mt-1">Assigned</h4>
              </div>
            </div>
          </div>

          <!-- Severity Breakdown -->
          <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
            <div class="p-4 border-b">
              <h4 class="text-sm font-medium">Incidents by Severity</h4>
            </div>
            <div class="p-4">
              <div class="grid gap-3 grid-cols-2">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-red-500"></div>
                    <span class="text-sm">High</span>
                  </div>
                  <span class="text-sm font-medium">{dashboardData.incidentCounts.bySeverity.high}</span>
                </div>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-orange-500"></div>
                    <span class="text-sm">Medium</span>
                  </div>
                  <span class="text-sm font-medium">{dashboardData.incidentCounts.bySeverity.medium}</span>
                </div>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                    <span class="text-sm">Low</span>
                  </div>
                  <span class="text-sm font-medium">{dashboardData.incidentCounts.bySeverity.low}</span>
                </div>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-blue-500"></div>
                    <span class="text-sm">Info</span>
                  </div>
                  <span class="text-sm font-medium">{dashboardData.incidentCounts.bySeverity.informational}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      {:else}
        <!-- No data available -->
        <div class="text-center py-8">
          <AlertCircle class="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p class="text-sm text-muted-foreground mb-2">No incident data available</p>
          <p class="text-xs text-muted-foreground">Data will be loaded by the background refresh job</p>
        </div>
      {/if}
    {/if}
  </div>
</div>

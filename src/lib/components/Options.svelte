<!--
  Modern Options Page
  Clean, modern UI built with Bits UI components
-->

<script lang="ts">
  import { onMount } from 'svelte';
  import { Button, Separator, Accordion } from 'bits-ui';
  import { Settings, Shield, Info, Save, RotateCcw, Download, Activity, User, LogIn, LogOut, AlertCircle, Bell, Bug, Code, Plus, Trash2, Edit2 } from 'lucide-svelte';
  import browser from 'webextension-polyfill';
  import { msSecurityClient } from '../security-client.js';
  import { logger } from '../audit-logger.js';
  import { DEFAULT_SETTINGS, getDefaultSettings, mergeWithDefaults, type SettingsSchema, type IOCTemplateCollection, type KQLTemplate, addTemplate, updateTemplate, removeTemplate, generateTemplateId } from '../default-settings.js';

  // State management
  let activeTab = $state('status');
  let isAuthenticated = $state(false);
  let isLoading = $state(false);
  let authState = $state<any>(null);
  let error = $state('');
  let settingsLoaded = $state(false);
  
  // Initialize settings with defaults - will be populated from storage
  let settings = $state<SettingsSchema>(getDefaultSettings());

  // Template management state
  let editingTemplate = $state<{type: keyof IOCTemplateCollection, id: string} | null>(null);
  let newTemplateName = $state('');
  let newTemplateQuery = $state('');

  let extensionInfo = $state({
    id: '',
    version: '',
    manifestVersion: 0,
    redirectUri: ''
  });

  // Template management functions
  function addNewTemplate(iocType: keyof IOCTemplateCollection) {
    if (!newTemplateName.trim() || !newTemplateQuery.trim()) {
      error = 'Template name and query are required';
      return;
    }

    try {
      settings = addTemplate(settings, iocType, {
        name: newTemplateName.trim(),
        query: newTemplateQuery.trim()
      });
      
      // Reset form
      newTemplateName = '';
      newTemplateQuery = '';
      
      // Save settings
      saveSettings();
      
      logger.debug('Added new template', { iocType, name: newTemplateName });
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to add template';
      logger.error('Failed to add template', { error: err });
    }
  }

  function updateExistingTemplate(iocType: keyof IOCTemplateCollection, templateId: string, updates: Partial<Omit<KQLTemplate, 'id'>>) {
    try {
      settings = updateTemplate(settings, iocType, templateId, updates);
      saveSettings();
      logger.debug('Updated template', { iocType, templateId, updates });
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to update template';
      logger.error('Failed to update template', { error: err });
    }
  }

  function deleteTemplate(iocType: keyof IOCTemplateCollection, templateId: string) {
    try {
      settings = removeTemplate(settings, iocType, templateId);
      saveSettings();
      logger.debug('Deleted template', { iocType, templateId });
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to delete template';
      logger.error('Failed to delete template', { error: err });
    }
  }

  function startEditingTemplate(iocType: keyof IOCTemplateCollection, templateId: string) {
    editingTemplate = { type: iocType, id: templateId };
  }

  function stopEditingTemplate() {
    editingTemplate = null;
  }

  // Tab management
  function setActiveTab(tab: string) {
    activeTab = tab;
  }

  // Authentication functions
  async function handleLogin() {
    if (isLoading) return;
    
    isLoading = true;
    error = '';
    
    try {
      const tenantId = settings.oauth.tenantId || undefined;
      const response = await msSecurityClient.login(tenantId);
      
      if (response.success && response.data) {
        isAuthenticated = response.data.isAuthenticated;
        authState = response.data;
        
        // Trigger initial data hydration for first-time login from options page
        try {
          await browser.runtime.sendMessage({
            type: 'MS_SECURITY_REFRESH_NOW',
            requestId: `options-login-hydration-${Date.now()}`,
            timestamp: Date.now(),
            data: {}
          });
        } catch (hydrationError) {
          logger.warn('Failed to trigger initial data hydration from options:', { error: hydrationError instanceof Error ? hydrationError.message : String(hydrationError) });
        }
      } else {
        const errorMsg = msSecurityClient.getErrorMessage(response);
        error = errorMsg;
        logger.error('Authentication failed:', errorMsg);
      }
    } catch (err) {
      error = 'Authentication failed';
      logger.error('Authentication error:', err);
    } finally {
      isLoading = false;
    }
  }

  async function handleLogout() {
    if (isLoading) return;
    
    isLoading = true;
    error = '';
    
    try {
      const response = await msSecurityClient.logout();
      
      if (response.success) {
        isAuthenticated = false;
        authState = null;
      } else {
        const errorMsg = msSecurityClient.getErrorMessage(response);
        error = errorMsg;
        logger.error('Logout failed:', errorMsg);
      }
    } catch (err) {
      error = 'Logout failed';
      logger.error('Logout error:', err);
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
      logger.error('Failed to check authentication status:', err);
      isAuthenticated = false;
      authState = null;
    }
  }

  // Settings functions
  async function saveSettings() {
    try {
      // Create a clean settings object by deep cloning to remove Svelte proxies
      const settingsToSave = JSON.parse(JSON.stringify(mergeWithDefaults(settings)));
      
      await browser.storage.local.set({ xdr_settings: settingsToSave });
      alert('Settings saved successfully!');
      
      // Notify background script of settings update
      try {
        await browser.runtime.sendMessage({
          type: 'SETTINGS_UPDATED',
          requestId: `settings-${Date.now()}`,
          timestamp: Date.now(),
          data: {}
        });
      } catch (msgError) {
        logger.warn('Failed to notify background script:', { error: msgError instanceof Error ? msgError.message : String(msgError) });
      }
      
    } catch (error) {
      logger.error('Error saving settings:', error);
      alert(`Error saving settings: ${error instanceof Error ? error.message : error}`);
    }
  }

  async function loadSettings() {
    try {
      const result = await browser.storage.local.get({ xdr_settings: null });
      
      if (result.xdr_settings) {
        // Merge stored settings with defaults
        settings = mergeWithDefaults(result.xdr_settings);
      } else {
        // No stored settings found, use defaults
        settings = getDefaultSettings();
      }
      
      settingsLoaded = true;
    } catch (error) {
      logger.error('Error loading settings:', error);
      // On error, use defaults
      settings = getDefaultSettings();
      settingsLoaded = true;
    }
  }

  function resetSettings() {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      settings = getDefaultSettings();
    }
  }

  function exportSettings() {
    const dataStr = JSON.stringify(settings, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'xdr-settings.json';
    link.click();
    URL.revokeObjectURL(url);
  }

  // Load settings on mount
  onMount(async () => {
    try {
      // Check authentication status first
      await checkAuthenticationStatus();
      
      // Load settings
      await loadSettings();

      // Get extension info
      const manifest = browser.runtime.getManifest();
      const extensionId = browser.runtime.id;
      const userAgent = navigator.userAgent.toLowerCase();
      
      let browserName = 'chrome';
      if (userAgent.includes('firefox')) {
        browserName = 'firefox';
      } else if (userAgent.includes('edge')) {
        browserName = 'edge';
      }
      
      const redirectUri = browserName === 'firefox' 
        ? browser.identity.getRedirectURL()
        : `https://${extensionId}.chromiumapp.org/`;
      
      extensionInfo.id = extensionId;
      extensionInfo.version = manifest.version;
      extensionInfo.manifestVersion = manifest.manifest_version;
      extensionInfo.redirectUri = redirectUri;
    } catch (error) {
      logger.error('Error during initialization:', error);
    }
  });
</script>

<div class="container max-w-4xl mx-auto p-6 space-y-6">
  <!-- Header -->
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-3xl font-bold tracking-tight">Settings</h1>
      <p class="text-muted-foreground">Configure your security extension</p>
    </div>
    <div class="flex items-center gap-2">
      <Button.Root 
        class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
        onclick={exportSettings}
      >
        <Download class="w-3 h-3 mr-1" />
        Export
      </Button.Root>
      <Button.Root 
        class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
        onclick={resetSettings}
      >
        <RotateCcw class="w-3 h-3 mr-1" />
        Reset
      </Button.Root>
      <Button.Root 
        class="rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
        onclick={saveSettings}
        disabled={!settingsLoaded}
      >
        <Save class="w-3 h-3 mr-1" />
        Save
      </Button.Root>
    </div>
  </div>

  <!-- Tabs -->
  <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
    <div class="flex border-b">
      <button 
        class="flex items-center gap-2 px-6 py-4 text-sm font-medium border-b-2 transition-colors {activeTab === 'status' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
        onclick={() => setActiveTab('status')}
      >
        <Activity class="w-4 h-4" />
        Status
      </button>
      <button 
        class="flex items-center gap-2 px-6 py-4 text-sm font-medium border-b-2 transition-colors {activeTab === 'api' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
        onclick={() => setActiveTab('api')}
      >
        <Settings class="w-4 h-4" />
        API Settings
      </button>
      <button 
        class="flex items-center gap-2 px-6 py-4 text-sm font-medium border-b-2 transition-colors {activeTab === 'notifications' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
        onclick={() => setActiveTab('notifications')}
      >
        <Bell class="w-4 h-4" />
        Notifications
      </button>
      <button 
        class="flex items-center gap-2 px-6 py-4 text-sm font-medium border-b-2 transition-colors {activeTab === 'kql' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
        onclick={() => setActiveTab('kql')}
      >
        <Code class="w-4 h-4" />
        KQL Templates
      </button>
      <button 
        class="flex items-center gap-2 px-6 py-4 text-sm font-medium border-b-2 transition-colors {activeTab === 'info' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
        onclick={() => setActiveTab('info')}
      >
        <Info class="w-4 h-4" />
        Extension Info
      </button>
    </div>

    <div class="p-6">
      {#if !settingsLoaded}
        <!-- Loading State -->
        <div class="flex items-center justify-center py-12">
          <div class="flex items-center gap-3">
            <div class="w-5 h-5 animate-spin rounded-full border-2 border-muted border-t-primary"></div>
            <span class="text-sm text-muted-foreground">Loading settings...</span>
          </div>
        </div>
      {:else if activeTab === 'status'}
        <!-- Status Tab -->
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold mb-4">Connection Status</h3>
            <p class="text-sm text-muted-foreground mb-6">Monitor your Microsoft Security API connection and manage authentication</p>
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

          <div class="space-y-6">
            <!-- Connection Status Card -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="flex items-center justify-between mb-4">
                  <h4 class="text-sm font-semibold">Connection Status</h4>
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
                </div>
                
                <div class="space-y-3">
                  <div class="flex justify-between text-sm">
                    <span class="text-muted-foreground">Authentication</span>
                    <span class="font-medium">{isAuthenticated ? 'Connected' : 'Not Connected'}</span>
                  </div>
                  
                  {#if authState?.scopes && authState.scopes.length > 0}
                    <div class="flex justify-between text-sm">
                      <span class="text-muted-foreground">Permissions</span>
                      <span class="font-medium">{authState.scopes.length} scope(s)</span>
                    </div>
                  {/if}
                </div>

                <Separator.Root class="my-4" />

                <div class="flex gap-2">
                  {#if !isAuthenticated}
                    <Button.Root 
                      class="flex-1 rounded-full bg-black text-white shadow-mini hover:bg-black/95 inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
                      onclick={handleLogin}
                      disabled={isLoading}
                    >
                      {#if isLoading}
                        <div class="w-3 h-3 mr-2 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent"></div>
                      {:else}
                        <LogIn class="w-3 h-3 mr-2" />
                      {/if}
                      {isLoading ? 'Connecting...' : 'Connect'}
                    </Button.Root>
                  {:else}
                    <Button.Root 
                      class="flex-1 rounded-full border border-input bg-background shadow-mini hover:bg-accent hover:text-accent-foreground inline-flex h-8 items-center justify-center px-3 text-[10px] font-semibold active:scale-[0.98] active:transition-all"
                      onclick={handleLogout}
                      disabled={isLoading}
                    >
                      {#if isLoading}
                        <div class="w-3 h-3 mr-2 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent"></div>
                      {:else}
                        <LogOut class="w-3 h-3 mr-2" />
                      {/if}
                      {isLoading ? 'Disconnecting...' : 'Disconnect'}
                    </Button.Root>
                  {/if}
                </div>
              </div>
            </div>

            <!-- User Information Section -->
            {#if isAuthenticated}
              <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
                <div class="p-6">
                  <div class="flex items-center gap-2 mb-4">
                    <User class="w-4 h-4" />
                    <h4 class="text-sm font-semibold">User Information</h4>
                  </div>
                  
                  {#if authState}
                    <div class="space-y-4">
                      <!-- User Details -->
                      <div class="space-y-3">
                        {#if authState.user?.displayName}
                          <div class="flex justify-between text-sm">
                            <span class="text-muted-foreground">Name</span>
                            <span class="font-medium">{authState.user.displayName}</span>
                          </div>
                        {/if}
                        
                        {#if authState.user?.userPrincipalName}
                          <div class="flex justify-between text-sm">
                            <span class="text-muted-foreground">Email</span>
                            <span class="font-medium text-xs">{authState.user.userPrincipalName}</span>
                          </div>
                        {/if}
                        
                        {#if authState.tenantId}
                          <div class="flex justify-between text-sm">
                            <span class="text-muted-foreground">Tenant</span>
                            <span class="font-medium text-xs font-mono">{authState.tenantId.substring(0, 8)}...</span>
                          </div>
                        {/if}
                      </div>

                      <!-- Permissions List -->
                      {#if authState.scopes && authState.scopes.length > 0}
                        <Separator.Root class="my-4" />
                        <div class="space-y-3">
                          <span class="text-sm font-medium">Permissions ({authState.scopes.length})</span>
                          <div class="space-y-2 max-h-48 overflow-y-auto">
                            {#each authState.scopes as scope, index}
                              <div class="flex items-center justify-between p-2 rounded-md bg-muted/50">
                                <div class="flex items-center gap-2">
                                  <div class="w-1.5 h-1.5 rounded-full bg-green-500"></div>
                                  <span class="text-xs font-mono">{scope}</span>
                                </div>
                                <span class="text-xs text-muted-foreground">#{index + 1}</span>
                              </div>
                            {/each}
                          </div>
                        </div>
                      {/if}
                    </div>
                  {:else}
                    <div class="text-center py-8">
                      <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-green-100 flex items-center justify-center">
                        <User class="w-6 h-6 text-green-600" />
                      </div>
                      <p class="text-sm font-medium">Connected</p>
                      <p class="text-xs text-muted-foreground mt-1">User details loading...</p>
                    </div>
                  {/if}
                </div>
              </div>
            {/if}
          </div>
        </div>

      {:else if activeTab === 'api'}
        <!-- API Settings -->
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold mb-4">API Settings</h3>
            <p class="text-sm text-muted-foreground mb-6">Configure API behavior, authentication, and refresh settings</p>
          </div>

          <div class="space-y-6">
            <!-- OAuth Configuration Section -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">OAuth Configuration</h4>
                  <p class="text-sm text-muted-foreground mt-1">Configure your custom tenant authentication settings</p>
                </div>
                
                <div class="space-y-4">
                  <div class="grid gap-6 md:grid-cols-2">
                    <div class="space-y-2">
                      <label for="clientId" class="text-sm font-medium">Client ID</label>
                      <input 
                        id="clientId"
                        type="text" 
                        bind:value={settings.oauth.clientId}
                        class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        placeholder="Enter your application client ID"
                      />
                    </div>

                    <div class="space-y-2">
                      <label for="tenantId" class="text-sm font-medium">Tenant ID</label>
                      <input 
                        id="tenantId"
                        type="text" 
                        bind:value={settings.oauth.tenantId}
                        class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        placeholder="Enter your custom tenant ID"
                      />
                    </div>
                  </div>

                  <div class="rounded-lg border bg-muted/50 p-4">
                    <h5 class="text-sm font-medium mb-2">Configuration Help</h5>
                    <p class="text-xs text-muted-foreground">
                      Enter your Azure AD application's Client ID and your organization's Tenant ID. 
                      These values are required for authentication with your custom tenant.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <!-- API Configuration Section -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">API Configuration</h4>
                  <p class="text-sm text-muted-foreground mt-1">Configure timeout, retry attempts, and data filtering</p>
                </div>
                
                <div class="space-y-4">
                  <div class="grid gap-6 md:grid-cols-3">
                    <div class="space-y-2">
                      <label for="timeout" class="text-sm font-medium">Timeout (seconds)</label>
                      <input 
                        id="timeout"
                        type="number" 
                        bind:value={settings.api.timeout}
                        min="10"
                        max="300"
                        class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      />
                    </div>

                    <div class="space-y-2">
                      <label for="retryAttempts" class="text-sm font-medium">Retry Attempts</label>
                      <input 
                        id="retryAttempts"
                        type="number" 
                        bind:value={settings.api.retryAttempts}
                        min="1"
                        max="10"
                        class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      />
                    </div>

                    <div class="space-y-2">
                      <label for="timeRangeDays" class="text-sm font-medium">Time Range (days)</label>
                      <input 
                        id="timeRangeDays"
                        type="number" 
                        bind:value={settings.api.timeRangeDays}
                        min="1"
                        max="180"
                        class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Auto Refresh Settings -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">Auto Refresh Settings</h4>
                  <p class="text-sm text-muted-foreground mt-1">Configure automatic data refresh intervals</p>
                </div>
                
                <div class="space-y-4">
                  <div class="flex items-center space-x-3">
                    <input 
                      id="autoRefresh"
                      type="checkbox" 
                      bind:checked={settings.ui.autoRefresh}
                      class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                    />
                    <label for="autoRefresh" class="text-sm font-medium">Enable auto refresh</label>
                  </div>

                  {#if settings.ui.autoRefresh}
                    <div class="space-y-2">
                      <label for="refreshInterval" class="text-sm font-medium">Refresh Interval (minutes)</label>
                      <input 
                        id="refreshInterval"
                        type="number" 
                        bind:value={settings.ui.refreshInterval}
                        min="1"
                        max="60"
                        class="flex h-10 w-32 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      />
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </div>

      {:else if activeTab === 'notifications'}
        <!-- Notifications Tab -->
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold mb-4">Notifications</h3>
            <p class="text-sm text-muted-foreground mb-6">Configure browser notifications and alerts</p>
          </div>

          <div class="space-y-6">
            <!-- General Notification Settings -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">General Settings</h4>
                  <p class="text-sm text-muted-foreground mt-1">Configure browser notification preferences</p>
                </div>
                
                <div class="space-y-4">
                  <div class="flex items-center space-x-3">
                    <input 
                      id="notifications"
                      type="checkbox" 
                      bind:checked={settings.ui.notifications}
                      class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                    />
                    <div class="space-y-1">
                      <label for="notifications" class="text-sm font-medium">Enable browser notifications</label>
                      <p class="text-xs text-muted-foreground">Allow the extension to send browser notifications</p>
                    </div>
                  </div>

                  {#if settings.ui.notifications}
                    <div class="ml-7 space-y-4">
                      <div class="flex items-center space-x-3">
                        <input 
                          id="notifyOnNewAssignments"
                          type="checkbox" 
                          bind:checked={settings.ui.notifyOnNewAssignments}
                          class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                        />
                        <div class="space-y-1">
                          <label for="notifyOnNewAssignments" class="text-sm font-medium">New incident assignments</label>
                          <p class="text-xs text-muted-foreground">Get notified when new incidents are assigned to you</p>
                        </div>
                      </div>
                      
                      <div class="flex items-center space-x-3">
                        <input 
                          id="notifyOnHighSeverity"
                          type="checkbox" 
                          bind:checked={settings.ui.notifyOnHighSeverity}
                          class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                        />
                        <div class="space-y-1">
                          <label for="notifyOnHighSeverity" class="text-sm font-medium">High severity incidents</label>
                          <p class="text-xs text-muted-foreground">Get notified when high severity incidents are detected</p>
                        </div>
                      </div>
                      
                      <div class="flex items-center space-x-3">
                        <input 
                          id="notifyOnMediumSeverity"
                          type="checkbox" 
                          bind:checked={settings.ui.notifyOnMediumSeverity}
                          class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                        />
                        <div class="space-y-1">
                          <label for="notifyOnMediumSeverity" class="text-sm font-medium">Medium severity incidents</label>
                          <p class="text-xs text-muted-foreground">Get notified when medium severity incidents are detected</p>
                        </div>
                      </div>
                      
                      <div class="flex items-center space-x-3">
                        <input 
                          id="notifyOnLowSeverity"
                          type="checkbox" 
                          bind:checked={settings.ui.notifyOnLowSeverity}
                          class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                        />
                        <div class="space-y-1">
                          <label for="notifyOnLowSeverity" class="text-sm font-medium">Low severity incidents</label>
                          <p class="text-xs text-muted-foreground">Get notified when low severity incidents are detected</p>
                        </div>
                      </div>
                      
                      <div class="flex items-center space-x-3">
                        <input 
                          id="notifyOnInformationalSeverity"
                          type="checkbox" 
                          bind:checked={settings.ui.notifyOnInformationalSeverity}
                          class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                        />
                        <div class="space-y-1">
                          <label for="notifyOnInformationalSeverity" class="text-sm font-medium">Informational incidents</label>
                          <p class="text-xs text-muted-foreground">Get notified when informational incidents are detected</p>
                        </div>
                      </div>
                    </div>
                  {/if}
                </div>
              </div>
            </div>

            <!-- Notification Preferences -->
            {#if settings.ui.notifications}
              <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
                <div class="p-6">
                  <div class="mb-4">
                    <h4 class="text-sm font-semibold">Notification Preferences</h4>
                    <p class="text-sm text-muted-foreground mt-1">Important information about browser notifications</p>
                  </div>
                  
                  <div class="space-y-4">
                    <p class="text-sm text-muted-foreground">
                      Browser notifications will appear as desktop notifications when the browser is running.
                      Make sure notifications are enabled for this extension in your browser settings.
                    </p>
                    
                    <div class="rounded-lg border border-blue-200 bg-blue-50 p-4">
                      <div class="flex items-start gap-3">
                        <div class="w-5 h-5 rounded-full bg-blue-600 flex items-center justify-center mt-0.5">
                          <div class="w-2 h-2 bg-white rounded-full"></div>
                        </div>
                        <div class="space-y-1">
                          <p class="text-sm font-medium text-blue-900">Browser Permission Required</p>
                          <p class="text-xs text-blue-700">
                            If notifications aren't working, check your browser's notification permissions for this extension.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            {/if}
          </div>
        </div>

      {:else if activeTab === 'kql'}
        <!-- KQL Templates -->
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold mb-4">KQL Templates</h3>
            <p class="text-sm text-muted-foreground mb-6">
              Manage multiple KQL query templates for each IOC type. Use $PLACEHOLDER$ in your queries that will be replaced with actual IOC values when hunting.
            </p>
          </div>

          <!-- IOC Types Accordion -->
          <Accordion.Root type="single" class="space-y-4">
            {#each Object.entries(settings.kql.templates) as [iocType, templates]}
              {@const typedIOCType = iocType as keyof IOCTemplateCollection}
              {@const iocTypeDisplayNames = {
                domains: 'Domains',
                ips: 'IP Addresses', 
                urls: 'URLs',
                sha256Hashes: 'SHA256 Hashes',
                sha1Hashes: 'SHA1 Hashes',
                md5Hashes: 'MD5 Hashes',
                emails: 'Email Addresses',
                files: 'Files'
              }}
              {@const placeholderExamples = {
                domains: '$PLACEHOLDER$',
                ips: '$PLACEHOLDER$',
                urls: '$PLACEHOLDER$', 
                sha256Hashes: '$PLACEHOLDER$',
                sha1Hashes: '$PLACEHOLDER$',
                md5Hashes: '$PLACEHOLDER$',
                emails: '$PLACEHOLDER$',
                files: '$PLACEHOLDER$'
              }}
              
              <Accordion.Item value={iocType} class="rounded-lg border bg-card">
                <Accordion.Header>
                  <Accordion.Trigger class="w-full px-6 py-4 text-left hover:bg-muted/50 transition-colors rounded-t-lg data-[state=open]:rounded-b-none">
                    <div class="flex items-center justify-between">
                      <div class="flex items-center gap-3">
                        <h4 class="text-sm font-semibold">{iocTypeDisplayNames[typedIOCType]}</h4>
                        <span class="inline-flex items-center rounded-full bg-primary/10 text-primary px-2 py-1 text-xs font-medium">
                          {templates.length} template{templates.length !== 1 ? 's' : ''}
                        </span>
                      </div>
                      <div class="text-xs text-muted-foreground">
                        ▼
                      </div>
                    </div>
                  </Accordion.Trigger>
                </Accordion.Header>
                
                <Accordion.Content class="px-6 pb-6 data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden">
                  <div class="space-y-4 pt-4 border-t">
                    <!-- Existing Templates -->
                    {#each templates as template}
                      <div class="rounded-lg border p-4 space-y-3">
                        <div class="flex items-center justify-between">
                          <div class="flex items-center gap-2">
                            <h5 class="text-sm font-medium">{template.name}</h5>
                          </div>
                          <div class="flex items-center gap-1">
                            <Button.Root
                              class="h-8 w-8 p-0"
                              onclick={() => startEditingTemplate(typedIOCType, template.id)}
                            >
                              <Edit2 class="w-3 h-3" />
                            </Button.Root>
                            <Button.Root
                              class="h-8 w-8 p-0 text-destructive hover:text-destructive"
                              onclick={() => deleteTemplate(typedIOCType, template.id)}
                            >
                              <Trash2 class="w-3 h-3" />
                            </Button.Root>
                          </div>
                        </div>
                        
                        {#if editingTemplate?.type === typedIOCType && editingTemplate?.id === template.id}
                          <!-- Edit Mode -->
                          <div class="space-y-3">
                            <div>
                              <label for="template-name-{template.id}" class="text-xs font-medium text-muted-foreground">Template Name</label>
                              <input
                                id="template-name-{template.id}"
                                type="text"
                                bind:value={template.name}
                                onblur={() => updateExistingTemplate(typedIOCType, template.id, { name: template.name })}
                                class="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                              />
                            </div>
                            <div>
                              <label for="template-query-{template.id}" class="text-xs font-medium text-muted-foreground">KQL Query</label>
                              <textarea
                                id="template-query-{template.id}"
                                bind:value={template.query}
                                onblur={() => updateExistingTemplate(typedIOCType, template.id, { query: template.query })}
                                rows="8"
                                class="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                              ></textarea>
                            </div>
                            <div class="flex gap-2">
                              <Button.Root
                                onclick={() => stopEditingTemplate()}
                              >
                                Done
                              </Button.Root>
                            </div>
                          </div>
                        {:else}
                          <!-- View Mode -->
                          <div class="bg-muted/50 rounded p-3">
                            <pre class="text-xs font-mono text-muted-foreground whitespace-pre-wrap">{template.query}</pre>
                          </div>
                        {/if}
                      </div>
                    {/each}
                    
                    <!-- Add New Template -->
                    {#if templates.length < 10}
                      <div class="rounded-lg border border-dashed p-4 space-y-3">
                        <h5 class="text-sm font-medium">Add New Template</h5>
                        <div class="space-y-3">
                          <div>
                            <label for="new-template-name-{iocType}" class="text-xs font-medium text-muted-foreground">Template Name</label>
                            <input
                              id="new-template-name-{iocType}"
                              type="text"
                              bind:value={newTemplateName}
                              placeholder="e.g. Device Hunt, Email Hunt, etc."
                              class="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                            />
                          </div>
                          <div>
                            <label for="new-template-query-{iocType}" class="text-xs font-medium text-muted-foreground">
                              KQL Query (use {placeholderExamples[typedIOCType]} placeholder)
                            </label>
                            <textarea
                              id="new-template-query-{iocType}"
                              bind:value={newTemplateQuery}
                              placeholder={templates[0]?.query || `DeviceNetworkEvents | where SomeField in (${placeholderExamples[typedIOCType]}) | limit 100`}
                              rows="6"
                              class="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                            ></textarea>
                          </div>
                          <Button.Root
                            onclick={() => addNewTemplate(typedIOCType)}
                            disabled={!newTemplateName.trim() || !newTemplateQuery.trim()}
                            class="w-full"
                          >
                            <Plus class="w-4 h-4 mr-2" />
                            Add Template
                          </Button.Root>
                        </div>
                      </div>
                    {:else}
                      <div class="rounded-lg border border-orange-200 bg-orange-50 p-4">
                        <p class="text-sm text-orange-800">
                          Maximum of 10 templates per IOC type reached. Remove a template to add a new one.
                        </p>
                      </div>
                    {/if}
                  </div>
                </Accordion.Content>
              </Accordion.Item>
            {/each}
          </Accordion.Root>

          <!-- Template Usage Guide -->
          <div class="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div class="flex items-start gap-3">
              <Info class="w-5 h-5 text-blue-600 mt-0.5" />
              <div class="space-y-2">
                <p class="text-sm font-medium text-blue-900">Template Usage</p>
                <div class="text-xs text-blue-700 space-y-1">
                  <p>• Use $PLACEHOLDER$ in your queries that will be replaced with actual IOC values</p>
                  <p>• Templates support standard KQL syntax and operators</p>
                  <p>• You can have up to 10 templates per IOC type</p>
                  <p>• At least one template must exist per IOC type</p>
                  <p>• Changes are saved automatically when you modify templates</p>
                </div>
              </div>
            </div>
          </div>
        </div>

      {:else if activeTab === 'info'}
        <!-- Extension Info -->
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold mb-4">Extension Information</h3>
            <p class="text-sm text-muted-foreground mb-6">View extension details and configuration information</p>
          </div>

          <div class="space-y-6">
            <!-- Extension Details -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">Extension Details</h4>
                  <p class="text-sm text-muted-foreground mt-1">Basic information about this browser extension</p>
                </div>
                
                <div class="space-y-4">
                  <div class="space-y-4">
                    <div>
                      <label for="extensionId" class="text-sm font-medium text-muted-foreground">Extension ID</label>
                      <input 
                        id="extensionId"
                        type="text" 
                        value={extensionInfo.id}
                        readonly
                        class="flex h-10 w-full rounded-md border border-input bg-muted px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 mt-1 font-mono"
                      />
                    </div>

                    <div class="grid gap-6 md:grid-cols-2">
                      <div>
                        <label for="extensionVersion" class="text-sm font-medium text-muted-foreground">Version</label>
                        <input 
                          id="extensionVersion"
                          type="text" 
                          value={extensionInfo.version}
                          readonly
                          class="flex h-10 w-full rounded-md border border-input bg-muted px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 mt-1"
                        />
                      </div>

                      <div>
                        <label for="manifestVersion" class="text-sm font-medium text-muted-foreground">Manifest Version</label>
                        <input 
                          id="manifestVersion"
                          type="text" 
                          value="V{extensionInfo.manifestVersion}"
                          readonly
                          class="flex h-10 w-full rounded-md border border-input bg-muted px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 mt-1"
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Configuration -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">OAuth Configuration</h4>
                  <p class="text-sm text-muted-foreground mt-1">Redirect URI for Azure AD application setup</p>
                </div>
                
                <div class="space-y-4">
                  <div>
                    <label for="redirectUri" class="text-sm font-medium text-muted-foreground">Redirect URI</label>
                    <input 
                      id="redirectUri"
                      type="text" 
                      value={extensionInfo.redirectUri}
                      readonly
                      class="flex h-10 w-full rounded-md border border-input bg-muted px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 mt-1"
                    />
                    <p class="text-xs text-muted-foreground mt-1">
                      Use this URI when configuring your Azure AD application redirect URIs
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <!-- Debug Settings -->
            <div class="rounded-lg border bg-card text-card-foreground shadow-sm">
              <div class="p-6">
                <div class="mb-4">
                  <h4 class="text-sm font-semibold">Debug Logging</h4>
                  <p class="text-sm text-muted-foreground mt-1">Control debug output for development and troubleshooting</p>
                </div>
                
                <div class="space-y-4">
                  <div class="flex items-center space-x-3">
                    <input
                      id="debug-mode-toggle"
                      type="checkbox"
                      bind:checked={settings.debug.enabled}
                      class="w-4 h-4 text-primary border-gray-300 rounded focus:ring-primary"
                    />
                    <div class="space-y-0.5">
                      <label for="debug-mode-toggle" class="text-sm font-medium">Enable Debug Mode</label>
                      <p class="text-xs text-muted-foreground">Show detailed logging in browser console</p>
                    </div>
                  </div>

                  {#if settings.debug.enabled}
                    <div class="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
                      <div class="flex items-start gap-3">
                        <div class="w-5 h-5 rounded-full bg-yellow-600 flex items-center justify-center mt-0.5">
                          <div class="w-2 h-2 bg-white rounded-full"></div>
                        </div>
                        <div class="space-y-1">
                          <p class="text-sm font-medium text-yellow-900">Development Mode Warning</p>
                          <p class="text-xs text-yellow-700">
                            Debug mode should be disabled in production for security and performance reasons.
                            Debug logs may contain sensitive information.
                          </p>
                        </div>
                      </div>
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </div>

      {/if}
    </div>
  </div>
</div>

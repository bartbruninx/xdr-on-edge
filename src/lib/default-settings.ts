/**
 * Default Settings Configuration
 * Centralized management of default values for the extension
 */

export interface KQLTemplate {
  id: string;
  name: string;
  query: string;
}

export interface IOCTemplateCollection {
  domains: KQLTemplate[];
  ips: KQLTemplate[];
  urls: KQLTemplate[];
  sha256Hashes: KQLTemplate[];
  sha1Hashes: KQLTemplate[];
  md5Hashes: KQLTemplate[];
  emails: KQLTemplate[];
  files: KQLTemplate[];
}

export interface SettingsSchema {
  oauth: {
    clientId: string;
    tenantId: string;
    customScopes: string[];
  };
  api: {
    timeout: number;
    retryAttempts: number;
    timeRangeDays: number;
  };
  ui: {
    theme: 'light' | 'dark' | 'auto';
    autoRefresh: boolean;
    refreshInterval: number;
    notifications: boolean;
    notifyOnNewAssignments: boolean;
    notifyOnHighSeverity: boolean;
    notifyOnMediumSeverity: boolean;
    notifyOnLowSeverity: boolean;
    notifyOnInformationalSeverity: boolean;
  };
  debug: {
    enabled: boolean;
  };
  kql: {
    templates: IOCTemplateCollection;
  };
}

export const DEFAULT_SETTINGS: SettingsSchema = {
  oauth: {
    clientId: '',
    tenantId: 'common',
    customScopes: []
  },
  api: {
    timeout: 30,
    retryAttempts: 3,
    timeRangeDays: 30
  },
  ui: {
    theme: 'auto',
    autoRefresh: true,
    refreshInterval: 5,
    notifications: true,
    notifyOnNewAssignments: true,
    notifyOnHighSeverity: true,
    notifyOnMediumSeverity: true,
    notifyOnLowSeverity: true,
    notifyOnInformationalSeverity: true
  },
  debug: {
    enabled: false
  },
  kql: {
    templates: {
      domains: [
        {
          id: 'domains-network',
          name: 'Network Events Only',
          query: 'DeviceNetworkEvents | where RemoteUrl has_any($PLACEHOLDER$) | limit 100'
        },
        {
          id: 'domains-comprehensive',
          name: 'Comprehensive Domain Hunt',
          query: `let domainList = dynamic($PLACEHOLDER$);
union
(
    DnsEvents
    | where QueryType has_any(domainList) or Name has_any(domainList)
    | project TimeGenerated, Domain = QueryType, SourceTable = "DnsEvents"
),
(
    IdentityQueryEvents
    | where QueryTarget has_any(domainList)
    | project Timestamp, Domain = QueryTarget, SourceTable = "IdentityQueryEvents"
),
(
    DeviceNetworkEvents
    | where RemoteUrl has_any(domainList)
    | project Timestamp, Domain = RemoteUrl, SourceTable = "DeviceNetworkEvents"
),
(
    DeviceNetworkInfo
    | extend DnsAddresses = parse_json(DnsAddresses), ConnectedNetworks = parse_json(ConnectedNetworks)
    | mv-expand DnsAddresses, ConnectedNetworks
    | where DnsAddresses has_any(domainList) or ConnectedNetworks.Name has_any(domainList)
    | project Timestamp, Domain = coalesce(DnsAddresses, ConnectedNetworks.Name), SourceTable = "DeviceNetworkInfo"
),
(
    EmailUrlInfo
    | where UrlDomain has_any(domainList)
    | project Timestamp, Domain = UrlDomain, SourceTable = "EmailUrlInfo"
),
(
    UrlClickEvents
    | where Url has_any(domainList)
    | project Timestamp, Domain = Url, SourceTable = "UrlClickEvents"
)
| order by TimeGenerated desc`,
        }
      ],
      ips: [
        {
          id: 'ips-network',
          name: 'Network Events',
          query: 'DeviceNetworkEvents | where RemoteIP in ($PLACEHOLDER$) | limit 100'
        }
      ],
      urls: [
        {
          id: 'urls-network',
          name: 'Network Events',
          query: 'DeviceNetworkEvents | where RemoteUrl in ($PLACEHOLDER$) | limit 100'
        }
      ],
      sha256Hashes: [
        {
          id: 'sha256-files',
          name: 'File Events',
          query: 'DeviceFileEvents | where SHA256 in ($PLACEHOLDER$) | limit 100'
        },
        {
          id: 'sha256-comprehensive',
          name: 'Comprehensive File Hunt',
          query: `// Define a list of suspicious SHA256 hashes
let suspiciousHashes = dynamic($PLACEHOLDER$);

// Union all relevant tables to hunt for the hashes
union (
    DeviceFileEvents
    | where SHA256 has_any (suspiciousHashes)
    | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, SourceTable = "DeviceFileEvents"
), (
    EmailAttachmentInfo
    | where SHA256 has_any (suspiciousHashes)
    | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, FileName, SHA256, SourceTable = "EmailAttachmentInfo"
), (
    CloudAppEvents
    | where FileSha256 has_any (suspiciousHashes)
    | project Timestamp, ActivityType, FileName = FileOriginalName, FileSha256, SourceTable = "CloudAppEvents"
)`
        }
      ],
      sha1Hashes: [
        {
          id: 'sha1-files',
          name: 'File Events',
          query: 'DeviceFileEvents | where SHA1 in ($PLACEHOLDER$) | limit 100'
        }
      ],
      md5Hashes: [
        {
          id: 'md5-files',
          name: 'File Events',
          query: 'DeviceFileEvents | where MD5 in ($PLACEHOLDER$) | limit 100'
        }
      ],
      emails: [
        {
          id: 'emails-events',
          name: 'Email Events',
          query: 'EmailEvents | where SenderFromAddress in ($PLACEHOLDER$) or RecipientEmailAddress in ($PLACEHOLDER$) | limit 100'
        }
      ],
      files: [
        {
          id: 'files-events',
          name: 'File Events',
          query: 'DeviceFileEvents | where FileName in ($PLACEHOLDER$) | limit 100'
        }
      ]
    }
  }
};

/**
 * Utility function to create a deep copy of default settings
 */
export function getDefaultSettings(): SettingsSchema {
  return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
}

/**
 * Utility function to merge stored settings with defaults
 * This ensures that missing properties are filled with default values
 */
export function mergeWithDefaults(stored: any): SettingsSchema {
  const defaults = getDefaultSettings();
  
  return {
    oauth: {
      clientId: stored.oauth?.clientId || defaults.oauth.clientId,
      tenantId: stored.oauth?.tenantId || defaults.oauth.tenantId,
      customScopes: stored.oauth?.customScopes || defaults.oauth.customScopes
    },
    api: {
      timeout: stored.api?.timeout || defaults.api.timeout,
      retryAttempts: stored.api?.retryAttempts || defaults.api.retryAttempts,
      timeRangeDays: stored.api?.timeRangeDays || defaults.api.timeRangeDays
    },
    ui: {
      theme: stored.ui?.theme || defaults.ui.theme,
      autoRefresh: stored.ui?.autoRefresh !== undefined ? stored.ui.autoRefresh : defaults.ui.autoRefresh,
      refreshInterval: stored.ui?.refreshInterval || defaults.ui.refreshInterval,
      notifications: stored.ui?.notifications !== undefined ? stored.ui.notifications : defaults.ui.notifications,
      notifyOnNewAssignments: stored.ui?.notifyOnNewAssignments !== undefined ? stored.ui.notifyOnNewAssignments : defaults.ui.notifyOnNewAssignments,
      notifyOnHighSeverity: stored.ui?.notifyOnHighSeverity !== undefined ? stored.ui.notifyOnHighSeverity : defaults.ui.notifyOnHighSeverity,
      notifyOnMediumSeverity: stored.ui?.notifyOnMediumSeverity !== undefined ? stored.ui.notifyOnMediumSeverity : defaults.ui.notifyOnMediumSeverity,
      notifyOnLowSeverity: stored.ui?.notifyOnLowSeverity !== undefined ? stored.ui.notifyOnLowSeverity : defaults.ui.notifyOnLowSeverity,
      notifyOnInformationalSeverity: stored.ui?.notifyOnInformationalSeverity !== undefined ? stored.ui.notifyOnInformationalSeverity : defaults.ui.notifyOnInformationalSeverity
    },
    debug: {
      enabled: stored.debug?.enabled !== undefined ? stored.debug.enabled : defaults.debug.enabled
    },
    kql: {
      templates: {
        domains: stored.kql?.templates?.domains || defaults.kql.templates.domains,
        ips: stored.kql?.templates?.ips || defaults.kql.templates.ips,
        urls: stored.kql?.templates?.urls || defaults.kql.templates.urls,
        sha256Hashes: stored.kql?.templates?.sha256Hashes || defaults.kql.templates.sha256Hashes,
        sha1Hashes: stored.kql?.templates?.sha1Hashes || defaults.kql.templates.sha1Hashes,
        md5Hashes: stored.kql?.templates?.md5Hashes || defaults.kql.templates.md5Hashes,
        emails: stored.kql?.templates?.emails || defaults.kql.templates.emails,
        files: stored.kql?.templates?.files || defaults.kql.templates.files
      }
    }
  };
}

/**
 * Utility functions for template management
 */
export function generateTemplateId(): string {
  return `template-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function getDefaultTemplate(iocType: keyof IOCTemplateCollection): KQLTemplate | undefined {
  const defaults = getDefaultSettings();
  return defaults.kql.templates[iocType][0]; // Return first template as default
}

export function addTemplate(settings: SettingsSchema, iocType: keyof IOCTemplateCollection, template: Omit<KQLTemplate, 'id'>): SettingsSchema {
  const newTemplate: KQLTemplate = {
    ...template,
    id: generateTemplateId()
  };
  
  const templates = [...settings.kql.templates[iocType]];
  
  // Limit to 10 templates per IOC type
  if (templates.length >= 10) {
    throw new Error(`Maximum of 10 templates allowed per IOC type`);
  }
  
  templates.push(newTemplate);
  
  return {
    ...settings,
    kql: {
      ...settings.kql,
      templates: {
        ...settings.kql.templates,
        [iocType]: templates
      }
    }
  };
}

export function updateTemplate(settings: SettingsSchema, iocType: keyof IOCTemplateCollection, templateId: string, updates: Partial<Omit<KQLTemplate, 'id'>>): SettingsSchema {
  const templates = settings.kql.templates[iocType].map(template => 
    template.id === templateId ? { ...template, ...updates } : template
  );
  
  return {
    ...settings,
    kql: {
      ...settings.kql,
      templates: {
        ...settings.kql.templates,
        [iocType]: templates
      }
    }
  };
}

export function removeTemplate(settings: SettingsSchema, iocType: keyof IOCTemplateCollection, templateId: string): SettingsSchema {
  const templates = settings.kql.templates[iocType];
  
  // Prevent removing the last template
  if (templates.length === 1) {
    throw new Error('Cannot remove the last template');
  }
  
  const filteredTemplates = templates.filter(template => template.id !== templateId);
  
  return {
    ...settings,
    kql: {
      ...settings.kql,
      templates: {
        ...settings.kql.templates,
        [iocType]: filteredTemplates
      }
    }
  };
}

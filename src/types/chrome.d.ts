// Import WebExtension polyfill types
import type { Browser } from 'webextension-polyfill';

// Make browser available globally (polyfill handles chrome vs browser namespace)
declare const browser: Browser;

// Legacy Chrome API types for backwards compatibility
declare namespace chrome {
  namespace tabs {
    interface Tab {
      id?: number;
      url?: string;
      title?: string;
      active?: boolean;
      // Add other tab properties as needed
    }

    function query(
      queryInfo: { active?: boolean; currentWindow?: boolean },
      callback: (tabs: Tab[]) => void
    ): void;

    function sendMessage(
      tabId: number,
      message: any,
      callback?: (response: any) => void
    ): void;
  }

  namespace action {
    const onClicked: {
      addListener(callback: (tab: chrome.tabs.Tab) => void): void;
    };
  }

  namespace runtime {
    function sendMessage(
      message: any,
      callback?: (response: any) => void
    ): void;

    const onMessage: {
      addListener(
        callback: (message: any, sender: any, sendResponse: (response?: any) => void) => void | boolean
      ): void;
    };
  }

  namespace storage {
    namespace sync {
      function get(
        keys: string[] | { [key: string]: any },
        callback: (items: { [key: string]: any }) => void
      ): void;

      function set(
        items: { [key: string]: any },
        callback?: () => void
      ): void;
    }
  }
}

// Make chrome available globally for legacy support
declare const chrome: typeof chrome;

# 🛡️ XDR on Edge

A cross-browser extension that brings Microsoft Security capabilities to your browser for incident monitoring, IOC management, and threat hunting.

![Browser Support](https://img.shields.io/badge/Browser-Chrome%20%7C%20Firefox%20%7C%20Edge-blue)
![Manifest](https://img.shields.io/badge/Manifest-V3-green)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue)
![Svelte](https://img.shields.io/badge/Svelte-5.35-orange)

## 🚀 Features

- **🔐 OAuth2 Authentication** - Secure PKCE flow with Microsoft Entra ID
- **📊 Incident Dashboard** - Real-time security incident monitoring
- **🔍 IOC Management** - Website scanning and manual IOC collection
- **🎯 Threat Hunting** - KQL template-based hunting with Microsoft Security
- **🔔 Smart Notifications** - Background monitoring with severity-based alerts

## � Core Modules

### 📊 Dashboard
- Live incident monitoring with auto-refresh
- Severity-based filtering and alerts
- Assignment tracking and status updates

### 🔍 IOC Management
- **Website Scanning**: Extract IOCs (domains, IPs, URLs, hashes, emails) from web pages
- **Manual Entry**: Add IOCs with automatic type detection
- **Smart Storage**: Persistent IOC collection with export capabilities
- **Defanged Support**: Handles defanged indicators (hxxp, [.], etc.)

### 🎯 Threat Hunting
- **KQL Templates**: Pre-configured queries for different IOC types
- **Multi-Query Union**: Automatic query combination with proper syntax
- **Direct Launch**: One-click hunting in Microsoft Security portal
- **Template Management**: Customizable KQL templates in settings

## 🛠️ Technology Stack

- **[Svelte 5](https://svelte.dev/)** with TypeScript - Reactive UI framework
- **[Vite 7](https://vite.dev/)** - Build tool and dev server
- **[TailwindCSS 4](https://tailwindcss.com/)** - Utility-first styling
- **[Bits UI](https://www.bits-ui.com/)** - Headless components
- **[WebExtension Polyfill](https://github.com/mozilla/webextension-polyfill)** - Cross-browser compatibility

## 📋 Prerequisites

- **Node.js** 18+ and **npm** 9+
- **Microsoft Entra ID** application registration  
- **Chrome** 88+, **Firefox** 109+, or **Edge** 88+

## 🚀 Quick Start

### Option A: Download Release (Recommended)
1. Visit [GitHub Releases](https://github.com/bartbruninx/xdr-on-edge/releases)
2. Download the appropriate browser package:
   - `xdr-on-edge-chrome-vX.X.X.zip` for Chrome
   - `xdr-on-edge-firefox-vX.X.X.zip` for Firefox  
   - `xdr-on-edge-edge-vX.X.X.zip` for Edge
3. Extract the zip file
4. Skip to **Install in Browser** section below

### Option B: Build from Source
```bash
git clone <repository-url>
cd xdr-on-edge
npm install
# Build for All browsers
npm run build:all
# OR Build for individual target
npm run build:chrome
npm run build:firefox  
npm run build:edge
```

### 2. Microsoft Entra ID Configuration

#### Create App Registration
1. Go to [Azure Portal](https://portal.azure.com/) → **Entra ID** → **App registrations** → **New registration**
2. Set name: `XDR on Edge` or choose your own
3. Choose Single Tenant account type

#### Add API Permissions
Go to **API permissions** → **Add permission** → **Microsoft Graph** → **Delegated**:
- `offline_access` - Maintain access to data you have given it access to
- `openid` - Sign users in
- `profile` - View users' basic profile
- `User.Read` - Sign in and read user profile
- `SecurityIncident.Read.All` - Read incidents (requires admin consent)

#### Configure Authentication
1. **Authentication** → **Add platform** → **Single-page application**
2. Add redirect URIs (get the actual URI from the extension's Options page > Extension info > OAUTH > Redirect URI). 

#### Get Client ID and Tenant ID
Copy the **Application (client) ID** and **Directory (tenant) ID** from the Overview page.

### 3. Build & Install

#### Install in Browser
- **Chrome**: `chrome://extensions/` → Enable Developer mode → Load unpacked → Select `dist-chrome/` (or extracted release folder)
- **Firefox**: `about:debugging` → This Firefox → Load Temporary Add-on → Select `dist-firefox/manifest.json` (or extracted release folder)
- **Edge**: `edge://extensions/` → Enable Developer mode → Load unpacked → Select `dist-edge/` (or extracted release folder)

### 4. Configure Extension
1. Click extension icon in browser toolbar
2. Go to Settings (gear icon)
3. Enter your **Client ID** and **Tenant ID**
4. Save and return to dashboard
5. Click **Sign In** to authenticate

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Microsoft Graph Security API** for the security data
- **Svelte Team** for the amazing reactive framework
- **Mozilla & Chrome Teams** for WebExtension APIs
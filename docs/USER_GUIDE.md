🌐 **Language / Lingua**: **🇬🇧 English** | [🇮🇹 Italiano](USER_GUIDE.it.md)  
⬅️ [Back to Main README](../README.md) | 🛠️ [Advanced Architecture & Contributor Guide](CONTRIBUTING_AND_ARCHITECTURE.md)

# 👤 Warp IM — Complete Basic User Guide

[![License: PEFL v1.0](https://raw.githubusercontent.com/RubensRainelli/pefl-license-spec/main/badges/pefl-badge-red.svg)](../LICENSE)

Welcome to **Warp IM**, the universal native messenger created by **Rubens Rainelli** under the **Personal and Educational Free License v1.0 (PEFL v1.0)**.  
This step-by-step guide explains how to install Warp IM on your device, approve the PEFL v1.0 license at startup, customize the look & feel (**SuperThemes** and **Light / Dark / OLED** color palettes), manage multiple accounts per protocol, and organize your chats.

---

## 📥 1. Downloading & Installing Warp IM

Download the latest release package for your operating system from the official [**GitHub Releases**](https://github.com/RubensRainelli/warp-im/releases) page.

### 🐧 Linux (Debian / Ubuntu / Mint / Pop!_OS — `.deb`)
1. Download `warp-im_<version>_amd64.deb`.
2. Install it using `apt`:
   ```bash
   sudo apt install ./warp-im_<version>_amd64.deb
   ```
3. Launch **Warp IM** from your application menu or by typing `warp-im` in a terminal.

### 🐧 Linux (Universal Portable — `.AppImage`)
1. Download `Warp_IM-<version>-x86_64.AppImage`.
2. Mark it as executable and run it directly (no root privileges or installation required):
   ```bash
   chmod +x Warp_IM-<version>-x86_64.AppImage
   ./Warp_IM-<version>-x86_64.AppImage
   ```

### 🪟 Windows 10 / 11 (`x86_64`)
1. Download `warp-im-<version>-windows-x86_64.zip` and extract the archive.
2. **Portable Mode**: Double-click `warp-im.exe` directly.
3. **Local User Installation**: Right-click `Install-WarpIM.ps1` and select *Run with PowerShell* to install Warp IM under `%LOCALAPPDATA%\Programs\WarpIM`.

### 🍎 macOS (Apple Silicon `M1/M2/M3/M4` & Intel Universal — `.dmg`)
1. Download `Warp-IM-<version>-macos-universal.dmg`.
2. Double-click the `.dmg` file and drag **Warp IM.app** into your **Applications** folder.
3. Launch **Warp IM** from Launchpad or Spotlight.

### 📱 Android & iOS (Mobile Native)
- **Android 8.0+ (`arm64-v8a` — Signed `.apk`)**: Download [**`warp-im-0.1.0-android-arm64-v8a.apk`**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-android-arm64-v8a.apk) directly from GitHub Releases and tap it on your Android phone to install.
- **iOS (`aarch64-apple-ios`)**: Install via Xcode / TestFlight using the static library bundle `libwarp_app_ios_aarch64.tar.gz`.
- When running on a phone screen (or when clicking the **`📱 Mobile`** button in the top bar on Desktop), Warp IM automatically switches to a single-pane touch navigation stack.

---

## ⚖️ 2. First Launch: Approving the PEFL v1.0 License (Clause 3)

In compliance with **Clause 3** of the **Personal and Educational Free License v1.0 (PEFL v1.0)**:
1. **Foreground License Modal**: When you launch Warp IM for the first time, the full **PEFL v1.0** license modal appears in the foreground.
2. **Language Switcher**: Inside the modal, click **`🇮🇹 Italiano`** or **`🇬🇧 English`** at the top right to read the license in your preferred language.
3. **Explicit Approval**:
   - Click **`✅ Accetto / I Accept PEFL v1.0`** if you are using Warp IM for **personal, domestic, educational, academic, student, or non-profit** purposes (100% free).
   - Click **`❌ Rifiuta ed Esci / Decline & Exit`** if you do not agree or if you are on a corporate/business machine without a commercial license from **Rubens Rainelli** (`rubens@rainelli.it`).
4. **7-Day Memory**: Your approval is saved locally for **7 days**. After 7 days, Warp IM will display the license again for re-confirmation. You can also view the license at any time by clicking the **`⚖️ PEFL v1.0`** badge in the top toolbar.

---

## 🚀 2B. Welcome Screen: Adding a Real Account vs Trying the Interactive Demo Mockup

When you open Warp IM with 0 active accounts configured, it does **not** force fake mockup data by default. Instead, it displays the **Welcome / Onboarding Screen**:
1. **`➕ Add Account (Login / Sign-Up / Bot)`**: Click any of the 8 protocol cards (`Telegram`, `Matrix`, `XMPP`, `Nostr`, `SimpleX`, `IRCv3`, `Stoat`, `Mattermost`) to open its login/registration screen and immediately start chatting.
2. **`🧪 Load Interactive Demo Mockup`**: If you want to explore the UI, the 4 SuperThemes, and multi-account features immediately without credentials, click **`🧪 Carica Mockup Demo Interattivo`**. You can exit Demo Mode and wipe the demo data at any time by clicking **`🧹 Esci dal Mockup`** in the sidebar header or inside **`⚙️ Impostazioni`**.

---

## ⚙️ 3. Settings Section (`☰` / `⚙️ Impostazioni`), Themes & Keyboard Shortcuts

All application settings are organized inside the dedicated **Settings Section (`⚙️ Impostazioni`)**, opened by clicking the **`☰`** menu button at the top left of the sidebar:

### A. Choosing a Structural Layout (`SuperTheme`)
Inside **`⚙️ Impostazioni` → `Layout Strutturale (SuperTheme)`**:
1. **`Telegram`**: Modeled after Telegram Desktop & Mobile, featuring scrollable horizontal folder tabs above the chat list, `48px` circular avatars, online dots, unread pill badges, and rounded message bubbles (left-aligned incoming bubbles with sender avatar, right-aligned outgoing bubbles with `✓✓` ticks).
2. **`WhatsApp`**: Organizes conversations into minimal tabs (`All`, `Unread`, `Groups`) with split incoming/outgoing bubbles.
3. **`Discord`**: Activates a vertical **Server/Workspace Icon Rail** on the far left, a dedicated channel tree sidebar, and compact flat message rows.
4. **`IRC Dense`**: High-density monospace layout with compact `[HH:MM]` timestamps, ideal for IRCv3 and XMPP rooms.

### B. Choosing a Color Theme (`ThemePalette`)
Inside **`⚙️ Impostazioni` → `Palette Colori`**:
- **`☀️ Light`**: High-contrast daylight palette (`#F8FAFC` / `#FFFFFF`).
- **`🌙 Dark`**: Balanced slate dark palette (`#0F172A`).
- **`🖤 OLED`**: True **Pure Black (`#000000`)** background that completely turns off pixels on AMOLED/OLED screens.
- **`Night TG`**: Classic Telegram Night blue palette (`#17212B`).
- **`Discord Dark`**: Ash-grey & blurple palette (`#313338`).
- **`Catppuccin`**: Warm pastel Catppuccin Mocha palette (`#1E1E2E`).

### C. Configurable Send Shortcut (`Enter` vs `Ctrl+Enter` / `Alt+Enter`)
Inside **`⚙️ Impostazioni` → `Comportamento Tastiera e Invio Messaggi`**, choose your preferred keyboard behavior for the multi-line message composer:
- **`Enter` Sends (`Invio` invia)**: Pressing `Enter` sends the message immediately, while `Ctrl+Enter`, `Alt+Enter`, or `Shift+Enter` inserts a new line (`\n`).
- **`Ctrl+Enter / Alt+Enter` Sends (`Ctrl+Invio / Alt+Invio` invia)**: Pressing `Enter` inserts a new line (`\n`), and the message is sent only when you press `Ctrl+Enter` or `Alt+Enter` (or click the `➤` send button).

### D. Resizable Desktop Panes & Horizontal Scroll on Filter Tabs
- **Resizable Layout Columns (`Drag-to-Resize`)**: On Desktop, drag the vertical divider between the sidebar (or channel tree) and the chat viewport to freely resize the column widths.
- **Horizontal Scrolling on Filter Categories & Accounts**: The horizontal chat category/folder bar (`Tutte`, `Non lette`, `Lavoro`, `Gruppi`) and the account bar support **mouse wheel horizontal scrolling**, touch/trackpad flicking, and **`‹` / `›`** scroll buttons.

---

## 👥 4. Multi-Account per Protocol, New Chats & Chat List Isolation Modes

Warp IM allows you to connect **multiple accounts on the same protocol simultaneously** (for example: a personal Telegram account and a Telegram Test DC2 account, or two IRC networks `Libera.Chat` and `OFTC`).

### How to Log In (`🔑 Login`), Register (`✨ Sign-Up`), or Connect a Bot (`🤖 @BotFather`)
1. Click the **`👤+`** button in the sidebar header (or **`➕ Aggiungi Account`** inside `⚙️ Impostazioni`).
2. Select any of the **8 protocols** (`Telegram`, `Matrix`, `XMPP`, `Nostr`, `SimpleX`, `IRCv3`, `Stoat`, `Mattermost`).
3. Choose the desired action using the mode buttons at the top of the modal:
   - **On the 7 open protocols (`Matrix`, `XMPP`, `Nostr`, `SimpleX`, `IRCv3`, `Stoat`, `Mattermost`)**:
     - **`🔑 Login (Existing Account)`**: Sign in with an existing account.
     - **`✨ Sign-Up (Create New Account)`**: Register a brand-new account directly inside Warp IM.
   - **On `Telegram` (User Login or Bot Login Only)**:
     - **`👤 User Login (Phone + OTP)`**: Sign in with your phone number and OTP verification code (+ optional 2FA).
     - **`🤖 Log in as Bot (@BotFather Token)`**: Paste your `@BotFather` token (`123456789:AAH...`) to sign in directly as a Telegram Bot.
4. Clicking **`Conferma / Connetti`** persists the account in your local SQLite database and immediately activates its conversations.

### ➕ Creating a New Chat / Channel & Real-Time Search
- **New Chat / Channel (`➕`)**: Click the **`➕`** button next to the search bar in the sidebar header to start a new direct message, group, or channel on the active account.
- **Instant Chat Search (`🔍 Cerca chat...`)**: Type in the sidebar search box to filter conversations in real time by title, message preview, or account badge.

### ✈️ Telegram Backend Environment Selector (Public Production vs Test DC2)
Inside **`⚙️ Impostazioni`** or inside the **`➕ Add Account` → `Telegram`** panel, you can choose which Telegram MTProto backend to use:
- **`🌐 Public Production Backend (DC1–DC5)`**: Connects your Telegram user or bot account to the official production Data Centers (`149.154.167.50:443`).
- **`🧪 Test Server Backend (Test DC2 — 149.154.167.40:443)`**: Connects your account or bot to the official Telegram Test DC2 sandbox (`149.154.167.40:443`, `use_test_dc = true`).

### Choosing How Your Chat Lists Are Organized (4 Isolation Modes)
Inside **`⚙️ Impostazioni` → `Isolamento Liste Chat`**:
1. **`🌐 Unificata` (Unified Inbox)**: Merges all active accounts into a single chronological chat list with compact account badges (`TG•1`, `MX•1`, `IRC•LIB`).
2. **`🔌 Per Protocollo` (Per Protocol)**: Filters the sidebar to show only accounts belonging to the selected protocol.
3. **`🔒 Per Account` (Strict Per-Account Silo)**: Complete isolation per individual account when clicking its chip in the Account Bar.
4. **`⚖️ Ibrida` (Hybrid Custom Folders)**: Combines unified custom folders with isolated per-account silos.

---

## 🔌 5. Message Actions, Protocols & Accounts

- **Reply (`↩`), React (`👍`, `❤️`), Edit (`✎`), and Delete (`🗑`)**: Every message bubble provides quick action buttons to quote/reply, toggle emoji reactions, edit message text in place, or delete the message.
- **Pin Chats (`📌`)**: Click the **`📌`** icon in the active chat header to pin or unpin a conversation.
- **Enable/Disable Protocols or Accounts**: Inside **`⚙️ Impostazioni`** (or via the Account Bar chips), toggle any protocol or individual account **ON** or **OFF** on the fly.

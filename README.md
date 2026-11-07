🌐 **Language / Lingua**: **🇬🇧 English** | [🇮🇹 Italiano](README.it.md)  
📖 **Documentation**: [👤 User Guide](docs/USER_GUIDE.md) | [🛠️ Technical & Contributor Guide](docs/CONTRIBUTING_AND_ARCHITECTURE.md)

# 🚀 Warp IM — All Your Chats in One Fast Native App

[![License: PEFL v1.0](https://raw.githubusercontent.com/RubensRainelli/pefl-license-spec/main/badges/pefl-badge-red.svg)](LICENSE)
[![Multi-Platform CI](https://github.com/RubensRainelli/warp-im/actions/workflows/ci.yml/badge.svg)](https://github.com/RubensRainelli/warp-im/actions/workflows/ci.yml)
[![Release Packages](https://github.com/RubensRainelli/warp-im/actions/workflows/release.yml/badge.svg)](https://github.com/RubensRainelli/warp-im/releases)

> [!WARNING]
> **🚧 Active Development Notice (Pre-Release `v0.x` — Not Yet Stable)**  
> **Warp IM** is currently in an **advanced stage of active development** and **should not yet be considered a final stable release (`v1.0`)**.  
> You can already download, install, and test the application on Desktop (Windows, Linux, macOS) and explore its multi-protocol, multi-account, and theming features, while mobile builds (Android/iOS) and several live network workflows are being finalized toward the upcoming **`v1.0`** milestone.

---

## 💬 What is Warp IM?

Tired of running half a dozen heavy messaging apps that eat up gigabytes of memory on your computer or phone?  
**Warp IM** is an ultra-lightweight (uses **under 50 MB of RAM**), fast, privacy-respecting native messenger that brings **8 different messaging networks** together into a single clean app.

With **Warp IM**, you are always in control of your experience:
- **Enable only the networks you actually use**, and turn off the rest with a single click.
- **Connect multiple accounts** (personal, school, bots, or community accounts) and choose whether to see everything in a **Unified Inbox** or keep accounts **strictly separated**.
- **Transform the app's look & feel on the fly**: switch instantaneously between **Telegram style**, **WhatsApp style**, **Discord Server Rail style**, or **Compact IRC style**, paired with **Light**, **Dark**, or **Pure Black OLED (`#000000`)** color themes.

---

## 📥 Download Warp IM (All Platforms)

Download the pre-built package for your operating system directly from [**GitHub Releases**](https://github.com/RubensRainelli/warp-im/releases/latest):

| Platform | Package Format | Direct Download Link | Installation Notes |
|----------|----------------|----------------------|--------------------|
| 🪟 **Windows 10 / 11** (`64-bit`) | `.zip` (Portable + Installer) | [**⬇️ Download for Windows (`warp-im-0.1.0-windows-x86_64.zip`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-windows-x86_64.zip) | Extract the `.zip` and run `warp-im.exe` (or run `Install-WarpIM.ps1`) |
| 🐧 **Linux (Ubuntu / Debian / Mint)** | `.deb` Package | [**⬇️ Download `.deb` (`warp-im_0.1.0_amd64.deb`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im_0.1.0_amd64.deb) | Install with `sudo apt install ./warp-im_0.1.0_amd64.deb` |
| 🐧 **Linux (Universal Portable)** | `.AppImage` | [**⬇️ Download `.AppImage` (`Warp_IM-0.1.0-x86_64.AppImage`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/Warp_IM-0.1.0-x86_64.AppImage) | No installation required (`chmod +x` and run) |
| 🍎 **macOS** (`Apple Silicon & Intel`) | `.dmg` Disk Image | [**⬇️ Download for macOS (`Warp-IM-0.1.0-macos-universal.dmg`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/Warp-IM-0.1.0-macos-universal.dmg) | Open the `.dmg` and drag **Warp IM.app** to *Applications* |
| 🤖 **Android 8.0+** (`arm64-v8a` — *Beta*) | Signed `.apk` Package | [**⬇️ Download Android APK (`warp-im-0.1.0-android-arm64-v8a.apk`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-android-arm64-v8a.apk) | Download and tap the `.apk` file on your Android phone *(pre-v1.0 build)* |
| 📱 **iOS** (`aarch64` — *Beta*) | Native Bundle `.tar.gz` | [**⬇️ Download iOS Build (`libwarp_app_ios_aarch64.tar.gz`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/libwarp_app_ios_aarch64.tar.gz) | Xcode / TestFlight static bundle *(pre-v1.0 preview)* |
| 📦 **Linux Source Archive** | `.tar.gz` | [**⬇️ Download Sources (`warp-im-0.1.0-linux-sources.tar.gz`)**](https://github.com/RubensRainelli/warp-im/releases/download/v0.1.0/warp-im-0.1.0-linux-sources.tar.gz) | Complete source archive for manual builds |

👉 **[Browse all releases and SHA-256 checksums on the GitHub Releases page](https://github.com/RubensRainelli/warp-im/releases)**

---

## 🌐 Supported Protocols (Login, Sign-Up & Bot Support)

Warp IM supports **8 messaging protocols**. On every protocol that permits it, you can both **register a brand-new account directly inside Warp IM (`✨ Sign-Up`)** or **log in to an existing account (`🔑 Login`)**:

| Protocol | What You Can Do | Account Login & In-App Sign-Up | Security & Privacy |
|----------|-----------------|--------------------------------|--------------------|
| ✈️ **Telegram** | Direct messages, Groups, Channels & Forum Topics | **🔑 User Login** (Phone + OTP + 2FA)<br>**🤖 Bot Login** (`@BotFather` Token)<br>⚙️ Switch between **Public Production** & **Test DC2 Server**<br>*(Login only: Telegram requires its official mobile app to register a new SIM card)* | MTProto Cloud + Secret Chats |
| 🟩 **Matrix** | 1-on-1 chats, Rooms, Spaces & Threads | **✨ In-App Sign-Up** on any open homeserver<br>**🔑 Login** with an existing account | End-to-End Encrypted (**Olm / Megolm**) |
| 💬 **XMPP (Jabber)** | Direct chats & multi-user group rooms (MUC) | **✨ In-Band Sign-Up** on public XMPP servers<br>**🔑 Login** with your JID address | End-to-End Encrypted (**OMEMO**) |
| 💜 **Nostr** | Private direct messages & decentralized channels | **✨ Instant 1-Click Sign-Up** (generates local cryptographic keys with no central server)<br>**🔑 Login** with `nsec1` private key | **Gift-Wrapped DMs (NIP-17 / NIP-59)** |
| 🛡️ **SimpleX Chat** | Anonymous chats with zero phone numbers or user IDs | **✨ Create Anonymous Profile (Sign-Up)**<br>**🔑 Connect** via QR code or invitation link | **Double Ratchet E2EE** over pairwise queues |
| #️⃣ **IRCv3** | IRC networks & channels with history and reactions | **✨ Register Nickname (NickServ / Ergo Sign-Up)**<br>**🔑 Login** via SASL or Soju/Ergo Bouncer | TLS + SASL Authentication |
| 🦊 **Stoat (ex Revolt)** | Community servers, text channels & threads | **✨ Create New Account (Sign-Up)**<br>**🔑 Login** with email/password or session token | TLS + Granular channel permissions |
| 🏢 **Mattermost** | Study/project teams, public/private channels & threads | **✨ Server Account Sign-Up**<br>**🔑 Login** with credentials, MFA, or Personal Token | TLS + Team workspace controls |

---

## ✨ Key User Features

### 🎨 1. Customize Your Layout & Colors (`SuperThemes` + `Light / Dark / OLED`)
Everyone has a different favorite chat layout. Warp IM lets you change both **how the window is organized** and **which colors it uses** at any time:
- **4 Structural Layouts (`SuperThemes`)**:
  - **Telegram Style**: Horizontal folder tabs at the top, expandable Forum Topics, and rounded chat bubbles.
  - **WhatsApp Style**: Clean, distraction-free category tabs (*All*, *Unread*, *Groups*).
  - **Discord Style**: Left vertical Server/Workspace icon rail + collapsible channel tree.
  - **Compact IRC Style**: High-density text view with compact timestamps for busy channels.
- **6 Color Palettes (including Light, Dark & Pure Black OLED)**:
  - **☀️ Light** for bright environments and daytime use.
  - **🌙 Dark**, **Night Telegram**, **Discord Dark**, and **Catppuccin Mocha** for comfortable everyday use.
  - **🖤 OLED (`#000000`)**: True **Pure Black** background that turns off physical pixels on AMOLED/OLED screens to save battery.

### 👥 2. Multi-Account Support: Unified Inbox or Strictly Separated Lists
Connect **multiple accounts even on the same protocol** (for example: your personal Telegram account, a Telegram Bot token from `@BotFather`, and a Telegram Test DC2 account).  
Choose how your sidebar is organized with one click:
- **🌐 Unified Inbox**: Merges all active accounts into a single chronological chat list.
- **🔌 Per Protocol**: Shows only conversations from the protocol you select (e.g., all Telegram accounts or all Matrix accounts).
- **🔒 Strictly Separated per Account**: Each individual account gets its own isolated chat list with zero mixing between accounts.
- **⚖️ Hybrid Custom Folders**: Combine custom filter folders with isolated accounts.

### 🤖 3. Advanced Telegram Features (Bot Token Login & Backend Switcher)
Open **`🔐 Auth / Add Account`** and select **Telegram** to access two dedicated features:
- **Log in as a Bot (`@BotFather`)**: Paste any Telegram Bot Token (`123456789:AAH...`) to log in directly as a Bot and read/send messages without writing code.
- **Backend Environment Selector (Public vs Test DC2)**: Switch at any time between **Telegram Public Production Data Centers** and the official **Telegram Test Server (DC2)**.

### 🔌 4. Pause or Enable Any Protocol or Account Instantly
Click any protocol button or account badge in the top bar to pause or resume it on the fly without losing your local chat history.

---

## 📖 User & Developer Guides

- 👤 **[Complete User Guide (English)](docs/USER_GUIDE.md)**: Step-by-step instructions for installing Warp IM, adding accounts, switching themes, and organizing your chats.
- 🛠️ **[Technical Architecture & Contributor Guide (English)](docs/CONTRIBUTING_AND_ARCHITECTURE.md)**: In-depth documentation for developers who want to build from source or contribute new protocol plugins.

---

## ⚖️ License: PEFL v1.0 (Personal and Educational Free License)

**Warp IM** is licensed under the [**Personal and Educational Free License v1.0 (PEFL v1.0)**](https://github.com/RubensRainelli/pefl-license-spec) — Copyright (c) 2026 **Rubens Rainelli** ([`LICENSE`](LICENSE) | [`LICENSE.it`](LICENSE.it) | [`NOTICE.md`](NOTICE.md)).

### Quick Summary for Users:
- ✅ **100% Free for Personal, Domestic, Educational, Student & Non-Profit Use**: You are free to download, install, and use Warp IM at home, for school/university study, academic research, or within registered non-profit organizations.
- 🚫 **No Corporate or Commercial Use Without a License**: Installing or using Warp IM on company computers, enterprise servers, for business/professional activities, or within religious organizations is strictly prohibited without prior written authorization and a commercial license agreement from the Author.
- 🔔 **Startup Approval (Clause 3)**: At first launch (and once every **7 days** thereafter), Warp IM displays the PEFL v1.0 license in the foreground (in Italian and English) and asks you to click **I Accept** before using the app.

### 📬 Author Contact (for inquiries or commercial licensing)
- **Author**: Rubens Rainelli
- **Email**: [rubens@rainelli.it](mailto:rubens@rainelli.it)
- **GitHub**: [https://github.com/RubensRainelli/](https://github.com/RubensRainelli/)
- **Phone**: (+39) 342 811 5882

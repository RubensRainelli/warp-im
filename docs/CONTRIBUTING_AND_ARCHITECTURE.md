🌐 **Language / Lingua**: **🇬🇧 English** | [🇮🇹 Italiano](CONTRIBUTING_AND_ARCHITECTURE.it.md)  
⬅️ [Back to Main README](../README.md) | 👤 [Basic User Guide](USER_GUIDE.md) | 🤖 [AI Agent File Map (`AGENTS.md`)](../AGENTS.md)

# 🛠️ Warp IM — Advanced Architecture & Contributor Guide

[![License: PEFL v1.0](https://raw.githubusercontent.com/RubensRainelli/pefl-license-spec/main/badges/pefl-badge-red.svg)](../LICENSE)

This document is the authoritative technical reference for software engineers, contributors, and AI coding agents working on **Warp IM** under the **Personal and Educational Free License v1.0 (PEFL v1.0)** — Copyright (c) 2026 **Rubens Rainelli** (`rubens@rainelli.it`).

---

## 🏛️ 1. Four-Crate Workspace Architecture

Warp IM is structured as a Cargo Workspace divided into **4 strictly decoupled crates**:

```text
warp-im/
├── crates/
│   ├── warp-core/       # Protocol-agnostic SDK, UniversalId, Topology, Capabilities, Auth FSM, Cross-Platform
│   ├── warp-storage/    # SQLite WAL, <1ms Transactional Outbox, 4 Isolation Modes, MediaProxy, PEFL Clause 3 DB
│   ├── warp-protocols/  # ProtocolRegistry + 8 isolated adapters (Telegram, Matrix, XMPP, Nostr, SimpleX, IRC, Stoat, Mattermost)
│   └── warp-app/        # Slint GPU UI, Dual-Layer ThemeManager (4 SuperThemes x 6 Palettes), 16ms Coalescer
├── themes/
│   ├── superthemes/     # telegram.toml, whatsapp.toml, discord.toml, irc_classic.toml
│   └── palettes/        # light.toml, dark.toml, oled.toml, night_telegram.toml, discord_dark.toml, catppuccin_mocha.toml
├── packaging/           # Linux (.deb, AppImage, desktop, svg), macOS (Info.plist), Android (Manifest), iOS (Info.plist)
└── scripts/
    └── package-linux.sh # Reproducible local & CI packager for .deb, AppDir/AppImage, and clean linux-sources.tar.gz
```

### 🔴 Crate 1: `crates/warp-core` (Zero-I/O Domain SDK)
- **Zero dependencies** on SQLite, Slint, or protocol-specific networking crates; 100% compatible with Desktop, Mobile, and `wasm32-unknown-unknown`.
- **`UniversalId` (`warp://<protocol>/<account_id>/<remote_id>`)**: Stored inline on the stack up to 24 bytes via `CompactString`. Eliminates assumptions about 64-bit integer IDs (Telegram), Matrix room IDs (`!room:domain`), ULIDs (Stoat), or pairwise queue IDs (SimpleX).
- **`AccountId` & `AccountProfile`**: Decouples `ProtocolKind` from account identity (`1 ProtocolKind` $\rightarrow$ `N AccountId`), enabling multiple simultaneous accounts on the same protocol with distinct badges (`TG•1`, `TG•DC2`, `IRC•LIB`, `IRC•OFTC`).
- **3-Level Dynamic Topology (`ContainerHierarchy`)**:
  - **Level 1 (`UnifiedContainer`)**: Server (Stoat), Workspace (Mattermost), Space (Matrix), Bouncer/Network (IRCv3), or Forum Supergroup (Telegram).
  - **Level 2 (`UnifiedChat` — `ContainerChannel` / `DirectMessage` / `FlatGroup`)**: Channels inside a container or standalone chats.
  - **Level 3 (`UnifiedChat` — `ThreadOrTopic`)**: Forum topics or message threads.
- **Granular Capability Bitmasks (`bitflags`)**: `ProtocolCapabilities`, `ChatCapabilities`, and `MessageCapabilities` (e.g., `CAN_EDIT_ONLY_LAST`, `IS_E2EE_ACTIVE`, `CAN_SEND_VOICE`) drive the UI declaratively.
- **Declarative Auth State Machine (`AuthFlowDescriptor`)**: Protocols emit `AuthStep` descriptors (`PhoneAndOtp`, `ProvideServerUrl`, `ImportPrivateKeyNsec`, `ScanOrDisplayQrInvite`, `UsernamePasswordSasl`) rendered dynamically by Slint.

### 🟠 Crate 2: `crates/warp-storage` (SQLite WAL, Outbox & Media Proxy)
- **SQLite WAL Engine (`db.rs`)**: Configured with `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;` for concurrent reads and sub-millisecond writes.
- **4 Chat List Isolation Modes (`ChatListIsolationMode`)**:
  - `UnifiedInbox`: Queries all enabled accounts where `include_in_unified_inbox = 1`.
  - `PerProtocol`: Filters containers and chats by `protocol_slug`.
  - `PerAccount`: Filters strictly by `account_id` for zero cross-account bleed.
  - `HybridCustom`: Evaluates `FolderFilterRule` JSON definitions.
- **Transactional Outbox (`outbox.rs`)**: `enqueue_and_persist_optimistic()` writes the message into `messages` with `DeliveryState::Pending` and inserts a job into `outbox_queue` in **< 1ms**, allowing instant UI rendering before network transmission.
- **Zero-Migration State (`protocol_kv_state`)**: Stores per-account binary/JSON sync tokens (`pts`, `since`, ratchet state) without altering SQL tables.
- **PEFL v1.0 Clause 3 Persistence**: `has_valid_pefl_eula_acceptance()` and `record_pefl_eula_acceptance()` enforce the 7-day (`604,800,000 ms`) EULA expiration policy.

### 🟡 Crate 3: `crates/warp-protocols` (`ProtocolRegistry` & 8 Adapters)
- **`ProtocolRegistry` (`registry.rs`)**: Manages `HashMap<AccountId, Arc<dyn MessagingBackend>>`, runtime per-protocol toggles (`set_protocol_enabled`), per-account toggles (`set_account_enabled`), and fan-in of `BackendEvent` streams.
- **8 Isolated Protocol Adapters (`src/adapters/*.rs`)**:
  1. `telegram.rs`: MTProto 2.0, `.private/telegram/config.toml` loader (Test DC2 `149.154.167.40:443`), 2FA, Forum Topics.
  2. `matrix.rs`: Client-Server + Megolm E2EE, Spaces $\rightarrow$ Rooms $\rightarrow$ Threads, `mxc://` media.
  3. `xmpp.rs`: RFC 6120 + OMEMO (`aesgcm://`), XEP-0308 Last Message Correction (`CAN_EDIT_ONLY_LAST`).
  4. `nostr.rs`: NIP-17 / NIP-59 Gift-Wrapped DMs, NIP-28 Channels, immutable signed events.
  5. `simplex.rs`: Identity-less pairwise SMP queues (`snd_queue_id`/`rcv_queue_id`), X3DH + Double Ratchet, XFTP.
  6. `irc.rs`: RFC 1459 + IRCv3.2 tags, `CAP LS 302`, `SASL PLAIN`, `BATCH chathistory`, Soju/Ergo bouncer support.
  7. `stoat.rs`: REST + Bonfire WebSocket, ULID addressing, Server $\rightarrow$ Channels $\rightarrow$ Threads.
  8. `mattermost.rs`: REST v4 + WebSocket, Team Workspace $\rightarrow$ Channels $\rightarrow$ Threads.

### 🔵 Crate 4: `crates/warp-app` (Slint GPU UI, Dual-Layer Themes & 16ms Bridge)
- **`ThemeManager` (`theme_manager.rs`)**: Loads and applies **4 `SuperThemeConfig`** (`telegram`, `whatsapp`, `discord`, `irc_classic`) and **6 `ThemePaletteConfig`** (`light`, `dark`, `oled`, `night_telegram`, `discord_dark`, `catppuccin_mocha`) independently at runtime.
- **16ms Frame Coalescer (`ui_bridge.rs`)**: Drains `BackendEvent` bursts on a `16ms` ticker and performs a single batch projection into Slint's `VecModel`.

---

## 🤖 2. Strict AI Agent File-Ownership Protocol (`AGENTS.md`)

When multiple developers or AI subagents collaborate on Warp IM, they **MUST** follow the isolation matrix defined in [`AGENTS.md`](../AGENTS.md):

| Agent / Developer Scope | ✅ Permitted Files (Read/Write) | 🚫 Forbidden Files (Read-Only / Do Not Touch) |
|---|---|---|
| **Protocol Adapter Specialist** | Only `crates/warp-protocols/src/adapters/<protocol>.rs` | `warp-core/*`, `warp-storage/*`, `warp-app/*`, other `adapters/*.rs`, `LICENSE*` |
| **Core SDK & Topology** | `crates/warp-core/src/*.rs` | `crates/warp-protocols/src/adapters/*`, `crates/warp-app/ui/*`, `LICENSE*` |
| **Storage, Outbox & Media** | `crates/warp-storage/src/*.rs` | `crates/warp-protocols/src/adapters/*`, `crates/warp-app/ui/*`, `LICENSE*` |
| **Slint UI & Theme Engine** | `crates/warp-app/**`, `themes/**/*.toml` | `crates/warp-storage/*`, `crates/warp-protocols/src/adapters/*`, `LICENSE*` |
| **Packaging & Docs Architect** | `.github/workflows/*.yml`, `packaging/**`, `scripts/package-linux.sh`, `README*.md`, `docs/*.md` | `crates/**`, `Cargo.toml`, `LICENSE`, `LICENSE.it`, `NOTICE.md` |

---

## 🔌 3. How to Add a 9th Protocol in 30 Minutes

Thanks to the **Open-Closed Principle**, implementing a 9th protocol (e.g., `Signal` or `DeltaChat`) requires **zero changes** to `warp-storage` (SQLite) or `warp-app` (Slint UI):

### Step 1: Create `crates/warp-protocols/src/adapters/my_proto.rs`
Prepend the mandatory **PEFL v1.0** license header and implement `MessagingBackend` + `ProtocolPlugin`:

```rust
/*
 * Personal and Educational Free License (PEF License / PEFL)
 * Version 1.0 - 2026-05-26
 * Copyright (c) 2026 Rubens Rainelli
 */

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::broadcast;
use warp_core::*;

pub struct MyProtoBackend {
    account_id: AccountId,
    tx: broadcast::Sender<BackendEvent>,
}

#[async_trait]
impl MessagingBackend for MyProtoBackend {
    fn account_id(&self) -> &AccountId { &self.account_id }
    fn protocol(&self) -> ProtocolKind { ProtocolKind::from_slug("my_proto") }
    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::SUPPORTS_E2EE | ProtocolCapabilities::SUPPORTS_REACTIONS
    }
    fn sync_state(&self) -> SyncState { SyncState::LiveSynced }

    async fn submit_auth_step(&self, _flow: &str, _sub: AuthStepSubmission) -> Result<AuthFlowDescriptor, WarpError> {
        Ok(self.initial_auth_flow())
    }
    async fn connect(&self) -> Result<(), WarpError> { Ok(()) }
    async fn disconnect(&self) -> Result<(), WarpError> { Ok(()) }
    async fn fetch_hierarchy(&self) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError> {
        Ok((vec![], vec![]))
    }
    async fn fetch_messages(&self, _chat: &UniversalId, _before: Option<i64>, _limit: usize) -> Result<Vec<UnifiedMessage>, WarpError> {
        Ok(vec![])
    }
    async fn send_message(&self, req: OutboundMessageRequest) -> Result<UniversalId, WarpError> {
        Ok(UniversalId::new(self.protocol(), self.account_id.clone(), "remote-msg-001"))
    }
    async fn edit_message(&self, _: &UniversalId, _: &UniversalId, _: &str) -> Result<(), WarpError> { Ok(()) }
    async fn delete_message(&self, _: &UniversalId, _: &UniversalId, _: bool) -> Result<(), WarpError> { Ok(()) }
    async fn react_to_message(&self, _: &UniversalId, _: &UniversalId, _: &str, _: bool) -> Result<(), WarpError> { Ok(()) }
    async fn fetch_and_decrypt_media(&self, att: &MediaAttachment) -> Result<ResolvedMediaBytes, WarpError> {
        Ok(ResolvedMediaBytes {
            media_uri: att.media_uri.clone(),
            mime_type: att.mime_type.clone(),
            bytes: vec![],
            cached_disk_path: None,
        })
    }
    fn subscribe(&self) -> broadcast::Receiver<BackendEvent> { self.tx.subscribe() }
}

pub struct MyProtoPlugin;
impl ProtocolPlugin for MyProtoPlugin {
    fn protocol(&self) -> ProtocolKind { ProtocolKind::from_slug("my_proto") }
    fn build_backend(&self, account_id: AccountId, _cfg: serde_json::Value) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        let (tx, _) = broadcast::channel(64);
        Ok(Arc::new(MyProtoBackend { account_id, tx }))
    }
}
```

### Step 2: Register the Plugin in `ProtocolRegistry`
```rust
registry.register_plugin(Box::new(MyProtoPlugin));
```
Your new protocol immediately inherits:
- Multi-account management & all 4 `ChatListIsolationMode` views;
- `< 1ms` SQLite WAL Optimistic UI & `OutboxEngine` retry queue;
- All 4 `SuperThemes` × 6 `ThemePalettes`;
- Declarative Slint onboarding via `initial_auth_flow()`.

---

## 📦 4. Building & Packaging Multi-Platform Releases

### Local Linux Packaging (`.deb`, `AppDir`/`AppImage`, `linux-sources.tar.gz`)
Run the reproducible packaging script:
```bash
./scripts/package-linux.sh --version 0.1.0
# Add --build-appimage if appimagetool is installed on your PATH:
./scripts/package-linux.sh --version 0.1.0 --build-appimage
```
Generated artifacts in `dist/linux/`:
1. `warp-im-0.1.0-linux-sources.tar.gz` (excludes `.git/`, `.private/`, `target/`, `dist/`).
2. `warp-im_0.1.0_amd64.deb` (installs `/usr/bin/warp-im`, `/usr/share/applications/warp-im.desktop`, `/usr/share/icons/hicolor/scalable/apps/warp-im.svg`, `/usr/share/doc/warp-im/copyright`).
3. `Warp_IM.AppDir` & `Warp_IM-0.1.0-x86_64.AppImage`.
4. `SHA256SUMS`.

### Cross-Platform Compilation Targets
- **Windows (`x86_64-pc-windows-msvc`)**:
  ```bash
  cargo build --release --target x86_64-pc-windows-msvc -p warp-app
  ```
- **macOS Universal (`aarch64-apple-darwin` + `x86_64-apple-darwin`)**:
  ```bash
  cargo build --release --target aarch64-apple-darwin -p warp-app
  cargo build --release --target x86_64-apple-darwin -p warp-app
  lipo -create target/aarch64-apple-darwin/release/warp-app target/x86_64-apple-darwin/release/warp-app -output warp-im-universal
  ```
- **Android Native (`aarch64-linux-android` via `cargo-ndk`)**:
  ```bash
  cargo ndk -t arm64-v8a build --release --lib -p warp-app
  ```
- **iOS Native (`aarch64-apple-ios` & `aarch64-apple-ios-sim`)**:
  ```bash
  cargo build --release --target aarch64-apple-ios --lib -p warp-app
  ```
- **WebAssembly Core SDK (`wasm32-unknown-unknown`)**:
  ```bash
  cargo check --target wasm32-unknown-unknown -p warp-core
  ```

### Automated GitHub Actions Workflows
- **`.github/workflows/ci.yml`**: Runs on every push and PR across `ubuntu-latest`, `windows-latest`, and `macos-latest`. Performs PEFL v1.0 file and header auditing, `cargo test --workspace`, `WARP_HEADLESS_CHECK=1 cargo run -p warp-app`, and tests `scripts/package-linux.sh`.
- **`.github/workflows/release.yml`**: Triggered by pushing a `v*.*.*` git tag (or manually via `workflow_dispatch`). Builds all 7 platform packages (`linux-sources.tar.gz`, `.deb`, `.AppImage`, Windows `.zip`, macOS `.dmg`, Android `arm64-v8a`, iOS `aarch64`) and publishes them to GitHub Releases with `SHA256SUMS.txt`.

---

## ⚖️ 5. Mandatory PEFL v1.0 Legal & Technical Rules for Contributors

1. **Preserve License Files**: Never modify or delete `LICENSE`, `LICENSE.it`, or `NOTICE.md`.
2. **Mandatory Source Headers**: Every `.rs`, `.slint`, `.sh`, and `.yml` file must begin with the official **PEFL v1.0** copyright header attributing **Rubens Rainelli** (`rubens@rainelli.it`).
3. **Never Bypass Clause 3 EULA**: Never disable, skip, or weaken the startup EULA modal (`show-pefl-eula-modal`) or its 7-day expiration (`WarpStorage::PEFL_SEVEN_DAYS_MS`).
4. **No Re-Licensing (Clause 5)**: Derivative works or contributions must remain under **PEFL v1.0** (`LicenseRef-PEFL-1.0`). Re-licensing under MIT, Apache, GPL, or any other license is strictly prohibited.

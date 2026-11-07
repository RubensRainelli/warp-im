🌐 **Lingua / Language**: [🇬🇧 English](CONTRIBUTING_AND_ARCHITECTURE.md) | **🇮🇹 Italiano**  
⬅️ [Torna al README Principale](../README.it.md) | 👤 [Guida Utente Base](USER_GUIDE.it.md) | 🤖 [Mappa Agenti AI (`AGENTS.md`)](../AGENTS.md)

# 🛠️ Warp IM — Guida Avanzata all'Architettura e ai Contributi

[![Licenza: PEFL v1.0](https://raw.githubusercontent.com/RubensRainelli/pefl-license-spec/main/badges/pefl-badge-red.svg)](../LICENSE.it)

Questo documento costituisce il riferimento tecnico ufficiale per sviluppatori, contributori e agenti di codifica AI che operano su **Warp IM** sotto licenza **Personal and Educational Free License v1.0 (PEFL v1.0)** — Copyright (c) 2026 **Rubens Rainelli** (`rubens@rainelli.it`).

---

## 🏛️ 1. Architettura Interna dei 4 Crate del Workspace

Warp IM è strutturato come un Cargo Workspace suddiviso in **4 crate rigorosamente disaccoppiati**:

```text
warp-im/
├── crates/
│   ├── warp-core/       # SDK Protocol-Agnostic, UniversalId, Topologia, Capabilities, Auth FSM, Cross-Platform
│   ├── warp-storage/    # SQLite WAL, Outbox Transazionale <1ms, 4 Modalità Isolamento, MediaProxy, DB PEFL Clausola 3
│   ├── warp-protocols/  # ProtocolRegistry + 8 adapter isolati (Telegram, Matrix, XMPP, Nostr, SimpleX, IRC, Stoat, Mattermost)
│   └── warp-app/        # UI GPU Slint, ThemeManager a Doppio Livello (4 SuperTheme x 6 Palette), Coalescer a 16ms
├── themes/
│   ├── superthemes/     # telegram.toml, whatsapp.toml, discord.toml, irc_classic.toml
│   └── palettes/        # light.toml, dark.toml, oled.toml, night_telegram.toml, discord_dark.toml, catppuccin_mocha.toml
├── packaging/           # Linux (.deb, AppImage, desktop, svg), macOS (Info.plist), Android (Manifest), iOS (Info.plist)
└── scripts/
    └── package-linux.sh # Script di pacchettizzazione per .deb, AppDir/AppImage e archivio pulito linux-sources.tar.gz
```

### 🔴 Crate 1: `crates/warp-core` (SDK di Dominio Zero-I/O)
- **Zero dipendenze** da SQLite, Slint o librerie di rete specifiche dei protocolli; compilabile al 100% su Desktop, Mobile e `wasm32-unknown-unknown`.
- **`UniversalId` (`warp://<protocol>/<account_id>/<remote_id>`)**: Allocato sullo stack fino a 24 byte tramite `CompactString`. Elimina qualsiasi assunzione su ID numerici a 64 bit (Telegram), ID stanza Matrix (`!room:domain`), ULID (Stoat) o code pairwise (SimpleX).
- **`AccountId` e `AccountProfile`**: Disaccoppia `ProtocolKind` dall'identità dell'account (`1 ProtocolKind` $\rightarrow$ `N AccountId`), consentendo più account simultanei sullo stesso protocollo con badge distinti (`TG•1`, `TG•DC2`, `IRC•LIB`, `IRC•OFTC`).
- **Topologia Dinamica a 3 Livelli (`ContainerHierarchy`)**:
  - **Livello 1 (`UnifiedContainer`)**: Server (Stoat), Workspace (Mattermost), Space (Matrix), Rete/Bouncer (IRCv3) o Supergruppo Forum (Telegram).
  - **Livello 2 (`UnifiedChat` — `ContainerChannel` / `DirectMessage` / `FlatGroup`)**: Canali dentro un container o chat dirette/gruppi piatti.
  - **Livello 3 (`UnifiedChat` — `ThreadOrTopic`)**: Topic dei forum o thread di discussione.
- **Bitmask di Capacità Granulari (`bitflags`)**: `ProtocolCapabilities`, `ChatCapabilities` e `MessageCapabilities` (es. `CAN_EDIT_ONLY_LAST`, `IS_E2EE_ACTIVE`, `CAN_SEND_VOICE`) guidano la UI Slint in modo dichiarativo.
- **Macchina a Stati di Onboarding (`AuthFlowDescriptor`)**: Ogni protocollo espone step `AuthStep` dichiarativi (`PhoneAndOtp`, `ProvideServerUrl`, `ImportPrivateKeyNsec`, `ScanOrDisplayQrInvite`, `UsernamePasswordSasl`) renderizzati automaticamente da Slint.

### 🟠 Crate 2: `crates/warp-storage` (SQLite WAL, Outbox e Media Proxy)
- **Motore SQLite WAL (`db.rs`)**: Configurato con `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;` per letture concorrenti e scritture sotto il millisecondo.
- **4 Modalità di Isolamento Liste Chat (`ChatListIsolationMode`)**:
  - `UnifiedInbox`: Interroga tutti gli account attivi con `include_in_unified_inbox = 1`.
  - `PerProtocol`: Filtra container e chat per `protocol_slug`.
  - `PerAccount`: Filtra rigorosamente per singolo `account_id` garantendo zero contaminazione tra account.
  - `HybridCustom`: Applica le regole JSON di `FolderFilterRule`.
- **Outbox Transazionale (`outbox.rs`)**: `enqueue_and_persist_optimistic()` salva il messaggio in `messages` con stato `DeliveryState::Pending` e accoda il job in `outbox_queue` in **< 1ms**, garantendo una Optimistic UI istantanea prima ancora dell'invio in rete.
- **Stato Protocolli a Zero Migrazioni (`protocol_kv_state`)**: Memorizza i cursori di sincronizzazione (`pts`, `since`, stato ratchet) per singolo account senza mai richiedere migrazioni SQL.
- **Persistenza EULA PEFL v1.0 Clausola 3**: `has_valid_pefl_eula_acceptance()` e `record_pefl_eula_acceptance()` applicano la scadenza tassativa di 7 giorni (`604.800.000 ms`).

### 🟡 Crate 3: `crates/warp-protocols` (`ProtocolRegistry` e 8 Adapter)
- **`ProtocolRegistry` (`registry.rs`)**: Gestisce `HashMap<AccountId, Arc<dyn MessagingBackend>>`, attivazione/disattivazione a caldo per intero protocollo (`set_protocol_enabled`) o per singolo account (`set_account_enabled`), e il fan-in degli eventi `BackendEvent`.
- **8 Adapter Protocollo Isolati (`src/adapters/*.rs`)**:
  1. `telegram.rs`: MTProto 2.0, caricamento `.private/telegram/config.toml` (Server di test DC2 `149.154.167.40:443`), 2FA, Forum Topics.
  2. `matrix.rs`: Client-Server + Megolm E2EE, Space $\rightarrow$ Stanze $\rightarrow$ Thread, media `mxc://`.
  3. `xmpp.rs`: RFC 6120 + OMEMO (`aesgcm://`), XEP-0308 Last Message Correction (`CAN_EDIT_ONLY_LAST`).
  4. `nostr.rs`: DM cifrati NIP-17 / NIP-59 Gift-Wrapped, canali NIP-28, eventi firmati immutabili.
  5. `simplex.rs`: Code pairwise SMP prive di ID utente (`snd_queue_id`/`rcv_queue_id`), X3DH + Double Ratchet, XFTP.
  6. `irc.rs`: RFC 1459 + tag IRCv3.2, `CAP LS 302`, `SASL PLAIN`, `BATCH chathistory`, supporto bouncer Soju/Ergo.
  7. `stoat.rs`: REST + Bonfire WebSocket, indirizzamento ULID, Server $\rightarrow$ Canali $\rightarrow$ Thread.
  8. `mattermost.rs`: REST v4 + WebSocket, Workspace Team $\rightarrow$ Canali $\rightarrow$ Thread.

### 🔵 Crate 4: `crates/warp-app` (UI GPU Slint, Temi a Doppio Livello e Bridge a 16ms)
- **`ThemeManager` (`theme_manager.rs`)**: Carica e applica a caldo i **4 `SuperThemeConfig`** (`telegram`, `whatsapp`, `discord`, `irc_classic`) e le **6 `ThemePaletteConfig`** (`light`, `dark`, `oled`, `night_telegram`, `discord_dark`, `catppuccin_mocha`) in modo totalmente indipendente.
- **Coalescer a 16ms (`ui_bridge.rs`)**: Raggruppa le raffiche di `BackendEvent` ogni `16ms` ed esegue un'unica proiezione batch nel `VecModel` di Slint.

---

## 🤖 2. Protocollo di Isolamento File per Agenti AI (`AGENTS.md`)

Quando più sviluppatori o sub-agenti AI lavorano in parallelo su Warp IM, devono rispettare **tassativamente** la matrice di isolamento definita in [`AGENTS.md`](../AGENTS.md):

| Ruolo Agente / Sviluppatore | ✅ FILE CONSENTITI (Lettura/Scrittura) | 🚫 FILE VIETATI (Sola Lettura / Non Toccare) |
|---|---|---|
| **Specialista Singolo Protocollo** | Solo `crates/warp-protocols/src/adapters/<protocollo>.rs` | `warp-core/*`, `warp-storage/*`, `warp-app/*`, altri `adapters/*.rs`, `LICENSE*` |
| **Core SDK & Topologia** | `crates/warp-core/src/*.rs` | `crates/warp-protocols/src/adapters/*`, `crates/warp-app/ui/*`, `LICENSE*` |
| **Storage, Outbox & Media** | `crates/warp-storage/src/*.rs` | `crates/warp-protocols/src/adapters/*`, `crates/warp-app/ui/*`, `LICENSE*` |
| **UI Slint & Motore Temi** | `crates/warp-app/**`, `themes/**/*.toml` | `crates/warp-storage/*`, `crates/warp-protocols/src/adapters/*`, `LICENSE*` |
| **Packaging & Documentazione** | `.github/workflows/*.yml`, `packaging/**`, `scripts/package-linux.sh`, `README*.md`, `docs/*.md` | `crates/**`, `Cargo.toml`, `LICENSE`, `LICENSE.it`, `NOTICE.md` |

---

## 🔌 3. Come Implementare un 9° Protocollo in 30 Minuti

Grazie al **Principio Open-Closed**, aggiungere un 9° protocollo (es. `Signal` o `DeltaChat`) richiede **zero modifiche** al database (`warp-storage`) o alla UI (`warp-app`):

### Passo 1: Crea `crates/warp-protocols/src/adapters/mio_proto.rs`
Inserisci in cima l'header obbligatorio **PEFL v1.0** e implementa `MessagingBackend` + `ProtocolPlugin`:

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

pub struct MioProtoBackend {
    account_id: AccountId,
    tx: broadcast::Sender<BackendEvent>,
}

#[async_trait]
impl MessagingBackend for MioProtoBackend {
    fn account_id(&self) -> &AccountId { &self.account_id }
    fn protocol(&self) -> ProtocolKind { ProtocolKind::from_slug("mio_proto") }
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

pub struct MioProtoPlugin;
impl ProtocolPlugin for MioProtoPlugin {
    fn protocol(&self) -> ProtocolKind { ProtocolKind::from_slug("mio_proto") }
    fn build_backend(&self, account_id: AccountId, _cfg: serde_json::Value) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        let (tx, _) = broadcast::channel(64);
        Ok(Arc::new(MioProtoBackend { account_id, tx }))
    }
}
```

### Passo 2: Registra il Plugin nel `ProtocolRegistry`
```rust
registry.register_plugin(Box::new(MioProtoPlugin));
```
Il nuovo protocollo eredita automaticamente:
- Gestione multi-account e tutte le 4 modalità `ChatListIsolationMode`;
- Optimistic UI in `< 1ms` su SQLite WAL e coda di invio `OutboxEngine`;
- Tutte le 24 combinazioni `4 SuperTheme × 6 ThemePalette`;
- Form di login dichiarativo in Slint tramite `initial_auth_flow()`.

---

## 📦 4. Compilazione e Pacchettizzazione Multipiattaforma

### Pacchettizzazione Locale su Linux (`.deb`, `AppDir`/`AppImage`, `linux-sources.tar.gz`)
Esegui lo script di pacchettizzazione:
```bash
./scripts/package-linux.sh --version 0.1.0
# Aggiungi --build-appimage se appimagetool è installato nel tuo PATH:
./scripts/package-linux.sh --version 0.1.0 --build-appimage
```
Artefatti generati in `dist/linux/`:
1. `warp-im-0.1.0-linux-sources.tar.gz` (archivio sorgente pulito senza `.git/`, `.private/`, `target/`, `dist/`).
2. `warp-im_0.1.0_amd64.deb` (installa `/usr/bin/warp-im`, `/usr/share/applications/warp-im.desktop`, `/usr/share/icons/hicolor/scalable/apps/warp-im.svg`, `/usr/share/doc/warp-im/copyright`).
3. `Warp_IM.AppDir` e `Warp_IM-0.1.0-x86_64.AppImage`.
4. `SHA256SUMS`.

### Target di Cross-Compilazione Multipiattaforma
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
- **Android Nativo (`aarch64-linux-android` tramite `cargo-ndk`)**:
  ```bash
  cargo ndk -t arm64-v8a build --release --lib -p warp-app
  ```
- **iOS Nativo (`aarch64-apple-ios` e `aarch64-apple-ios-sim`)**:
  ```bash
  cargo build --release --target aarch64-apple-ios --lib -p warp-app
  ```
- **WebAssembly Core SDK (`wasm32-unknown-unknown`)**:
  ```bash
  cargo check --target wasm32-unknown-unknown -p warp-core
  ```

### Pipeline Automatizzate GitHub Actions
- **`.github/workflows/ci.yml`**: Eseguito ad ogni push e Pull Request su `ubuntu-latest`, `windows-latest` e `macos-latest`. Verifica la presenza dei file e degli header PEFL v1.0, esegue `cargo test --workspace`, `WARP_HEADLESS_CHECK=1 cargo run -p warp-app` e testa `scripts/package-linux.sh`.
- **`.github/workflows/release.yml`**: Attivato dai tag `v*.*.*` (o manualmente tramite `workflow_dispatch`). Compila tutti i 7 pacchetti multipiattaforma (`linux-sources.tar.gz`, `.deb`, `.AppImage`, Windows `.zip`, macOS `.dmg`, Android `arm64-v8a`, iOS `aarch64`) e li pubblica su GitHub Releases con `SHA256SUMS.txt`.

---

## ⚖️ 5. Regole Legali e Tecniche Obbligatorie PEFL v1.0 per i Contributori

1. **Integrità dei File di Licenza**: Non modificare né rimuovere mai `LICENSE`, `LICENSE.it` o `NOTICE.md`.
2. **Header Obbligatorio nei File Sorgente**: Ogni file `.rs`, `.slint`, `.sh` e `.yml` deve iniziare con l'header ufficiale **PEFL v1.0** con attribuzione a **Rubens Rainelli** (`rubens@rainelli.it`).
3. **Divieto di Aggiramento della Clausola 3 (EULA)**: Non disattivare, saltare o ridurre mai il controllo EULA in primo piano (`show-pefl-eula-modal`) o la sua scadenza a 7 giorni (`WarpStorage::PEFL_SEVEN_DAYS_MS`).
4. **Divieto di Rilicenziamento (Clausola 5)**: Tutte le opere derivate e i contributi devono rimanere sotto licenza **PEFL v1.0** (`LicenseRef-PEFL-1.0`). È severamente vietato rilicenziare il codice sotto MIT, Apache, GPL o qualsiasi altra licenza.

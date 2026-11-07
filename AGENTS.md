# 🤖 AGENTS.md — AI Agent Architecture Map & Strict File-Ownership Protocol

**Progetto:** Warp IM (Universal Native Multi-Protocol Messenger)  
**Licenza:** Personal and Educational Free License (PEFL v1.0) — Copyright (c) 2026 Rubens Rainelli  

> **⚠️ REGOLA D'ORO PER TUTTI GLI AGENTI E SUB-AGENTI AI:**  
> Prima di leggere o modificare qualsiasi file nel repository, **consulta obbligatoriamente questa mappa**.  
> Ogni agente deve operare **ESCLUSIVAMENTE** sui file assegnati al proprio ruolo (**File Consentiti**) e **NON DEVE MAI TOCCARE** i file appartenenti ad altri domini (**File Vietati**), evitando conflitti di compilazione, regressioni o spreco di contesto.

---

## 🗺️ 1. Mappa Completa del Repository: Quale File Fa Cosa

### 📦 Root & Licenza PEFL v1.0
| File / Cartella | Scopo Preciso | Chi Può Modificarlo |
|---|---|---|
| `Cargo.toml` | Manifesto Cargo Workspace (`warp-core`, `warp-storage`, `warp-protocols`, `warp-app`) e dipendenze condivise. | Solo **Lead Orchestrator** |
| `LICENSE` / `LICENSE.it` | Testo integrale immutabile della licenza **PEFL v1.0** (Inglese e Italiano). | **NESSUNO (Immutabile)** |
| `NOTICE.md` | Attribuzione ufficiale a **Rubens Rainelli** e contatti per licenze commerciali. | **NESSUNO (Immutabile)** |
| `AI_INSTRUCTIONS.md` | Direttive obbligatorie per la conformità **PEFL v1.0** (Clausola 3 EULA in primo piano, header file). | Solo **Lead Orchestrator** |
| `AGENTS.md` | **(Questo file)** Mappa architetturale e regole di isolamento file per gli agenti AI. | Solo **Lead Orchestrator** |
| `README.md` / `README.it.md` | Documentazione principale bilingue (Inglese e Italiano) con tabella protocolli, funzionalità e link alle guide. | **Agente Packaging & Docs** / **Lead Orchestrator** |
| `docs/USER_GUIDE*.md` | Guide utente base (EN/IT): installazione pacchetti, SuperThemes, temi Chiaro/Scuro/OLED, Multi-Account. | **Agente Packaging & Docs** |
| `docs/CONTRIBUTING_AND_ARCHITECTURE*.md` | Guide avanzate per sviluppatori/contributori (EN/IT): architettura interna, 9° protocollo, build multi-OS. | **Agente Packaging & Docs** |
| `.github/workflows/{ci,release}.yml` | Pipeline CI e compilazione pacchetti GitHub Releases (`Windows`, `Linux Sources/Deb/AppImage`, `macOS`, `Android`, `iOS`). | **Agente Packaging & Docs** |
| `packaging/**` & `scripts/package-linux.sh` | Metadati e script di pacchettizzazione Desktop (`.deb`, `AppImage`, `.dmg`) e Mobile (`AndroidManifest.xml`, `Info.plist`). | **Agente Packaging & Docs** |
| `.private/telegram/` | Configurazione privata locale Telegram (`api_id`, `api_hash`, DC2 test server `149.154.167.40:443`). Ignorata da Git (`.gitignore`). | **Solo Lettura** da `telegram.rs` |

---

### 🔴 Crate 1: `crates/warp-core` (SDK Protocol-Agnostic, Topologia, Multi-Account & Cross-Platform)
Zero dipendenze da SQLite, Slint o librerie di rete specifiche dei protocolli. Compilabile al 100% su Desktop, Mobile e `wasm32-unknown-unknown`.

| File | Cosa Contiene e Cosa Fa |
|---|---|
| `crates/warp-core/src/lib.rs` | Esporta i tipi pubblici di `warp-core` e contiene i test di roundtrip `UniversalId`, `ChatCapabilities` e multi-account. |
| `crates/warp-core/src/id.rs` | Definisce `ProtocolKind` (gli 8 protocolli + `Custom`), `AccountId` (consente **N account per lo stesso protocollo**) e `UniversalId` (`warp://<protocol>/<account_id>/<remote_id>`). |
| `crates/warp-core/src/models.rs` | Definisce: <br>• `AccountProfile` (profilo account multiplo per protocollo, badge corto es. `TG•1`, `TG•DC2`, `IRC•LIB`, `IRC•OFTC`, flag `include_in_unified_inbox`)<br>• `ChatListIsolationMode` (`UnifiedInbox`, `PerProtocol`, `PerAccount`, `HybridCustom` — per chi ama le viste unificate e chi le odia)<br>• `ContainerHierarchy`, `UnifiedContainer` (Livello 1: Server/Workspace/Space/Network), `UnifiedChat` (Livello 2: Canale/DM/Gruppo, Livello 3: Thread/Topic), `UnifiedMessage`, `FolderFilterRule`. |
| `crates/warp-core/src/capabilities.rs` | Bitmask `bitflags`: `ProtocolCapabilities`, `ChatCapabilities` e `MessageCapabilities` (es. `CAN_EDIT_ONLY_LAST` per IRC/XMPP, `IS_E2EE_ACTIVE` per Matrix/SimpleX/Nostr). |
| `crates/warp-core/src/auth.rs` | Macchina a stati dichiarativa `AuthFlowDescriptor`, `AuthStep`, `AuthInputField`, `AuthStepSubmission` per renderizzare i form di login in Slint senza codice specifico per protocollo. |
| `crates/warp-core/src/plugin.rs` | Trait `MessagingBackend` e `ProtocolPlugin`, `BackendEvent` (incluso `ProtocolToggled` e `AccountToggled`), `OutboundMessageRequest`, `ResolvedMediaBytes`. |
| `crates/warp-core/src/platform.rs` | Astrazione Cross-Platform: `PlatformTarget` (`DesktopLinux`, `DesktopMacOs`, `DesktopWindows`, `MobileAndroid`, `MobileIos`, `WebWasm32`), `FormFactorMode` (`DesktopWide`, `TabletAdaptive`, `MobileCompactSinglePane`), `TransportCapabilities` (filtra raw TCP su WASM) e `AppLifecycleEvent` (flush WAL su background mobile). |

---

### 🟠 Crate 2: `crates/warp-storage` (SQLite WAL, Isolamento Liste Multi-Account, Outbox & Media Proxy)
Persistenza locale asincrona (< 1ms per Optimistic UI) e gestione cache media.

| File | Cosa Contiene e Cosa Fa |
|---|---|
| `crates/warp-storage/src/lib.rs` | Re-export di `WarpStorage`, `OutboxEngine`, `MediaProxy` + suite di test d'integrazione (Outbox <50 righe, multi-account per protocollo e modalità di isolamento liste chat). |
| `crates/warp-storage/src/db.rs` | Schema SQLite WAL (`accounts`, `protocol_toggles`, `containers`, `chats`, `messages`, `outbox_queue`, `folders`, `protocol_kv_state`). Implementa `list_chats_by_isolation` e `list_containers_by_isolation` (`UnifiedInbox`, `PerProtocol`, `PerAccount`, `HybridCustom`), persistenza EULA PEFL Clausola 3 (7 giorni) e checkpoint ciclo di vita Mobile. |
| `crates/warp-storage/src/outbox.rs` | `OutboxEngine`: scrittura ottimistica immediata in `messages` (`DeliveryState::Pending`) + accodamento in `outbox_queue` e worker con exponential backoff. |
| `crates/warp-storage/src/media_proxy.rs` | `MediaProxy`: risoluzione URI `warp-media://<protocol>/<account_id>/<remote_media_id>`, cache LRU in RAM e su disco con decifratura on-the-fly. |

---

### 🟡 Crate 3: `crates/warp-protocols` (ProtocolRegistry, Simulatore & 8 Adapter Isolati)
Ogni protocollo vive nel **proprio file esclusivo** dentro `crates/warp-protocols/src/adapters/`.

| File | Cosa Contiene e Cosa Fa |
|---|---|
| `crates/warp-protocols/src/lib.rs` | Esporta `ProtocolRegistry`, `adapters`, `seed_simulated_environment`. |
| `crates/warp-protocols/src/registry.rs` | `ProtocolRegistry`: mappa `HashMap<AccountId, Arc<dyn MessagingBackend>>` (supporta **più account contemporanei per lo stesso protocollo**), attivazione/disattivazione a runtime per intero protocollo o per singolo account, fan-in `BackendEvent`. |
| `crates/warp-protocols/src/simulator.rs` | `SimulatedMultiProtocolBackend` e `seed_simulated_environment`: popola 10 account realistici sugli 8 protocolli (inclusi 2 account Telegram `tg_main` + `tg_dc2_lab` e 2 account IRC `soju_libera` + `irc_oftc`). |
| `crates/warp-protocols/src/adapters/mod.rs` | Registra i plugin dietro Cargo Feature Flags (`proto-telegram`, `proto-matrix`, `proto-xmpp`, `proto-nostr`, `proto-simplex`, `proto-irc`, `proto-stoat`, `proto-mattermost`). |
| `crates/warp-protocols/src/adapters/telegram.rs` | **Adapter 1 — Telegram (`grammers` MTProto):** caricamento `.private/telegram/config.toml` (DC2 `149.154.167.40:443`), auth flow 2FA, Forum Topics, `pts`/`qts`/`date` state in `protocol_kv_state`. |
| `crates/warp-protocols/src/adapters/irc.rs` | **Adapter 6 — IRCv3 (`irc` + Soju/Ergo):** parser RFC 1459 + `@tags` IRCv3.2, `CAP LS 302`, `SASL PLAIN`, `BATCH chathistory`, `draft/edit`, `+draft/react`, multi-network (`soju.im/upstream`). |
| `crates/warp-protocols/src/adapters/simplex.rs` | **Adapter 5 — SimpleX Chat (SMP Queues):** state machine SMP pairwise (`snd_queue_id`/`rcv_queue_id`) senza ID utente globali, X3DH + Double Ratchet in `protocol_metadata`, file transfer `XFTP`. |
| `crates/warp-protocols/src/adapters/matrix.rs` | **Adapter 2 — Matrix (`matrix-rust-sdk`):** Spaces $\rightarrow$ Rooms $\rightarrow$ Threads, Megolm E2EE, `mxc://` media. |
| `crates/warp-protocols/src/adapters/xmpp.rs` | **Adapter 3 — XMPP (`tokio-xmpp`):** JID Roster, MUC, OMEMO (`aesgcm://`), XEP-0308 Last Message Correction. |
| `crates/warp-protocols/src/adapters/nostr.rs` | **Adapter 4 — Nostr (`nostr-sdk`):** NIP-17 / NIP-59 Gift-Wrapped DMs, NIP-28 Channels, messaggi immutabili firmati. |
| `crates/warp-protocols/src/adapters/stoat.rs` | **Adapter 7 — Stoat (ex Revolt):** Server $\rightarrow$ Channels $\rightarrow$ Threads, ULID addressing, Bonfire WebSocket. |
| `crates/warp-protocols/src/adapters/mattermost.rs` | **Adapter 8 — Mattermost:** Team Workspace $\rightarrow$ Channels $\rightarrow$ Threads, REST v4 + WebSocket. |

---

### 🔵 Crate 4: `crates/warp-app` (Slint GPU UI, Supertheme Engine, Multi-Account Bar & Mobile/Desktop/WASM Targets)

| File | Cosa Contiene e Cosa Fa |
|---|---|
| `crates/warp-app/src/lib.rs` | Entrypoint libreria condivisa Cross-Platform (`rlib`, `cdylib`, `staticlib`) per Desktop, Mobile Native (`Android`/`iOS`) e `wasm32-unknown-unknown`. |
| `crates/warp-app/src/main.rs` | Entrypoint binario Desktop Native che invoca `warp_app::run_warp_app()`. |
| `crates/warp-app/src/theme_manager.rs` | Motore a doppio livello: carica e applica a caldo **SuperTheme** (`telegram`, `discord`, `whatsapp`, `irc_classic`) e **ThemePalette** (`light`, `dark`, `oled`, `night_telegram`, `discord_dark`, `catppuccin_mocha`). |
| `crates/warp-app/src/ui_bridge.rs` | Coalescer asincrono a **16ms** (`Tokio <-> Slint`), filtro `ChatListIsolationMode` (`Unificata`, `Per Protocollo`, `Separata per Account`, `Ibrida`), switch form-factor `Desktop / Mobile` e verifica EULA PEFL v1.0 Clausola 3. |
| `crates/warp-app/ui/globals.slint` | Singola sorgente di verità Slint per `ThemePalette`, `SuperTheme` (incluso `is-mobile-compact` e `mobile-showing-chat`), `UiAccountItem`, `UiChatListItem`, `UiMessageItem`, `UiActiveChatCapabilities`. |
| `crates/warp-app/ui/navigation.slint` | `PolymorphicNavigation`: cambia struttura tra Cartelle Orizzontali (Telegram), Server Rail Verticale + Canali (Discord) e Tab Minimali (WhatsApp), mostrando i badge per-account (`TG•1`, `TG•DC2`, `IRC•LIB`, `IRC•OFTC`) e adattandosi a schermo intero su Mobile. |
| `crates/warp-app/ui/chat_viewport.slint` | `PolymorphicChatViewport`: cambia bolle messaggi (`Telegram` / `DiscordFlatRow` / `WhatsAppSplit`) e nasconde/mostra dinamicamente i pulsanti in base a `ChatCapabilities` e `MessageCapabilities`. |
| `crates/warp-app/ui/app.slint` | `MainWindow`: toolbar di controllo, selettore `ChatListIsolationMode`, selettore `Account Attivi`, switch `🖥️ Desktop / 📱 Mobile`, viewport responsiva, ispettore `AuthFlowDescriptor` e modale obbligatoria **PEFL v1.0 Clausola 3**. |
| `crates/warp-app/themes/superthemes/*.toml` | Preset ergonomici/strutturali (`telegram.toml`, `discord.toml`, `whatsapp.toml`, `irc_classic.toml`). |
| `crates/warp-app/themes/palettes/*.toml` | Preset cromatici (`light_daylight.toml`, `dark_slate.toml`, `oled_pitch_black.toml`, `night_telegram.toml`, `discord_dark.toml`, `catppuccin_mocha.toml`). |

---

## 🔒 2. Matrice di Isolamento per Sub-Agenti (Cosa Toccare vs Cosa NON Toccare)

Quando viene lanciato un Sub-Agente per lavorare su una feature o su un protocollo specifico, esso deve rispettare **tassativamente** questi confini:

| Ruolo Sub-Agente | ✅ FILE CONSENTITI (Scrittura) | 🚫 FILE VIETATI (NON TOCCARE MAI) |
|---|---|---|
| **Agente Protocollo Specifico**<br>*(es. Telegram, Matrix, XMPP, Nostr, SimpleX, IRC, Stoat, Mattermost)* | **SOLO** `crates/warp-protocols/src/adapters/<protocollo>.rs` | `warp-core/*`, `warp-storage/*`, `warp-app/*`, `registry.rs`, e qualsiasi altro file adapter in `adapters/*.rs`. |
| **Agente Core SDK & Topologia** | `crates/warp-core/src/*.rs` | `crates/warp-protocols/src/adapters/*`, `crates/warp-app/ui/*`, `LICENSE*`. |
| **Agente Storage, Outbox & Media** | `crates/warp-storage/src/*.rs` | `crates/warp-protocols/src/adapters/*`, `crates/warp-app/ui/*`, `LICENSE*`. |
| **Agente UI Slint & Supertheme** | `crates/warp-app/ui/*.slint`, `crates/warp-app/src/*.rs`, `crates/warp-app/themes/**/*.toml` | `crates/warp-storage/src/*`, `crates/warp-protocols/src/adapters/*`, `LICENSE*`. |
| **Agente Packaging & Docs** | `.github/workflows/*.yml`, `packaging/**`, `scripts/**`, `README*.md`, `docs/**` | `crates/**`, `Cargo.toml`, `LICENSE*`. |

---

## 📱🌐 3. Regole Architetturali Cross-Platform (Desktop + Mobile + WebAssembly `wasm32-unknown-unknown`)

1. **Nessuna dipendenza OS-specifica non protetta da `cfg`**:
   - In `warp-core` e `warp-protocols`, le primitive compatibili con `wasm32-unknown-unknown` (`sync`, `macros`, `time`, `serde`, `bitflags`, `compact_str`) sono sempre attive, mentre i socket TCP raw (`tokio::net`) o il filesystem nativo sono usati solo quando `TransportCapabilities::RAW_TCP_TLS` o `LOCAL_FILESYSTEM_CACHE` sono presenti.
   - Su WebAssembly (`PlatformTarget::WebWasm32`), i protocolli usano WebSocket `wss://` o HTTPS REST/WebTransport.
2. **UI Slint Responsiva (`DesktopWide` vs `MobileCompactSinglePane`)**:
   - Non creare mai componenti `.slint` duplicati per Desktop e Mobile. Usa sempre `SuperTheme.is-mobile-compact` e `SuperTheme.mobile-showing-chat` in `globals.slint` per passare dal layout multi-colonna Desktop allo stack a singola schermata Mobile.
3. **Multi-Account e Separazione Liste Chat (`ChatListIsolationMode`)**:
   - Non assumere mai un solo account per protocollo (`1 ProtocolKind != 1 AccountId`).
   - Usa sempre `(AccountId, ProtocolKind)` e rispetta `ChatListIsolationMode` (`UnifiedInbox`, `PerProtocol`, `PerAccount`, `HybridCustom`).
4. **Conformità Licenza PEFL v1.0**:
   - Ogni nuovo file sorgente `.rs` o `.slint` deve iniziare con l'header ufficiale **PEFL v1.0** (`Copyright (c) 2026 Rubens Rainelli`).
   - Non rimuovere né aggirare mai il controllo EULA in primo piano della Clausola 3.

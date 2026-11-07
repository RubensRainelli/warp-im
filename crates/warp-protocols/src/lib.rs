/*
 * Personal and Educational Free License (PEF License / PEFL)
 * Version 1.0 - 2026-05-26
 * Copyright (c) 2026 Rubens Rainelli
 *
 * Contact Details:
 *   Email: rubens@rainelli.it
 *   GitHub: https://github.com/RubensRainelli/
 *   Tel: (+39) 342 811 5882
 *
 * Personal and educational free use permitted.
 * Corporate, business or enterprise use prohibited without written authorization and fee.
 * The full license can be found in the LICENSE file.
 */

//! # `warp-protocols` — Multi-Protocol Plugin Registry, 8 Adapters & Topology Simulator
//!
//! Implements the protocol plugin registry and all 8 first-class protocol adapters for **Warp IM**:
//! - **Telegram** (`proto-telegram`): MTProto `grammers` adapter with Forum Topics, `pts` state, `mtproto://` media
//! - **Matrix** (`proto-matrix`): `matrix-rust-sdk` Olm/Megolm E2EE, Matrix Spaces, Threads, `mxc://` media
//! - **XMPP** (`proto-xmpp`): `tokio-xmpp` / `xmpp-parsers` OMEMO, XEP-0308 `CAN_EDIT_ONLY_LAST`, `aesgcm://` media
//! - **Nostr** (`proto-nostr`): `nostr-sdk` NIP-17/NIP-59 Gift-Wrapped DMs & NIP-28 Channels, `blossom://` media
//! - **SimpleX** (`proto-simplex`): `simplexmq` pairwise unidirectional SMP queues without global user IDs
//! - **IRCv3** (`proto-irc`): `irc` + Soju/Ergo bouncer (`chathistory`, `message-tags`, no voice/file upload)
//! - **Stoat** (`proto-stoat`): Stoat (formerly Revolt) REST + Bonfire WebSocket, Server -> Channels (ULIDs)
//! - **Mattermost** (`proto-mattermost`): REST v4 + WebSocket, Enterprise Workspace -> Channels -> Threads

pub mod adapters;
pub mod registry;
pub mod simulator;

#[cfg(feature = "proto-telegram")]
pub use adapters::TelegramBackendEnvironment;
pub use registry::ProtocolRegistry;
pub use simulator::{
    bootstrap_live_authenticated_account, process_outbound_and_generate_protocol_response,
    seed_simulated_environment, ProtocolError, SimulatedMultiProtocolBackend,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use warp_core::{
        AccountId, ChatCapabilities, MediaAttachment, MessagingBackend, OutboundMessageRequest,
        ProtocolKind, ProtocolPlugin, SyncState, UniversalId, WarpError,
    };
    use warp_storage::{MessageDispatcher, OutboxEngine, WarpStorage};

    /// Demonstration of the Open-Closed Principle: a 9th protocol plugin registered dynamically
    /// without altering a single line of `warp-core`, `warp-storage`, or `warp-app`.
    struct NinthCustomPlugin;

    impl ProtocolPlugin for NinthCustomPlugin {
        fn protocol(&self) -> ProtocolKind {
            ProtocolKind::Custom("delta_chat".into())
        }

        fn build_backend(
            &self,
            account_id: AccountId,
            _config_json: serde_json::Value,
        ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
            Ok(Arc::new(SimulatedMultiProtocolBackend::new(
                account_id,
                self.protocol(),
            )))
        }
    }

    #[tokio::test]
    async fn all_8_protocols_seed_and_open_closed_9th_plugin_works() {
        let storage = WarpStorage::open_in_memory().expect("in-memory SQLite WAL");
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());

        assert_eq!(registry.list_registered_protocols().len(), 8);
        assert_eq!(registry.enabled_protocols().len(), 8);

        seed_simulated_environment(&storage, &registry)
            .await
            .expect("seed all 8 protocols");

        let containers = storage.list_containers(true).unwrap();
        let chats = storage.list_chats(true).unwrap();
        assert_eq!(storage.list_accounts().unwrap().len(), 10);
        assert_eq!(containers.len(), 5);
        assert_eq!(chats.len(), 13);

        // Register a 9th custom protocol plugin at runtime (Open-Closed Principle)
        registry.register_plugin(Box::new(NinthCustomPlugin));
        assert_eq!(registry.list_registered_protocols().len(), 9);

        let custom_proto = ProtocolKind::Custom("delta_chat".into());
        let custom_acc = AccountId::new("dc_acc_1");
        let custom_backend = registry
            .build_and_register_backend(&custom_proto, custom_acc.clone(), serde_json::json!({}))
            .unwrap();
        custom_backend.connect().await.unwrap();
        assert_eq!(custom_backend.sync_state(), SyncState::LiveSynced);

        // OutboxEngine works seamlessly with Arc<ProtocolRegistry> as MessageDispatcher
        let outbox = OutboxEngine::new(storage.clone(), registry.clone());
        let tg_chat_id = UniversalId::new(
            ProtocolKind::Telegram,
            "tg_main",
            "forum_-1001998877_topic_42",
        );
        let pending = outbox
            .send_optimistic(&tg_chat_id, "Rubens", "Testing MTProto outbox!".into(), None)
            .unwrap();
        assert!(pending.id.remote_id.starts_with("local-"));

        let confirmed_count = outbox.flush_once().await.unwrap();
        assert_eq!(confirmed_count, 1);
    }

    #[tokio::test]
    async fn runtime_protocol_toggle_and_capability_enforcement() {
        let storage = WarpStorage::open_in_memory().unwrap();
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        seed_simulated_environment(&storage, &registry)
            .await
            .unwrap();

        // 1. Nostr NIP-17 rejects message edits (cryptographic immutability)
        let nostr_backend = registry.get_backend(&AccountId::new("nostr_main")).unwrap();
        let nostr_chat = UniversalId::new(ProtocolKind::Nostr, "nostr_main", "peer_pk");
        let nostr_msg = UniversalId::new(ProtocolKind::Nostr, "nostr_main", "nostr_ev_501");
        let edit_res = nostr_backend
            .edit_message(&nostr_chat, &nostr_msg, "mutated")
            .await;
        assert!(matches!(edit_res, Err(WarpError::UnsupportedCapability(_))));

        // 2. IRCv3 rejects native binary file attachments
        let irc_backend = registry
            .get_backend(&AccountId::new("soju_libera"))
            .unwrap();
        let irc_chat = UniversalId::new(ProtocolKind::Irc, "soju_libera", "libera.chat/#rust-lang");
        let irc_attach_req = OutboundMessageRequest {
            local_id: UniversalId::new(ProtocolKind::Irc, "soju_libera", "local-1"),
            chat_id: irc_chat.clone(),
            thread_id: None,
            text: "binary attachment".into(),
            reply_to_id: None,
            attachments: vec![MediaAttachment {
                media_uri: "warp-media://irc/soju_libera/1".into(),
                source_url: "https://example.com/a.bin".into(),
                mime_type: "application/octet-stream".into(),
                file_name: None,
                size_bytes: 12,
                encryption_metadata: serde_json::json!({}),
            }],
            protocol_metadata: serde_json::json!({}),
        };
        assert!(matches!(
            irc_backend.send_message(irc_attach_req).await,
            Err(WarpError::UnsupportedCapability(_))
        ));

        // 3. Stoat #announcements read-only channel rejects outbound messages
        let stoat_ro_chat = UniversalId::new(
            ProtocolKind::Stoat,
            "stoat_main",
            "01H8STOATCHANannouncements_ro",
        );
        let stoat_ro_req = OutboundMessageRequest {
            local_id: UniversalId::new(ProtocolKind::Stoat, "stoat_main", "local-2"),
            chat_id: stoat_ro_chat,
            thread_id: None,
            text: "attempt write to read-only".into(),
            reply_to_id: None,
            attachments: vec![],
            protocol_metadata: serde_json::json!({}),
        };
        assert!(matches!(
            registry.dispatch(stoat_ro_req).await,
            Err(WarpError::UnsupportedCapability(_))
        ));

        // 4. Disabling a protocol at runtime pauses its backend and blocks dispatch
        registry
            .set_protocol_enabled(ProtocolKind::Matrix, false)
            .await
            .unwrap();
        assert!(!registry.is_protocol_enabled(&ProtocolKind::Matrix));
        let mx_backend = registry.get_backend(&AccountId::new("mx_org")).unwrap();
        assert_eq!(mx_backend.sync_state(), SyncState::PausedByUser);

        let mx_req = OutboundMessageRequest {
            local_id: UniversalId::new(ProtocolKind::Matrix, "mx_org", "local-3"),
            chat_id: UniversalId::new(ProtocolKind::Matrix, "mx_org", "!olm_megolm_spec:matrix.org"),
            thread_id: None,
            text: "should fail while paused".into(),
            reply_to_id: None,
            attachments: vec![],
            protocol_metadata: serde_json::json!({}),
        };
        assert!(matches!(
            registry.dispatch(mx_req).await,
            Err(WarpError::ProtocolDisabled(_))
        ));

        // Re-enabling Matrix restores LiveSynced state
        registry
            .set_protocol_enabled(ProtocolKind::Matrix, true)
            .await
            .unwrap();
        assert_eq!(mx_backend.sync_state(), SyncState::LiveSynced);
        assert!(ChatCapabilities::irc_channel(true).contains(ChatCapabilities::CAN_EDIT_ONLY_LAST));
    }

    #[tokio::test]
    async fn test_in_app_signup_across_supported_protocols_and_telegram_bot_login() {
        use warp_core::{AuthFlowDescriptor, AuthStep, AuthStepSubmission, OnboardingMode};

        let storage = WarpStorage::open_in_memory().unwrap();
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        seed_simulated_environment(&storage, &registry)
            .await
            .unwrap();

        // Telegram is Login-Only (User Phone+OTP or Bot Token), whereas the other 7 support in-app Sign-Up
        assert!(!AuthFlowDescriptor::supports_in_app_signup(&ProtocolKind::Telegram));
        assert!(AuthFlowDescriptor::supports_bot_token_login(&ProtocolKind::Telegram));
        for proto in [
            ProtocolKind::Matrix,
            ProtocolKind::Xmpp,
            ProtocolKind::Nostr,
            ProtocolKind::SimpleX,
            ProtocolKind::Irc,
            ProtocolKind::Stoat,
            ProtocolKind::Mattermost,
        ] {
            assert!(AuthFlowDescriptor::supports_in_app_signup(&proto));
        }

        // 1. Matrix Sign-Up
        let mx = registry.get_backend(&AccountId::new("mx_org")).unwrap();
        let mut mx_sub = AuthStepSubmission::default();
        mx_sub.values.insert("onboarding_mode".into(), "signup".into());
        mx_sub.values.insert("homeserver_url".into(), "https://matrix.org".into());
        mx_sub.values.insert("username".into(), "new_warp_user".into());
        mx_sub.values.insert("password".into(), "StrongSecret123!".into());
        let mx_res = mx.submit_auth_step("signup-matrix-cs", mx_sub).await.unwrap();
        assert!(matches!(mx_res.current_step, AuthStep::Completed { .. }));

        // 2. XMPP XEP-0077 In-Band Registration Sign-Up
        let xmpp = registry.get_backend(&AccountId::new("xmpp_work")).unwrap();
        let mut xm_sub = AuthStepSubmission::default();
        xm_sub.values.insert("onboarding_mode".into(), "signup".into());
        xm_sub.values.insert("server_domain".into(), "conversations.im".into());
        xm_sub.values.insert("username".into(), "alice_ibr".into());
        xm_sub.values.insert("password".into(), "XmppSecret123!".into());
        let xm_res = xmpp.submit_auth_step("signup-xmpp-ibr", xm_sub).await.unwrap();
        assert!(matches!(xm_res.current_step, AuthStep::Completed { .. }));

        // 3. Nostr Local Keypair + Kind 0 Sign-Up
        let nostr = registry.get_backend(&AccountId::new("nostr_main")).unwrap();
        let mut no_sub = AuthStepSubmission::default();
        no_sub.values.insert("onboarding_mode".into(), "signup".into());
        no_sub.values.insert("display_name".into(), "Rubens Nostr".into());
        let no_res = nostr.submit_auth_step("signup-nostr-keygen", no_sub).await.unwrap();
        assert!(matches!(no_res.current_step, AuthStep::Completed { .. }));

        // 4. SimpleX Anonymous Profile Sign-Up
        let sx = registry.get_backend(&AccountId::new("smp_anon")).unwrap();
        let mut sx_sub = AuthStepSubmission::default();
        sx_sub.values.insert("onboarding_mode".into(), "signup".into());
        sx_sub.values.insert("display_name".into(), "anon_warp".into());
        let sx_res = sx.submit_auth_step("signup-simplex-profile", sx_sub).await.unwrap();
        assert!(matches!(sx_res.current_step, AuthStep::Completed { .. }));

        // 5. IRCv3 NickServ / Ergo ACCTREG Sign-Up
        let irc = registry.get_backend(&AccountId::new("soju_libera")).unwrap();
        let mut irc_sub = AuthStepSubmission::default();
        irc_sub.values.insert("onboarding_mode".into(), "signup".into());
        irc_sub.values.insert("nickname".into(), "warp_nick".into());
        irc_sub.values.insert("password".into(), "IrcPass123!".into());
        irc_sub.values.insert("email".into(), "warp@example.org".into());
        let irc_res = irc.submit_auth_step("signup-ircv3-acctreg", irc_sub).await.unwrap();
        assert!(matches!(irc_res.current_step, AuthStep::Completed { .. }));

        // 6. Stoat Account Sign-Up
        let stoat = registry.get_backend(&AccountId::new("stoat_main")).unwrap();
        let mut st_sub = AuthStepSubmission::default();
        st_sub.values.insert("onboarding_mode".into(), "signup".into());
        st_sub.values.insert("username".into(), "warp_pilot".into());
        st_sub.values.insert("email".into(), "pilot@stoat.chat".into());
        st_sub.values.insert("password".into(), "StoatPass123!".into());
        let st_res = stoat.submit_auth_step("signup-stoat-account", st_sub).await.unwrap();
        assert!(matches!(st_res.current_step, AuthStep::Completed { .. }));

        // 7. Mattermost User Sign-Up
        let mm = registry.get_backend(&AccountId::new("mm_corp")).unwrap();
        let mut mm_sub = AuthStepSubmission::default();
        mm_sub.values.insert("onboarding_mode".into(), "signup".into());
        mm_sub.values.insert("username".into(), "devops_warp".into());
        mm_sub.values.insert("email".into(), "devops@acme.corp".into());
        mm_sub.values.insert("password".into(), "MmPass123!".into());
        let mm_res = mm.submit_auth_step("signup-mattermost-v4", mm_sub).await.unwrap();
        assert!(matches!(mm_res.current_step, AuthStep::Completed { .. }));

        // 8. Telegram Bot Token Descriptor & Login
        let bot_desc = AuthFlowDescriptor::for_protocol_and_mode(
            ProtocolKind::Telegram,
            OnboardingMode::TelegramBotToken,
            false,
        );
        assert!(matches!(bot_desc.current_step, AuthStep::TelegramBotToken { .. }));
    }

    #[tokio::test]
    async fn bootstrap_live_authenticated_account_populates_initial_chats_and_folders() {
        use std::collections::BTreeMap;

        let storage = WarpStorage::open_in_memory().unwrap();
        let registry = ProtocolRegistry::with_compiled_plugins();

        // Start from a completely empty first-run database
        assert!(storage.list_accounts().unwrap().is_empty());
        assert!(storage.list_folders().unwrap().is_empty());

        let mut tg_inputs = BTreeMap::new();
        tg_inputs.insert("onboarding_mode".into(), "bot_token".into());
        tg_inputs.insert("bot_token".into(), "123456:ABC-DEF".into());
        let tg_acc = AccountId::new("tg_bot_live");
        let tg_primary = bootstrap_live_authenticated_account(
            &storage,
            &registry,
            ProtocolKind::Telegram,
            &tg_acc,
            "Telegram • @warp_bot",
            &tg_inputs,
        )
        .await
        .unwrap();

        assert_eq!(tg_primary.title.as_str(), "★ Messaggi Salvati (Cloud)");
        assert_eq!(storage.list_accounts().unwrap().len(), 1);
        assert_eq!(storage.list_folders().unwrap().len(), 4);
        assert_eq!(storage.list_chats(true).unwrap().len(), 2);

        let mut irc_inputs = BTreeMap::new();
        irc_inputs.insert("server_url".into(), "ircs://irc.libera.chat:6697".into());
        irc_inputs.insert("channel".into(), "#warp-im".into());
        let irc_acc = AccountId::new("irc_live_1");
        let irc_primary = bootstrap_live_authenticated_account(
            &storage,
            &registry,
            ProtocolKind::Irc,
            &irc_acc,
            "IRCv3 • Libera",
            &irc_inputs,
        )
        .await
        .unwrap();

        assert_eq!(irc_primary.title.as_str(), "#warp-im");
        assert_eq!(storage.list_accounts().unwrap().len(), 2);
        assert!(!storage.list_containers(true).unwrap().is_empty());
    }
}


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

//! # `warp-storage` — Unified SQLite WAL Storage, Transactional Outbox & Media Proxy
//!
//! Implements the persistence, optimistic delivery, and media decryption layers for **Warp IM**:
//! - [`db::WarpStorage`]: Polymorphic SQLite WAL database supporting 1-to-3 level
//!   `ContainerHierarchy`, per-protocol runtime toggles, `protocol_metadata` JSON extensibility,
//!   binary protocol KV state, granular folder rules, and composite-indexed message queries.
//! - [`outbox::OutboxEngine`]: Transactional Outbox guaranteeing `< 1ms` local echo
//!   (`DeliveryState::Pending`) with asynchronous reconciliation (`DeliveryState::Sent`)
//!   and exponential backoff retries (`500ms * 2^attempt`).
//! - [`media_proxy::MediaProxy`]: On-the-fly in-RAM media decryption proxy for
//!   `warp-media://<protocol>/<account_id>/<media_id>` across MTProto, Matrix Megolm,
//!   XMPP OMEMO AES-GCM, Nostr Blossom, and HTTP Bearer streams.

pub mod db;
pub mod media_proxy;
pub mod outbox;

pub use db::{AccountRecord, OutboxQueueItem, StorageError, WarpStorage};
pub use media_proxy::MediaProxy;
pub use outbox::{MessageDispatcher, OutboxEngine};

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use compact_str::CompactString;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use warp_core::{
        AccountId, ChatCapabilities, ChatTopologyKind, ContainerHierarchy, ContainerKind,
        DeliveryState, FolderFilterRule, MediaAttachment, MessageCapabilities,
        OutboundMessageRequest, ProtocolKind, UnifiedChat, UnifiedContainer, UnifiedMessage,
        UniversalId, WarpError,
    };

    struct MockDispatcher {
        should_fail: AtomicBool,
    }

    #[async_trait]
    impl MessageDispatcher for MockDispatcher {
        async fn dispatch(&self, req: OutboundMessageRequest) -> Result<UniversalId, WarpError> {
            if self.should_fail.load(Ordering::SeqCst) {
                Err(WarpError::Transport("simulated relay timeout".to_string()))
            } else {
                Ok(UniversalId::new(
                    req.chat_id.protocol.clone(),
                    req.chat_id.account_id.clone(),
                    "remote-confirmed-999",
                ))
            }
        }
    }

    #[test]
    fn sqlite_protocol_toggles_and_3_level_hierarchy_roundtrip() {
        let storage = WarpStorage::open_in_memory().expect("in-memory SQLite should initialize");

        // All 8 built-in protocols should be enabled by default.
        let enabled = storage.list_enabled_protocols().unwrap();
        assert_eq!(enabled.len(), 8);
        assert!(storage.is_protocol_enabled(&ProtocolKind::Irc).unwrap());

        // Upsert accounts.
        let tg_acc = AccountId::new("tg_main");
        let irc_acc = AccountId::new("soju_libera");
        storage
            .upsert_account(&tg_acc, &ProtocolKind::Telegram, "Telegram Personal", true, "{}")
            .unwrap();
        storage
            .upsert_account(&irc_acc, &ProtocolKind::Irc, "Libera.Chat Bouncer", true, "{}")
            .unwrap();
        assert_eq!(storage.list_accounts().unwrap().len(), 2);

        // Insert a Level-1 IRC Network Container and a Level-2 IRC Channel.
        let irc_net_id = UniversalId::new(ProtocolKind::Irc, "soju_libera", "net_libera");
        let irc_chan_id = UniversalId::new(ProtocolKind::Irc, "soju_libera", "#rust-lang");
        let container = UnifiedContainer {
            id: irc_net_id.clone(),
            kind: ContainerKind::IrcNetwork,
            title: CompactString::from("Libera.Chat"),
            icon_initials: CompactString::from("LC"),
            avatar_url: None,
            unread_count: 3,
            mention_count: 1,
            child_chat_ids: vec![irc_chan_id.clone()],
            protocol_metadata: serde_json::json!({ "bouncer": "soju", "chathistory": true }),
        };
        storage.upsert_container(&container).unwrap();

        let tg_chat_id = UniversalId::new(ProtocolKind::Telegram, "tg_main", "-100123456");
        let tg_chat = UnifiedChat {
            id: tg_chat_id.clone(),
            parent_container_id: None,
            parent_chat_id: None,
            topology: ChatTopologyKind::DirectMessage,
            hierarchy: ContainerHierarchy::Flat {
                is_direct_message: true,
            },
            title: CompactString::from("Alice (Telegram)"),
            subtitle: Some(CompactString::from("online")),
            avatar_initials: CompactString::from("AT"),
            avatar_url: None,
            last_message_preview: Some(CompactString::from("Hello from MTProto")),
            last_activity_ts: 1_700_000_200_000,
            unread_count: 1,
            mention_count: 0,
            is_pinned: true,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured(),
            protocol_metadata: serde_json::json!({ "access_hash": 918273645_i64 }),
        };
        storage.upsert_chat(&tg_chat).unwrap();

        let irc_chat = UnifiedChat {
            id: irc_chan_id.clone(),
            parent_container_id: Some(irc_net_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id: irc_net_id.clone(),
                container_kind: ContainerKind::IrcNetwork,
                category_name: Some(CompactString::from("Channels")),
            },
            title: CompactString::from("#rust-lang"),
            subtitle: Some(CompactString::from("Rust Programming Language")),
            avatar_initials: CompactString::from("RL"),
            avatar_url: None,
            last_message_preview: Some(CompactString::from("cargo check passed")),
            last_activity_ts: 1_700_000_100_000,
            unread_count: 3,
            mention_count: 1,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::irc_channel(true),
            protocol_metadata: serde_json::json!({ "isupport": ["CHATHISTORY", "UTF8ONLY"] }),
        };
        storage.upsert_chat(&irc_chat).unwrap();

        assert_eq!(storage.list_chats(true).unwrap().len(), 2);
        assert_eq!(storage.list_containers(true).unwrap().len(), 1);

        // Disable IRCv3 protocol at runtime: IRC containers and chats must be filtered out
        // when `only_enabled_protocols = true`, while preserved on disk when `false`.
        storage
            .set_protocol_enabled(&ProtocolKind::Irc, false)
            .unwrap();
        assert!(!storage.is_protocol_enabled(&ProtocolKind::Irc).unwrap());
        assert_eq!(storage.list_chats(true).unwrap().len(), 1);
        assert_eq!(storage.list_chats(false).unwrap().len(), 2);
        assert_eq!(storage.list_containers(true).unwrap().len(), 0);
        assert_eq!(storage.list_containers(false).unwrap().len(), 1);
    }

    #[test]
    fn indexed_messages_chronological_order_and_kv_folders() {
        let storage = WarpStorage::open_in_memory().unwrap();
        let chat_id = UniversalId::new(ProtocolKind::Matrix, "mx_org", "!room:matrix.org");

        for idx in 1..=5 {
            let msg = UnifiedMessage {
                id: UniversalId::new(ProtocolKind::Matrix, "mx_org", format!("$event_{idx}")),
                local_outbox_id: None,
                chat_id: chat_id.clone(),
                thread_id: None,
                sender_id: CompactString::from("@user:matrix.org"),
                sender_display_name: CompactString::from("Matrix User"),
                sender_initials: CompactString::from("MU"),
                sender_avatar_url: None,
                is_outgoing: false,
                text: format!("Message #{idx}"),
                reply_to_id: None,
                reply_preview: None,
                timestamp_ms: 1_700_000_000_000 + (idx * 1000),
                edited_at_ms: None,
                delivery_state: DeliveryState::Delivered,
                reactions: Vec::new(),
                attachments: Vec::new(),
                capabilities: MessageCapabilities::CAN_REACT | MessageCapabilities::CAN_REPLY_QUOTE,
                protocol_metadata: serde_json::json!({ "megolm_session_id": "sess_abc" }),
            };
            storage.upsert_message(&msg).unwrap();
        }

        // Request latest 3 messages: should return #3, #4, #5 in ascending chronological order.
        let recent = storage.list_messages(&chat_id, 3).unwrap();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].text, "Message #3");
        assert_eq!(recent[1].text, "Message #4");
        assert_eq!(recent[2].text, "Message #5");

        // Binary KV state roundtrip.
        let acc = AccountId::new("mx_org");
        storage
            .set_kv_state(&acc, &ProtocolKind::Matrix, "sync_batch_token", b"s72595_1938")
            .unwrap();
        let token = storage
            .get_kv_state(&acc, &ProtocolKind::Matrix, "sync_batch_token")
            .unwrap();
        assert_eq!(token.as_deref(), Some(b"s72595_1938".as_slice()));

        // Folder filter rule roundtrip.
        let folder = FolderFilterRule {
            id: CompactString::from("folder_e2ee"),
            name: CompactString::from("Encrypted"),
            icon: CompactString::from("🔒"),
            included_protocols: vec![
                ProtocolKind::Matrix,
                ProtocolKind::SimpleX,
                ProtocolKind::Nostr,
            ],
            included_accounts: Vec::new(),
            included_topologies: Vec::new(),
            container_filter: None,
            pinned_chat_ids: Vec::new(),
            excluded_chat_ids: Vec::new(),
            unread_only: false,
        };
        storage.upsert_folder(1, &folder).unwrap();
        let folders = storage.list_folders().unwrap();
        assert_eq!(folders, vec![folder]);
    }

    #[test]
    fn multi_account_same_protocol_and_chat_list_isolation_modes() {
        use warp_core::{AccountProfile, ChatListIsolationMode};

        let storage = WarpStorage::open_in_memory().unwrap();
        let tg_personal = AccountId::new("tg_personal");
        let tg_work_dc2 = AccountId::new("tg_work_dc2");
        let irc_libera = AccountId::new("irc_libera");

        storage
            .upsert_account_profile(
                &AccountProfile {
                    account_id: tg_personal.clone(),
                    protocol: ProtocolKind::Telegram,
                    display_name: "Telegram • Personale".into(),
                    handle_or_uri: "@rubens_personal".into(),
                    short_badge: "TG•1".into(),
                    enabled: true,
                    include_in_unified_inbox: true,
                    sort_order: 1,
                },
                "{}",
            )
            .unwrap();
        storage
            .upsert_account_profile(
                &AccountProfile {
                    account_id: tg_work_dc2.clone(),
                    protocol: ProtocolKind::Telegram,
                    display_name: "Telegram • Work DC2".into(),
                    handle_or_uri: "+9996621234".into(),
                    short_badge: "TG•2".into(),
                    enabled: true,
                    include_in_unified_inbox: true,
                    sort_order: 2,
                },
                "{}",
            )
            .unwrap();
        storage
            .upsert_account_profile(
                &AccountProfile {
                    account_id: irc_libera.clone(),
                    protocol: ProtocolKind::Irc,
                    display_name: "IRCv3 • Libera".into(),
                    handle_or_uri: "ircs://irc.libera.chat".into(),
                    short_badge: "IRC".into(),
                    enabled: true,
                    include_in_unified_inbox: true,
                    sort_order: 3,
                },
                "{}",
            )
            .unwrap();

        let make_chat = |proto: ProtocolKind, acc: &str, remote: &str, title: &str| UnifiedChat {
            id: UniversalId::new(proto, acc, remote),
            parent_container_id: None,
            parent_chat_id: None,
            topology: ChatTopologyKind::DirectMessage,
            hierarchy: ContainerHierarchy::Flat {
                is_direct_message: true,
            },
            title: CompactString::from(title),
            subtitle: None,
            avatar_initials: "CH".into(),
            avatar_url: None,
            last_message_preview: None,
            last_activity_ts: 1_730_000_000_000,
            unread_count: 1,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured(),
            protocol_metadata: serde_json::json!({}),
        };

        storage
            .upsert_chat(&make_chat(
                ProtocolKind::Telegram,
                "tg_personal",
                "chat_family",
                "Family Group",
            ))
            .unwrap();
        storage
            .upsert_chat(&make_chat(
                ProtocolKind::Telegram,
                "tg_work_dc2",
                "chat_dc2_lab",
                "DC2 Engineering",
            ))
            .unwrap();
        storage
            .upsert_chat(&make_chat(
                ProtocolKind::Irc,
                "irc_libera",
                "#rust",
                "#rust",
            ))
            .unwrap();

        // 1. UnifiedInbox: all 3 chats from all 3 accounts appear together
        let unified = storage
            .list_chats_by_isolation(ChatListIsolationMode::UnifiedInbox, None, None)
            .unwrap();
        assert_eq!(unified.len(), 3);

        // 2. PerProtocol (Telegram): both Telegram accounts appear (2 chats), IRC is excluded
        let per_proto_tg = storage
            .list_chats_by_isolation(
                ChatListIsolationMode::PerProtocol,
                Some(&ProtocolKind::Telegram),
                None,
            )
            .unwrap();
        assert_eq!(per_proto_tg.len(), 2);

        // 3. PerAccount (Strict Isolation for users who hate unified views):
        // Selecting tg_work_dc2 shows ONLY tg_work_dc2's chat (1 chat), strictly separated from tg_personal!
        let per_acc_dc2 = storage
            .list_chats_by_isolation(
                ChatListIsolationMode::PerAccount,
                None,
                Some(&tg_work_dc2),
            )
            .unwrap();
        assert_eq!(per_acc_dc2.len(), 1);
        assert_eq!(per_acc_dc2[0].account_id(), &tg_work_dc2);

        // 4. Exclude tg_work_dc2 from UnifiedInbox -> UnifiedInbox now has 2 chats, while PerAccount still has 1
        storage
            .set_account_unified_inclusion(&tg_work_dc2, false)
            .unwrap();
        let unified_after_exclusion = storage
            .list_chats_by_isolation(ChatListIsolationMode::UnifiedInbox, None, None)
            .unwrap();
        assert_eq!(unified_after_exclusion.len(), 2);
        assert!(!unified_after_exclusion
            .iter()
            .any(|c| c.account_id() == &tg_work_dc2));

        // 5. Disable only tg_personal account -> tg_work_dc2 remains enabled
        storage.set_account_enabled(&tg_personal, false).unwrap();
        let remaining_enabled = storage.list_chats(true).unwrap();
        assert_eq!(remaining_enabled.len(), 2);
        assert!(!remaining_enabled
            .iter()
            .any(|c| c.account_id() == &tg_personal));
    }

    #[tokio::test]
    async fn transactional_outbox_optimistic_echo_retry_and_confirmation() {
        let storage = WarpStorage::open_in_memory().unwrap();
        let dispatcher = Arc::new(MockDispatcher {
            should_fail: AtomicBool::new(true),
        });
        let outbox = OutboxEngine::new(storage.clone(), dispatcher.clone());

        let chat_id = UniversalId::new(ProtocolKind::Nostr, "npub_local", "pubkey_hex_peer");
        let optimistic = outbox
            .send_optimistic(&chat_id, "Satoshi", "NIP-17 gift wrap test".to_string(), None)
            .unwrap();

        assert_eq!(optimistic.delivery_state, DeliveryState::Pending);
        let msgs = storage.list_messages(&chat_id, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].delivery_state, DeliveryState::Pending);

        // 1st flush fails -> scheduled with exponential backoff (attempt = 1, DeliveryState::Sending(1)).
        let confirmed = outbox.flush_once().await.unwrap();
        assert_eq!(confirmed, 0);
        let msgs_after_fail = storage.list_messages(&chat_id, 10).unwrap();
        assert_eq!(msgs_after_fail[0].delivery_state, DeliveryState::Sending(1));

        // Enable dispatcher success and flush past the backoff window.
        dispatcher.should_fail.store(false, Ordering::SeqCst);
        let future_now = db::now_unix_ms() + 5_000;
        let confirmed_retry = outbox.flush_due_at(future_now).await.unwrap();
        assert_eq!(confirmed_retry, 1);

        let msgs_final = storage.list_messages(&chat_id, 10).unwrap();
        assert_eq!(msgs_final.len(), 1);
        assert_eq!(msgs_final[0].delivery_state, DeliveryState::Sent);
        assert_eq!(msgs_final[0].id.remote_id.as_str(), "remote-confirmed-999");
        assert!(storage.fetch_due_outbox_items(future_now + 10_000).unwrap().is_empty());
    }

    #[tokio::test]
    async fn media_proxy_in_ram_decryption_and_cache() {
        let proxy = MediaProxy::new();
        let acc = AccountId::new("xmpp_work");
        let uri = MediaProxy::format_uri(&ProtocolKind::Xmpp, &acc, "omemo_img_42");

        let attachment = MediaAttachment {
            media_uri: uri.clone(),
            source_url: CompactString::from("aesgcm://upload.montague.lit/f/42#key_iv_hex"),
            mime_type: CompactString::from("image/webp"),
            file_name: Some(CompactString::from("diagram.webp")),
            size_bytes: 4096,
            encryption_metadata: serde_json::json!({ "cipher": "AES-256-GCM" }),
        };

        assert_eq!(proxy.cached_count(), 0);
        let resolved = proxy.resolve(&attachment).await.unwrap();
        assert_eq!(resolved.media_uri, uri);
        assert!(!resolved.bytes.is_empty());
        assert_eq!(proxy.cached_count(), 1);

        // Subsequent resolution hits RAM cache directly.
        let cached_hit = proxy.resolve(&attachment).await.unwrap();
        assert_eq!(cached_hit, resolved);
    }

    #[test]
    fn user_chat_creation_message_mutations_account_deletion_and_reset() {
        let storage = WarpStorage::open_in_memory().unwrap();
        let acc1 = AccountId::new("tg_user_live");
        let acc2 = AccountId::new("irc_user_live");

        storage
            .upsert_account(&acc1, &ProtocolKind::Telegram, "Telegram Live", true, "{}")
            .unwrap();
        storage
            .upsert_account(&acc2, &ProtocolKind::Irc, "IRC Live", true, "{}")
            .unwrap();

        // App settings roundtrip
        assert_eq!(storage.get_app_setting("send_shortcut_mode").unwrap(), None);
        storage
            .set_app_setting("send_shortcut_mode", "ctrl_enter")
            .unwrap();
        assert_eq!(
            storage.get_app_setting("send_shortcut_mode").unwrap().as_deref(),
            Some("ctrl_enter")
        );

        // 1. create_user_chat creates the chat + welcome message with protocol capabilities
        let tg_chat = storage
            .create_user_chat(
                &acc1,
                ProtocolKind::Telegram,
                "📌 Messaggi Salvati",
                "saved_messages",
                false,
            )
            .unwrap();
        assert_eq!(tg_chat.title.as_str(), "📌 Messaggi Salvati");
        assert!(tg_chat.capabilities.contains(ChatCapabilities::CAN_EDIT));
        assert!(tg_chat.capabilities.contains(ChatCapabilities::CAN_SEND_VOICE));

        let irc_chat = storage
            .create_user_chat(
                &acc2,
                ProtocolKind::Irc,
                "#warp-im",
                "irc.libera.chat/#warp-im",
                true,
            )
            .unwrap();
        assert!(!irc_chat.capabilities.contains(ChatCapabilities::CAN_SEND_VOICE));
        assert!(irc_chat
            .capabilities
            .contains(ChatCapabilities::CAN_EDIT_ONLY_LAST));

        let tg_msgs = storage.list_messages(&tg_chat.id, 10).unwrap();
        assert_eq!(tg_msgs.len(), 1);
        let welcome_msg_id = tg_msgs[0].id.clone();

        // 2. update_message_text updates text, sets edited_at_ms, and updates parent chat preview
        storage
            .update_message_text(&welcome_msg_id, "Messaggio modificato dal test!")
            .unwrap();
        let edited_msgs = storage.list_messages(&tg_chat.id, 10).unwrap();
        assert_eq!(edited_msgs[0].text, "Messaggio modificato dal test!");
        assert!(edited_msgs[0].edited_at_ms.is_some());
        let refreshed_chat = storage.get_chat(&tg_chat.id).unwrap().unwrap();
        assert_eq!(
            refreshed_chat.last_message_preview.as_deref(),
            Some("Messaggio modificato dal test!")
        );

        // 3. toggle_message_reaction adds and removes reaction cleanly
        storage
            .toggle_message_reaction(&welcome_msg_id, "🔥", "tg_user_live")
            .unwrap();
        let after_react = storage.list_messages(&tg_chat.id, 10).unwrap();
        assert_eq!(after_react[0].reactions.len(), 1);
        assert_eq!(after_react[0].reactions[0].emoji.as_str(), "🔥");
        assert_eq!(after_react[0].reactions[0].count, 1);
        assert!(after_react[0].reactions[0].reacted_by_me);

        storage
            .toggle_message_reaction(&welcome_msg_id, "🔥", "tg_user_live")
            .unwrap();
        let after_unreact = storage.list_messages(&tg_chat.id, 10).unwrap();
        assert!(after_unreact[0].reactions.is_empty());

        // 4. toggle_chat_pinned and mark_chat_read
        let pinned_now = storage.toggle_chat_pinned(&tg_chat.id).unwrap();
        assert!(pinned_now);
        assert!(storage.get_chat(&tg_chat.id).unwrap().unwrap().is_pinned);
        storage.mark_chat_read(&tg_chat.id).unwrap();
        assert_eq!(
            storage.get_chat(&tg_chat.id).unwrap().unwrap().unread_count,
            0
        );

        // 5. delete_message removes message and updates chat preview
        storage.delete_message(&welcome_msg_id).unwrap();
        assert!(storage.list_messages(&tg_chat.id, 10).unwrap().is_empty());
        assert!(storage
            .get_chat(&tg_chat.id)
            .unwrap()
            .unwrap()
            .last_message_preview
            .is_none());

        // 6. delete_account removes only acc1 and its chats/messages, leaving acc2 intact
        storage.delete_account(&acc1).unwrap();
        let remaining_accs = storage.list_accounts().unwrap();
        assert_eq!(remaining_accs.len(), 1);
        assert_eq!(remaining_accs[0].account_id, acc2);
        assert!(storage.get_chat(&tg_chat.id).unwrap().is_none());
        assert!(storage.get_chat(&irc_chat.id).unwrap().is_some());

        // 7. clear_all_user_and_demo_data wipes all accounts, chats, containers, messages, and resets demo_mode_active
        storage.set_app_setting("demo_mode_active", "true").unwrap();
        storage.clear_all_user_and_demo_data().unwrap();
        assert!(storage.list_accounts().unwrap().is_empty());
        assert!(storage.list_chats(false).unwrap().is_empty());
        assert!(storage.list_containers(false).unwrap().is_empty());
        assert_eq!(
            storage.get_app_setting("demo_mode_active").unwrap().as_deref(),
            Some("false")
        );
    }

    #[test]
    fn media_attachments_clear_history_delete_chat_and_account_config_json() {
        let storage = WarpStorage::open_in_memory().unwrap();
        let acc = AccountId::new("tg_bot_live");

        storage
            .upsert_account(
                &acc,
                &ProtocolKind::Telegram,
                "Telegram Bot",
                true,
                r#"{"bot_token":"123456789:AAH_test_secret_token","server_host":"api.telegram.org"}"#,
            )
            .unwrap();

        let cfg = storage
            .get_account_config_json(&acc)
            .unwrap()
            .expect("config json should exist");
        assert_eq!(
            cfg.get("bot_token").and_then(|v| v.as_str()),
            Some("123456789:AAH_test_secret_token")
        );
        assert!(storage
            .get_account_config_json(&AccountId::new("nonexistent"))
            .unwrap()
            .is_none());

        let chat = storage
            .create_user_chat(&acc, ProtocolKind::Telegram, "Marco Rossi", "35827073", false)
            .unwrap();
        let chat_uri = chat.id.to_uri();

        // Send voice note, image, and document attachments
        let voice_msg = storage
            .send_media_attachment_message(
                &chat.id,
                "Rubens",
                "voice",
                "nota_vocale.ogg",
                "Test audio",
                1_730_920_000_000,
            )
            .unwrap();
        assert!(voice_msg.text.contains("🎤 Nota Vocale"));
        assert_eq!(voice_msg.attachments.len(), 1);
        assert_eq!(voice_msg.attachments[0].mime_type.as_str(), "audio/ogg; codecs=opus");

        let img_msg = storage
            .send_media_attachment_message(
                &chat.id,
                "Rubens",
                "image",
                "screenshot.png",
                "",
                1_730_920_001_000,
            )
            .unwrap();
        assert!(img_msg.text.contains("🖼️ Immagine"));
        assert_eq!(img_msg.attachments.len(), 1);

        let file_msg = storage
            .send_media_attachment_message(
                &chat.id,
                "Rubens",
                "file",
                "architettura.pdf",
                "Specifica v1",
                1_730_920_002_000,
            )
            .unwrap();
        assert!(file_msg.text.contains("📎 Allegato"));
        assert_eq!(file_msg.attachments[0].mime_type.as_str(), "application/pdf");

        assert_eq!(storage.list_messages(&chat.id, 20).unwrap().len(), 4);

        // Clear chat history -> 0 messages, preview becomes "Nessun messaggio"
        storage.clear_chat_history(&chat_uri).unwrap();
        assert!(storage.list_messages(&chat.id, 20).unwrap().is_empty());
        let cleared_chat = storage.get_chat(&chat.id).unwrap().unwrap();
        assert_eq!(
            cleared_chat.last_message_preview.as_deref(),
            Some("Nessun messaggio")
        );

        // Delete chat -> removed from chats table
        storage.delete_chat(&chat_uri).unwrap();
        assert!(storage.get_chat(&chat.id).unwrap().is_none());
    }
}



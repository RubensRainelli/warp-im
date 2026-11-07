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

//! 16ms Event Coalescer (`Tokio <-> Slint`) & Capability Mapper.
//!
//! Ensures zero UI thread blocking and 60/120Hz frame pacing:
//! - No network adapter ever touches Slint directly.
//! - All [`BackendEvent`]s from `ProtocolRegistry` are buffered in Tokio and coalesced
//!   in 16ms windows before invoking `slint::invoke_from_event_loop` in a single batch.
//! - Maps [`ChatCapabilities`] and [`MessageCapabilities`] directly into Slint properties.

use crate::theme_manager::{parse_hex_color, ThemeManager};
use crate::{
    MainWindow, SuperTheme, UiAccountItem, UiActiveChatCapabilities, UiAuthFieldItem,
    UiChatListItem, UiFolderTabItem, UiMessageItem, UiProtocolToggleItem, UiServerRailItem,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use warp_core::{
    AccountId, AuthFlowDescriptor, AuthStep, BackendEvent, ChatCapabilities, ChatListIsolationMode,
    MessageCapabilities, OnboardingMode, ProtocolKind, UnifiedChat, UnifiedContainer, UniversalId,
};
use warp_protocols::{
    bootstrap_live_authenticated_account, process_outbound_and_generate_protocol_response,
    seed_simulated_environment, ProtocolRegistry, TelegramBackendEnvironment,
};
use warp_storage::{OutboxEngine, WarpStorage};

/// Commands sent from Slint UI callbacks into the asynchronous Tokio bridge.
#[derive(Debug, Clone)]
pub enum UiBridgeCommand {
    SendMessage {
        chat_uri: String,
        text: String,
        reply_preview: Option<String>,
    },
    SendAttachment {
        chat_uri: String,
        kind: String,
    },
    ToggleProtocol {
        protocol_slug: String,
        enabled: bool,
    },
    ToggleAccountEnabled {
        account_id: String,
        enabled: bool,
    },
    RemoveAccount {
        account_id: String,
    },
    SwitchIsolationMode {
        mode_slug: String,
    },
    SwitchTelegramBackendMode {
        mode_slug: String,
    },
    ReactToMessage {
        chat_uri: String,
        message_uri: String,
        emoji: String,
    },
    DeleteMessage {
        chat_uri: String,
        message_uri: String,
    },
    EditMessage {
        chat_uri: String,
        message_uri: String,
        new_text: String,
    },
    TogglePinChat {
        chat_uri: String,
    },
    ClearChatHistory {
        chat_uri: String,
    },
    DeleteActiveChat {
        chat_uri: String,
    },
    CreateNewChat {
        account_id: String,
        title: String,
        remote_target: String,
        is_group: bool,
    },
    SubmitAuthModal {
        protocol: ProtocolKind,
        mode: OnboardingMode,
        inputs: std::collections::BTreeMap<String, String>,
    },
    ActivateDemoMockup,
    ExitDemoMockup,
    ForceRefresh,
}

/// Shared UI filter selection state (including Multi-Account & Chat List Isolation Mode).
#[derive(Debug, Clone)]
pub struct UiSelectionState {
    pub isolation_mode: ChatListIsolationMode,
    pub active_account_id: String,
    pub active_protocol_filter: ProtocolKind,
    pub active_folder_id: String,
    pub active_container_uri: String,
    pub active_chat_uri: String,
    pub telegram_backend_mode: String,
    pub search_query: String,
    pub send_on_enter: bool,
}

impl Default for UiSelectionState {
    fn default() -> Self {
        Self {
            isolation_mode: ChatListIsolationMode::UnifiedInbox,
            active_account_id: "tg_main".to_string(),
            active_protocol_filter: ProtocolKind::Telegram,
            active_folder_id: "all".to_string(),
            active_container_uri: String::new(),
            active_chat_uri: String::new(),
            telegram_backend_mode: "public".to_string(),
            search_query: String::new(),
            send_on_enter: true,
        }
    }
}

/// Maps `warp_core::ChatCapabilities` bitflags into the Slint `UiActiveChatCapabilities` struct.
pub fn map_chat_capabilities_to_ui(caps: ChatCapabilities) -> UiActiveChatCapabilities {
    UiActiveChatCapabilities {
        can_send_messages: caps.contains(ChatCapabilities::CAN_SEND_MESSAGES),
        can_edit: caps.contains(ChatCapabilities::CAN_EDIT),
        can_edit_only_last: caps.contains(ChatCapabilities::CAN_EDIT_ONLY_LAST),
        can_delete_for_all: caps.contains(ChatCapabilities::CAN_DELETE_FOR_ALL),
        can_react: caps.contains(ChatCapabilities::CAN_REACT),
        can_reply_quote: caps.contains(ChatCapabilities::CAN_REPLY_QUOTE),
        can_pin: caps.contains(ChatCapabilities::CAN_PIN),
        can_send_voice: caps.contains(ChatCapabilities::CAN_SEND_VOICE),
        can_upload_files: caps.contains(ChatCapabilities::CAN_UPLOAD_FILES),
        supports_threads: caps.contains(ChatCapabilities::SUPPORTS_THREADS),
        is_e2ee_active: caps.contains(ChatCapabilities::IS_E2EE_ACTIVE),
        is_read_only: caps.contains(ChatCapabilities::IS_READ_ONLY),
    }
}

/// Returns crisp 2-letter vector monograms for protocol catalog entries so `swash` outline
/// rendering never encounters missing color-emoji glyphs.
pub fn protocol_catalog_entries() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("telegram", "Telegram", "TG"),
        ("whatsapp", "WhatsApp", "WA"),
        ("signal", "Signal", "SG"),
        ("discord", "Discord", "DC"),
        ("matrix", "Matrix", "MX"),
        ("xmpp", "XMPP", "XM"),
        ("nostr", "Nostr", "NS"),
        ("simplex", "SimpleX", "SX"),
        ("irc", "IRCv3", "IR"),
        ("stoat", "Stoat", "ST"),
        ("mattermost", "Mattermost", "MM"),
        ("demo", "Demo", "DM"),
    ]
}

/// Sanitizes any text or badge coming from storage so that `U+1Fxxx` color emojis and `U+FE0F`
/// variation selectors are converted to crisp outline-font-compatible symbols and badges.
pub fn sanitize_for_outline_renderer(input: &str) -> String {
    let replaced = input
        .replace('\u{fe0f}', "")
        .replace('\u{1f4f7}', "[Foto]")
        .replace('\u{1f5bc}', "[Foto]")
        .replace('\u{1f4c4}', "[File]")
        .replace('\u{1f4ce}', "[File]")
        .replace('\u{1f3a4}', "[Nota Vocale]")
        .replace('\u{1f4cd}', "[Posizione]")
        .replace('\u{1f44d}', "+1")
        .replace('\u{2764}', "♥")
        .replace('\u{1f525}', "★")
        .replace('\u{1f389}', "★")
        .replace('\u{1f980}', "★")
        .replace('\u{26a1}', "★")
        .replace('\u{2728}', "★")
        .replace('\u{2705}', "✓")
        .replace('\u{1f4cc}', "★")
        .replace('\u{270f}', "✎")
        .replace('\u{1f512}', "★")
        .replace('\u{1f510}', "★");
    replaced
        .chars()
        .filter(|&c| (c as u32) < 0x1F000)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Builds the Slint `UiAuthFieldItem` list for an [`AuthFlowDescriptor`], filtering out
/// `"auth_mode"`, `"onboarding_mode"`, and `"backend_env"` because those are controlled by the
/// dedicated segmented toggle buttons at the top of the Auth Modal.
pub fn build_auth_fields_model(flow: &AuthFlowDescriptor) -> Vec<UiAuthFieldItem> {
    flow.fields
        .iter()
        .filter(|spec| {
            spec.key != "auth_mode"
                && spec.key != "onboarding_mode"
                && spec.key != "backend_env"
        })
        .map(|f| UiAuthFieldItem {
            key: SharedString::from(f.key.as_str()),
            label: SharedString::from(sanitize_for_outline_renderer(f.label.as_str())),
            placeholder: SharedString::from(sanitize_for_outline_renderer(f.placeholder.as_str())),
            value: SharedString::from(f.default_value.as_deref().unwrap_or("")),
            is_secret: f.is_secret,
        })
        .collect()
}

/// Pre-computed snapshot built off-thread and applied onto Slint `VecModel`s in a single batch.
#[derive(Debug, Clone)]
pub struct CoalescedUiSnapshot {
    pub protocol_toggles: Vec<UiProtocolToggleItem>,
    pub accounts: Vec<UiAccountItem>,
    pub isolation_mode_slug: String,
    pub active_account_id: String,
    pub active_protocol_slug: String,
    pub telegram_backend_mode: String,
    pub folder_tabs: Vec<UiFolderTabItem>,
    pub server_rail: Vec<UiServerRailItem>,
    pub visible_chats: Vec<UiChatListItem>,
    pub active_chat_uri: String,
    pub active_chat_title: String,
    pub active_chat_subtitle: String,
    pub active_chat_badge: String,
    pub active_capabilities: UiActiveChatCapabilities,
    pub messages: Vec<UiMessageItem>,
    pub pinned_chat_uri: String,
    pub active_chat_is_pinned: bool,
    pub send_on_enter: bool,
    pub is_demo_mockup_active: bool,
}

/// Computes a complete `CoalescedUiSnapshot` from `WarpStorage` and `ProtocolRegistry`.
pub fn build_ui_snapshot(
    storage: &WarpStorage,
    registry: &ProtocolRegistry,
    selection: &mut UiSelectionState,
) -> CoalescedUiSnapshot {
    let enabled_protocols = registry.enabled_protocols();

    // 1. Build 8 Protocol Toggle Items
    let protocol_toggles: Vec<UiProtocolToggleItem> = ProtocolKind::BUILTIN_PROTOCOLS
        .iter()
        .map(|proto| UiProtocolToggleItem {
            slug: SharedString::from(proto.as_slug()),
            name: SharedString::from(proto.display_name()),
            badge: SharedString::from(proto.short_badge()),
            enabled: enabled_protocols.contains(proto),
            brand_color: parse_hex_color(proto.brand_color_hex()),
        })
        .collect();

    // 2. Fetch all accounts and all enabled chats to compute per-account badges & unread counts
    let account_records = storage.list_accounts().unwrap_or_default();
    let all_enabled_chats = storage.list_chats(true).unwrap_or_default();

    let mut account_badge_map: HashMap<String, String> = HashMap::new();
    let mut account_unread_map: HashMap<String, i32> = HashMap::new();
    for chat in &all_enabled_chats {
        *account_unread_map
            .entry(chat.id.account_id.to_string())
            .or_insert(0) += chat.unread_count as i32;
    }

    let accounts: Vec<UiAccountItem> = account_records
        .iter()
        .filter(|acct| enabled_protocols.contains(&acct.protocol))
        .map(|acct| {
            account_badge_map.insert(acct.account_id.to_string(), acct.short_badge.to_string());
            let unread = account_unread_map
                .get(acct.account_id.as_str())
                .copied()
                .unwrap_or(0);
            UiAccountItem {
                account_id: SharedString::from(acct.account_id.as_str()),
                protocol_slug: SharedString::from(acct.protocol.as_slug()),
                protocol_badge: SharedString::from(acct.protocol.short_badge()),
                display_name: SharedString::from(sanitize_for_outline_renderer(
                    acct.display_name.as_str(),
                )),
                handle_or_uri: SharedString::from(acct.handle_or_uri.as_str()),
                short_badge: SharedString::from(acct.short_badge.as_str()),
                enabled: acct.enabled,
                include_in_unified: acct.include_in_unified_inbox,
                unread_count: unread,
                brand_color: parse_hex_color(acct.protocol.brand_color_hex()),
            }
        })
        .collect();

    // Ensure active_account_id is valid
    if !accounts
        .iter()
        .any(|a| a.account_id.as_str() == selection.active_account_id)
    {
        if let Some(first_acct) = accounts.first() {
            selection.active_account_id = first_acct.account_id.to_string();
            selection.active_protocol_filter =
                ProtocolKind::from_slug(first_acct.protocol_slug.as_str());
        }
    }

    // 3. Fetch containers and chats respecting the user's chosen `ChatListIsolationMode`
    let active_acct_id: AccountId = selection.active_account_id.clone().into();
    let all_containers: Vec<UnifiedContainer> = storage
        .list_containers_by_isolation(
            selection.isolation_mode,
            Some(&selection.active_protocol_filter),
            Some(&active_acct_id),
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|c| {
            enabled_protocols.contains(&c.id.protocol) && registry.is_account_enabled(&c.id.account_id)
        })
        .collect();

    let all_chats: Vec<UnifiedChat> = storage
        .list_chats_by_isolation(
            selection.isolation_mode,
            Some(&selection.active_protocol_filter),
            Some(&active_acct_id),
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|c| {
            enabled_protocols.contains(c.protocol()) && registry.is_account_enabled(c.account_id())
        })
        .collect();

    // 4. Build Folder Tabs
    let folders = storage.list_folders().unwrap_or_default();
    let mut folder_tabs = Vec::with_capacity(folders.len() + 1);
    let total_unread: i32 = all_chats.iter().map(|c| c.unread_count as i32).sum();
    folder_tabs.push(UiFolderTabItem {
        id: SharedString::from("all"),
        name: SharedString::from("All Chats"),
        icon: SharedString::from("•"),
        unread_count: total_unread,
    });
    for rule in &folders {
        if rule.id.as_str() == "all" {
            continue;
        }
        let unread: i32 = all_chats
            .iter()
            .filter(|c| rule.matches(c, &enabled_protocols))
            .map(|c| c.unread_count as i32)
            .sum();
        let clean_icon = sanitize_for_outline_renderer(rule.icon.as_str());
        folder_tabs.push(UiFolderTabItem {
            id: SharedString::from(rule.id.as_str()),
            name: SharedString::from(sanitize_for_outline_renderer(rule.name.as_str())),
            icon: SharedString::from(if clean_icon.is_empty() { "•" } else { clean_icon.as_str() }),
            unread_count: unread,
        });
    }

    // 5. Build Server Rail (Home + Active Containers from Stoat, Mattermost, Matrix, IRC, Telegram Forum)
    let mut server_rail = Vec::with_capacity(all_containers.len() + 1);
    server_rail.push(UiServerRailItem {
        uri: SharedString::from(""),
        title: SharedString::from("Direct Messages & Unified"),
        initials: SharedString::from("W"),
        protocol_badge: SharedString::from("ALL"),
        unread_count: total_unread,
        mention_count: 0,
        is_home: true,
    });
    for container in &all_containers {
        server_rail.push(UiServerRailItem {
            uri: SharedString::from(container.id.to_uri()),
            title: SharedString::from(sanitize_for_outline_renderer(container.title.as_str())),
            initials: SharedString::from(container.icon_initials.as_str()),
            protocol_badge: SharedString::from(container.id.protocol.short_badge()),
            unread_count: container.unread_count as i32,
            mention_count: container.mention_count as i32,
            is_home: false,
        });
    }

    // 6. Filter Visible Chats by Folder, Container & Search Query
    let active_folder_rule = folders
        .iter()
        .find(|f| f.id.as_str() == selection.active_folder_id);
    let query_lower = selection.search_query.trim().to_ascii_lowercase();

    let filtered_chats: Vec<&UnifiedChat> = all_chats
        .iter()
        .filter(|chat| {
            if !query_lower.is_empty() {
                let title_match = chat.title.to_ascii_lowercase().contains(&query_lower);
                let sub_match = chat
                    .subtitle
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&query_lower);
                let preview_match = chat
                    .last_message_preview
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&query_lower);
                let proto_match = chat
                    .protocol()
                    .display_name()
                    .to_ascii_lowercase()
                    .contains(&query_lower);
                if !(title_match || sub_match || preview_match || proto_match) {
                    return false;
                }
            }
            if !selection.active_container_uri.is_empty() {
                let parent_uri = chat
                    .parent_container_id
                    .as_ref()
                    .map(|id| id.to_uri())
                    .unwrap_or_default();
                return parent_uri == selection.active_container_uri;
            }
            if let Some(rule) = active_folder_rule {
                return rule.matches(chat, &enabled_protocols);
            }
            true
        })
        .collect();

    // Ensure active_chat_uri points to a valid visible chat if possible
    if selection.active_chat_uri.is_empty()
        || !filtered_chats
            .iter()
            .any(|c| c.id.to_uri() == selection.active_chat_uri)
    {
        if let Some(first) = filtered_chats.first() {
            selection.active_chat_uri = first.id.to_uri();
        } else if let Some(first_any) = all_chats.first() {
            selection.active_chat_uri = first_any.id.to_uri();
        } else {
            selection.active_chat_uri.clear();
        }
    }

    let pinned_chat_uri = filtered_chats
        .iter()
        .find(|c| c.is_pinned)
        .map(|c| c.id.to_uri())
        .unwrap_or_default();

    let visible_chats: Vec<UiChatListItem> = filtered_chats
        .iter()
        .map(|chat| {
            let acct_badge = account_badge_map
                .get(chat.id.account_id.as_str())
                .cloned()
                .unwrap_or_else(|| chat.protocol().short_badge().to_string());
            UiChatListItem {
                uri: SharedString::from(chat.id.to_uri()),
                parent_container_uri: SharedString::from(
                    chat.parent_container_id
                        .as_ref()
                        .map(|u| u.to_uri())
                        .unwrap_or_default(),
                ),
                account_id: SharedString::from(chat.id.account_id.as_str()),
                account_badge: SharedString::from(acct_badge),
                title: SharedString::from(sanitize_for_outline_renderer(chat.title.as_str())),
                subtitle: SharedString::from(sanitize_for_outline_renderer(
                    chat.subtitle.as_deref().unwrap_or(""),
                )),
                initials: SharedString::from(chat.avatar_initials.as_str()),
                protocol_badge: SharedString::from(chat.protocol().short_badge()),
                protocol_slug: SharedString::from(chat.protocol().as_slug()),
                last_preview: SharedString::from(sanitize_for_outline_renderer(
                    chat.last_message_preview.as_deref().unwrap_or(""),
                )),
                timestamp_text: SharedString::from(format_hh_mm(chat.last_activity_ts)),
                unread_count: chat.unread_count as i32,
                is_e2ee: chat.capabilities.contains(ChatCapabilities::IS_E2EE_ACTIVE),
                is_thread: chat.parent_chat_id.is_some(),
                is_online: chat.is_online,
            }
        })
        .collect();

    // 7. Active Chat Metadata & Messages
    let active_chat = all_chats
        .iter()
        .find(|c| c.id.to_uri() == selection.active_chat_uri);

    let active_chat_is_pinned = active_chat.map(|c| c.is_pinned).unwrap_or(false);

    let (active_chat_title, active_chat_subtitle, active_chat_badge, chat_caps, raw_messages) =
        if let Some(chat) = active_chat {
            let msgs = storage.list_messages(&chat.id, 100).unwrap_or_default();
            (
                sanitize_for_outline_renderer(chat.title.as_str()),
                sanitize_for_outline_renderer(
                    chat.subtitle
                        .as_deref()
                        .unwrap_or(chat.id.to_uri().as_str()),
                ),
                chat.protocol().short_badge().to_string(),
                chat.capabilities,
                msgs,
            )
        } else if accounts.is_empty() {
            (
                "Benvenuto in Warp IM".to_string(),
                "Aggiungi un account reale (Login / Sign-Up) o avvia la Modalità Demo".to_string(),
                "WARP".to_string(),
                ChatCapabilities::empty(),
                Vec::new(),
            )
        } else {
            (
                "Nessuna chat selezionata".to_string(),
                "Seleziona una conversazione a sinistra o tocca + Nuova Chat".to_string(),
                "WARP".to_string(),
                ChatCapabilities::empty(),
                Vec::new(),
            )
        };

    let last_outgoing_idx = raw_messages.iter().rposition(|m| m.is_outgoing);

    let messages: Vec<UiMessageItem> = raw_messages
        .iter()
        .enumerate()
        .map(|(idx, msg)| {
            let is_last_outgoing = Some(idx) == last_outgoing_idx;
            let derived_caps = MessageCapabilities::derive_from_chat(
                chat_caps,
                msg.is_outgoing,
                is_last_outgoing,
            );
            let reactions_summary = msg
                .reactions
                .iter()
                .map(|r| {
                    let clean_emoji = sanitize_for_outline_renderer(r.emoji.as_str());
                    format!(
                        "{} {}",
                        if clean_emoji.is_empty() {
                            "+1"
                        } else {
                            clean_emoji.as_str()
                        },
                        r.count
                    )
                })
                .collect::<Vec<_>>()
                .join("  ");

            UiMessageItem {
                uri: SharedString::from(msg.id.to_uri()),
                sender_name: SharedString::from(sanitize_for_outline_renderer(
                    msg.sender_display_name.as_str(),
                )),
                sender_initials: SharedString::from(msg.sender_initials.as_str()),
                protocol_badge: SharedString::from(msg.id.protocol.short_badge()),
                text: SharedString::from(sanitize_for_outline_renderer(msg.text.as_str())),
                timestamp_text: SharedString::from(format_hh_mm(msg.timestamp_ms)),
                delivery_badge: SharedString::from(msg.delivery_state.status_badge()),
                is_outgoing: msg.is_outgoing,
                reply_preview: SharedString::from(sanitize_for_outline_renderer(
                    msg.reply_preview.as_deref().unwrap_or(""),
                )),
                reactions_summary: SharedString::from(reactions_summary),
                can_edit: derived_caps.contains(MessageCapabilities::CAN_EDIT),
                can_delete_for_all: derived_caps.contains(MessageCapabilities::CAN_DELETE_FOR_ALL),
                can_react: derived_caps.contains(MessageCapabilities::CAN_REACT),
                can_reply: derived_caps.contains(MessageCapabilities::CAN_REPLY_QUOTE),
                can_pin: derived_caps.contains(MessageCapabilities::CAN_PIN),
            }
        })
        .collect();

    if let Ok(Some(saved_mode)) = storage.get_kv_state(
        &AccountId::new("tg_main"),
        &ProtocolKind::Telegram,
        "telegram_backend_mode",
    ) {
        if let Ok(mode_str) = String::from_utf8(saved_mode) {
            selection.telegram_backend_mode =
                TelegramBackendEnvironment::from_slug(&mode_str)
                    .as_slug()
                    .to_string();
        }
    }

    if let Ok(Some(shortcut_mode)) = storage.get_app_setting("send_shortcut_mode") {
        selection.send_on_enter = shortcut_mode != "ctrl_enter";
    }

    let is_demo_mockup_active = storage
        .get_app_setting("demo_mode_active")
        .ok()
        .flatten()
        .as_deref()
        == Some("true");

    CoalescedUiSnapshot {
        protocol_toggles,
        accounts,
        isolation_mode_slug: selection.isolation_mode.as_slug().to_string(),
        active_account_id: selection.active_account_id.clone(),
        active_protocol_slug: selection.active_protocol_filter.as_slug().to_string(),
        telegram_backend_mode: selection.telegram_backend_mode.clone(),
        folder_tabs,
        server_rail,
        visible_chats,
        active_chat_uri: selection.active_chat_uri.clone(),
        active_chat_title,
        active_chat_subtitle,
        active_chat_badge,
        active_capabilities: map_chat_capabilities_to_ui(chat_caps),
        messages,
        pinned_chat_uri,
        active_chat_is_pinned,
        send_on_enter: selection.send_on_enter,
        is_demo_mockup_active,
    }
}

/// Applies a [`CoalescedUiSnapshot`] onto the Slint `MainWindow` on the UI event loop thread.
pub fn apply_snapshot_to_window(window: &MainWindow, snap: CoalescedUiSnapshot) {
    let has_no_accounts = snap.accounts.is_empty();
    let (top_px, bottom_px) = crate::android_platform::current_android_safe_insets();
    if top_px > 0.0 || bottom_px > 0.0 {
        let st = window.global::<SuperTheme>();
        st.set_safe_area_top(top_px);
        st.set_safe_area_bottom(bottom_px);
    }
    window.set_protocol_toggles(ModelRc::from(Rc::new(VecModel::from(
        snap.protocol_toggles,
    ))));
    window.set_accounts(ModelRc::from(Rc::new(VecModel::from(snap.accounts))));
    window.set_isolation_mode(SharedString::from(snap.isolation_mode_slug));
    window.set_active_account_id(SharedString::from(snap.active_account_id));
    window.set_active_protocol_filter(SharedString::from(snap.active_protocol_slug));
    window.set_telegram_backend_mode(SharedString::from(snap.telegram_backend_mode));
    window.set_folder_tabs(ModelRc::from(Rc::new(VecModel::from(snap.folder_tabs))));
    window.set_server_rail(ModelRc::from(Rc::new(VecModel::from(snap.server_rail))));
    window.set_chats(ModelRc::from(Rc::new(VecModel::from(snap.visible_chats))));
    window.set_active_chat_uri(SharedString::from(snap.active_chat_uri));
    window.set_active_chat_title(SharedString::from(snap.active_chat_title));
    window.set_active_chat_subtitle(SharedString::from(snap.active_chat_subtitle));
    window.set_active_chat_protocol_badge(SharedString::from(snap.active_chat_badge));
    window.set_active_chat_capabilities(snap.active_capabilities);
    window.set_messages(ModelRc::from(Rc::new(VecModel::from(snap.messages))));
    window.set_pinned_chat_uri(SharedString::from(snap.pinned_chat_uri));
    window.set_active_chat_is_pinned(snap.active_chat_is_pinned);
    window.set_send_on_enter(snap.send_on_enter);
    window.set_is_demo_mockup_active(snap.is_demo_mockup_active);
    window.set_show_welcome_screen(has_no_accounts && !snap.is_demo_mockup_active);
}

/// Applies the user's selected Telegram Backend Environment (`PublicProduction` vs `TestDc2`)
/// into `WarpStorage` (persisting the setting in `protocol_kv_state` and updating the Telegram chat subtitles).
pub fn apply_telegram_backend_mode_to_storage(
    storage: &WarpStorage,
    selection: &mut UiSelectionState,
    mode_slug: &str,
) -> TelegramBackendEnvironment {
    let env = TelegramBackendEnvironment::from_slug(mode_slug);
    selection.telegram_backend_mode = env.as_slug().to_string();
    let _ = storage.set_kv_state(
        &AccountId::new("tg_main"),
        &ProtocolKind::Telegram,
        "telegram_backend_mode",
        env.as_slug().as_bytes(),
    );

    if let Ok(chats) = storage.list_chats(false) {
        for mut chat in chats {
            if chat.protocol() == &ProtocolKind::Telegram {
                chat.protocol_metadata["backend_env"] = serde_json::json!(env.as_slug());
                chat.protocol_metadata["dc_endpoint"] =
                    serde_json::json!(env.default_dc_endpoint());
                if chat.id.account_id.as_str() == "tg_main" && chat.parent_chat_id.is_none() {
                    chat.subtitle = Some(
                        format!(
                            "MTProto 2.0 • {} ({})",
                            sanitize_for_outline_renderer(env.short_badge()),
                            env.default_dc_endpoint()
                        )
                        .into(),
                    );
                }
                let _ = storage.upsert_chat(&chat);
            }
        }
    }

    env
}

/// Populates the Declarative `AuthFlowDescriptor` inspector modal on the Slint `MainWindow`.
pub fn apply_auth_flow_to_window(window: &MainWindow, flow: &AuthFlowDescriptor) {
    window.set_auth_modal_protocol(SharedString::from(flow.protocol.display_name()));
    window.set_auth_modal_supports_signup(AuthFlowDescriptor::supports_in_app_signup(
        &flow.protocol,
    ));
    window.set_auth_modal_supports_bot_login(AuthFlowDescriptor::supports_bot_token_login(
        &flow.protocol,
    ));
    let mode_slug = match &flow.current_step {
        AuthStep::TelegramBotToken { .. } => "bot_token",
        AuthStep::AccountRegistration { .. } => "signup",
        _ => "login",
    };
    window.set_auth_modal_mode(SharedString::from(mode_slug));
    window.set_auth_modal_title(SharedString::from(sanitize_for_outline_renderer(
        flow.step_title.as_str(),
    )));
    window.set_auth_modal_description(SharedString::from(sanitize_for_outline_renderer(
        flow.step_description.as_str(),
    )));
    window.set_auth_modal_status_text(SharedString::from(""));

    let qr_hint = match &flow.current_step {
        AuthStep::ScanOrDisplayQrInvite { qr_payload_uri, .. } => qr_payload_uri.as_str(),
        _ => "",
    };
    window.set_auth_modal_qr_hint(SharedString::from(qr_hint));

    let fields = build_auth_fields_model(flow);
    window.set_auth_modal_fields(ModelRc::from(Rc::new(VecModel::from(fields))));
}

/// Spawns the 16ms (60/120Hz) asynchronous Tokio Coalescer loop.
///
/// Drains both `BackendEvent`s from `ProtocolRegistry` and `UiBridgeCommand`s from Slint,
/// batches SQLite writes + Outbox dispatches, and triggers at most one
/// `slint::invoke_from_event_loop` update per 16ms tick.
pub fn spawn_16ms_coalescer(
    window_weak: slint::Weak<MainWindow>,
    storage: WarpStorage,
    registry: Arc<ProtocolRegistry>,
    outbox: Arc<OutboxEngine>,
    selection: Arc<Mutex<UiSelectionState>>,
    mut cmd_rx: mpsc::UnboundedReceiver<UiBridgeCommand>,
) -> tokio::task::JoinHandle<()> {
    let mut event_rx = registry.subscribe();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(16));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            let mut dirty = false;

            // 1. Drain all UI commands queued during the last 16ms
            while let Ok(cmd) = cmd_rx.try_recv() {
                dirty = true;
                match cmd {
                    UiBridgeCommand::SendMessage {
                        chat_uri,
                        text,
                        reply_preview,
                    } => {
                        if let Ok(chat_id) = UniversalId::from_uri(&chat_uri) {
                            let reply_to = reply_preview.as_deref().map(|prev| {
                                UniversalId::from_uri(prev).unwrap_or_else(|_| {
                                    UniversalId::new(
                                        chat_id.protocol.clone(),
                                        chat_id.account_id.as_str(),
                                        prev,
                                    )
                                })
                            });
                            let text_for_reply = text.clone();
                            let reply_to_for_reply = reply_to.clone();
                            if let Ok(_optimistic_msg) = outbox.send_optimistic(
                                &chat_id,
                                "Tu (Warp IM)",
                                text,
                                reply_to,
                            ) {
                                // Flush outbox immediately on background worker + dispatch live protocol & smart reply
                                let outbox_clone = outbox.clone();
                                let cmd_storage = storage.clone();
                                let cmd_registry = registry.clone();
                                tokio::spawn(async move {
                                    let _ = outbox_clone.flush_once().await;
                                    // Notify coalescer after remote confirmation
                                    if let Ok(msgs) = cmd_storage.list_messages(&chat_id, 1) {
                                        if let Some(last) = msgs.last() {
                                            cmd_registry
                                                .emit_event(BackendEvent::MessageUpdated(last.clone()));
                                        }
                                    }
                                    let _ = process_outbound_and_generate_protocol_response(
                                        &cmd_storage,
                                        &cmd_registry,
                                        &chat_id,
                                        &text_for_reply,
                                        reply_to_for_reply,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                    UiBridgeCommand::SendAttachment { chat_uri, kind } => {
                        if let Ok(chat_id) = UniversalId::from_uri(&chat_uri) {
                            let (file_name, caption) = match kind.as_str() {
                                "voice" => ("nota_vocale_opus.ogg", "Messaggio vocale (0:08)"),
                                "photo" | "image" => ("foto_camera_hd.png", "Immagine condivisa"),
                                "location" => (
                                    "posizione_gps.geojson",
                                    "[Posizione] Posizione condivisa (45.4642° N, 9.1900° E)",
                                ),
                                _ => ("documento_allegato.pdf", "File condiviso via Warp IM"),
                            };
                            if let Ok(sent_msg) = storage.send_media_attachment_message(
                                &chat_id,
                                "Tu (Warp IM)",
                                &kind,
                                file_name,
                                caption,
                                0,
                            ) {
                                let cmd_storage = storage.clone();
                                let cmd_registry = registry.clone();
                                let outbound_text = sent_msg.text.clone();
                                tokio::spawn(async move {
                                    let _ = process_outbound_and_generate_protocol_response(
                                        &cmd_storage,
                                        &cmd_registry,
                                        &chat_id,
                                        &outbound_text,
                                        None,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                    UiBridgeCommand::ToggleProtocol {
                        protocol_slug,
                        enabled,
                    } => {
                        let proto = ProtocolKind::from_slug(&protocol_slug);
                        let _ = storage.set_protocol_enabled(&proto, enabled);
                        let _ = registry.set_protocol_enabled(proto, enabled).await;
                    }
                    UiBridgeCommand::ToggleAccountEnabled {
                        account_id,
                        enabled,
                    } => {
                        let acct: AccountId = account_id.into();
                        let _ = storage.set_account_enabled(&acct, enabled);
                        let _ = registry.set_account_enabled(acct, enabled).await;
                    }
                    UiBridgeCommand::RemoveAccount { account_id } => {
                        let acct = AccountId::new(&account_id);
                        let _ = storage.delete_account(&acct);
                        let _ = registry.set_account_enabled(acct, false).await;
                        if let Ok(mut s) = selection.lock() {
                            if s.active_account_id == account_id {
                                s.active_account_id.clear();
                                s.active_chat_uri.clear();
                                s.active_container_uri.clear();
                            }
                        }
                    }
                    UiBridgeCommand::SwitchTelegramBackendMode { mode_slug } => {
                        if let Ok(mut s) = selection.lock() {
                            apply_telegram_backend_mode_to_storage(&storage, &mut s, &mode_slug);
                        }
                    }
                    UiBridgeCommand::SwitchIsolationMode { mode_slug } => {
                        let mode = ChatListIsolationMode::from_slug(&mode_slug);
                        let _ = storage.set_chat_list_isolation_mode(mode);
                        if let Ok(mut s) = selection.lock() {
                            s.isolation_mode = mode;
                            s.active_container_uri.clear();
                        }
                    }
                    UiBridgeCommand::ReactToMessage {
                        chat_uri: _,
                        message_uri,
                        emoji,
                    } => {
                        if let Ok(msg_id) = UniversalId::from_uri(&message_uri) {
                            let _ = storage.toggle_message_reaction(&msg_id, &emoji, "me");
                        }
                    }
                    UiBridgeCommand::DeleteMessage {
                        chat_uri,
                        message_uri,
                    } => {
                        if let (Ok(chat_id), Ok(msg_id)) = (
                            UniversalId::from_uri(&chat_uri),
                            UniversalId::from_uri(&message_uri),
                        ) {
                            if let Some(backend) = registry.get_backend(&chat_id.account_id) {
                                let _ = backend.delete_message(&chat_id, &msg_id, true).await;
                            }
                            let _ = storage.delete_message(&msg_id);
                        }
                    }
                    UiBridgeCommand::EditMessage {
                        chat_uri,
                        message_uri,
                        new_text,
                    } => {
                        if let (Ok(chat_id), Ok(msg_id)) = (
                            UniversalId::from_uri(&chat_uri),
                            UniversalId::from_uri(&message_uri),
                        ) {
                            if let Some(backend) = registry.get_backend(&chat_id.account_id) {
                                let _ = backend.edit_message(&chat_id, &msg_id, &new_text).await;
                            }
                            let _ = storage.update_message_text(&msg_id, &new_text);
                        }
                    }
                    UiBridgeCommand::TogglePinChat { chat_uri } => {
                        if let Ok(chat_id) = UniversalId::from_uri(&chat_uri) {
                            let _ = storage.toggle_chat_pinned(&chat_id);
                        }
                    }
                    UiBridgeCommand::ClearChatHistory { chat_uri } => {
                        let _ = storage.clear_chat_history(&chat_uri);
                    }
                    UiBridgeCommand::DeleteActiveChat { chat_uri } => {
                        let _ = storage.delete_chat(&chat_uri);
                        if let Ok(mut s) = selection.lock() {
                            if s.active_chat_uri == chat_uri {
                                s.active_chat_uri.clear();
                            }
                        }
                    }
                    UiBridgeCommand::CreateNewChat {
                        account_id,
                        title,
                        remote_target,
                        is_group,
                    } => {
                        let acct = AccountId::new(if account_id.trim().is_empty() {
                            "tg_main"
                        } else {
                            account_id.trim()
                        });
                        let proto = storage
                            .list_accounts()
                            .ok()
                            .and_then(|list| {
                                list.into_iter()
                                    .find(|a| a.account_id == acct)
                                    .map(|a| a.protocol)
                            })
                            .unwrap_or(ProtocolKind::Telegram);
                        if let Ok(new_chat) = storage.create_user_chat(
                            &acct,
                            proto,
                            &title,
                            &remote_target,
                            is_group,
                        ) {
                            if let Ok(mut s) = selection.lock() {
                                s.active_account_id = acct.to_string();
                                s.active_chat_uri = new_chat.id.to_uri();
                            }
                        }
                    }
                    UiBridgeCommand::SubmitAuthModal {
                        protocol,
                        mode,
                        mut inputs,
                    } => {
                        inputs.insert("onboarding_mode".to_string(), mode.as_slug().to_string());
                        let handle_candidate = inputs
                            .get("username")
                            .or_else(|| inputs.get("phone_number"))
                            .or_else(|| inputs.get("jid"))
                            .or_else(|| inputs.get("display_name"))
                            .or_else(|| inputs.get("bot_token"))
                            .cloned()
                            .unwrap_or_else(|| protocol.as_slug().to_string());
                        let clean_slug: String = handle_candidate
                            .chars()
                            .filter(|c| c.is_ascii_alphanumeric())
                            .take(10)
                            .collect::<String>()
                            .to_ascii_lowercase();
                        let acct_id_str = if clean_slug.is_empty() {
                            format!("{}_user", protocol.as_slug())
                        } else {
                            format!("{}_{}", protocol.as_slug(), clean_slug)
                        };
                        let acct_id = AccountId::new(&acct_id_str);
                        let label = if mode == OnboardingMode::TelegramBotToken {
                            format!("{} Bot ({})", protocol.display_name(), acct_id_str)
                        } else {
                            format!("{} ({})", protocol.display_name(), handle_candidate)
                        };
                        if let Ok(primary_chat) = bootstrap_live_authenticated_account(
                            &storage,
                            &registry,
                            protocol.clone(),
                            &acct_id,
                            &label,
                            &inputs,
                        )
                        .await
                        {
                            if let Ok(mut s) = selection.lock() {
                                s.active_account_id = acct_id.to_string();
                                s.active_protocol_filter = protocol;
                                s.active_chat_uri = primary_chat.id.to_uri();
                                s.active_container_uri.clear();
                            }
                        }
                    }
                    UiBridgeCommand::ActivateDemoMockup => {
                        let _ = seed_simulated_environment(&storage, &registry).await;
                        let _ = storage.set_app_setting("demo_mode_active", "true");
                        if let Ok(mut s) = selection.lock() {
                            s.active_chat_uri.clear();
                            s.active_container_uri.clear();
                        }
                    }
                    UiBridgeCommand::ExitDemoMockup => {
                        let _ = storage.clear_all_user_and_demo_data();
                        if let Ok(mut s) = selection.lock() {
                            s.active_chat_uri.clear();
                            s.active_container_uri.clear();
                            s.search_query.clear();
                        }
                    }
                    UiBridgeCommand::ForceRefresh => {}
                }
            }

            // 2. Drain all BackendEvents accumulated in the 16ms window
            while let Ok(ev) = event_rx.try_recv() {
                dirty = true;
                match ev {
                    BackendEvent::MessageReceived(msg) | BackendEvent::MessageUpdated(msg) => {
                        let _ = storage.upsert_message(&msg);
                    }
                    BackendEvent::HierarchyUpdated {
                        containers, chats, ..
                    } => {
                        for c in &containers {
                            let _ = storage.upsert_container(c);
                        }
                        for ch in &chats {
                            let _ = storage.upsert_chat(ch);
                        }
                    }
                    BackendEvent::ProtocolToggled { protocol, enabled } => {
                        let _ = storage.set_protocol_enabled(&protocol, enabled);
                    }
                    BackendEvent::AccountToggled {
                        account_id,
                        enabled,
                        ..
                    } => {
                        let _ = storage.set_account_enabled(&account_id, enabled);
                    }
                    _ => {}
                }
            }

            // 3. If any state changed in this 16ms frame, compute snapshot and batch-update Slint UI
            if dirty {
                let snap = {
                    let mut sel = selection.lock().unwrap();
                    build_ui_snapshot(&storage, &registry, &mut sel)
                };
                let weak = window_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(win) = weak.upgrade() {
                        apply_snapshot_to_window(&win, snap);
                    }
                });
            }
        }
    })
}

/// Verbatim English PEFL v1.0 license text (`LICENSE`).
pub const PEFL_LICENSE_EN: &str = include_str!("../../../LICENSE");

/// Verbatim Italian PEFL v1.0 license text (`LICENSE.it`).
pub const PEFL_LICENSE_IT: &str = include_str!("../../../LICENSE.it");

/// Local persistence file for 7-day PEFL Clause 3 approval (`templates/pefl-license-approval-cli.sh` convention).
pub const PEFL_APPROVAL_CACHE_FILE: &str = ".pefl_accepted_warp-im";

/// Checks whether PEFL v1.0 Clause 3 EULA approval is currently valid (approved within the last 7 days)
/// in either `WarpStorage` or the local `.pefl_accepted_warp-im` persistence file.
pub fn is_pefl_clause3_approved(storage: &WarpStorage, now_ms: i64) -> bool {
    if storage.is_pefl_eula_valid(now_ms).unwrap_or(false) {
        return true;
    }
    if let Ok(raw) = std::fs::read_to_string(PEFL_APPROVAL_CACHE_FILE) {
        if let Ok(accepted_at_ms) = raw.trim().parse::<i64>() {
            let elapsed = now_ms.saturating_sub(accepted_at_ms);
            if elapsed >= 0 && elapsed <= WarpStorage::PEFL_SEVEN_DAYS_MS {
                let _ = storage.record_pefl_eula_acceptance(accepted_at_ms);
                return true;
            }
        }
    }
    false
}

/// Records the user's explicit PEFL v1.0 Clause 3 approval in `WarpStorage` and optionally
/// in the 7-day local persistence file `.pefl_accepted_warp-im`.
pub fn record_pefl_clause3_approval(storage: &WarpStorage, now_ms: i64, remember_7_days: bool) {
    let _ = storage.record_pefl_eula_acceptance(now_ms);
    if remember_7_days {
        let _ = std::fs::write(PEFL_APPROVAL_CACHE_FILE, format!("{now_ms}\n"));
    } else {
        let _ = std::fs::remove_file(PEFL_APPROVAL_CACHE_FILE);
    }
}

/// Initializes the PEFL v1.0 Clause 3 Foreground EULA modal on `MainWindow`.
pub fn init_pefl_eula_modal(window: &MainWindow, storage: &WarpStorage, now_ms: i64) {
    let approved = is_pefl_clause3_approved(storage, now_ms);
    window.set_pefl_license_lang(SharedString::from("IT"));
    window.set_pefl_license_text(SharedString::from(PEFL_LICENSE_IT));
    window.set_pefl_remember_7_days(true);
    window.set_show_pefl_eula_modal(!approved);
}

/// Wires all Slint `MainWindow` callbacks to the `ThemeManager`, `UiSelectionState`, `WarpStorage`, and `UiBridgeCommand` channel.
pub fn wire_window_callbacks(
    window: &MainWindow,
    storage: WarpStorage,
    theme_manager: Arc<ThemeManager>,
    selection: Arc<Mutex<UiSelectionState>>,
    cmd_tx: mpsc::UnboundedSender<UiBridgeCommand>,
) {
    // PEFL v1.0 Clause 3 Language Switcher (IT / EN)
    {
        let win_weak = window.as_weak();
        window.on_switch_pefl_lang(move |lang| {
            if let Some(win) = win_weak.upgrade() {
                if lang.as_str() == "EN" {
                    win.set_pefl_license_lang(SharedString::from("EN"));
                    win.set_pefl_license_text(SharedString::from(PEFL_LICENSE_EN));
                } else {
                    win.set_pefl_license_lang(SharedString::from("IT"));
                    win.set_pefl_license_text(SharedString::from(PEFL_LICENSE_IT));
                }
            }
        });
    }

    // PEFL v1.0 Clause 3 Explicit User Approval + Immediate Android Runtime Permissions Request
    {
        let win_weak = window.as_weak();
        let st = storage.clone();
        window.on_accept_pefl_eula(move |remember_7_days| {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            record_pefl_clause3_approval(&st, now_ms, remember_7_days);
            let _ = crate::android_platform::request_android_permissions_now();
            if let Some(win) = win_weak.upgrade() {
                win.set_show_pefl_eula_modal(false);
            }
        });
    }

    // PEFL v1.0 Clause 3 Decline & Immediate Exit
    {
        window.on_decline_pefl_eula(move || {
            eprintln!("PEFL v1.0 license was not approved. Exiting Warp IM as required by Clause 3.");
            std::process::exit(1);
        });
    }

    // SuperTheme hot-switch
    {
        let win_weak = window.as_weak();
        let tm = theme_manager.clone();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_switch_supertheme(move |id| {
            if let Some(win) = win_weak.upgrade() {
                tm.apply_supertheme(&win, id.as_str());
                // Reset container filter when switching to flat folder views
                if id.as_str() != "discord" && id.as_str() != "irc_classic" {
                    if let Ok(mut s) = sel.lock() {
                        s.active_container_uri.clear();
                    }
                }
                let _ = tx.send(UiBridgeCommand::ForceRefresh);
            }
        });
    }

    // ThemePalette hot-switch
    {
        let win_weak = window.as_weak();
        let tm = theme_manager;
        window.on_switch_palette(move |id| {
            if let Some(win) = win_weak.upgrade() {
                tm.apply_palette(&win, id.as_str());
            }
        });
    }

    // Runtime Protocol Enable/Disable toggle
    {
        let tx = cmd_tx.clone();
        window.on_toggle_protocol(move |slug, enabled| {
            let _ = tx.send(UiBridgeCommand::ToggleProtocol {
                protocol_slug: slug.to_string(),
                enabled,
            });
        });
    }

    // Switch Telegram Backend Environment (`public` = Production DC1-DC5 vs `test_dc2` = Test Server DC2)
    {
        let win_weak = window.as_weak();
        let tx = cmd_tx.clone();
        window.on_switch_telegram_backend_mode(move |mode_slug| {
            let env = TelegramBackendEnvironment::from_slug(mode_slug.as_str());
            if let Some(win) = win_weak.upgrade() {
                win.set_telegram_backend_mode(SharedString::from(env.as_slug()));
                if win.get_auth_modal_protocol().as_str() == "Telegram" {
                    let current_mode =
                        OnboardingMode::from_slug(win.get_auth_modal_mode().as_str());
                    let flow = AuthFlowDescriptor::for_protocol_and_mode(
                        ProtocolKind::Telegram,
                        current_mode,
                        env.is_test_server(),
                    );
                    apply_auth_flow_to_window(&win, &flow);
                }
            }
            let _ = tx.send(UiBridgeCommand::SwitchTelegramBackendMode {
                mode_slug: env.as_slug().to_string(),
            });
        });
    }

    // Switch Chat List Isolation Mode (`unified`, `per_protocol`, `per_account`, `hybrid_custom`)
    {
        let tx = cmd_tx.clone();
        window.on_switch_isolation_mode(move |mode_slug| {
            let _ = tx.send(UiBridgeCommand::SwitchIsolationMode {
                mode_slug: mode_slug.to_string(),
            });
        });
    }

    // Select Active Account (used by `PerAccount` and `PerProtocol` isolation modes)
    {
        let st = storage.clone();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_select_account(move |account_id| {
            let acct_str = account_id.to_string();
            let proto = st
                .list_accounts()
                .ok()
                .and_then(|list| {
                    list.into_iter()
                        .find(|a| a.account_id.as_str() == acct_str)
                        .map(|a| a.protocol)
                })
                .unwrap_or(ProtocolKind::Telegram);
            if let Ok(mut s) = sel.lock() {
                s.active_account_id = acct_str;
                s.active_protocol_filter = proto;
                s.active_container_uri.clear();
            }
            let _ = tx.send(UiBridgeCommand::ForceRefresh);
        });
    }

    // Toggle Individual Account Enabled/Disabled
    {
        let tx = cmd_tx.clone();
        window.on_toggle_account_enabled(move |account_id, enabled| {
            let _ = tx.send(UiBridgeCommand::ToggleAccountEnabled {
                account_id: account_id.to_string(),
                enabled,
            });
        });
    }

    // Cross-Platform Form Factor Toggle (Desktop Dual-Pane <-> Mobile Single-Pane)
    {
        let win_weak = window.as_weak();
        window.on_toggle_mobile_form_factor(move || {
            if let Some(win) = win_weak.upgrade() {
                let st = win.global::<SuperTheme>();
                let next_mobile = !st.get_is_mobile_compact();
                st.set_is_mobile_compact(next_mobile);
                st.set_mobile_showing_chat(false);
            }
        });
    }

    // Mobile Back Navigation (Chat Viewport -> Chat List)
    {
        let win_weak = window.as_weak();
        window.on_mobile_navigate_back(move || {
            if let Some(win) = win_weak.upgrade() {
                win.global::<SuperTheme>().set_mobile_showing_chat(false);
            }
        });
    }

    // Search Query Filter in Chat Sidebar
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_search_query_edited(move |query| {
            if let Ok(mut s) = sel.lock() {
                s.search_query = query.to_string();
            }
            let _ = tx.send(UiBridgeCommand::ForceRefresh);
        });
    }

    // Quick Add Contact from Sidebar (`+ID` button)
    {
        let win_weak = window.as_weak();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_quick_add_contact(move |target| {
            let clean = target.trim().to_string();
            if clean.is_empty() {
                return;
            }
            let acct_id = sel
                .lock()
                .map(|s| s.active_account_id.clone())
                .unwrap_or_else(|_| "tg_main".to_string());
            let _ = tx.send(UiBridgeCommand::CreateNewChat {
                account_id: acct_id,
                title: clean.clone(),
                remote_target: clean,
                is_group: false,
            });
            if let Some(win) = win_weak.upgrade() {
                win.set_quick_contact_id(SharedString::from(""));
                if win.global::<SuperTheme>().get_is_mobile_compact() {
                    win.global::<SuperTheme>().set_mobile_showing_chat(true);
                }
            }
        });
    }

    // Toggle Send on Enter (`true` = Enter sends, `false` = Ctrl+Enter / Alt+Enter sends)
    {
        let win_weak = window.as_weak();
        let st = storage.clone();
        let sel = selection.clone();
        window.on_toggle_send_on_enter(move |send_on_enter| {
            let val = if send_on_enter { "enter" } else { "ctrl_enter" };
            let _ = st.set_app_setting("send_shortcut_mode", val);
            if let Ok(mut s) = sel.lock() {
                s.send_on_enter = send_on_enter;
            }
            if let Some(win) = win_weak.upgrade() {
                win.set_send_on_enter(send_on_enter);
            }
        });
    }

    // Open Dedicated Settings Modal
    {
        let win_weak = window.as_weak();
        window.on_open_settings_modal(move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_show_settings_modal(true);
            }
        });
    }

    // Open New Chat / Channel Modal
    {
        let win_weak = window.as_weak();
        window.on_open_new_chat_modal(move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_show_new_chat_modal(true);
            }
        });
    }

    // Create New Chat / Channel
    {
        let win_weak = window.as_weak();
        let tx = cmd_tx.clone();
        window.on_create_new_chat(move |account_id, title, remote_target, is_group| {
            let _ = tx.send(UiBridgeCommand::CreateNewChat {
                account_id: account_id.to_string(),
                title: title.to_string(),
                remote_target: remote_target.to_string(),
                is_group,
            });
            if let Some(win) = win_weak.upgrade() {
                win.set_show_new_chat_modal(false);
            }
        });
    }

    // Toggle Pin on Active Chat
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_toggle_pin_active_chat(move || {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            if !chat_uri.is_empty() {
                let _ = tx.send(UiBridgeCommand::TogglePinChat { chat_uri });
            }
        });
    }

    // Send Media / Voice / File / Location Attachment in Active Chat
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_send_attachment(move |kind| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            if !chat_uri.is_empty() {
                let _ = tx.send(UiBridgeCommand::SendAttachment {
                    chat_uri,
                    kind: kind.to_string(),
                });
            }
        });
    }

    // Clear Chat History in Active Chat
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_clear_chat_history(move || {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            if !chat_uri.is_empty() {
                let _ = tx.send(UiBridgeCommand::ClearChatHistory { chat_uri });
            }
        });
    }

    // Delete / Leave Active Chat
    {
        let win_weak = window.as_weak();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_delete_active_chat(move || {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            if !chat_uri.is_empty() {
                let _ = tx.send(UiBridgeCommand::DeleteActiveChat { chat_uri });
            }
            if let Some(win) = win_weak.upgrade() {
                win.global::<SuperTheme>().set_mobile_showing_chat(false);
            }
        });
    }

    // Remove Individual Account
    {
        let tx = cmd_tx.clone();
        window.on_remove_account(move |account_id| {
            let acct = account_id.trim().to_string();
            if !acct.is_empty() {
                let _ = tx.send(UiBridgeCommand::RemoveAccount { account_id: acct });
            }
        });
    }

    // Activate Demo / Mockup Environment on demand
    {
        let win_weak = window.as_weak();
        let tx = cmd_tx.clone();
        window.on_activate_demo_mockup(move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_show_welcome_screen(false);
                win.set_is_demo_mockup_active(true);
            }
            let _ = tx.send(UiBridgeCommand::ActivateDemoMockup);
        });
    }

    // Exit Demo / Mockup Environment & Wipe Demo Data
    {
        let win_weak = window.as_weak();
        let tx = cmd_tx.clone();
        window.on_exit_demo_mockup(move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_is_demo_mockup_active(false);
                win.set_show_welcome_screen(true);
                win.set_show_settings_modal(false);
            }
            let _ = tx.send(UiBridgeCommand::ExitDemoMockup);
        });
    }

    // Select Folder Tab
    {
        let win_weak = window.as_weak();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_select_folder(move |folder_id| {
            if let Ok(mut s) = sel.lock() {
                s.active_folder_id = folder_id.to_string();
                s.active_container_uri.clear();
            }
            if let Some(win) = win_weak.upgrade() {
                win.set_active_folder_id(folder_id);
                win.set_active_container_uri(SharedString::from(""));
            }
            let _ = tx.send(UiBridgeCommand::ForceRefresh);
        });
    }

    // Select Server Rail Container (Discord / Stoat / Mattermost / IRC / Matrix Space)
    {
        let win_weak = window.as_weak();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_select_container(move |container_uri| {
            if let Ok(mut s) = sel.lock() {
                s.active_container_uri = container_uri.to_string();
            }
            if let Some(win) = win_weak.upgrade() {
                win.set_active_container_uri(container_uri);
            }
            let _ = tx.send(UiBridgeCommand::ForceRefresh);
        });
    }

    // Select Chat / Channel / Thread (marks read & pushes Chat View on Mobile Single-Pane stack)
    {
        let win_weak = window.as_weak();
        let st = storage.clone();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_select_chat(move |chat_uri| {
            if let Ok(chat_id) = UniversalId::from_uri(chat_uri.as_str()) {
                let _ = st.mark_chat_read(&chat_id);
            }
            if let Ok(mut s) = sel.lock() {
                s.active_chat_uri = chat_uri.to_string();
            }
            if let Some(win) = win_weak.upgrade() {
                win.set_active_chat_uri(chat_uri);
                win.set_replying_to_message_id(SharedString::from(""));
                win.set_reply_to_preview(SharedString::from(""));
                win.set_editing_message_id(SharedString::from(""));
                win.set_editing_message_preview(SharedString::from(""));
                if win.global::<SuperTheme>().get_is_mobile_compact() {
                    win.global::<SuperTheme>().set_mobile_showing_chat(true);
                }
            }
            let _ = tx.send(UiBridgeCommand::ForceRefresh);
        });
    }

    // Send Optimistic Message (or Commit Edit if editing-message-id is active)
    {
        let win_weak = window.as_weak();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_send_message(move |text| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            if chat_uri.is_empty() || text.trim().is_empty() {
                return;
            }
            let mut reply_preview: Option<String> = None;
            let mut edit_msg_id = String::new();
            if let Some(win) = win_weak.upgrade() {
                edit_msg_id = win.get_editing_message_id().to_string();
                let rp = win.get_reply_to_preview().to_string();
                if !rp.is_empty() {
                    reply_preview = Some(rp);
                }
                win.set_replying_to_message_id(SharedString::from(""));
                win.set_reply_to_preview(SharedString::from(""));
                win.set_editing_message_id(SharedString::from(""));
                win.set_editing_message_preview(SharedString::from(""));
            }
            if !edit_msg_id.is_empty() {
                let _ = tx.send(UiBridgeCommand::EditMessage {
                    chat_uri,
                    message_uri: edit_msg_id,
                    new_text: text.to_string(),
                });
            } else {
                let _ = tx.send(UiBridgeCommand::SendMessage {
                    chat_uri,
                    text: text.to_string(),
                    reply_preview,
                });
            }
        });
    }

    // Reply to Message (populates reply banner above composer)
    {
        let win_weak = window.as_weak();
        let st = storage;
        window.on_reply_to_message(move |msg_uri| {
            let preview = UniversalId::from_uri(msg_uri.as_str())
                .ok()
                .and_then(|id| st.get_message(&id).ok().flatten())
                .map(|m| {
                    format!(
                        "{}: {}",
                        sanitize_for_outline_renderer(m.sender_display_name.as_str()),
                        sanitize_for_outline_renderer(m.text.as_str())
                    )
                })
                .unwrap_or_else(|| "Messaggio citato".to_string());
            if let Some(win) = win_weak.upgrade() {
                win.set_editing_message_id(SharedString::from(""));
                win.set_editing_message_preview(SharedString::from(""));
                win.set_replying_to_message_id(msg_uri);
                win.set_reply_to_preview(SharedString::from(preview));
            }
        });
    }

    // Start Editing a Message (populates edit banner + composer text)
    {
        let win_weak = window.as_weak();
        window.on_start_edit_message(move |msg_uri, current_text| {
            if let Some(win) = win_weak.upgrade() {
                win.set_replying_to_message_id(SharedString::from(""));
                win.set_reply_to_preview(SharedString::from(""));
                win.set_editing_message_id(msg_uri);
                win.set_editing_message_preview(current_text.clone());
                win.set_composer_text(current_text);
            }
        });
    }

    // Commit Edited Message
    {
        let win_weak = window.as_weak();
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_commit_edit_message(move |msg_uri, new_text| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            if !chat_uri.is_empty() && !new_text.trim().is_empty() {
                let _ = tx.send(UiBridgeCommand::EditMessage {
                    chat_uri,
                    message_uri: msg_uri.to_string(),
                    new_text: new_text.to_string(),
                });
            }
            if let Some(win) = win_weak.upgrade() {
                win.set_editing_message_id(SharedString::from(""));
                win.set_editing_message_preview(SharedString::from(""));
                win.set_composer_text(SharedString::from(""));
            }
        });
    }

    // Cancel Reply or Edit Banner
    {
        let win_weak = window.as_weak();
        window.on_cancel_reply_or_edit(move || {
            if let Some(win) = win_weak.upgrade() {
                win.set_replying_to_message_id(SharedString::from(""));
                win.set_reply_to_preview(SharedString::from(""));
                win.set_editing_message_id(SharedString::from(""));
                win.set_editing_message_preview(SharedString::from(""));
            }
        });
    }

    // React to Message (`react-message` and `react-to-message`)
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_react_message(move |msg_uri, emoji| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            let _ = tx.send(UiBridgeCommand::ReactToMessage {
                chat_uri,
                message_uri: msg_uri.to_string(),
                emoji: emoji.to_string(),
            });
        });
    }
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_react_to_message(move |msg_uri, emoji| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            let _ = tx.send(UiBridgeCommand::ReactToMessage {
                chat_uri,
                message_uri: msg_uri.to_string(),
                emoji: emoji.to_string(),
            });
        });
    }

    // Delete Message
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_delete_message(move |msg_uri| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            let _ = tx.send(UiBridgeCommand::DeleteMessage {
                chat_uri,
                message_uri: msg_uri.to_string(),
            });
        });
    }

    // Edit Message (fallback direct callback)
    {
        let sel = selection.clone();
        let tx = cmd_tx.clone();
        window.on_edit_message(move |msg_uri| {
            let chat_uri = sel.lock().map(|s| s.active_chat_uri.clone()).unwrap_or_default();
            let _ = tx.send(UiBridgeCommand::EditMessage {
                chat_uri,
                message_uri: msg_uri.to_string(),
                new_text: "✎ [Messaggio modificato]".to_string(),
            });
        });
    }

    // Inspect Declarative AuthFlowDescriptor for any of the 8 protocols
    {
        let win_weak = window.as_weak();
        window.on_inspect_protocol_auth(move |slug| {
            if let Some(win) = win_weak.upgrade() {
                let proto = ProtocolKind::from_slug(slug.as_str());
                let is_test = TelegramBackendEnvironment::from_slug(
                    win.get_telegram_backend_mode().as_str(),
                )
                .is_test_server();
                let flow =
                    AuthFlowDescriptor::for_protocol_and_mode(proto, OnboardingMode::Login, is_test);
                apply_auth_flow_to_window(&win, &flow);
            }
        });
    }

    // Switch Onboarding Mode inside Auth Modal (`login` vs `signup` vs `bot_token`)
    {
        let win_weak = window.as_weak();
        window.on_switch_auth_modal_mode(move |mode_slug| {
            if let Some(win) = win_weak.upgrade() {
                let proto = protocol_from_display_label(win.get_auth_modal_protocol().as_str());
                let mode = OnboardingMode::from_slug(mode_slug.as_str());
                let is_test = TelegramBackendEnvironment::from_slug(
                    win.get_telegram_backend_mode().as_str(),
                )
                .is_test_server();
                let flow = AuthFlowDescriptor::for_protocol_and_mode(proto, mode, is_test);
                apply_auth_flow_to_window(&win, &flow);
            }
        });
    }

    // Update a single field inside the Auth Modal
    {
        let win_weak = window.as_weak();
        window.on_update_auth_field(move |field_key, new_val| {
            if let Some(win) = win_weak.upgrade() {
                use slint::Model;
                let model = win.get_auth_modal_fields();
                let count = model.row_count();
                for idx in 0..count {
                    if let Some(mut item) = model.row_data(idx) {
                        if item.key == field_key {
                            item.value = new_val.clone();
                            model.set_row_data(idx, item);
                            break;
                        }
                    }
                }
            }
        });
    }

    // Submit the Auth Modal (`Login`, `Telegram Bot Token`, or `Sign-Up`) -> Persists Account & Chats!
    {
        let win_weak = window.as_weak();
        let tx = cmd_tx.clone();
        window.on_submit_auth_modal(move || {
            if let Some(win) = win_weak.upgrade() {
                use slint::Model;
                let proto_label = win.get_auth_modal_protocol().to_string();
                let proto = protocol_from_display_label(&proto_label);
                let mode = OnboardingMode::from_slug(win.get_auth_modal_mode().as_str());

                let mut inputs = std::collections::BTreeMap::new();
                let model = win.get_auth_modal_fields();
                for idx in 0..model.row_count() {
                    if let Some(item) = model.row_data(idx) {
                        inputs.insert(item.key.to_string(), item.value.to_string());
                    }
                }
                inputs.insert(
                    "backend_env".to_string(),
                    win.get_telegram_backend_mode().to_string(),
                );

                let _ = tx.send(UiBridgeCommand::SubmitAuthModal {
                    protocol: proto,
                    mode,
                    inputs,
                });

                let status_msg = match mode {
                    OnboardingMode::TelegramBotToken => format!(
                        "✓ {} Bot configurato e collegato con successo!",
                        proto_label
                    ),
                    OnboardingMode::SignUp => format!(
                        "✓ Nuovo account {} creato, registrato e attivo!",
                        proto_label
                    ),
                    OnboardingMode::Login => format!(
                        "✓ Account {} collegato e sincronizzato con successo!",
                        proto_label
                    ),
                };
                win.set_auth_modal_status_text(SharedString::from(status_msg.as_str()));
                win.set_status_toast_text(SharedString::from(status_msg));
                win.set_show_welcome_screen(false);
                win.set_show_protocol_picker_modal(false);
                win.set_show_auth_modal(false);
                win.global::<SuperTheme>().set_mobile_keyboard_open(false);
                crate::android_platform::set_android_soft_keyboard_visible(false);
            }
        });
    }

    // SuperTheme Soft Keyboard + Built-In Mobile Touch Keyboard + Android Permissions Callbacks
    {
        let win_weak = window.as_weak();
        window
            .global::<SuperTheme>()
            .on_request_soft_keyboard(move |target, label| {
                if let Some(win) = win_weak.upgrade() {
                    let st = win.global::<SuperTheme>();
                    st.set_mobile_keyboard_target(target);
                    st.set_mobile_keyboard_label(label);
                    st.set_mobile_keyboard_open(true);
                }
                crate::android_platform::set_android_soft_keyboard_visible(true);
            });
    }

    {
        let win_weak = window.as_weak();
        window.global::<SuperTheme>().on_hide_soft_keyboard(move || {
            if let Some(win) = win_weak.upgrade() {
                win.global::<SuperTheme>().set_mobile_keyboard_open(false);
            }
            crate::android_platform::set_android_soft_keyboard_visible(false);
        });
    }

    {
        let win_weak = window.as_weak();
        window
            .global::<SuperTheme>()
            .on_request_android_permissions(move || {
                let granted = crate::android_platform::request_android_permissions_now();
                if let Some(win) = win_weak.upgrade() {
                    let msg = if granted {
                        "✓ Permessi Android richiesti con successo (Storage, Notifiche, Audio, Camera)"
                    } else {
                        "✓ Richiesta permessi Android registrata (Storage locale SQLite WAL attivo)"
                    };
                    win.set_status_toast_text(SharedString::from(msg));
                }
            });
    }

    {
        let win_weak = window.as_weak();
        let sel = selection;
        let tx = cmd_tx;
        window
            .global::<SuperTheme>()
            .on_mobile_key_tap(move |key_str| {
                let Some(win) = win_weak.upgrade() else {
                    return;
                };
                let st = win.global::<SuperTheme>();
                let target = st.get_mobile_keyboard_target().to_string();
                let key = key_str.as_str();

                if key == "ENTER" {
                    match target.as_str() {
                        "composer" => {
                            let current = win.get_composer_text().to_string();
                            if !current.trim().is_empty() {
                                win.set_composer_text(SharedString::from(""));
                                win.invoke_send_message(SharedString::from(current));
                            }
                        }
                        "quick_contact" => {
                            let current = win.get_quick_contact_id().to_string();
                            if !current.trim().is_empty() {
                                win.invoke_quick_add_contact(SharedString::from(current));
                            }
                            st.set_mobile_keyboard_open(false);
                            crate::android_platform::set_android_soft_keyboard_visible(false);
                        }
                        _ => {
                            st.set_mobile_keyboard_open(false);
                            crate::android_platform::set_android_soft_keyboard_visible(false);
                        }
                    }
                    return;
                }

                let apply_key = |current: &str, k: &str| -> String {
                    match k {
                        "CLEAR" => String::new(),
                        "BACKSPACE" => {
                            let mut s = current.to_string();
                            s.pop();
                            s
                        }
                        other => {
                            let mut s = current.to_string();
                            s.push_str(other);
                            s
                        }
                    }
                };

                if let Some(field_key) = target.strip_prefix("auth:") {
                    use slint::Model;
                    let model = win.get_auth_modal_fields();
                    let count = model.row_count();
                    let mut matched_idx: Option<usize> = None;
                    for idx in 0..count {
                        if let Some(item) = model.row_data(idx) {
                            if item.key.as_str() == field_key {
                                matched_idx = Some(idx);
                                break;
                            }
                        }
                    }
                    if matched_idx.is_none() && field_key == "phone_or_token" {
                        for idx in 0..count {
                            if let Some(item) = model.row_data(idx) {
                                if item.key.as_str() == "phone_number"
                                    || item.key.as_str() == "bot_token"
                                    || item.key.as_str() == "username"
                                {
                                    matched_idx = Some(idx);
                                    break;
                                }
                            }
                        }
                        if matched_idx.is_none() && count > 0 {
                            matched_idx = Some(0);
                        }
                    }
                    if let Some(idx) = matched_idx {
                        if let Some(mut item) = model.row_data(idx) {
                            let next_val = apply_key(item.value.as_str(), key);
                            item.value = SharedString::from(next_val);
                            model.set_row_data(idx, item);
                        }
                    }
                } else {
                    match target.as_str() {
                        "search" => {
                            let next_val = apply_key(win.get_search_query().as_str(), key);
                            win.set_search_query(SharedString::from(next_val.as_str()));
                            if let Ok(mut s) = sel.lock() {
                                s.search_query = next_val;
                            }
                            let _ = tx.send(UiBridgeCommand::ForceRefresh);
                        }
                        "quick_contact" => {
                            let next_val = apply_key(win.get_quick_contact_id().as_str(), key);
                            win.set_quick_contact_id(SharedString::from(next_val));
                        }
                        "new_chat" => {
                            let next_val =
                                apply_key(win.get_new_chat_remote_target().as_str(), key);
                            win.set_new_chat_remote_target(SharedString::from(next_val));
                        }
                        "new_chat_title" => {
                            let next_val = apply_key(win.get_new_chat_title().as_str(), key);
                            win.set_new_chat_title(SharedString::from(next_val));
                        }
                        "composer" | _ => {
                            let next_val = apply_key(win.get_composer_text().as_str(), key);
                            win.set_composer_text(SharedString::from(next_val));
                        }
                    }
                }

                if st.get_mobile_keyboard_shift()
                    && key.chars().count() == 1
                    && key.chars().all(|c| c.is_ascii_uppercase())
                {
                    st.set_mobile_keyboard_shift(false);
                }
            });
    }
}

fn protocol_from_display_label(label: &str) -> ProtocolKind {
    let lower = label.trim().to_ascii_lowercase();
    if lower.contains("telegram") {
        ProtocolKind::Telegram
    } else if lower.contains("matrix") {
        ProtocolKind::Matrix
    } else if lower.contains("xmpp") || lower.contains("jabber") {
        ProtocolKind::Xmpp
    } else if lower.contains("nostr") {
        ProtocolKind::Nostr
    } else if lower.contains("simplex") {
        ProtocolKind::SimpleX
    } else if lower.contains("irc") {
        ProtocolKind::Irc
    } else if lower.contains("stoat") || lower.contains("revolt") {
        ProtocolKind::Stoat
    } else if lower.contains("mattermost") {
        ProtocolKind::Mattermost
    } else {
        ProtocolKind::from_slug(&lower)
    }
}

fn format_hh_mm(timestamp_ms: i64) -> String {
    let total_secs = (timestamp_ms / 1000).rem_euclid(86_400);
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    format!("{:02}:{:02}", hours, mins)
}

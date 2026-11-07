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

//! Dynamic Topology Model (`ContainerHierarchy`, `UnifiedContainer`, `UnifiedChat`, `UnifiedMessage`).
//!
//! Unifies 3 distinct structural paradigms across the 8 protocols into a single
//! polymorphic hierarchy:
//! 1. **Flat 1-to-1 & Group Chats**: Telegram DMs/Groups, XMPP Rosters/MUCs, SimpleX Queues, Nostr NIP-17 DMs.
//! 2. **2-Level Workspace/Server/Space -> Channel**: Stoat Servers, Mattermost Teams, Matrix Spaces, IRC Networks (`Soju`/`Ergo` bouncers).
//! 3. **3-Level Container/Group -> Channel -> Topic/Thread**: Telegram Forum Topics, Mattermost Threads, Matrix Threads.
//!
//! Includes `protocol_metadata: serde_json::Value` on `UnifiedContainer`, `UnifiedChat`, and
//! `UnifiedMessage` so any protocol adapter can store arbitrary state (`file_reference`,
//! `access_hash`, Nostr relay hints, SimpleX ratchet IDs, IRC `msgid` tags) without ever
//! altering the SQLite schema.

use crate::capabilities::{ChatCapabilities, MessageCapabilities};
use crate::ids::{AccountId, ProtocolKind, UniversalId};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};

/// Top-level organizational container kind (Level 1 in a 2-level or 3-level hierarchy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    /// Mattermost Team / Enterprise Workspace
    Workspace,
    /// Stoat (ex-Revolt) Server
    Server,
    /// Matrix Space (`m.space`)
    Space,
    /// IRCv3 Network or BouncerUpstream (e.g., Libera.Chat via Soju/Ergo)
    IrcNetwork,
    /// Telegram Supergroup with Forum Topics enabled
    ForumGroup,
}

/// Represents a Level-1 Container (Server, Workspace, Matrix Space, IRC Network, or Telegram Forum).
///
/// - In the **Discord Supertheme**, each `UnifiedContainer` is rendered as a circular/squircle
///   server icon in the left-most vertical Server Rail.
/// - In the **Telegram Supertheme**, containers can be projected as granular Folder Tabs
///   or expandable Forum Groups with nested Topic sub-rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedContainer {
    pub id: UniversalId,
    pub kind: ContainerKind,
    pub title: CompactString,
    pub icon_initials: CompactString,
    pub avatar_url: Option<CompactString>,
    pub unread_count: u32,
    pub mention_count: u32,
    pub child_chat_ids: Vec<UniversalId>,
    #[serde(default)]
    pub protocol_metadata: serde_json::Value,
}

/// Structural topology classification of a [`UnifiedChat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatTopologyKind {
    /// Flat 1-to-1 Direct Message (Telegram DM, XMPP JID, SimpleX Queue, Nostr NIP-17 DM).
    DirectMessage,
    /// Standalone Group Chat without a parent Server/Workspace container.
    FlatGroup,
    /// Level-2 Channel inside a [`UnifiedContainer`] (Stoat/Mattermost/IRC/Matrix Space channel).
    ContainerChannel,
    /// Level-3 Topic or Thread inside a parent [`UnifiedChat`] (Telegram Forum Topic, Mattermost/Matrix Thread).
    ThreadOrTopic,
}

/// Complete 1-to-3 level topological descriptor for any chat room or thread.
///
/// Bridges the structural gap between flat messengers (Telegram/WhatsApp/SimpleX)
/// and workspace/server messengers (Stoat/Mattermost/Matrix Spaces/IRC):
/// - `Flat`: standalone DM or group (`parent_container_id = None`, `parent_chat_id = None`)
/// - `ServerChannel`: channel belonging to a `UnifiedContainer` (`parent_container_id = Some(...)`)
/// - `NestedThread`: topic/thread inside a channel or forum group (`parent_chat_id = Some(...)`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum ContainerHierarchy {
    /// Level 1 flat chat (1-to-1 DM or standalone group).
    Flat {
        is_direct_message: bool,
    },
    /// Level 2 channel inside a Server, Workspace, Matrix Space, or IRC Network.
    ServerChannel {
        container_id: UniversalId,
        container_kind: ContainerKind,
        category_name: Option<CompactString>,
    },
    /// Level 3 thread or forum topic nested under a parent chat (and optionally a top-level container).
    NestedThread {
        container_id: Option<UniversalId>,
        parent_chat_id: UniversalId,
        topic_title: CompactString,
    },
}

impl ContainerHierarchy {
    pub fn container_id(&self) -> Option<&UniversalId> {
        match self {
            Self::Flat { .. } => None,
            Self::ServerChannel { container_id, .. } => Some(container_id),
            Self::NestedThread { container_id, .. } => container_id.as_ref(),
        }
    }

    pub fn parent_chat_id(&self) -> Option<&UniversalId> {
        match self {
            Self::NestedThread { parent_chat_id, .. } => Some(parent_chat_id),
            _ => None,
        }
    }
}

/// Protocol-agnostic representation of a conversation, channel, queue, or thread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedChat {
    pub id: UniversalId,
    pub parent_container_id: Option<UniversalId>,
    pub parent_chat_id: Option<UniversalId>,
    pub topology: ChatTopologyKind,
    pub hierarchy: ContainerHierarchy,
    pub title: CompactString,
    pub subtitle: Option<CompactString>,
    pub avatar_initials: CompactString,
    pub avatar_url: Option<CompactString>,
    pub last_message_preview: Option<CompactString>,
    pub last_activity_ts: i64,
    pub unread_count: u32,
    pub mention_count: u32,
    pub is_pinned: bool,
    pub is_muted: bool,
    pub is_online: bool,
    pub capabilities: ChatCapabilities,
    /// Extensible JSON metadata for protocol-specific fields (e.g., Telegram `access_hash`,
    /// Nostr relay list, SimpleX double-ratchet queue info, IRC `chathistory` token).
    #[serde(default)]
    pub protocol_metadata: serde_json::Value,
}

impl UnifiedChat {
    pub fn protocol(&self) -> &ProtocolKind {
        &self.id.protocol
    }

    pub fn account_id(&self) -> &AccountId {
        &self.id.account_id
    }
}

/// Outbox & remote delivery lifecycle state for Optimistic UI (< 1ms local echo).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum DeliveryState {
    /// Stored locally in SQLite and queued in `outbox_queue` (< 1ms optimistic insert).
    Pending,
    /// Outbox worker is actively dispatching to the protocol adapter (with retry count).
    Sending(u32),
    /// Confirmed by remote server/relay with a definitive `remote_id`.
    Sent,
    /// Delivered to recipient device/queue.
    Delivered,
    /// Read receipt received from recipient.
    Read,
    /// Permanent or transient failure with diagnostic description.
    Failed(CompactString),
}

impl DeliveryState {
    pub fn status_badge(&self) -> &'static str {
        match self {
            Self::Pending => "⏳",
            Self::Sending(_) => "↗",
            Self::Sent => "✓",
            Self::Delivered => "✓✓",
            Self::Read => "✓✓",
            Self::Failed(_) => "⚠",
        }
    }
}

/// Abstract Media Proxy attachment (`warp-media://<protocol>/<account_id>/<media_id>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaAttachment {
    /// Canonical `warp-media://` URI resolved by the Media Proxy.
    pub media_uri: CompactString,
    /// Origin protocol scheme (`mtproto://`, `mxc://`, `aesgcm://`, `blossom://`, `https://`).
    pub source_url: CompactString,
    pub mime_type: CompactString,
    pub file_name: Option<CompactString>,
    pub size_bytes: u64,
    /// Protocol-specific decryption parameters (AES-GCM key/IV for XMPP OMEMO,
    /// Matrix Megolm attachment key, Telegram `file_reference`, Nostr NIP-96 sha256).
    #[serde(default)]
    pub encryption_metadata: serde_json::Value,
}

/// Aggregated emoji reaction on a [`UnifiedMessage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageReaction {
    pub emoji: CompactString,
    pub count: u32,
    pub reacted_by_me: bool,
}

/// Protocol-agnostic representation of a single chat message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedMessage {
    pub id: UniversalId,
    pub local_outbox_id: Option<CompactString>,
    pub chat_id: UniversalId,
    pub thread_id: Option<UniversalId>,
    pub sender_id: CompactString,
    pub sender_display_name: CompactString,
    pub sender_initials: CompactString,
    pub sender_avatar_url: Option<CompactString>,
    pub is_outgoing: bool,
    pub text: String,
    pub reply_to_id: Option<UniversalId>,
    pub reply_preview: Option<CompactString>,
    pub timestamp_ms: i64,
    pub edited_at_ms: Option<i64>,
    pub delivery_state: DeliveryState,
    pub reactions: Vec<MessageReaction>,
    pub attachments: Vec<MediaAttachment>,
    pub capabilities: MessageCapabilities,
    /// Extensible per-protocol metadata (`file_reference`, Nostr event sig, SimpleX msg_id, IRC tags).
    #[serde(default)]
    pub protocol_metadata: serde_json::Value,
}

/// User-customizable granular folder filter rule (stored in SQLite `folders` table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderFilterRule {
    pub id: CompactString,
    pub name: CompactString,
    pub icon: CompactString,
    /// If non-empty, only chats from these protocols are shown in this folder.
    pub included_protocols: Vec<ProtocolKind>,
    /// If non-empty, only chats belonging to these specific `AccountId`s are shown in this folder.
    #[serde(default)]
    pub included_accounts: Vec<AccountId>,
    /// If non-empty, only chats matching these topologies are shown.
    pub included_topologies: Vec<ChatTopologyKind>,
    /// If Some(container_id), filters to channels/threads inside a specific Server/Workspace.
    pub container_filter: Option<UniversalId>,
    /// Explicitly included chat IDs regardless of protocol/topology filter.
    pub pinned_chat_ids: Vec<UniversalId>,
    /// Explicitly excluded chat IDs.
    pub excluded_chat_ids: Vec<UniversalId>,
    pub unread_only: bool,
}

impl FolderFilterRule {
    /// Evaluates whether `chat` belongs in this folder given the currently active user protocols.
    pub fn matches(&self, chat: &UnifiedChat, enabled_protocols: &[ProtocolKind]) -> bool {
        if !enabled_protocols.contains(chat.protocol()) {
            return false;
        }
        if self.excluded_chat_ids.contains(&chat.id) {
            return false;
        }
        if self.pinned_chat_ids.contains(&chat.id) {
            return !self.unread_only || chat.unread_count > 0;
        }
        if !self.included_accounts.is_empty() && !self.included_accounts.contains(chat.account_id())
        {
            return false;
        }
        if let Some(ref target_container) = self.container_filter {
            if chat.parent_container_id.as_ref() != Some(target_container)
                && &chat.id != target_container
            {
                return false;
            }
        }
        if !self.included_protocols.is_empty() && !self.included_protocols.contains(chat.protocol())
        {
            return false;
        }
        if !self.included_topologies.is_empty() && !self.included_topologies.contains(&chat.topology)
        {
            return false;
        }
        if self.unread_only && chat.unread_count == 0 {
            return false;
        }
        true
    }
}

/// User preference controlling whether chat lists across multiple accounts and protocols
/// are merged into a Unified Inbox or strictly separated.
///
/// Designed for both camps of users:
/// - Those who **love Unified Views** (`UnifiedInbox` / `HybridCustom`)
/// - Those who **hate Unified Views** and want strict compartmentalization (`PerAccount` / `PerProtocol`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChatListIsolationMode {
    /// Merges all enabled accounts (where `include_in_unified_inbox == true`) into a single
    /// unified chat list & folder system.
    #[default]
    UnifiedInbox,
    /// Separates chat lists by protocol (`Telegram`, `IRCv3`, `Matrix`, etc.), merging multiple
    /// accounts of the same protocol into that protocol's view.
    PerProtocol,
    /// Strict per-account isolation ("Silo Mode"): every single account has its own completely
    /// separate chat list, container rail, and unread counter. Two accounts of the same protocol
    /// (e.g. Personal Telegram vs Work/DC2 Telegram) never mix.
    PerAccount,
    /// Hybrid mode: accounts with `include_in_unified_inbox == true` appear in the Unified Inbox,
    /// while accounts with `include_in_unified_inbox == false` are kept in isolated per-account tabs.
    HybridCustom,
}

impl ChatListIsolationMode {
    pub fn as_slug(&self) -> &'static str {
        match self {
            Self::UnifiedInbox => "unified",
            Self::PerProtocol => "per_protocol",
            Self::PerAccount => "per_account",
            Self::HybridCustom => "hybrid",
        }
    }

    pub fn from_slug(slug: &str) -> Self {
        match slug.trim().to_ascii_lowercase().as_str() {
            "per_protocol" | "protocol" => Self::PerProtocol,
            "per_account" | "account" | "isolated" | "separated" => Self::PerAccount,
            "hybrid" | "hybrid_custom" => Self::HybridCustom,
            _ => Self::UnifiedInbox,
        }
    }

    pub fn display_label(&self) -> &'static str {
        match self {
            Self::UnifiedInbox => "Unified Inbox",
            Self::PerProtocol => "Per Protocollo",
            Self::PerAccount => "Per Account (Separata)",
            Self::HybridCustom => "Ibrida (Unified + Silos)",
        }
    }
}

/// First-class descriptor for an individual user account (supports N accounts per protocol).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProfile {
    pub account_id: AccountId,
    pub protocol: ProtocolKind,
    /// User-friendly label (e.g. `"Telegram • Personale"`, `"Telegram • Test DC2 Lab"`).
    pub display_name: CompactString,
    /// Account handle, phone number, JID, npub, or server URI.
    pub handle_or_uri: CompactString,
    /// Short badge displayed on chat rows when multiple accounts are unified (e.g. `"TG•1"`, `"TG•DC2"`).
    pub short_badge: CompactString,
    /// Whether this specific account is currently active/connected.
    pub enabled: bool,
    /// Whether this account's chats are allowed into the Unified Inbox (`true`), or kept strictly
    /// isolated in its own account view (`false`).
    pub include_in_unified_inbox: bool,
    pub sort_order: i32,
}


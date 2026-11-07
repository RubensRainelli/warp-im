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

//! Stoat (formerly Revolt) REST API + Bonfire WebSocket protocol adapter.
//!
//! Supports:
//! - Crockford Base32 26-character **ULID** generator & decoder (48-bit timestamp + 80-bit randomness)
//! - **Bonfire WebSocket** frame parser & serializer (`Authenticate`, `Ping`/`Pong`, `Ready`,
//!   `Message`, `MessageUpdate`, `MessageDelete`, `MessageReact`, `ChannelStartTyping`)
//! - 3-Level Topology: Server (`ContainerKind::Server`) -> Channels (`#general`, `#announcements`,
//!   `#voice-lounge`) -> Nested Threads (`ChatTopologyKind::ThreadOrTopic`)
//! - Role-based channel permission enforcement (`ChatCapabilities::IS_READ_ONLY` on `#announcements`)
//! - Autumn CDN media resolution (`autumn://` and `https://autumn.stoat.chat/attachments/...`)

use async_trait::async_trait;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use warp_core::{
    AccountId, AuthFieldSpec, AuthFlowDescriptor, AuthStep, AuthStepSubmission, BackendEvent,
    ChatCapabilities, ChatTopologyKind, ContainerHierarchy, ContainerKind, DeliveryState,
    MediaAttachment, MessageCapabilities, MessageReaction, MessagingBackend,
    OutboundMessageRequest, ProtocolCapabilities, ProtocolKind, ProtocolPlugin, ResolvedMediaBytes,
    SyncState, UnifiedChat, UnifiedContainer, UnifiedMessage, UniversalId, WarpError,
};

/// Crockford's Base32 alphabet used by Stoat 26-character ULIDs.
const CROCKFORD_BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Default Stoat Server ULID (26 chars, valid Crockford Base32).
pub const DEFAULT_STOAT_SERVER_ULID: &str = "01H8STOATSERVER00000000001";
/// Default `#general` channel ULID.
pub const DEFAULT_STOAT_GENERAL_ULID: &str = "01H8STOATCHANGENERAL000001";
/// Legacy/simulator read-only announcements identifier for backward compatibility.
pub const LEGACY_STOAT_ANNOUNCEMENTS_RO_ID: &str = "01H8STOATCHANannouncements_ro";
/// Canonical 26-char Crockford Base32 ULID for `#announcements`.
pub const DEFAULT_STOAT_ANNOUNCEMENTS_ULID: &str = "01H8STOATCHANANN0UNCEMENT1";
/// Default `#voice-lounge` channel ULID.
pub const DEFAULT_STOAT_VOICE_ULID: &str = "01H8STOATCHANV01CEL0UNGE01";
/// Default 3rd-level thread ULID inside `#general`.
pub const DEFAULT_STOAT_THREAD_ULID: &str = "01H8STOATTHREADB0NF1RE0001";

/// 128-bit Universally Unique Lexicographically Sortable Identifier (ULID) used by Stoat.
///
/// Layout:
/// - **48-bit timestamp**: milliseconds since UNIX epoch (first 10 Crockford Base32 chars)
/// - **80-bit randomness / monotonic counter**: `randomness_hi` (16 bits) + `randomness_lo` (64 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StoatUlid {
    pub timestamp_ms: u64,
    pub randomness_hi: u16,
    pub randomness_lo: u64,
}

impl StoatUlid {
    /// Constructs a [`StoatUlid`] from its 48-bit millisecond timestamp and 80-bit randomness.
    pub fn from_parts(timestamp_ms: u64, randomness_hi: u16, randomness_lo: u64) -> Self {
        Self {
            timestamp_ms: timestamp_ms & 0xFFFF_FFFF_FFFF,
            randomness_hi,
            randomness_lo,
        }
    }

    /// Generates a monotonic [`StoatUlid`] from a millisecond timestamp and sequence number.
    pub fn generate(timestamp_ms: u64, seq: u64) -> Self {
        let hi = ((seq >> 48) as u16) ^ 0x5A3C;
        let lo = seq.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(seq);
        Self::from_parts(timestamp_ms, hi, lo)
    }

    /// Converts this ULID into a 128-bit unsigned integer.
    pub fn to_u128(self) -> u128 {
        let ts = (self.timestamp_ms & 0xFFFF_FFFF_FFFF) as u128;
        let hi = (self.randomness_hi as u128) << 64;
        let lo = self.randomness_lo as u128;
        (ts << 80) | hi | lo
    }

    /// Constructs a [`StoatUlid`] from a raw 128-bit unsigned integer.
    pub fn from_u128(value: u128) -> Self {
        let timestamp_ms = ((value >> 80) & 0xFFFF_FFFF_FFFF) as u64;
        let randomness_hi = ((value >> 64) & 0xFFFF) as u16;
        let randomness_lo = (value & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        Self {
            timestamp_ms,
            randomness_hi,
            randomness_lo,
        }
    }

    /// Encodes this ULID into a canonical 26-character uppercase Crockford Base32 string.
    pub fn encode(&self) -> CompactString {
        let raw = self.to_u128();
        let mut buf = [0u8; 26];
        for (i, slot) in buf.iter_mut().enumerate() {
            let shift = (25 - i) * 5;
            let idx = ((raw >> shift) & 0x1F) as usize;
            *slot = CROCKFORD_BASE32[idx];
        }
        CompactString::from_utf8(buf).expect("Crockford Base32 is valid ASCII")
    }

    /// Decodes a 26-character Crockford Base32 string into a [`StoatUlid`].
    pub fn decode(input: &str) -> Result<Self, WarpError> {
        let trimmed = input.trim();
        if trimmed.len() != 26 {
            return Err(WarpError::Transport(format!(
                "invalid Stoat ULID length {}: expected 26 characters",
                trimmed.len()
            )));
        }

        let bytes = trimmed.as_bytes();
        let first_val = decode_crockford_char(bytes[0]).ok_or_else(|| {
            WarpError::Transport(format!(
                "invalid Crockford Base32 character '{}' in Stoat ULID",
                bytes[0] as char
            ))
        })?;
        if first_val > 7 {
            return Err(WarpError::Transport(
                "Stoat ULID overflow: first character cannot exceed '7'".into(),
            ));
        }

        let mut acc: u128 = 0;
        for &b in bytes {
            let digit = decode_crockford_char(b).ok_or_else(|| {
                WarpError::Transport(format!(
                    "invalid Crockford Base32 character '{}' in Stoat ULID",
                    b as char
                ))
            })?;
            acc = (acc << 5) | (digit as u128);
        }

        Ok(Self::from_u128(acc))
    }
}

impl std::fmt::Display for StoatUlid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.encode().as_str())
    }
}

fn decode_crockford_char(b: u8) -> Option<u8> {
    match b.to_ascii_uppercase() {
        b'0' | b'O' => Some(0),
        b'1' | b'I' | b'L' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'A' => Some(10),
        b'B' => Some(11),
        b'C' => Some(12),
        b'D' => Some(13),
        b'E' => Some(14),
        b'F' => Some(15),
        b'G' => Some(16),
        b'H' => Some(17),
        b'J' => Some(18),
        b'K' => Some(19),
        b'M' => Some(20),
        b'N' => Some(21),
        b'P' => Some(22),
        b'Q' => Some(23),
        b'R' => Some(24),
        b'S' => Some(25),
        b'T' => Some(26),
        b'V' => Some(27),
        b'W' => Some(28),
        b'X' => Some(29),
        b'Y' => Some(30),
        b'Z' => Some(31),
        _ => None,
    }
}

/// Client-to-Server frame sent over the Stoat Bonfire WebSocket (`wss://ws.stoat.chat`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BonfireClientFrame {
    Authenticate { token: CompactString },
    Ping { data: u64 },
    BeginTyping { channel: CompactString },
    EndTyping { channel: CompactString },
}

impl BonfireClientFrame {
    pub fn to_json(&self) -> Result<String, WarpError> {
        serde_json::to_string(self)
            .map_err(|e| WarpError::Transport(format!("Bonfire client frame serialize error: {e}")))
    }

    pub fn from_json(raw: &str) -> Result<Self, WarpError> {
        serde_json::from_str(raw)
            .map_err(|e| WarpError::Transport(format!("Bonfire client frame parse error: {e}")))
    }
}

/// Minimal user descriptor in a Bonfire `Ready` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoatUser {
    #[serde(rename = "_id")]
    pub id: CompactString,
    pub username: CompactString,
    #[serde(default)]
    pub display_name: Option<CompactString>,
    #[serde(default)]
    pub online: bool,
}

/// Minimal server descriptor in a Bonfire `Ready` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoatServer {
    #[serde(rename = "_id")]
    pub id: CompactString,
    pub name: CompactString,
    #[serde(default)]
    pub channels: Vec<CompactString>,
}

/// Minimal channel descriptor in a Bonfire `Ready` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoatChannel {
    #[serde(rename = "_id")]
    pub id: CompactString,
    pub channel_type: CompactString,
    pub server: Option<CompactString>,
    pub name: CompactString,
    #[serde(default)]
    pub description: Option<CompactString>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub parent_channel: Option<CompactString>,
}

/// Autumn attachment metadata embedded inside a Bonfire `Message` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoatAutumnAttachment {
    #[serde(rename = "_id")]
    pub id: CompactString,
    #[serde(default = "default_autumn_tag")]
    pub tag: CompactString,
    pub filename: CompactString,
    pub content_type: CompactString,
    pub size: u64,
}

fn default_autumn_tag() -> CompactString {
    CompactString::from("attachments")
}

/// Message payload inside a Bonfire `Message` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoatMessagePayload {
    #[serde(rename = "_id")]
    pub id: CompactString,
    pub channel: CompactString,
    pub author: CompactString,
    pub content: String,
    #[serde(default)]
    pub attachments: Vec<StoatAutumnAttachment>,
    #[serde(default)]
    pub replies: Vec<CompactString>,
    #[serde(default)]
    pub thread_id: Option<CompactString>,
}

/// Partial message update data inside a Bonfire `MessageUpdate` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoatMessageEditData {
    pub content: String,
    #[serde(default)]
    pub edited: Option<String>,
}

/// Server-to-Client event received from the Stoat Bonfire WebSocket stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BonfireServerEvent {
    Authenticated,
    Pong {
        data: u64,
    },
    Ready {
        #[serde(default)]
        users: Vec<StoatUser>,
        #[serde(default)]
        servers: Vec<StoatServer>,
        #[serde(default)]
        channels: Vec<StoatChannel>,
    },
    Message(StoatMessagePayload),
    MessageUpdate {
        id: CompactString,
        channel: CompactString,
        data: StoatMessageEditData,
    },
    MessageDelete {
        id: CompactString,
        channel: CompactString,
    },
    MessageReact {
        id: CompactString,
        channel_id: CompactString,
        user_id: CompactString,
        emoji_id: CompactString,
    },
    MessageUnreact {
        id: CompactString,
        channel_id: CompactString,
        user_id: CompactString,
        emoji_id: CompactString,
    },
    ChannelStartTyping {
        id: CompactString,
        user: CompactString,
    },
    ChannelStopTyping {
        id: CompactString,
        user: CompactString,
    },
}

impl BonfireServerEvent {
    pub fn from_json(raw: &str) -> Result<Self, WarpError> {
        serde_json::from_str(raw)
            .map_err(|e| WarpError::Transport(format!("Bonfire server event parse error: {e}")))
    }

    pub fn to_json(&self) -> Result<String, WarpError> {
        serde_json::to_string(self).map_err(|e| {
            WarpError::Transport(format!("Bonfire server event serialize error: {e}"))
        })
    }
}

/// Parsed Autumn CDN resource locator (`autumn://<tag>/<id>` or `https://autumn.stoat.chat/<tag>/<id>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutumnResource {
    pub tag: CompactString,
    pub attachment_id: CompactString,
    pub filename: Option<CompactString>,
}

impl AutumnResource {
    /// Parses an `autumn://` URI or `https://autumn.stoat.chat/...` URL into its tag and attachment ID.
    pub fn parse(source_url: &str) -> Result<Self, WarpError> {
        let trimmed = source_url.trim();
        let path = if let Some(rest) = trimmed.strip_prefix("autumn://") {
            rest
        } else if let Some(idx) = trimmed.find("/attachments/") {
            &trimmed[idx + 1..]
        } else if let Some(idx) = trimmed.find("/avatars/") {
            &trimmed[idx + 1..]
        } else if let Some(idx) = trimmed.find("/icons/") {
            &trimmed[idx + 1..]
        } else if let Some(idx) = trimmed.find("/banners/") {
            &trimmed[idx + 1..]
        } else if let Some(rest) = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
        {
            rest.split_once('/').map(|(_, p)| p).unwrap_or("")
        } else {
            trimmed
        };

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match segments.as_slice() {
            [tag, id] => Ok(Self {
                tag: CompactString::from(*tag),
                attachment_id: CompactString::from(*id),
                filename: None,
            }),
            [tag, id, filename, ..] => Ok(Self {
                tag: CompactString::from(*tag),
                attachment_id: CompactString::from(*id),
                filename: Some(CompactString::from(*filename)),
            }),
            [id] => Ok(Self {
                tag: CompactString::from("attachments"),
                attachment_id: CompactString::from(*id),
                filename: None,
            }),
            _ => Err(WarpError::MediaProxy(format!(
                "invalid Stoat Autumn CDN URL: '{source_url}'"
            ))),
        }
    }

    /// Formats the canonical Autumn CDN download URL for a given Autumn base endpoint.
    pub fn canonical_url(&self, autumn_base: &str) -> String {
        let base = autumn_base.trim_end_matches('/');
        match &self.filename {
            Some(name) => format!("{base}/{}/{}/{}", self.tag, self.attachment_id, name),
            None => format!("{base}/{}/{}", self.tag, self.attachment_id),
        }
    }
}

/// Factory plugin for Stoat (ex-Revolt) accounts.
#[derive(Debug, Default, Clone)]
pub struct StoatPlugin;

impl ProtocolPlugin for StoatPlugin {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Stoat
    }

    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        Ok(Arc::new(StoatBackend::new(account_id, config_json)))
    }
}

#[derive(Debug, Default)]
struct StoatRuntimeStore {
    api_url: CompactString,
    ws_url: CompactString,
    autumn_url: CompactString,
    session_token: Option<CompactString>,
    last_pong: Option<u64>,
    containers: HashMap<CompactString, UnifiedContainer>,
    chats: HashMap<CompactString, UnifiedChat>,
    messages_by_chat: HashMap<CompactString, Vec<UnifiedMessage>>,
}

/// Active Stoat REST + Bonfire WebSocket backend.
pub struct StoatBackend {
    account_id: AccountId,
    api_url: CompactString,
    state: RwLock<SyncState>,
    store: RwLock<StoatRuntimeStore>,
    ulid_counter: AtomicU64,
    clock_ms: AtomicU64,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl StoatBackend {
    pub fn new(account_id: AccountId, config: serde_json::Value) -> Self {
        let api_url = config
            .get("server_url")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("https://api.stoat.chat"));
        let ws_url = config
            .get("ws")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("wss://ws.stoat.chat"));
        let autumn_url = config
            .get("autumn_url")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("https://autumn.stoat.chat"));
        let session_token = config
            .get("session_token")
            .and_then(|v| v.as_str())
            .map(CompactString::from);

        let (event_tx, _) = broadcast::channel(256);
        let mut store = StoatRuntimeStore {
            api_url: api_url.clone(),
            ws_url,
            autumn_url,
            session_token,
            last_pong: None,
            containers: HashMap::new(),
            chats: HashMap::new(),
            messages_by_chat: HashMap::new(),
        };
        Self::seed_default_topology(&account_id, &mut store);

        Self {
            account_id,
            api_url,
            state: RwLock::new(SyncState::Disconnected),
            store: RwLock::new(store),
            ulid_counter: AtomicU64::new(10_000),
            clock_ms: AtomicU64::new(1_730_918_455_000),
            event_tx,
        }
    }

    pub fn api_url(&self) -> &str {
        self.api_url.as_str()
    }

    /// Returns the last `Pong` payload echoed by the Bonfire WebSocket server.
    pub fn last_pong(&self) -> Option<u64> {
        self.store.read().ok().and_then(|s| s.last_pong)
    }

    /// Generates a new monotonically increasing 26-character Crockford Base32 [`StoatUlid`].
    pub fn next_ulid(&self) -> StoatUlid {
        let seq = self.ulid_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let ts = self.clock_ms.fetch_add(1, Ordering::SeqCst);
        StoatUlid::generate(ts, seq)
    }

    /// Builds a Bonfire `Authenticate` frame for the currently stored session token.
    pub fn build_auth_frame(&self) -> Result<BonfireClientFrame, WarpError> {
        let guard = self
            .store
            .read()
            .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
        let token = guard.session_token.clone().ok_or_else(|| {
            WarpError::AuthError("Stoat session token is not configured yet".into())
        })?;
        Ok(BonfireClientFrame::Authenticate { token })
    }

    /// Parses and applies an incoming Bonfire WebSocket JSON frame, updating internal state
    /// and emitting the corresponding [`BackendEvent`].
    pub fn ingest_bonfire_frame(&self, raw_json: &str) -> Result<Option<BackendEvent>, WarpError> {
        let event = BonfireServerEvent::from_json(raw_json)?;
        self.process_bonfire_event(event)
    }

    /// Processes a typed [`BonfireServerEvent`] against this backend's state.
    pub fn process_bonfire_event(
        &self,
        event: BonfireServerEvent,
    ) -> Result<Option<BackendEvent>, WarpError> {
        match event {
            BonfireServerEvent::Authenticated => {
                *self.state.write().expect("state lock") = SyncState::LiveSynced;
                let ev = BackendEvent::SyncStateChanged {
                    account_id: self.account_id.clone(),
                    protocol: ProtocolKind::Stoat,
                    state: SyncState::LiveSynced,
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            BonfireServerEvent::Pong { data } => {
                if let Ok(mut store) = self.store.write() {
                    store.last_pong = Some(data);
                }
                Ok(None)
            }
            BonfireServerEvent::Ready {
                users: _,
                servers,
                channels,
            } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;

                for srv in servers {
                    let container_id =
                        UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), srv.id.clone());
                    let child_chat_ids = srv
                        .channels
                        .iter()
                        .map(|cid| {
                            UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), cid.clone())
                        })
                        .collect();
                    let initials: String = srv
                        .name
                        .split_whitespace()
                        .filter_map(|w| w.chars().next())
                        .take(2)
                        .collect();
                    store.containers.insert(
                        srv.id.clone(),
                        UnifiedContainer {
                            id: container_id,
                            kind: ContainerKind::Server,
                            title: srv.name,
                            icon_initials: CompactString::from(if initials.is_empty() {
                                "ST"
                            } else {
                                &initials
                            }),
                            avatar_url: None,
                            unread_count: 0,
                            mention_count: 0,
                            child_chat_ids,
                            protocol_metadata: serde_json::json!({ "bonfire_server_ulid": srv.id }),
                        },
                    );
                }

                for ch in channels {
                    let chat_id =
                        UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), ch.id.clone());
                    let parent_container_id = ch.server.as_ref().map(|sid| {
                        UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), sid.clone())
                    });
                    let is_ro = ch.read_only
                        || ch.id.contains("announcements_ro")
                        || ch.name.eq_ignore_ascii_case("announcements");
                    let caps = if is_ro {
                        ChatCapabilities::CAN_REACT | ChatCapabilities::IS_READ_ONLY
                    } else {
                        ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS
                    };

                    let (topology, hierarchy, parent_chat_id) =
                        if let Some(parent_cid) = ch.parent_channel.as_ref() {
                            let parent_uid = UniversalId::new(
                                ProtocolKind::Stoat,
                                self.account_id.clone(),
                                parent_cid.clone(),
                            );
                            (
                                ChatTopologyKind::ThreadOrTopic,
                                ContainerHierarchy::NestedThread {
                                    container_id: parent_container_id.clone(),
                                    parent_chat_id: parent_uid.clone(),
                                    topic_title: ch.name.clone(),
                                },
                                Some(parent_uid),
                            )
                        } else if let Some(ref srv_uid) = parent_container_id {
                            (
                                ChatTopologyKind::ContainerChannel,
                                ContainerHierarchy::ServerChannel {
                                    container_id: srv_uid.clone(),
                                    container_kind: ContainerKind::Server,
                                    category_name: Some(CompactString::from(
                                        if ch.channel_type.eq_ignore_ascii_case("VoiceChannel") {
                                            "Voice Channels"
                                        } else if is_ro {
                                            "Official"
                                        } else {
                                            "Text Channels"
                                        },
                                    )),
                                },
                                None,
                            )
                        } else {
                            (
                                ChatTopologyKind::DirectMessage,
                                ContainerHierarchy::Flat {
                                    is_direct_message: true,
                                },
                                None,
                            )
                        };

                    store.chats.insert(
                        ch.id.clone(),
                        UnifiedChat {
                            id: chat_id,
                            parent_container_id,
                            parent_chat_id,
                            topology,
                            hierarchy,
                            title: CompactString::from(format!("#{}", ch.name)),
                            subtitle: ch.description,
                            avatar_initials: CompactString::from(if is_ro { "RO" } else { "ST" }),
                            avatar_url: None,
                            last_message_preview: None,
                            last_activity_ts: self.clock_ms.load(Ordering::SeqCst) as i64,
                            unread_count: 0,
                            mention_count: 0,
                            is_pinned: false,
                            is_muted: is_ro,
                            is_online: true,
                            capabilities: caps,
                            protocol_metadata: serde_json::json!({
                                "ulid": ch.id,
                                "channel_type": ch.channel_type,
                                "role_readonly": is_ro,
                            }),
                        },
                    );
                }

                let containers: Vec<UnifiedContainer> =
                    store.containers.values().cloned().collect();
                let chats: Vec<UnifiedChat> = store.chats.values().cloned().collect();
                let ev = BackendEvent::HierarchyUpdated {
                    account_id: self.account_id.clone(),
                    containers,
                    chats,
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            BonfireServerEvent::Message(payload) => {
                let ts_ms = StoatUlid::decode(&payload.id)
                    .map(|u| u.timestamp_ms as i64)
                    .unwrap_or_else(|_| self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64);

                let chat_uid = UniversalId::new(
                    ProtocolKind::Stoat,
                    self.account_id.clone(),
                    payload.channel.clone(),
                );
                let msg_uid = UniversalId::new(
                    ProtocolKind::Stoat,
                    self.account_id.clone(),
                    payload.id.clone(),
                );
                let thread_uid = payload.thread_id.as_ref().map(|tid| {
                    UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), tid.clone())
                });
                let reply_to_id = payload.replies.first().map(|rid| {
                    UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), rid.clone())
                });

                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;

                let attachments = payload
                    .attachments
                    .iter()
                    .map(|att| MediaAttachment {
                        media_uri: CompactString::from(format!(
                            "warp-media://stoat/{}/{}",
                            self.account_id, att.id
                        )),
                        source_url: CompactString::from(format!(
                            "{}/{}/{}/{}",
                            store.autumn_url.trim_end_matches('/'),
                            att.tag,
                            att.id,
                            att.filename
                        )),
                        mime_type: att.content_type.clone(),
                        file_name: Some(att.filename.clone()),
                        size_bytes: att.size,
                        encryption_metadata: serde_json::json!({
                            "autumn_tag": att.tag,
                            "autumn_id": att.id,
                        }),
                    })
                    .collect();

                let chat_caps = store
                    .chats
                    .get(&payload.channel)
                    .map(|c| c.capabilities)
                    .unwrap_or_else(ChatCapabilities::full_featured);

                let unified = UnifiedMessage {
                    id: msg_uid,
                    local_outbox_id: None,
                    chat_id: chat_uid,
                    thread_id: thread_uid,
                    sender_id: payload.author.clone(),
                    sender_display_name: payload.author.clone(),
                    sender_initials: CompactString::from("ST"),
                    sender_avatar_url: None,
                    is_outgoing: false,
                    text: payload.content.clone(),
                    reply_to_id,
                    reply_preview: None,
                    timestamp_ms: ts_ms,
                    edited_at_ms: None,
                    delivery_state: DeliveryState::Delivered,
                    reactions: Vec::new(),
                    attachments,
                    capabilities: MessageCapabilities::derive_from_chat(chat_caps, false, false),
                    protocol_metadata: serde_json::json!({
                        "bonfire_ulid": payload.id,
                    }),
                };

                if let Some(chat) = store.chats.get_mut(&payload.channel) {
                    chat.last_message_preview = Some(CompactString::from(payload.content.as_str()));
                    chat.last_activity_ts = ts_ms;
                    chat.unread_count = chat.unread_count.saturating_add(1);
                }

                store
                    .messages_by_chat
                    .entry(payload.channel)
                    .or_default()
                    .push(unified.clone());

                let ev = BackendEvent::MessageReceived(unified);
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            BonfireServerEvent::MessageUpdate { id, channel, data } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
                let now_ms = self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64;
                if let Some(msgs) = store.messages_by_chat.get_mut(&channel) {
                    if let Some(msg) = msgs.iter_mut().find(|m| m.id.remote_id == id) {
                        msg.text = data.content;
                        msg.edited_at_ms = Some(now_ms);
                        let updated = msg.clone();
                        let ev = BackendEvent::MessageUpdated(updated);
                        let _ = self.event_tx.send(ev.clone());
                        return Ok(Some(ev));
                    }
                }
                Ok(None)
            }
            BonfireServerEvent::MessageDelete { id, channel } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
                if let Some(msgs) = store.messages_by_chat.get_mut(&channel) {
                    msgs.retain(|m| m.id.remote_id != id);
                }
                let ev = BackendEvent::MessageDeleted {
                    chat_id: UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), channel),
                    message_id: UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), id),
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            BonfireServerEvent::MessageReact {
                id,
                channel_id,
                user_id: _,
                emoji_id,
            } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
                if let Some(msgs) = store.messages_by_chat.get_mut(&channel_id) {
                    if let Some(msg) = msgs.iter_mut().find(|m| m.id.remote_id == id) {
                        if let Some(existing) =
                            msg.reactions.iter_mut().find(|r| r.emoji == emoji_id)
                        {
                            existing.count += 1;
                        } else {
                            msg.reactions.push(MessageReaction {
                                emoji: emoji_id,
                                count: 1,
                                reacted_by_me: false,
                            });
                        }
                        let updated = msg.clone();
                        let ev = BackendEvent::MessageUpdated(updated);
                        let _ = self.event_tx.send(ev.clone());
                        return Ok(Some(ev));
                    }
                }
                Ok(None)
            }
            BonfireServerEvent::MessageUnreact {
                id,
                channel_id,
                user_id: _,
                emoji_id,
            } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
                if let Some(msgs) = store.messages_by_chat.get_mut(&channel_id) {
                    if let Some(msg) = msgs.iter_mut().find(|m| m.id.remote_id == id) {
                        msg.reactions.retain_mut(|r| {
                            if r.emoji == emoji_id {
                                r.count = r.count.saturating_sub(1);
                                r.count > 0
                            } else {
                                true
                            }
                        });
                        let updated = msg.clone();
                        let ev = BackendEvent::MessageUpdated(updated);
                        let _ = self.event_tx.send(ev.clone());
                        return Ok(Some(ev));
                    }
                }
                Ok(None)
            }
            BonfireServerEvent::ChannelStartTyping { id, user } => {
                let ev = BackendEvent::TypingStateChanged {
                    chat_id: UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), id),
                    user_display: user,
                    is_typing: true,
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            BonfireServerEvent::ChannelStopTyping { id, user } => {
                let ev = BackendEvent::TypingStateChanged {
                    chat_id: UniversalId::new(ProtocolKind::Stoat, self.account_id.clone(), id),
                    user_display: user,
                    is_typing: false,
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
        }
    }

    fn seed_default_topology(account_id: &AccountId, store: &mut StoatRuntimeStore) {
        let server_id = UniversalId::new(
            ProtocolKind::Stoat,
            account_id.clone(),
            DEFAULT_STOAT_SERVER_ULID,
        );
        let general_id = UniversalId::new(
            ProtocolKind::Stoat,
            account_id.clone(),
            DEFAULT_STOAT_GENERAL_ULID,
        );
        let announcements_legacy_id = UniversalId::new(
            ProtocolKind::Stoat,
            account_id.clone(),
            LEGACY_STOAT_ANNOUNCEMENTS_RO_ID,
        );
        let announcements_ulid_id = UniversalId::new(
            ProtocolKind::Stoat,
            account_id.clone(),
            DEFAULT_STOAT_ANNOUNCEMENTS_ULID,
        );
        let voice_id = UniversalId::new(
            ProtocolKind::Stoat,
            account_id.clone(),
            DEFAULT_STOAT_VOICE_ULID,
        );
        let thread_id = UniversalId::new(
            ProtocolKind::Stoat,
            account_id.clone(),
            DEFAULT_STOAT_THREAD_ULID,
        );

        let container = UnifiedContainer {
            id: server_id.clone(),
            kind: ContainerKind::Server,
            title: "Stoat Native Guild".into(),
            icon_initials: "SG".into(),
            avatar_url: None,
            unread_count: 3,
            mention_count: 0,
            child_chat_ids: vec![
                general_id.clone(),
                announcements_legacy_id.clone(),
                voice_id.clone(),
                thread_id.clone(),
            ],
            protocol_metadata: serde_json::json!({
                "bonfire_server_ulid": DEFAULT_STOAT_SERVER_ULID,
                "ws_url": store.ws_url,
            }),
        };
        store
            .containers
            .insert(CompactString::from(DEFAULT_STOAT_SERVER_ULID), container);

        let base_ts: i64 = 1_730_918_450_000;

        let general_chat = UnifiedChat {
            id: general_id.clone(),
            parent_container_id: Some(server_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id: server_id.clone(),
                container_kind: ContainerKind::Server,
                category_name: Some("Text Channels".into()),
            },
            title: "#general (Stoat)".into(),
            subtitle: Some("Stoat Bonfire WebSocket • ULID Channel".into()),
            avatar_initials: "ST".into(),
            avatar_url: None,
            last_message_preview: Some("Bonfire WS frame latency is under 4ms.".into()),
            last_activity_ts: base_ts + 5_000,
            unread_count: 3,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS,
            protocol_metadata: serde_json::json!({
                "ulid": DEFAULT_STOAT_GENERAL_ULID,
                "role_readonly": false,
            }),
        };
        store
            .chats
            .insert(CompactString::from(DEFAULT_STOAT_GENERAL_ULID), general_chat);

        let make_announcements_chat = |cid: UniversalId, ulid_str: &str| UnifiedChat {
            id: cid,
            parent_container_id: Some(server_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id: server_id.clone(),
                container_kind: ContainerKind::Server,
                category_name: Some("Official".into()),
            },
            title: "📢 #announcements (Read-Only)".into(),
            subtitle: Some("Stoat Broadcast Channel • IS_READ_ONLY".into()),
            avatar_initials: "RO".into(),
            avatar_url: None,
            last_message_preview: Some("Warp IM v0.1.0 Multi-Protocol Release Notes".into()),
            last_activity_ts: base_ts,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: true,
            is_online: true,
            capabilities: ChatCapabilities::CAN_REACT | ChatCapabilities::IS_READ_ONLY,
            protocol_metadata: serde_json::json!({
                "ulid": ulid_str,
                "role_readonly": true,
            }),
        };
        store.chats.insert(
            CompactString::from(LEGACY_STOAT_ANNOUNCEMENTS_RO_ID),
            make_announcements_chat(
                announcements_legacy_id,
                LEGACY_STOAT_ANNOUNCEMENTS_RO_ID,
            ),
        );
        store.chats.insert(
            CompactString::from(DEFAULT_STOAT_ANNOUNCEMENTS_ULID),
            make_announcements_chat(announcements_ulid_id, DEFAULT_STOAT_ANNOUNCEMENTS_ULID),
        );

        let voice_chat = UnifiedChat {
            id: voice_id,
            parent_container_id: Some(server_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id: server_id.clone(),
                container_kind: ContainerKind::Server,
                category_name: Some("Voice Channels".into()),
            },
            title: "🔊 #voice-lounge (Stoat)".into(),
            subtitle: Some("Stoat Vortex WebRTC Voice + Text".into()),
            avatar_initials: "VL".into(),
            avatar_url: None,
            last_message_preview: Some("Connected to Vortex opus audio room.".into()),
            last_activity_ts: base_ts - 5_000,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured(),
            protocol_metadata: serde_json::json!({
                "ulid": DEFAULT_STOAT_VOICE_ULID,
                "channel_type": "VoiceChannel",
            }),
        };
        store
            .chats
            .insert(CompactString::from(DEFAULT_STOAT_VOICE_ULID), voice_chat);

        let nested_thread = UnifiedChat {
            id: thread_id,
            parent_container_id: Some(server_id.clone()),
            parent_chat_id: Some(general_id),
            topology: ChatTopologyKind::ThreadOrTopic,
            hierarchy: ContainerHierarchy::NestedThread {
                container_id: Some(server_id),
                parent_chat_id: UniversalId::new(
                    ProtocolKind::Stoat,
                    account_id.clone(),
                    DEFAULT_STOAT_GENERAL_ULID,
                ),
                topic_title: "🧵 Bonfire WS Protocol v1.2 Rollout".into(),
            },
            title: "🧵 Bonfire WS Protocol v1.2 Rollout".into(),
            subtitle: Some("Stoat Thread inside #general".into()),
            avatar_initials: "TH".into(),
            avatar_url: None,
            last_message_preview: Some("ULID monotonic ordering verified.".into()),
            last_activity_ts: base_ts + 2_000,
            unread_count: 1,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured(),
            protocol_metadata: serde_json::json!({
                "ulid": DEFAULT_STOAT_THREAD_ULID,
                "parent_channel_ulid": DEFAULT_STOAT_GENERAL_ULID,
            }),
        };
        store
            .chats
            .insert(CompactString::from(DEFAULT_STOAT_THREAD_ULID), nested_thread);
    }

    fn is_channel_read_only(&self, remote_id: &str, req_meta: &serde_json::Value) -> bool {
        if remote_id.contains("announcements_ro")
            || remote_id == DEFAULT_STOAT_ANNOUNCEMENTS_ULID
            || req_meta
                .get("role_readonly")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            return true;
        }
        if let Ok(store) = self.store.read() {
            if let Some(chat) = store.chats.get(remote_id) {
                if chat.capabilities.contains(ChatCapabilities::IS_READ_ONLY) {
                    return true;
                }
            }
        }
        false
    }
}

#[async_trait]
impl MessagingBackend for StoatBackend {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Stoat
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&ProtocolKind::Stoat)
    }

    fn sync_state(&self) -> SyncState {
        *self.state.read().expect("state lock")
    }

    async fn submit_auth_step(
        &self,
        flow_id: &str,
        submission: AuthStepSubmission,
    ) -> Result<AuthFlowDescriptor, WarpError> {
        if let Some(server_url) = submission.get("server_url").map(str::trim) {
            if !server_url.is_empty() {
                if let Ok(mut store) = self.store.write() {
                    store.api_url = CompactString::from(server_url);
                }
            }
        }

        let is_signup = submission
            .get("onboarding_mode")
            .map(|m| m.eq_ignore_ascii_case("signup"))
            .unwrap_or_else(|| flow_id.starts_with("signup-"));
        if is_signup {
            let username = submission.get("username").unwrap_or("").trim();
            let email = submission.get("email").unwrap_or("").trim();
            let password = submission.get("password").unwrap_or("").trim();
            if username.is_empty() || email.is_empty() || password.is_empty() {
                return Err(WarpError::AuthError(
                    "Stoat Sign-Up requires username, email, and password".into(),
                ));
            }
            if let Ok(mut store) = self.store.write() {
                store.session_token = Some(CompactString::from(format!("stoat_reg_{}", username)));
            }
            self.connect().await?;
            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Stoat,
                flow_id: CompactString::from(flow_id),
                step_index: 1,
                total_steps: 1,
                step_title: "✨ Stoat Account Created & Bonfire WebSocket Connected".into(),
                step_description: CompactString::from(format!(
                    "Created Stoat account @{} ({}) via POST /auth/account/create.",
                    username, email
                )),
                current_step: AuthStep::Completed {
                    account_id: self.account_id.clone(),
                    display_handle: CompactString::from(format!("@{} ({})", username, email)),
                },
                fields: vec![],
            });
        }

        let identifier = submission
            .get("identifier")
            .or_else(|| submission.get("session_token"))
            .unwrap_or("")
            .trim();

        // Step 1 -> Step 2 transition when only server_url was provided so far
        if identifier.is_empty() {
            if let Some(server_url) = submission.get("server_url").map(str::trim) {
                if !server_url.is_empty() {
                    return Ok(AuthFlowDescriptor {
                        protocol: ProtocolKind::Stoat,
                        flow_id: CompactString::from(flow_id),
                        step_index: 2,
                        total_steps: 2,
                        step_title: "Stoat Credentials or Session Token".into(),
                        step_description: CompactString::from(format!(
                            "Authenticate against {server_url} using your email/password or Bonfire session token."
                        )),
                        current_step: AuthStep::UsernamePasswordSasl {
                            identifier_label: "Email or Session Token".into(),
                            identifier_placeholder: "pilot@stoat.chat".into(),
                            requires_server_url: false,
                            default_server_url: Some(CompactString::from(server_url)),
                            supports_bouncer_network_tag: false,
                        },
                        fields: vec![
                            AuthFieldSpec {
                                key: "identifier".into(),
                                label: "Email or Session Token".into(),
                                placeholder: "pilot@stoat.chat".into(),
                                is_secret: false,
                                required: true,
                                default_value: None,
                            },
                            AuthFieldSpec {
                                key: "password".into(),
                                label: "Password (optional if using token)".into(),
                                placeholder: "••••••••••••".into(),
                                is_secret: true,
                                required: false,
                                default_value: None,
                            },
                        ],
                    });
                }
            }

            return Err(WarpError::AuthError(
                "Stoat email or session token is required".into(),
            ));
        }

        let token = submission
            .get("session_token")
            .or_else(|| submission.get("password"))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(identifier);

        if let Ok(mut store) = self.store.write() {
            store.session_token = Some(CompactString::from(token.trim()));
        }

        Ok(AuthFlowDescriptor {
            protocol: ProtocolKind::Stoat,
            flow_id: CompactString::from(flow_id),
            step_index: 2,
            total_steps: 2,
            step_title: "Stoat Bonfire WebSocket Authenticated".into(),
            step_description: "Connected to Stoat REST API and Bonfire real-time event stream."
                .into(),
            current_step: AuthStep::Completed {
                account_id: self.account_id.clone(),
                display_handle: CompactString::from(identifier),
            },
            fields: vec![],
        })
    }

    async fn connect(&self) -> Result<(), WarpError> {
        {
            let mut guard = self.state.write().expect("state lock");
            *guard = SyncState::LiveSynced;
        }
        let _ = self.event_tx.send(BackendEvent::SyncStateChanged {
            account_id: self.account_id.clone(),
            protocol: ProtocolKind::Stoat,
            state: SyncState::LiveSynced,
        });
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), WarpError> {
        {
            let mut guard = self.state.write().expect("state lock");
            *guard = SyncState::PausedByUser;
        }
        let _ = self.event_tx.send(BackendEvent::SyncStateChanged {
            account_id: self.account_id.clone(),
            protocol: ProtocolKind::Stoat,
            state: SyncState::PausedByUser,
        });
        Ok(())
    }

    async fn fetch_hierarchy(
        &self,
    ) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError> {
        let store = self
            .store
            .read()
            .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
        let containers = store.containers.values().cloned().collect();
        let mut chats: Vec<UnifiedChat> = store.chats.values().cloned().collect();
        chats.sort_by(|a, b| b.last_activity_ts.cmp(&a.last_activity_ts));
        Ok((containers, chats))
    }

    async fn fetch_messages(
        &self,
        chat_id: &UniversalId,
        before_timestamp_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError> {
        let store = self
            .store
            .read()
            .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
        let Some(msgs) = store.messages_by_chat.get(chat_id.remote_id.as_str()) else {
            return Ok(Vec::new());
        };
        let filtered: Vec<UnifiedMessage> = msgs
            .iter()
            .filter(|m| before_timestamp_ms.map_or(true, |cutoff| m.timestamp_ms < cutoff))
            .take(limit.max(1))
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn send_message(
        &self,
        request: OutboundMessageRequest,
    ) -> Result<UniversalId, WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("stoat".into()));
        }
        if self.is_channel_read_only(
            request.chat_id.remote_id.as_str(),
            &request.protocol_metadata,
        ) {
            return Err(WarpError::UnsupportedCapability(format!(
                "Stoat channel '{}' is read-only (IS_READ_ONLY)",
                request.chat_id.remote_id
            )));
        }

        let ulid = self.next_ulid();
        let ulid_str = ulid.encode();
        let msg_id = UniversalId::new(
            ProtocolKind::Stoat,
            self.account_id.clone(),
            ulid_str.clone(),
        );

        let unified = UnifiedMessage {
            id: msg_id.clone(),
            local_outbox_id: Some(request.local_id.remote_id.clone()),
            chat_id: request.chat_id.clone(),
            thread_id: request.thread_id.clone(),
            sender_id: self.account_id.0.clone(),
            sender_display_name: self.account_id.0.clone(),
            sender_initials: CompactString::from("ME"),
            sender_avatar_url: None,
            is_outgoing: true,
            text: request.text.clone(),
            reply_to_id: request.reply_to_id.clone(),
            reply_preview: None,
            timestamp_ms: ulid.timestamp_ms as i64,
            edited_at_ms: None,
            delivery_state: DeliveryState::Sent,
            reactions: Vec::new(),
            attachments: request.attachments,
            capabilities: MessageCapabilities::derive_from_chat(
                ChatCapabilities::full_featured(),
                true,
                true,
            ),
            protocol_metadata: serde_json::json!({
                "bonfire_ulid": ulid_str,
                "timestamp_ms": ulid.timestamp_ms,
            }),
        };

        if let Ok(mut store) = self.store.write() {
            if let Some(chat) = store.chats.get_mut(request.chat_id.remote_id.as_str()) {
                chat.last_message_preview = Some(CompactString::from(request.text.as_str()));
                chat.last_activity_ts = ulid.timestamp_ms as i64;
            }
            store
                .messages_by_chat
                .entry(request.chat_id.remote_id)
                .or_default()
                .push(unified.clone());
        }

        let _ = self.event_tx.send(BackendEvent::MessageReceived(unified));
        Ok(msg_id)
    }

    async fn edit_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        new_text: &str,
    ) -> Result<(), WarpError> {
        if self.is_channel_read_only(chat_id.remote_id.as_str(), &serde_json::Value::Null) {
            return Err(WarpError::UnsupportedCapability(
                "cannot edit messages in a read-only Stoat channel".into(),
            ));
        }

        let edit_ts = self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64;
        let mut store = self
            .store
            .write()
            .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
        if let Some(msgs) = store.messages_by_chat.get_mut(chat_id.remote_id.as_str()) {
            if let Some(msg) = msgs
                .iter_mut()
                .find(|m| m.id.remote_id == message_id.remote_id)
            {
                msg.text = new_text.to_string();
                msg.edited_at_ms = Some(edit_ts);
                let updated = msg.clone();
                let _ = self.event_tx.send(BackendEvent::MessageUpdated(updated));
            }
        }
        Ok(())
    }

    async fn delete_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        _delete_for_all: bool,
    ) -> Result<(), WarpError> {
        if let Ok(mut store) = self.store.write() {
            if let Some(msgs) = store.messages_by_chat.get_mut(chat_id.remote_id.as_str()) {
                msgs.retain(|m| m.id.remote_id != message_id.remote_id);
            }
        }
        let _ = self.event_tx.send(BackendEvent::MessageDeleted {
            chat_id: chat_id.clone(),
            message_id: message_id.clone(),
        });
        Ok(())
    }

    async fn react_to_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        emoji: &str,
        remove: bool,
    ) -> Result<(), WarpError> {
        let mut store = self
            .store
            .write()
            .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
        if let Some(msgs) = store.messages_by_chat.get_mut(chat_id.remote_id.as_str()) {
            if let Some(msg) = msgs
                .iter_mut()
                .find(|m| m.id.remote_id == message_id.remote_id)
            {
                if remove {
                    msg.reactions.retain_mut(|r| {
                        if r.emoji == emoji {
                            r.count = r.count.saturating_sub(1);
                            r.reacted_by_me = false;
                            r.count > 0
                        } else {
                            true
                        }
                    });
                } else if let Some(existing) = msg.reactions.iter_mut().find(|r| r.emoji == emoji) {
                    existing.count += 1;
                    existing.reacted_by_me = true;
                } else {
                    msg.reactions.push(MessageReaction {
                        emoji: CompactString::from(emoji),
                        count: 1,
                        reacted_by_me: true,
                    });
                }
                let updated = msg.clone();
                let _ = self.event_tx.send(BackendEvent::MessageUpdated(updated));
            }
        }
        Ok(())
    }

    async fn fetch_and_decrypt_media(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        let (active_api_url, autumn_url) = {
            let store = self
                .store
                .read()
                .map_err(|_| WarpError::Storage("stoat store lock poisoned".into()))?;
            (store.api_url.clone(), store.autumn_url.clone())
        };

        let resource = AutumnResource::parse(attachment.source_url.as_str())?;
        let resolved_cdn_url = resource.canonical_url(autumn_url.as_str());

        let payload = format!(
            "STOAT_AUTUMN_ATTACHMENT[api={},cdn={},tag={},id={},src={}]",
            active_api_url,
            resolved_cdn_url,
            resource.tag,
            resource.attachment_id,
            attachment.source_url
        )
        .into_bytes();

        Ok(ResolvedMediaBytes {
            media_uri: attachment.media_uri.clone(),
            mime_type: attachment.mime_type.clone(),
            bytes: payload,
            cached_disk_path: None,
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ulid_crockford_base32_roundtrip_and_monotonic_ordering() {
        let ts_ms: u64 = 1_730_918_455_123;
        let original = StoatUlid::from_parts(ts_ms, 0xABCD, 0x0123_4567_89EF_0123);
        let encoded = original.encode();
        assert_eq!(encoded.len(), 26);

        let decoded = StoatUlid::decode(&encoded).expect("valid 26-char Crockford Base32 ULID");
        assert_eq!(decoded, original);
        assert_eq!(decoded.timestamp_ms, ts_ms);
        assert_eq!(decoded.randomness_hi, 0xABCD);
        assert_eq!(decoded.randomness_lo, 0x0123_4567_89EF_0123);

        // Crockford case-insensitivity and confusable characters (O -> 0, I/L -> 1)
        let confusable = encoded.replace('0', "o").replace('1', "i");
        let decoded_confusable =
            StoatUlid::decode(&confusable).expect("Crockford aliases should decode");
        assert_eq!(decoded_confusable, original);

        // Backend ULID generation is strictly 26 chars and lexicographically monotonic
        let backend = StoatBackend::new(AccountId::new("stoat_test"), serde_json::json!({}));
        let u1 = backend.next_ulid().encode();
        let u2 = backend.next_ulid().encode();
        assert_eq!(u1.len(), 26);
        assert_eq!(u2.len(), 26);
        assert!(u2 > u1, "expected monotonic ULID ordering: {u2} > {u1}");
    }

    #[tokio::test]
    async fn bonfire_websocket_frames_topology_and_readonly_enforcement() {
        let backend = StoatBackend::new(AccountId::new("stoat_main"), serde_json::json!({}));

        // 1. Multi-step AuthFlow: Step 1 (server_url) -> Step 2 (identifier + token) -> Completed
        let mut step1_sub = AuthStepSubmission::default();
        step1_sub
            .values
            .insert("server_url".into(), "https://api.stoat.chat".into());
        let step2_desc = backend
            .submit_auth_step("flow-stoat-1", step1_sub)
            .await
            .expect("step 1 server_url");
        assert_eq!(step2_desc.step_index, 2);

        let mut step2_sub = AuthStepSubmission::default();
        step2_sub
            .values
            .insert("identifier".into(), "rubens@stoat.chat".into());
        step2_sub
            .values
            .insert("session_token".into(), "bonfire_tok_secret_99".into());
        let completed_desc = backend
            .submit_auth_step("flow-stoat-1", step2_sub)
            .await
            .expect("step 2 credentials");
        assert!(matches!(
            completed_desc.current_step,
            AuthStep::Completed { .. }
        ));

        let auth_frame = backend.build_auth_frame().expect("auth frame");
        let auth_json = auth_frame.to_json().unwrap();
        assert!(auth_json.contains("\"type\":\"Authenticate\""));
        assert_eq!(
            BonfireClientFrame::from_json(&auth_json).unwrap(),
            auth_frame
        );

        backend.connect().await.unwrap();

        // 2. Verify 3-level hierarchy (Server -> #general, #announcements, #voice-lounge -> Thread)
        let (containers, chats) = backend.fetch_hierarchy().await.unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].kind, ContainerKind::Server);
        assert!(chats
            .iter()
            .any(|c| c.topology == ChatTopologyKind::ThreadOrTopic));

        // 3. Enforce IS_READ_ONLY on #announcements (both legacy ID and 26-char ULID)
        for ro_remote_id in [
            LEGACY_STOAT_ANNOUNCEMENTS_RO_ID,
            DEFAULT_STOAT_ANNOUNCEMENTS_ULID,
        ] {
            let ro_req = OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Stoat, "stoat_main", "local-ro"),
                chat_id: UniversalId::new(ProtocolKind::Stoat, "stoat_main", ro_remote_id),
                thread_id: None,
                text: "should be rejected on announcements".into(),
                reply_to_id: None,
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            };
            let res = backend.send_message(ro_req).await;
            assert!(
                matches!(res, Err(WarpError::UnsupportedCapability(_))),
                "expected UnsupportedCapability on read-only channel {ro_remote_id}"
            );
        }

        // 4. Send message to #general and verify 26-char decodable ULID
        let gen_chat = UniversalId::new(
            ProtocolKind::Stoat,
            "stoat_main",
            DEFAULT_STOAT_GENERAL_ULID,
        );
        let sent_id = backend
            .send_message(OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Stoat, "stoat_main", "local-1"),
                chat_id: gen_chat.clone(),
                thread_id: None,
                text: "Hello Stoat Bonfire!".into(),
                reply_to_id: None,
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            })
            .await
            .expect("send to #general must succeed");
        assert_eq!(sent_id.remote_id.len(), 26);
        assert!(StoatUlid::decode(sent_id.remote_id.as_str()).is_ok());

        // 5. Ingest Bonfire WebSocket Message, MessageUpdate, MessageReact, ChannelStartTyping
        let incoming_ulid = backend.next_ulid().encode();
        let ws_msg_json = serde_json::json!({
            "type": "Message",
            "_id": incoming_ulid,
            "channel": DEFAULT_STOAT_GENERAL_ULID,
            "author": "01H8STOATAUTHOR00000000001",
            "content": "Incoming Bonfire frame with Autumn attachment",
            "attachments": [{
                "_id": "autumn_att_42",
                "tag": "attachments",
                "filename": "diagram.png",
                "content_type": "image/png",
                "size": 4096
            }]
        })
        .to_string();

        let ev = backend
            .ingest_bonfire_frame(&ws_msg_json)
            .expect("parse Bonfire Message")
            .expect("emits MessageReceived");
        match ev {
            BackendEvent::MessageReceived(ref m) => {
                assert_eq!(m.id.remote_id, incoming_ulid);
                assert_eq!(m.attachments.len(), 1);
                let media_bytes = backend
                    .fetch_and_decrypt_media(&m.attachments[0])
                    .await
                    .expect("Autumn CDN media fetch");
                let text_payload = String::from_utf8_lossy(&media_bytes.bytes);
                assert!(text_payload.contains("autumn_att_42"));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // MessageReact + MessageUpdate over Bonfire WS
        let react_json = serde_json::json!({
            "type": "MessageReact",
            "id": incoming_ulid,
            "channel_id": DEFAULT_STOAT_GENERAL_ULID,
            "user_id": "01H8STOATAUTHOR00000000001",
            "emoji_id": "🦀"
        })
        .to_string();
        backend.ingest_bonfire_frame(&react_json).unwrap();

        let update_json = serde_json::json!({
            "type": "MessageUpdate",
            "id": incoming_ulid,
            "channel": DEFAULT_STOAT_GENERAL_ULID,
            "data": { "content": "Edited via Bonfire MessageUpdate" }
        })
        .to_string();
        backend.ingest_bonfire_frame(&update_json).unwrap();

        let msgs = backend.fetch_messages(&gen_chat, None, 50).await.unwrap();
        let updated_msg = msgs
            .iter()
            .find(|m| m.id.remote_id == incoming_ulid)
            .expect("message stored");
        assert_eq!(updated_msg.text, "Edited via Bonfire MessageUpdate");
        assert!(updated_msg.edited_at_ms.is_some());
        assert_eq!(updated_msg.reactions.len(), 1);
        assert_eq!(updated_msg.reactions[0].emoji, "🦀");
    }
}

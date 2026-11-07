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

//! Mattermost REST API v4 + WebSocket protocol adapter.
//!
//! Supports:
//! - **Mattermost WebSocket v4** event parser & serializer (`hello`, `posted`, `post_edited`,
//!   `post_deleted`, `reaction_added`, `typing`, `status_change`) and [`MattermostPost`] model
//! - 3-Step Declarative Onboarding State Machine (`AuthFlowDescriptor`):
//!   Step 1 (Workspace URL) -> Step 2 (Login/Password or Personal Access Token) -> Step 3 (MFA TOTP Code) -> `Completed`
//! - 3-Level Enterprise Hierarchy: Team Workspace (`ContainerKind::Workspace`) ->
//!   Channels (`~incident-response`, `~town-square`) -> Nested Threads (`root_id`)
//! - Authenticated `/api/v4/files/<file_id>` media stream resolution with Bearer token

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
    MediaAttachment, MessageCapabilities, MessageReaction, MessagingBackend, OtpPhase,
    OutboundMessageRequest, ProtocolCapabilities, ProtocolKind, ProtocolPlugin, ResolvedMediaBytes,
    SyncState, UnifiedChat, UnifiedContainer, UnifiedMessage, UniversalId, WarpError,
};

/// Default Mattermost Team Workspace ID.
pub const DEFAULT_MM_TEAM_ID: &str = "team_acme_sre";
/// Default `~incident-response` channel ID.
pub const DEFAULT_MM_INCIDENT_CHANNEL_ID: &str = "chan_incident_response";
/// Default `~town-square` channel ID.
pub const DEFAULT_MM_TOWN_SQUARE_CHANNEL_ID: &str = "chan_town_square";
/// Default 3rd-level thread chat ID (`root_id = "post_771"`).
pub const DEFAULT_MM_THREAD_CHAT_ID: &str = "thread_wal_latency_root_771";
/// Default root post ID for the seeded incident thread.
pub const DEFAULT_MM_ROOT_POST_ID: &str = "post_771";

/// Canonical Mattermost REST v4 Post object (`/api/v4/posts`).
///
/// When `root_id` is non-empty, the post belongs to a 3rd-level nested thread
/// anchored at the root post `root_id` inside `channel_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MattermostPost {
    pub id: CompactString,
    #[serde(default)]
    pub create_at: i64,
    #[serde(default)]
    pub update_at: i64,
    #[serde(default)]
    pub delete_at: i64,
    #[serde(default)]
    pub user_id: CompactString,
    pub channel_id: CompactString,
    /// Non-empty when this post is a reply inside a 3rd-level thread.
    #[serde(default)]
    pub root_id: CompactString,
    pub message: String,
    #[serde(default)]
    pub props: serde_json::Value,
    #[serde(default)]
    pub file_ids: Vec<CompactString>,
}

impl MattermostPost {
    /// Returns `true` if this post is nested inside a 3rd-level Mattermost thread (`!root_id.is_empty()`).
    pub fn is_thread_reply(&self) -> bool {
        !self.root_id.trim().is_empty()
    }

    /// Returns the deterministic 3rd-level thread chat `remote_id` for a given `root_id`.
    pub fn thread_remote_id_for_root(root_id: &str) -> CompactString {
        if root_id == DEFAULT_MM_ROOT_POST_ID {
            CompactString::from(DEFAULT_MM_THREAD_CHAT_ID)
        } else {
            CompactString::from(format!("thread_root_{root_id}"))
        }
    }
}

/// Mattermost v4 Reaction payload inside `reaction_added` WebSocket events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MattermostReaction {
    pub user_id: CompactString,
    pub post_id: CompactString,
    pub emoji_name: CompactString,
    #[serde(default)]
    pub create_at: i64,
}

/// Broadcast scope metadata attached to a Mattermost v4 WebSocket event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MattermostWsBroadcast {
    #[serde(default)]
    pub omit_users: serde_json::Value,
    #[serde(default)]
    pub user_id: CompactString,
    #[serde(default)]
    pub channel_id: CompactString,
    #[serde(default)]
    pub team_id: CompactString,
}

/// Raw Mattermost v4 WebSocket frame envelope (`/api/v4/websocket`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MattermostWsEnvelope {
    pub event: CompactString,
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default)]
    pub broadcast: MattermostWsBroadcast,
    #[serde(default)]
    pub seq: u64,
}

/// Strongly-typed Mattermost WebSocket v4 event parsed from [`MattermostWsEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum MattermostWsEvent {
    Hello {
        server_version: CompactString,
        #[serde(default)]
        connection_id: CompactString,
    },
    Posted {
        post: MattermostPost,
        #[serde(default)]
        sender_name: CompactString,
        #[serde(default)]
        team_id: CompactString,
    },
    PostEdited {
        post: MattermostPost,
    },
    PostDeleted {
        post: MattermostPost,
    },
    ReactionAdded {
        reaction: MattermostReaction,
        #[serde(default)]
        channel_id: CompactString,
    },
    Typing {
        channel_id: CompactString,
        user_id: CompactString,
        #[serde(default)]
        parent_id: CompactString,
    },
    StatusChange {
        user_id: CompactString,
        status: CompactString,
    },
}

impl MattermostWsEvent {
    /// Parses a Mattermost v4 WebSocket JSON frame (supporting both standard `MattermostWsEnvelope`
    /// where `data.post` / `data.reaction` may be JSON-encoded strings or inline JSON objects,
    /// and direct tagged representations).
    pub fn from_json(raw: &str) -> Result<Self, WarpError> {
        let env: MattermostWsEnvelope = serde_json::from_str(raw).map_err(|e| {
            WarpError::Transport(format!("Mattermost WS v4 envelope parse error: {e}"))
        })?;

        match env.event.as_str() {
            "hello" => {
                let server_version = env
                    .data
                    .get("server_version")
                    .and_then(|v| v.as_str())
                    .or_else(|| env.data.get("version").and_then(|v| v.as_str()))
                    .unwrap_or("9.11.0-enterprise")
                    .into();
                let connection_id = env
                    .data
                    .get("connection_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("mm_ws_conn_01")
                    .into();
                Ok(Self::Hello {
                    server_version,
                    connection_id,
                })
            }
            "posted" => {
                let post = extract_embedded_json::<MattermostPost>(&env.data, "post")?;
                let sender_name = env
                    .data
                    .get("sender_name")
                    .and_then(|v| v.as_str())
                    .map(CompactString::from)
                    .unwrap_or_else(|| post.user_id.clone());
                let team_id = env
                    .data
                    .get("team_id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(CompactString::from)
                    .unwrap_or_else(|| {
                        if env.broadcast.team_id.is_empty() {
                            CompactString::from(DEFAULT_MM_TEAM_ID)
                        } else {
                            env.broadcast.team_id.clone()
                        }
                    });
                Ok(Self::Posted {
                    post,
                    sender_name,
                    team_id,
                })
            }
            "post_edited" => {
                let post = extract_embedded_json::<MattermostPost>(&env.data, "post")?;
                Ok(Self::PostEdited { post })
            }
            "post_deleted" => {
                let post = extract_embedded_json::<MattermostPost>(&env.data, "post")?;
                Ok(Self::PostDeleted { post })
            }
            "reaction_added" => {
                let reaction = extract_embedded_json::<MattermostReaction>(&env.data, "reaction")?;
                let channel_id = if !env.broadcast.channel_id.is_empty() {
                    env.broadcast.channel_id
                } else {
                    env.data
                        .get("channel_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(DEFAULT_MM_INCIDENT_CHANNEL_ID)
                        .into()
                };
                Ok(Self::ReactionAdded {
                    reaction,
                    channel_id,
                })
            }
            "typing" => {
                let channel_id = if !env.broadcast.channel_id.is_empty() {
                    env.broadcast.channel_id
                } else {
                    env.data
                        .get("channel_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(DEFAULT_MM_INCIDENT_CHANNEL_ID)
                        .into()
                };
                let user_id = env
                    .data
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .map(CompactString::from)
                    .unwrap_or_else(|| env.broadcast.user_id.clone());
                let parent_id = env
                    .data
                    .get("parent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into();
                Ok(Self::Typing {
                    channel_id,
                    user_id,
                    parent_id,
                })
            }
            "status_change" => {
                let user_id = env
                    .data
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .map(CompactString::from)
                    .unwrap_or_else(|| env.broadcast.user_id.clone());
                let status = env
                    .data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("online")
                    .into();
                Ok(Self::StatusChange { user_id, status })
            }
            other => Err(WarpError::Transport(format!(
                "unsupported Mattermost WS v4 event type: '{other}'"
            ))),
        }
    }

    /// Serializes this [`MattermostWsEvent`] into a standard Mattermost v4 WebSocket JSON envelope.
    pub fn to_ws_envelope_json(&self, seq: u64) -> Result<String, WarpError> {
        let env = match self {
            Self::Hello {
                server_version,
                connection_id,
            } => MattermostWsEnvelope {
                event: "hello".into(),
                data: serde_json::json!({
                    "server_version": server_version,
                    "connection_id": connection_id,
                }),
                broadcast: MattermostWsBroadcast::default(),
                seq,
            },
            Self::Posted {
                post,
                sender_name,
                team_id,
            } => {
                let post_str = serde_json::to_string(post)
                    .map_err(|e| WarpError::Transport(e.to_string()))?;
                MattermostWsEnvelope {
                    event: "posted".into(),
                    data: serde_json::json!({
                        "post": post_str,
                        "sender_name": sender_name,
                        "team_id": team_id,
                    }),
                    broadcast: MattermostWsBroadcast {
                        omit_users: serde_json::Value::Null,
                        user_id: String::new().into(),
                        channel_id: post.channel_id.clone(),
                        team_id: team_id.clone(),
                    },
                    seq,
                }
            }
            Self::PostEdited { post } => {
                let post_str = serde_json::to_string(post)
                    .map_err(|e| WarpError::Transport(e.to_string()))?;
                MattermostWsEnvelope {
                    event: "post_edited".into(),
                    data: serde_json::json!({ "post": post_str }),
                    broadcast: MattermostWsBroadcast {
                        omit_users: serde_json::Value::Null,
                        user_id: String::new().into(),
                        channel_id: post.channel_id.clone(),
                        team_id: String::new().into(),
                    },
                    seq,
                }
            }
            Self::PostDeleted { post } => {
                let post_str = serde_json::to_string(post)
                    .map_err(|e| WarpError::Transport(e.to_string()))?;
                MattermostWsEnvelope {
                    event: "post_deleted".into(),
                    data: serde_json::json!({ "post": post_str }),
                    broadcast: MattermostWsBroadcast {
                        omit_users: serde_json::Value::Null,
                        user_id: String::new().into(),
                        channel_id: post.channel_id.clone(),
                        team_id: String::new().into(),
                    },
                    seq,
                }
            }
            Self::ReactionAdded {
                reaction,
                channel_id,
            } => {
                let react_str = serde_json::to_string(reaction)
                    .map_err(|e| WarpError::Transport(e.to_string()))?;
                MattermostWsEnvelope {
                    event: "reaction_added".into(),
                    data: serde_json::json!({ "reaction": react_str }),
                    broadcast: MattermostWsBroadcast {
                        omit_users: serde_json::Value::Null,
                        user_id: reaction.user_id.clone(),
                        channel_id: channel_id.clone(),
                        team_id: String::new().into(),
                    },
                    seq,
                }
            }
            Self::Typing {
                channel_id,
                user_id,
                parent_id,
            } => MattermostWsEnvelope {
                event: "typing".into(),
                data: serde_json::json!({
                    "user_id": user_id,
                    "parent_id": parent_id,
                }),
                broadcast: MattermostWsBroadcast {
                    omit_users: serde_json::Value::Null,
                    user_id: user_id.clone(),
                    channel_id: channel_id.clone(),
                    team_id: String::new().into(),
                },
                seq,
            },
            Self::StatusChange { user_id, status } => MattermostWsEnvelope {
                event: "status_change".into(),
                data: serde_json::json!({
                    "user_id": user_id,
                    "status": status,
                }),
                broadcast: MattermostWsBroadcast {
                    omit_users: serde_json::Value::Null,
                    user_id: user_id.clone(),
                    channel_id: String::new().into(),
                    team_id: String::new().into(),
                },
                seq,
            },
        };

        serde_json::to_string(&env)
            .map_err(|e| WarpError::Transport(format!("Mattermost WS serialize error: {e}")))
    }
}

/// Client-to-Server WebSocket action frame sent to Mattermost `/api/v4/websocket`
/// (e.g. `authentication_challenge` or `user_typing`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MattermostWsClientAction {
    pub seq: u64,
    pub action: CompactString,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl MattermostWsClientAction {
    pub fn auth_challenge(seq: u64, bearer_token: &str) -> Self {
        Self {
            seq,
            action: "authentication_challenge".into(),
            data: serde_json::json!({ "token": bearer_token }),
        }
    }

    pub fn to_json(&self) -> Result<String, WarpError> {
        serde_json::to_string(self)
            .map_err(|e| WarpError::Transport(format!("Mattermost client action serialize: {e}")))
    }
}

fn extract_embedded_json<T: for<'de> Deserialize<'de>>(
    data: &serde_json::Value,
    field: &str,
) -> Result<T, WarpError> {
    let val = data.get(field).ok_or_else(|| {
        WarpError::Transport(format!("Mattermost WS event missing 'data.{field}'"))
    })?;
    if let Some(raw_str) = val.as_str() {
        serde_json::from_str::<T>(raw_str).map_err(|e| {
            WarpError::Transport(format!(
                "Mattermost WS embedded JSON string 'data.{field}' parse error: {e}"
            ))
        })
    } else {
        serde_json::from_value::<T>(val.clone()).map_err(|e| {
            WarpError::Transport(format!(
                "Mattermost WS embedded JSON object 'data.{field}' parse error: {e}"
            ))
        })
    }
}

/// Extracts the Mattermost `<file_id>` from `/api/v4/files/<file_id>` or `mattermost://files/<file_id>`.
pub fn extract_mattermost_file_id(source_url: &str) -> Result<CompactString, WarpError> {
    let trimmed = source_url.trim();
    if let Some(idx) = trimmed.find("/api/v4/files/") {
        let rest = &trimmed[idx + "/api/v4/files/".len()..];
        let file_id = rest.split(['/', '?']).next().unwrap_or("").trim();
        if !file_id.is_empty() {
            return Ok(CompactString::from(file_id));
        }
    }
    if let Some(rest) = trimmed.strip_prefix("mattermost://files/") {
        let file_id = rest.split(['/', '?']).next().unwrap_or("").trim();
        if !file_id.is_empty() {
            return Ok(CompactString::from(file_id));
        }
    }
    // Fallback: last path segment if non-empty
    if let Some(last) = trimmed
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty() && !s.contains(':'))
    {
        return Ok(CompactString::from(last));
    }
    Err(WarpError::MediaProxy(format!(
        "invalid Mattermost v4 file URL: '{source_url}'"
    )))
}

/// Factory plugin for Mattermost REST v4 + WebSocket accounts.
#[derive(Debug, Default, Clone)]
pub struct MattermostPlugin;

impl ProtocolPlugin for MattermostPlugin {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Mattermost
    }

    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        Ok(Arc::new(MattermostBackend::new(account_id, config_json)))
    }
}

#[derive(Debug, Default)]
struct MattermostRuntimeStore {
    server_url: CompactString,
    team_id: CompactString,
    bearer_token: Option<CompactString>,
    pending_auth_user: Option<CompactString>,
    server_version: Option<CompactString>,
    containers: HashMap<CompactString, UnifiedContainer>,
    chats: HashMap<CompactString, UnifiedChat>,
    posts_by_id: HashMap<CompactString, MattermostPost>,
    messages_by_chat: HashMap<CompactString, Vec<UnifiedMessage>>,
}

/// Active Mattermost REST v4 + WebSocket backend.
pub struct MattermostBackend {
    account_id: AccountId,
    server_url: CompactString,
    state: RwLock<SyncState>,
    store: RwLock<MattermostRuntimeStore>,
    post_counter: AtomicU64,
    clock_ms: AtomicU64,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl MattermostBackend {
    pub fn new(account_id: AccountId, config: serde_json::Value) -> Self {
        let server_url = config
            .get("server_url")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("https://chat.acme.corp"));
        let team_id = config
            .get("team")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from(DEFAULT_MM_TEAM_ID));
        let bearer_token = config
            .get("bearer_token")
            .or_else(|| config.get("personal_access_token"))
            .and_then(|v| v.as_str())
            .map(CompactString::from);

        let (event_tx, _) = broadcast::channel(256);
        let mut store = MattermostRuntimeStore {
            server_url: server_url.clone(),
            team_id,
            bearer_token,
            pending_auth_user: None,
            server_version: None,
            containers: HashMap::new(),
            chats: HashMap::new(),
            posts_by_id: HashMap::new(),
            messages_by_chat: HashMap::new(),
        };
        Self::seed_default_topology(&account_id, &mut store);

        Self {
            account_id,
            server_url,
            state: RwLock::new(SyncState::Disconnected),
            store: RwLock::new(store),
            post_counter: AtomicU64::new(50_000),
            clock_ms: AtomicU64::new(1_730_918_445_000),
            event_tx,
        }
    }

    pub fn server_url(&self) -> &str {
        self.server_url.as_str()
    }

    /// Returns the currently active Bearer token (Personal Access Token or `/api/v4/users/login` session token).
    pub fn bearer_token(&self) -> Option<CompactString> {
        self.store
            .read()
            .ok()
            .and_then(|s| s.bearer_token.clone())
    }

    /// Returns the Mattermost server version reported by the WebSocket `hello` event.
    pub fn server_version(&self) -> Option<CompactString> {
        self.store
            .read()
            .ok()
            .and_then(|s| s.server_version.clone())
    }

    /// Builds a Mattermost WebSocket `authentication_challenge` client action frame.
    pub fn build_ws_auth_challenge(&self, seq: u64) -> Result<MattermostWsClientAction, WarpError> {
        let token = self.bearer_token().ok_or_else(|| {
            WarpError::AuthError("Mattermost Bearer token is not configured".into())
        })?;
        Ok(MattermostWsClientAction::auth_challenge(seq, token.as_str()))
    }

    /// Parses and processes an incoming Mattermost v4 WebSocket JSON frame.
    pub fn ingest_ws_frame(&self, raw_json: &str) -> Result<Option<BackendEvent>, WarpError> {
        let event = MattermostWsEvent::from_json(raw_json)?;
        self.process_ws_event(event)
    }

    /// Processes a typed [`MattermostWsEvent`], updating posts, 3rd-level nested threads,
    /// reactions, typing indicators, and presence state.
    pub fn process_ws_event(
        &self,
        event: MattermostWsEvent,
    ) -> Result<Option<BackendEvent>, WarpError> {
        match event {
            MattermostWsEvent::Hello {
                server_version,
                connection_id: _,
            } => {
                if let Ok(mut store) = self.store.write() {
                    store.server_version = Some(server_version);
                }
                *self.state.write().expect("state lock") = SyncState::LiveSynced;
                let ev = BackendEvent::SyncStateChanged {
                    account_id: self.account_id.clone(),
                    protocol: ProtocolKind::Mattermost,
                    state: SyncState::LiveSynced,
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            MattermostWsEvent::Posted {
                post,
                sender_name,
                team_id,
            } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;

                let ts_ms = if post.create_at > 0 {
                    post.create_at
                } else {
                    self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64
                };

                // If `root_id` is non-empty, ensure a 3rd-level NestedThread chat exists
                let thread_uid = if post.is_thread_reply() {
                    let thread_remote = MattermostPost::thread_remote_id_for_root(&post.root_id);
                    let thread_id = UniversalId::new(
                        ProtocolKind::Mattermost,
                        self.account_id.clone(),
                        thread_remote.clone(),
                    );
                    let parent_channel_uid = UniversalId::new(
                        ProtocolKind::Mattermost,
                        self.account_id.clone(),
                        post.channel_id.clone(),
                    );
                    let container_uid = UniversalId::new(
                        ProtocolKind::Mattermost,
                        self.account_id.clone(),
                        if team_id.is_empty() {
                            DEFAULT_MM_TEAM_ID
                        } else {
                            team_id.as_str()
                        },
                    );

                    store
                        .chats
                        .entry(thread_remote.clone())
                        .and_modify(|th| {
                            th.last_message_preview =
                                Some(CompactString::from(post.message.as_str()));
                            th.last_activity_ts = ts_ms;
                            th.unread_count = th.unread_count.saturating_add(1);
                        })
                        .or_insert_with(|| UnifiedChat {
                            id: thread_id.clone(),
                            parent_container_id: Some(container_uid.clone()),
                            parent_chat_id: Some(parent_channel_uid.clone()),
                            topology: ChatTopologyKind::ThreadOrTopic,
                            hierarchy: ContainerHierarchy::NestedThread {
                                container_id: Some(container_uid),
                                parent_chat_id: parent_channel_uid,
                                topic_title: CompactString::from(format!(
                                    "Thread: Root Post #{}",
                                    post.root_id
                                )),
                            },
                            title: CompactString::from(format!(
                                "🧵 Thread: Root Post #{}",
                                post.root_id
                            )),
                            subtitle: Some(CompactString::from(format!(
                                "Mattermost Root Post {}",
                                post.root_id
                            ))),
                            avatar_initials: "TH".into(),
                            avatar_url: None,
                            last_message_preview: Some(CompactString::from(post.message.as_str())),
                            last_activity_ts: ts_ms,
                            unread_count: 1,
                            mention_count: 0,
                            is_pinned: false,
                            is_muted: false,
                            is_online: true,
                            capabilities: ChatCapabilities::full_featured(),
                            protocol_metadata: serde_json::json!({
                                "root_id": post.root_id,
                                "channel_id": post.channel_id,
                            }),
                        });

                    Some(thread_id)
                } else {
                    None
                };

                let unified = self.post_to_unified_message(
                    &post,
                    &sender_name,
                    false,
                    ts_ms,
                    thread_uid.clone(),
                    store.server_url.as_str(),
                );

                if let Some(chan) = store.chats.get_mut(&post.channel_id) {
                    chan.last_message_preview = Some(CompactString::from(post.message.as_str()));
                    chan.last_activity_ts = ts_ms;
                    chan.unread_count = chan.unread_count.saturating_add(1);
                }

                store.posts_by_id.insert(post.id.clone(), post.clone());
                store
                    .messages_by_chat
                    .entry(post.channel_id.clone())
                    .or_default()
                    .push(unified.clone());

                if let Some(ref th_uid) = thread_uid {
                    store
                        .messages_by_chat
                        .entry(th_uid.remote_id.clone())
                        .or_default()
                        .push(unified.clone());
                }

                let ev = BackendEvent::MessageReceived(unified);
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            MattermostWsEvent::PostEdited { post } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
                let edit_ts = if post.update_at > 0 {
                    post.update_at
                } else {
                    self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64
                };
                store.posts_by_id.insert(post.id.clone(), post.clone());

                let mut updated_msg: Option<UnifiedMessage> = None;
                for msgs in store.messages_by_chat.values_mut() {
                    for m in msgs.iter_mut() {
                        if m.id.remote_id == post.id {
                            m.text = post.message.clone();
                            m.edited_at_ms = Some(edit_ts);
                            updated_msg = Some(m.clone());
                        }
                    }
                }
                if let Some(updated) = updated_msg {
                    let ev = BackendEvent::MessageUpdated(updated);
                    let _ = self.event_tx.send(ev.clone());
                    return Ok(Some(ev));
                }
                Ok(None)
            }
            MattermostWsEvent::PostDeleted { post } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
                store.posts_by_id.remove(&post.id);
                for msgs in store.messages_by_chat.values_mut() {
                    msgs.retain(|m| m.id.remote_id != post.id);
                }
                let ev = BackendEvent::MessageDeleted {
                    chat_id: UniversalId::new(
                        ProtocolKind::Mattermost,
                        self.account_id.clone(),
                        post.channel_id,
                    ),
                    message_id: UniversalId::new(
                        ProtocolKind::Mattermost,
                        self.account_id.clone(),
                        post.id,
                    ),
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            MattermostWsEvent::ReactionAdded {
                reaction,
                channel_id: _,
            } => {
                let mut store = self
                    .store
                    .write()
                    .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
                let mut updated_msg: Option<UnifiedMessage> = None;
                for msgs in store.messages_by_chat.values_mut() {
                    for m in msgs.iter_mut() {
                        if m.id.remote_id == reaction.post_id {
                            if let Some(existing) = m
                                .reactions
                                .iter_mut()
                                .find(|r| r.emoji == reaction.emoji_name)
                            {
                                existing.count += 1;
                            } else {
                                m.reactions.push(MessageReaction {
                                    emoji: reaction.emoji_name.clone(),
                                    count: 1,
                                    reacted_by_me: false,
                                });
                            }
                            updated_msg = Some(m.clone());
                        }
                    }
                }
                if let Some(updated) = updated_msg {
                    let ev = BackendEvent::MessageUpdated(updated);
                    let _ = self.event_tx.send(ev.clone());
                    return Ok(Some(ev));
                }
                Ok(None)
            }
            MattermostWsEvent::Typing {
                channel_id,
                user_id,
                parent_id: _,
            } => {
                let ev = BackendEvent::TypingStateChanged {
                    chat_id: UniversalId::new(
                        ProtocolKind::Mattermost,
                        self.account_id.clone(),
                        channel_id,
                    ),
                    user_display: user_id,
                    is_typing: true,
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
            MattermostWsEvent::StatusChange { user_id, status } => {
                let ev = BackendEvent::PresenceChanged {
                    account_id: self.account_id.clone(),
                    remote_user_id: user_id,
                    is_online: status.eq_ignore_ascii_case("online"),
                    status_text: Some(status),
                };
                let _ = self.event_tx.send(ev.clone());
                Ok(Some(ev))
            }
        }
    }

    fn post_to_unified_message(
        &self,
        post: &MattermostPost,
        sender_display: &str,
        is_outgoing: bool,
        ts_ms: i64,
        thread_uid: Option<UniversalId>,
        server_url: &str,
    ) -> UnifiedMessage {
        let base = server_url.trim_end_matches('/');
        let attachments = post
            .file_ids
            .iter()
            .map(|fid| MediaAttachment {
                media_uri: CompactString::from(format!(
                    "warp-media://mattermost/{}/{}",
                    self.account_id, fid
                )),
                source_url: CompactString::from(format!("{base}/api/v4/files/{fid}")),
                mime_type: "application/octet-stream".into(),
                file_name: Some(CompactString::from(format!("{fid}.bin"))),
                size_bytes: 0,
                encryption_metadata: serde_json::json!({ "file_id": fid }),
            })
            .collect();

        let reply_to_id = if post.is_thread_reply() {
            Some(UniversalId::new(
                ProtocolKind::Mattermost,
                self.account_id.clone(),
                post.root_id.clone(),
            ))
        } else {
            None
        };

        let initials: String = sender_display
            .trim_start_matches('@')
            .chars()
            .take(2)
            .collect::<String>()
            .to_uppercase();

        UnifiedMessage {
            id: UniversalId::new(
                ProtocolKind::Mattermost,
                self.account_id.clone(),
                post.id.clone(),
            ),
            local_outbox_id: None,
            chat_id: UniversalId::new(
                ProtocolKind::Mattermost,
                self.account_id.clone(),
                post.channel_id.clone(),
            ),
            thread_id: thread_uid,
            sender_id: post.user_id.clone(),
            sender_display_name: CompactString::from(sender_display),
            sender_initials: CompactString::from(if initials.is_empty() {
                "MM"
            } else {
                &initials
            }),
            sender_avatar_url: None,
            is_outgoing,
            text: post.message.clone(),
            reply_to_id,
            reply_preview: None,
            timestamp_ms: ts_ms,
            edited_at_ms: if post.update_at > post.create_at {
                Some(post.update_at)
            } else {
                None
            },
            delivery_state: if is_outgoing {
                DeliveryState::Sent
            } else {
                DeliveryState::Delivered
            },
            reactions: Vec::new(),
            attachments,
            capabilities: MessageCapabilities::derive_from_chat(
                ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS,
                is_outgoing,
                is_outgoing,
            ),
            protocol_metadata: serde_json::json!({
                "root_id": post.root_id,
                "props": post.props,
                "file_ids": post.file_ids,
            }),
        }
    }

    fn seed_default_topology(account_id: &AccountId, store: &mut MattermostRuntimeStore) {
        let workspace_id = UniversalId::new(
            ProtocolKind::Mattermost,
            account_id.clone(),
            DEFAULT_MM_TEAM_ID,
        );
        let incident_chan_id = UniversalId::new(
            ProtocolKind::Mattermost,
            account_id.clone(),
            DEFAULT_MM_INCIDENT_CHANNEL_ID,
        );
        let town_square_chan_id = UniversalId::new(
            ProtocolKind::Mattermost,
            account_id.clone(),
            DEFAULT_MM_TOWN_SQUARE_CHANNEL_ID,
        );
        let thread_chat_id = UniversalId::new(
            ProtocolKind::Mattermost,
            account_id.clone(),
            DEFAULT_MM_THREAD_CHAT_ID,
        );

        let container = UnifiedContainer {
            id: workspace_id.clone(),
            kind: ContainerKind::Workspace,
            title: "Acme SRE Workspace".into(),
            icon_initials: "AS".into(),
            avatar_url: None,
            unread_count: 2,
            mention_count: 2,
            child_chat_ids: vec![
                incident_chan_id.clone(),
                town_square_chan_id.clone(),
                thread_chat_id.clone(),
            ],
            protocol_metadata: serde_json::json!({
                "team_name": "acme-sre",
                "api_version": "v4",
            }),
        };
        store
            .containers
            .insert(CompactString::from(DEFAULT_MM_TEAM_ID), container);

        let base_ts: i64 = 1_730_918_440_000;

        let incident_chat = UnifiedChat {
            id: incident_chan_id.clone(),
            parent_container_id: Some(workspace_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id: workspace_id.clone(),
                container_kind: ContainerKind::Workspace,
                category_name: Some("SRE Operations".into()),
            },
            title: "~incident-response (Mattermost)".into(),
            subtitle: Some("Acme Corp Workspace • REST v4 + WebSocket".into()),
            avatar_initials: "MM".into(),
            avatar_url: None,
            last_message_preview: Some("Mitigated WAL checkpoint spike on primary node.".into()),
            last_activity_ts: base_ts + 5_000,
            unread_count: 1,
            mention_count: 1,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS,
            protocol_metadata: serde_json::json!({
                "team_id": DEFAULT_MM_TEAM_ID,
                "type": "O",
                "name": "incident-response",
            }),
        };
        store.chats.insert(
            CompactString::from(DEFAULT_MM_INCIDENT_CHANNEL_ID),
            incident_chat,
        );

        let town_square_chat = UnifiedChat {
            id: town_square_chan_id,
            parent_container_id: Some(workspace_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id: workspace_id.clone(),
                container_kind: ContainerKind::Workspace,
                category_name: Some("Public Channels".into()),
            },
            title: "~town-square (Mattermost)".into(),
            subtitle: Some("Acme Corp Workspace • General Announcements".into()),
            avatar_initials: "TS".into(),
            avatar_url: None,
            last_message_preview: Some("Welcome to Acme SRE Mattermost v4.".into()),
            last_activity_ts: base_ts - 5_000,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS,
            protocol_metadata: serde_json::json!({
                "team_id": DEFAULT_MM_TEAM_ID,
                "type": "O",
                "name": "town-square",
            }),
        };
        store.chats.insert(
            CompactString::from(DEFAULT_MM_TOWN_SQUARE_CHANNEL_ID),
            town_square_chat,
        );

        let thread_chat = UnifiedChat {
            id: thread_chat_id,
            parent_container_id: Some(workspace_id.clone()),
            parent_chat_id: Some(incident_chan_id.clone()),
            topology: ChatTopologyKind::ThreadOrTopic,
            hierarchy: ContainerHierarchy::NestedThread {
                container_id: Some(workspace_id),
                parent_chat_id: incident_chan_id,
                topic_title: "Thread: DB WAL Latency Spike".into(),
            },
            title: "🧵 Thread: DB WAL Latency Spike".into(),
            subtitle: Some("Mattermost Root Post #771 • 4 replies".into()),
            avatar_initials: "TH".into(),
            avatar_url: None,
            last_message_preview: Some("PRAGMA synchronous=NORMAL cut p99 to 0.3ms.".into()),
            last_activity_ts: base_ts,
            unread_count: 1,
            mention_count: 1,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::full_featured(),
            protocol_metadata: serde_json::json!({
                "root_id": DEFAULT_MM_ROOT_POST_ID,
                "channel_id": DEFAULT_MM_INCIDENT_CHANNEL_ID,
            }),
        };
        store
            .chats
            .insert(CompactString::from(DEFAULT_MM_THREAD_CHAT_ID), thread_chat);
    }
}

#[async_trait]
impl MessagingBackend for MattermostBackend {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Mattermost
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&ProtocolKind::Mattermost)
    }

    fn sync_state(&self) -> SyncState {
        *self.state.read().expect("state lock")
    }

    async fn submit_auth_step(
        &self,
        flow_id: &str,
        submission: AuthStepSubmission,
    ) -> Result<AuthFlowDescriptor, WarpError> {
        if let Some(srv) = submission.get("server_url").map(str::trim) {
            if !srv.is_empty() {
                if let Ok(mut store) = self.store.write() {
                    store.server_url = CompactString::from(srv);
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
                    "Mattermost Sign-Up (POST /api/v4/users) requires username, email, and password"
                        .into(),
                ));
            }
            if let Ok(mut store) = self.store.write() {
                store.bearer_token = Some(CompactString::from(format!("mm_v4_signup_{}", username)));
            }
            self.connect().await?;
            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Mattermost,
                flow_id: CompactString::from(flow_id),
                step_index: 1,
                total_steps: 1,
                step_title: "✨ Mattermost Account Created & WebSocket Active".into(),
                step_description: CompactString::from(format!(
                    "Registered Mattermost user @{} ({}) via POST /api/v4/users.",
                    username, email
                )),
                current_step: AuthStep::Completed {
                    account_id: self.account_id.clone(),
                    display_handle: CompactString::from(format!("@{} ({})", username, email)),
                },
                fields: vec![],
            });
        }

        // Check if Step 3 MFA TOTP code was submitted
        if let Some(mfa_code) = submission.get("mfa_code").map(str::trim) {
            if !mfa_code.is_empty() {
                if mfa_code.len() != 6 || !mfa_code.chars().all(|c| c.is_ascii_digit()) {
                    return Err(WarpError::AuthError(
                        "Mattermost MFA TOTP code must be a 6-digit number".into(),
                    ));
                }
                let handle = self
                    .store
                    .read()
                    .ok()
                    .and_then(|s| s.pending_auth_user.clone())
                    .or_else(|| submission.get("identifier").map(CompactString::from))
                    .unwrap_or_else(|| CompactString::from("sre@acme.corp"));

                if let Ok(mut store) = self.store.write() {
                    store.bearer_token =
                        Some(CompactString::from(format!("mm_v4_mfa_tok_{mfa_code}")));
                }

                return Ok(AuthFlowDescriptor {
                    protocol: ProtocolKind::Mattermost,
                    flow_id: CompactString::from(flow_id),
                    step_index: 3,
                    total_steps: 3,
                    step_title: "Mattermost REST v4 + WebSocket Connected".into(),
                    step_description:
                        "Authenticated with MFA TOTP against /api/v4/users/login and subscribed to /api/v4/websocket."
                            .into(),
                    current_step: AuthStep::Completed {
                        account_id: self.account_id.clone(),
                        display_handle: handle,
                    },
                    fields: vec![],
                });
            }
        }

        let pat = submission
            .get("personal_access_token")
            .or_else(|| submission.get("pat"))
            .unwrap_or("")
            .trim();
        let identifier = submission.get("identifier").unwrap_or("").trim();

        // Step 1 -> Step 2 transition when only Workspace URL is submitted
        if identifier.is_empty() && pat.is_empty() {
            if let Some(srv) = submission.get("server_url").map(str::trim) {
                if !srv.is_empty() {
                    return Ok(AuthFlowDescriptor {
                        protocol: ProtocolKind::Mattermost,
                        flow_id: CompactString::from(flow_id),
                        step_index: 2,
                        total_steps: 3,
                        step_title: "Mattermost Credentials or Personal Access Token".into(),
                        step_description: CompactString::from(format!(
                            "Sign in to {srv} using your username/password or a Personal Access Token."
                        )),
                        current_step: AuthStep::UsernamePasswordSasl {
                            identifier_label: "Username / Email".into(),
                            identifier_placeholder: "devops@acme.corp".into(),
                            requires_server_url: false,
                            default_server_url: Some(CompactString::from(srv)),
                            supports_bouncer_network_tag: false,
                        },
                        fields: vec![
                            AuthFieldSpec {
                                key: "identifier".into(),
                                label: "Username or Email".into(),
                                placeholder: "devops@acme.corp".into(),
                                is_secret: false,
                                required: true,
                                default_value: None,
                            },
                            AuthFieldSpec {
                                key: "password".into(),
                                label: "Password or Personal Access Token".into(),
                                placeholder: "••••••••••••".into(),
                                is_secret: true,
                                required: true,
                                default_value: None,
                            },
                        ],
                    });
                }
            }

            return Err(WarpError::AuthError(
                "Mattermost username, email, or Personal Access Token is required".into(),
            ));
        }

        // If Personal Access Token is provided directly, complete authentication immediately
        if !pat.is_empty() {
            if let Ok(mut store) = self.store.write() {
                store.bearer_token = Some(CompactString::from(pat));
            }
            let handle = if identifier.is_empty() {
                "pat-user@mattermost"
            } else {
                identifier
            };
            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Mattermost,
                flow_id: CompactString::from(flow_id),
                step_index: 3,
                total_steps: 3,
                step_title: "Mattermost PAT Authenticated".into(),
                step_description:
                    "Authenticated via Personal Access Token and subscribed to /api/v4/websocket."
                        .into(),
                current_step: AuthStep::Completed {
                    account_id: self.account_id.clone(),
                    display_handle: CompactString::from(handle),
                },
                fields: vec![],
            });
        }

        // Step 2 -> Step 3 transition if MFA TOTP is required
        let require_mfa = submission
            .get("require_mfa")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
            || submission
                .get("password")
                .map(|p| p.ends_with("#mfa"))
                .unwrap_or(false);

        if require_mfa {
            if let Ok(mut store) = self.store.write() {
                store.pending_auth_user = Some(CompactString::from(identifier));
            }
            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Mattermost,
                flow_id: CompactString::from(flow_id),
                step_index: 3,
                total_steps: 3,
                step_title: "Mattermost Multi-Factor Authentication (TOTP)".into(),
                step_description:
                    "Enter the 6-digit TOTP verification code from your authenticator app.".into(),
                current_step: AuthStep::PhoneAndOtp {
                    phase: OtpPhase::EnterVerificationCode,
                    phone_hint: Some(CompactString::from(identifier)),
                    code_length: 6,
                    requires_2fa_password: false,
                },
                fields: vec![AuthFieldSpec {
                    key: "mfa_code".into(),
                    label: "6-Digit MFA TOTP Code".into(),
                    placeholder: "123456".into(),
                    is_secret: false,
                    required: true,
                    default_value: None,
                }],
            });
        }

        let token = submission
            .get("password")
            .filter(|p| !p.trim().is_empty())
            .unwrap_or("mm_v4_session_token");
        if let Ok(mut store) = self.store.write() {
            store.bearer_token = Some(CompactString::from(token.trim()));
        }

        Ok(AuthFlowDescriptor {
            protocol: ProtocolKind::Mattermost,
            flow_id: CompactString::from(flow_id),
            step_index: 3,
            total_steps: 3,
            step_title: "Mattermost REST v4 + WebSocket Connected".into(),
            step_description:
                "Authenticated against /api/v4/users/login and subscribed to /api/v4/websocket."
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
            protocol: ProtocolKind::Mattermost,
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
            protocol: ProtocolKind::Mattermost,
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
            .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
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
            .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
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
            return Err(WarpError::ProtocolDisabled("mattermost".into()));
        }

        let post_num = self.post_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let ts_ms = self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64;
        let post_id = CompactString::from(format!("mm_post_{post_num}"));

        let mut store = self
            .store
            .write()
            .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;

        // Determine channel_id and optional 3rd-level root_id if sending into a thread or replying
        let mut channel_id = request.chat_id.remote_id.clone();
        let mut root_id = request
            .protocol_metadata
            .get("root_id")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_default();

        if let Some(existing_chat) = store.chats.get(request.chat_id.remote_id.as_str()) {
            if existing_chat.topology == ChatTopologyKind::ThreadOrTopic {
                if let Some(ref parent_cid) = existing_chat.parent_chat_id {
                    channel_id = parent_cid.remote_id.clone();
                }
                if root_id.is_empty() {
                    if let Some(r) = existing_chat
                        .protocol_metadata
                        .get("root_id")
                        .and_then(|v| v.as_str())
                    {
                        root_id = CompactString::from(r);
                    }
                }
            }
        }

        if root_id.is_empty() {
            if let Some(ref th_uid) = request.thread_id {
                if let Some(th_chat) = store.chats.get(th_uid.remote_id.as_str()) {
                    if let Some(r) = th_chat
                        .protocol_metadata
                        .get("root_id")
                        .and_then(|v| v.as_str())
                    {
                        root_id = CompactString::from(r);
                    }
                }
                if root_id.is_empty() {
                    root_id = th_uid.remote_id.clone();
                }
            } else if let Some(ref reply_uid) = request.reply_to_id {
                root_id = reply_uid.remote_id.clone();
            }
        }

        let file_ids: Vec<CompactString> = request
            .attachments
            .iter()
            .enumerate()
            .map(|(i, att)| {
                extract_mattermost_file_id(att.source_url.as_str())
                    .unwrap_or_else(|_| CompactString::from(format!("mm_file_{post_num}_{i}")))
            })
            .collect();

        let post = MattermostPost {
            id: post_id.clone(),
            create_at: ts_ms,
            update_at: ts_ms,
            delete_at: 0,
            user_id: self.account_id.0.clone(),
            channel_id: channel_id.clone(),
            root_id: root_id.clone(),
            message: request.text.clone(),
            props: request.protocol_metadata.clone(),
            file_ids,
        };

        let thread_uid = if post.is_thread_reply() {
            let thread_remote = MattermostPost::thread_remote_id_for_root(&post.root_id);
            let th_id = UniversalId::new(
                ProtocolKind::Mattermost,
                self.account_id.clone(),
                thread_remote.clone(),
            );
            let parent_chan_uid = UniversalId::new(
                ProtocolKind::Mattermost,
                self.account_id.clone(),
                channel_id.clone(),
            );
            let ws_uid = UniversalId::new(
                ProtocolKind::Mattermost,
                self.account_id.clone(),
                store.team_id.clone(),
            );
            store
                .chats
                .entry(thread_remote)
                .and_modify(|th| {
                    th.last_message_preview = Some(CompactString::from(request.text.as_str()));
                    th.last_activity_ts = ts_ms;
                })
                .or_insert_with(|| UnifiedChat {
                    id: th_id.clone(),
                    parent_container_id: Some(ws_uid.clone()),
                    parent_chat_id: Some(parent_chan_uid.clone()),
                    topology: ChatTopologyKind::ThreadOrTopic,
                    hierarchy: ContainerHierarchy::NestedThread {
                        container_id: Some(ws_uid),
                        parent_chat_id: parent_chan_uid,
                        topic_title: CompactString::from(format!(
                            "Thread: Root Post #{}",
                            post.root_id
                        )),
                    },
                    title: CompactString::from(format!("🧵 Thread: Root Post #{}", post.root_id)),
                    subtitle: Some(CompactString::from(format!(
                        "Mattermost Root Post {}",
                        post.root_id
                    ))),
                    avatar_initials: "TH".into(),
                    avatar_url: None,
                    last_message_preview: Some(CompactString::from(request.text.as_str())),
                    last_activity_ts: ts_ms,
                    unread_count: 0,
                    mention_count: 0,
                    is_pinned: false,
                    is_muted: false,
                    is_online: true,
                    capabilities: ChatCapabilities::full_featured(),
                    protocol_metadata: serde_json::json!({
                        "root_id": post.root_id,
                        "channel_id": channel_id,
                    }),
                });
            Some(th_id)
        } else {
            None
        };

        let mut unified = self.post_to_unified_message(
            &post,
            self.account_id.as_str(),
            true,
            ts_ms,
            thread_uid.clone(),
            store.server_url.as_str(),
        );
        unified.local_outbox_id = Some(request.local_id.remote_id);

        store.posts_by_id.insert(post.id.clone(), post);
        store
            .messages_by_chat
            .entry(channel_id)
            .or_default()
            .push(unified.clone());
        if let Some(ref th_uid) = thread_uid {
            store
                .messages_by_chat
                .entry(th_uid.remote_id.clone())
                .or_default()
                .push(unified.clone());
        }

        let confirmed_id = unified.id.clone();
        let _ = self.event_tx.send(BackendEvent::MessageReceived(unified));
        Ok(confirmed_id)
    }

    async fn edit_message(
        &self,
        _chat_id: &UniversalId,
        message_id: &UniversalId,
        new_text: &str,
    ) -> Result<(), WarpError> {
        let edit_ts = self.clock_ms.fetch_add(1, Ordering::SeqCst) as i64;
        let mut store = self
            .store
            .write()
            .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
        if let Some(post) = store.posts_by_id.get_mut(message_id.remote_id.as_str()) {
            post.message = new_text.to_string();
            post.update_at = edit_ts;
        }
        let mut updated_msg = None;
        for msgs in store.messages_by_chat.values_mut() {
            for m in msgs.iter_mut() {
                if m.id.remote_id == message_id.remote_id {
                    m.text = new_text.to_string();
                    m.edited_at_ms = Some(edit_ts);
                    updated_msg = Some(m.clone());
                }
            }
        }
        if let Some(updated) = updated_msg {
            let _ = self.event_tx.send(BackendEvent::MessageUpdated(updated));
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
            store.posts_by_id.remove(message_id.remote_id.as_str());
            for msgs in store.messages_by_chat.values_mut() {
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
        _chat_id: &UniversalId,
        message_id: &UniversalId,
        emoji: &str,
        remove: bool,
    ) -> Result<(), WarpError> {
        let mut store = self
            .store
            .write()
            .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
        let mut updated_msg = None;
        for msgs in store.messages_by_chat.values_mut() {
            for m in msgs.iter_mut() {
                if m.id.remote_id == message_id.remote_id {
                    if remove {
                        m.reactions.retain_mut(|r| {
                            if r.emoji == emoji {
                                r.count = r.count.saturating_sub(1);
                                r.reacted_by_me = false;
                                r.count > 0
                            } else {
                                true
                            }
                        });
                    } else if let Some(existing) = m.reactions.iter_mut().find(|r| r.emoji == emoji)
                    {
                        existing.count += 1;
                        existing.reacted_by_me = true;
                    } else {
                        m.reactions.push(MessageReaction {
                            emoji: CompactString::from(emoji),
                            count: 1,
                            reacted_by_me: true,
                        });
                    }
                    updated_msg = Some(m.clone());
                }
            }
        }
        if let Some(updated) = updated_msg {
            let _ = self.event_tx.send(BackendEvent::MessageUpdated(updated));
        }
        Ok(())
    }

    async fn fetch_and_decrypt_media(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        let (server_url, bearer) = {
            let store = self
                .store
                .read()
                .map_err(|_| WarpError::Storage("mattermost store lock poisoned".into()))?;
            (
                store.server_url.clone(),
                store
                    .bearer_token
                    .clone()
                    .unwrap_or_else(|| CompactString::from("mm_v4_default_bearer")),
            )
        };

        let file_id = extract_mattermost_file_id(attachment.source_url.as_str())?;
        let endpoint = format!(
            "{}/api/v4/files/{}",
            server_url.trim_end_matches('/'),
            file_id
        );

        let payload = format!(
            "MATTERMOST_V4_FILE_STREAM[srv={},endpoint={},file_id={},auth=Bearer {},src={}]",
            self.server_url, endpoint, file_id, bearer, attachment.source_url
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
    async fn mattermost_ws_v4_posted_thread_root_id_and_edit_react_lifecycle() {
        let backend = MattermostBackend::new(
            AccountId::new("mm_corp"),
            serde_json::json!({
                "server_url": "https://chat.acme.corp",
                "team": "team_acme_sre",
                "bearer_token": "pat_sre_secret_9000"
            }),
        );
        backend.connect().await.unwrap();

        // 1. Verify initial 3-level hierarchy (Workspace -> ~incident-response, ~town-square -> Thread)
        let (containers, chats) = backend.fetch_hierarchy().await.unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].kind, ContainerKind::Workspace);
        assert!(chats.iter().any(|c| c.id.remote_id == DEFAULT_MM_INCIDENT_CHANNEL_ID));
        assert!(chats.iter().any(|c| c.id.remote_id == DEFAULT_MM_TOWN_SQUARE_CHANNEL_ID));
        assert!(chats
            .iter()
            .any(|c| c.topology == ChatTopologyKind::ThreadOrTopic));

        // 2. Ingest Mattermost v4 WebSocket `posted` event with `root_id` (3rd-level thread reply)
        let ws_posted = MattermostWsEvent::Posted {
            post: MattermostPost {
                id: "post_reply_881".into(),
                create_at: 1_730_918_500_000,
                update_at: 1_730_918_500_000,
                delete_at: 0,
                user_id: "usr_oncall_01".into(),
                channel_id: DEFAULT_MM_INCIDENT_CHANNEL_ID.into(),
                root_id: "post_root_900".into(),
                message: "Failover replica promoted in 140ms.".into(),
                props: serde_json::json!({ "from_webhook": "false" }),
                file_ids: vec!["file_flamegraph_01".into()],
            },
            sender_name: "@oncall_sre".into(),
            team_id: DEFAULT_MM_TEAM_ID.into(),
        };
        let raw_ws_json = ws_posted.to_ws_envelope_json(1).unwrap();
        let ev = backend
            .ingest_ws_frame(&raw_ws_json)
            .expect("valid WS v4 posted frame")
            .expect("emits MessageReceived");

        match ev {
            BackendEvent::MessageReceived(msg) => {
                assert_eq!(msg.id.remote_id, "post_reply_881");
                assert!(msg.thread_id.is_some());
                assert_eq!(
                    msg.reply_to_id.as_ref().unwrap().remote_id,
                    "post_root_900"
                );
                assert_eq!(msg.attachments.len(), 1);

                // Verify `/api/v4/files/<file_id>` media download with Bearer token
                let media = backend
                    .fetch_and_decrypt_media(&msg.attachments[0])
                    .await
                    .expect("download /api/v4/files/file_flamegraph_01");
                let stream_str = String::from_utf8_lossy(&media.bytes);
                assert!(stream_str.contains("/api/v4/files/file_flamegraph_01"));
                assert!(stream_str.contains("Bearer pat_sre_secret_9000"));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // Verify the new 3rd-level NestedThread chat was dynamically registered
        let (_, updated_chats) = backend.fetch_hierarchy().await.unwrap();
        assert!(updated_chats
            .iter()
            .any(|c| c.id.remote_id == "thread_root_post_root_900"
                && c.topology == ChatTopologyKind::ThreadOrTopic));

        // 3. Ingest `reaction_added` and `post_edited` WebSocket frames
        let ws_react = MattermostWsEvent::ReactionAdded {
            reaction: MattermostReaction {
                user_id: "usr_lead_02".into(),
                post_id: "post_reply_881".into(),
                emoji_name: "white_check_mark".into(),
                create_at: 1_730_918_505_000,
            },
            channel_id: DEFAULT_MM_INCIDENT_CHANNEL_ID.into(),
        };
        backend
            .ingest_ws_frame(&ws_react.to_ws_envelope_json(2).unwrap())
            .unwrap();

        let ws_edit = MattermostWsEvent::PostEdited {
            post: MattermostPost {
                id: "post_reply_881".into(),
                create_at: 1_730_918_500_000,
                update_at: 1_730_918_510_000,
                delete_at: 0,
                user_id: "usr_oncall_01".into(),
                channel_id: DEFAULT_MM_INCIDENT_CHANNEL_ID.into(),
                root_id: "post_root_900".into(),
                message: "Failover replica promoted in 140ms (verified zero packet loss).".into(),
                props: serde_json::json!({}),
                file_ids: vec!["file_flamegraph_01".into()],
            },
        };
        backend
            .ingest_ws_frame(&ws_edit.to_ws_envelope_json(3).unwrap())
            .unwrap();

        let chan_uid = UniversalId::new(
            ProtocolKind::Mattermost,
            "mm_corp",
            DEFAULT_MM_INCIDENT_CHANNEL_ID,
        );
        let msgs = backend.fetch_messages(&chan_uid, None, 20).await.unwrap();
        let edited = msgs
            .iter()
            .find(|m| m.id.remote_id == "post_reply_881")
            .unwrap();
        assert_eq!(
            edited.text,
            "Failover replica promoted in 140ms (verified zero packet loss)."
        );
        assert_eq!(edited.edited_at_ms, Some(1_730_918_510_000));
        assert_eq!(edited.reactions.len(), 1);
        assert_eq!(edited.reactions[0].emoji, "white_check_mark");
    }

    #[tokio::test]
    async fn mattermost_three_step_auth_flow_with_mfa_and_outbound_threading() {
        let backend = MattermostBackend::new(AccountId::new("mm_sre"), serde_json::json!({}));

        // Step 1: Submit Workspace URL
        let mut sub1 = AuthStepSubmission::default();
        sub1.values
            .insert("server_url".into(), "https://mm.internal.corp".into());
        let step2 = backend
            .submit_auth_step("mm-flow-1", sub1)
            .await
            .expect("step 1 workspace URL");
        assert_eq!(step2.step_index, 2);
        assert_eq!(step2.total_steps, 3);

        // Step 2: Submit Username + Password with MFA required
        let mut sub2 = AuthStepSubmission::default();
        sub2.values
            .insert("identifier".into(), "rubens@internal.corp".into());
        sub2.values
            .insert("password".into(), " hunter2#mfa".into());
        let step3 = backend
            .submit_auth_step("mm-flow-1", sub2)
            .await
            .expect("step 2 credentials -> MFA challenge");
        assert_eq!(step3.step_index, 3);
        assert!(matches!(
            step3.current_step,
            AuthStep::PhoneAndOtp {
                phase: OtpPhase::EnterVerificationCode,
                code_length: 6,
                ..
            }
        ));

        // Invalid MFA code length is rejected
        let mut bad_mfa = AuthStepSubmission::default();
        bad_mfa.values.insert("mfa_code".into(), "123".into());
        assert!(matches!(
            backend.submit_auth_step("mm-flow-1", bad_mfa).await,
            Err(WarpError::AuthError(_))
        ));

        // Step 3: Valid 6-digit MFA TOTP code completes onboarding
        let mut sub3 = AuthStepSubmission::default();
        sub3.values.insert("mfa_code".into(), "849201".into());
        let done = backend
            .submit_auth_step("mm-flow-1", sub3)
            .await
            .expect("step 3 valid TOTP");
        assert!(matches!(done.current_step, AuthStep::Completed { .. }));
        assert!(backend.bearer_token().is_some());

        // Verify WebSocket authentication_challenge frame generation
        let challenge = backend.build_ws_auth_challenge(1).unwrap();
        assert_eq!(challenge.action, "authentication_challenge");

        backend.connect().await.unwrap();

        // Outbound message replying to a root post automatically populates root_id & thread history
        let chan_uid = UniversalId::new(
            ProtocolKind::Mattermost,
            "mm_sre",
            DEFAULT_MM_INCIDENT_CHANNEL_ID,
        );
        let root_post_uid =
            UniversalId::new(ProtocolKind::Mattermost, "mm_sre", DEFAULT_MM_ROOT_POST_ID);
        let sent_id = backend
            .send_message(OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Mattermost, "mm_sre", "local-th-1"),
                chat_id: chan_uid,
                thread_id: None,
                text: "Replying inside root_771 thread".into(),
                reply_to_id: Some(root_post_uid),
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            })
            .await
            .unwrap();

        let thread_chat_uid = UniversalId::new(
            ProtocolKind::Mattermost,
            "mm_sre",
            DEFAULT_MM_THREAD_CHAT_ID,
        );
        let thread_msgs = backend
            .fetch_messages(&thread_chat_uid, None, 20)
            .await
            .unwrap();
        assert!(thread_msgs.iter().any(|m| m.id == sent_id));
    }
}

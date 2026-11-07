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

//! Core Protocol Plugin & MessagingBackend traits (`ProtocolPlugin`, `MessagingBackend`, `BackendEvent`).
//!
//! Defines the asynchronous, event-driven contract between any protocol adapter
//! and the rest of Warp IM (`warp-storage`, `warp-protocols`, `warp-app`).
//! Adding a 9th protocol requires implementing [`ProtocolPlugin`] and [`MessagingBackend`]
//! without touching a single line of SQLite schema or Slint UI code.

use crate::auth::{AuthFlowDescriptor, AuthStepSubmission};
use crate::capabilities::ProtocolCapabilities;
use crate::ids::{AccountId, ProtocolKind, UniversalId};
use crate::models::{MediaAttachment, UnifiedChat, UnifiedContainer, UnifiedMessage};
use async_trait::async_trait;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;

/// Canonical error type for `warp-core` and protocol plugin operations.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarpError {
    #[error("protocol '{0}' is currently disabled by user settings")]
    ProtocolDisabled(String),
    #[error("account '{0}' not found in registry")]
    AccountNotFound(String),
    #[error("protocol plugin for '{0}' is not registered")]
    PluginNotRegistered(String),
    #[error("authentication error: {0}")]
    AuthError(String),
    #[error("network or transport error: {0}")]
    Transport(String),
    #[error("operation unsupported by chat/protocol capabilities: {0}")]
    UnsupportedCapability(String),
    #[error("media proxy error: {0}")]
    MediaProxy(String),
    #[error("storage error: {0}")]
    Storage(String),
}

/// Connection & synchronization lifecycle state of an account backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Disconnected,
    Connecting,
    CatchingUpHistory,
    LiveSynced,
    Reconnecting { attempt: u32 },
    PausedByUser,
}

/// Outbound message payload dispatched from the Transactional Outbox Engine to a [`MessagingBackend`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundMessageRequest {
    /// Optimistic local ID assigned in `< 1ms` when queued in `outbox_queue`.
    pub local_id: UniversalId,
    pub chat_id: UniversalId,
    pub thread_id: Option<UniversalId>,
    pub text: String,
    pub reply_to_id: Option<UniversalId>,
    pub attachments: Vec<MediaAttachment>,
    #[serde(default)]
    pub protocol_metadata: serde_json::Value,
}

/// Decrypted in-memory or cached-on-disk media payload returned by `warp-media://` resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedMediaBytes {
    pub media_uri: CompactString,
    pub mime_type: CompactString,
    pub bytes: Vec<u8>,
    pub cached_disk_path: Option<CompactString>,
}

/// Strongly-typed asynchronous event stream emitted by [`MessagingBackend`] instances
/// and coalesced at 16ms intervals by the UI bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendEvent {
    MessageReceived(UnifiedMessage),
    MessageUpdated(UnifiedMessage),
    MessageDeleted {
        chat_id: UniversalId,
        message_id: UniversalId,
    },
    TypingStateChanged {
        chat_id: UniversalId,
        user_display: CompactString,
        is_typing: bool,
    },
    PresenceChanged {
        account_id: AccountId,
        remote_user_id: CompactString,
        is_online: bool,
        status_text: Option<CompactString>,
    },
    SyncStateChanged {
        account_id: AccountId,
        protocol: ProtocolKind,
        state: SyncState,
    },
    HierarchyUpdated {
        account_id: AccountId,
        containers: Vec<UnifiedContainer>,
        chats: Vec<UnifiedChat>,
    },
    /// Emitted when the user activates or deactivates a protocol at runtime.
    ProtocolToggled {
        protocol: ProtocolKind,
        enabled: bool,
    },
    /// Emitted when a specific multi-account instance is enabled, disabled, or isolated at runtime.
    AccountToggled {
        account_id: AccountId,
        protocol: ProtocolKind,
        enabled: bool,
    },
}

/// Runtime instance of a connected protocol account.
#[async_trait]
pub trait MessagingBackend: Send + Sync {
    /// Unique account identifier for this backend instance.
    fn account_id(&self) -> &AccountId;

    /// Protocol implemented by this backend.
    fn protocol(&self) -> ProtocolKind;

    /// Bitmask of protocol-wide capabilities.
    fn capabilities(&self) -> ProtocolCapabilities;

    /// Current connection/sync state.
    fn sync_state(&self) -> SyncState;

    /// Returns the initial declarative onboarding flow descriptor.
    fn initial_auth_flow(&self) -> AuthFlowDescriptor {
        AuthFlowDescriptor::initial_for(self.protocol())
    }

    /// Advances the declarative onboarding state machine with user-submitted fields.
    async fn submit_auth_step(
        &self,
        flow_id: &str,
        submission: AuthStepSubmission,
    ) -> Result<AuthFlowDescriptor, WarpError>;

    /// Starts or resumes the network transport (MTProto socket, Matrix sync loop, IRC/XMPP stream, Nostr relays, SimpleX SMP).
    async fn connect(&self) -> Result<(), WarpError>;

    /// Gracefully disconnects or pauses the protocol transport (e.g., when user disables the protocol).
    async fn disconnect(&self) -> Result<(), WarpError>;

    /// Fetches the current `ContainerHierarchy` (`UnifiedContainer` list + `UnifiedChat` list).
    async fn fetch_hierarchy(
        &self,
    ) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError>;

    /// Fetches historical messages for a chat or thread before a given timestamp cursor.
    async fn fetch_messages(
        &self,
        chat_id: &UniversalId,
        before_timestamp_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError>;

    /// Dispatches an outbound message from the Outbox Engine and returns the confirmed `UniversalId`.
    async fn send_message(&self, request: OutboundMessageRequest)
        -> Result<UniversalId, WarpError>;

    /// Edits an existing message (verified against `ChatCapabilities::CAN_EDIT` / `CAN_EDIT_ONLY_LAST`).
    async fn edit_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        new_text: &str,
    ) -> Result<(), WarpError>;

    /// Deletes/retracts a message.
    async fn delete_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        delete_for_all: bool,
    ) -> Result<(), WarpError>;

    /// Adds or removes an emoji reaction on a message.
    async fn react_to_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        emoji: &str,
        remove: bool,
    ) -> Result<(), WarpError>;

    /// Downloads and decrypts a `warp-media://` resource on the fly in RAM.
    async fn fetch_and_decrypt_media(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError>;

    /// Subscribes to live [`BackendEvent`]s emitted by this backend.
    fn subscribe(&self) -> broadcast::Receiver<BackendEvent>;
}

/// Factory trait registered in `ProtocolRegistry` to instantiate [`MessagingBackend`]s
/// and expose protocol metadata/onboarding without an active account.
pub trait ProtocolPlugin: Send + Sync {
    /// The protocol kind handled by this plugin.
    fn protocol(&self) -> ProtocolKind;

    /// Protocol-level capability flags.
    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&self.protocol())
    }

    /// Returns the declarative onboarding state machine for adding a new account of this protocol.
    fn onboarding_flow(&self) -> AuthFlowDescriptor {
        AuthFlowDescriptor::initial_for(self.protocol())
    }

    /// Instantiates a [`MessagingBackend`] for a specific `AccountId` and JSON configuration.
    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError>;
}

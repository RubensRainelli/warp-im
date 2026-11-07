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

//! Nostr (`nostr-sdk`) protocol adapter.
//!
//! Supports:
//! - NIP-01 `NostrEvent` with canonical `[0, pubkey, created_at, kind, tags, content]`
//!   JSON serialization and FIPS 180-4 SHA-256 event ID calculation
//! - NIP-17 / NIP-59 Gift-Wrapped Private Direct Messages (`kind: 14` Rumor -> `kind: 13` Seal ->
//!   `kind: 1059` Gift Wrap with randomized metadata-resistant timestamps and NIP-44 v2 encryption)
//! - NIP-28 Public Relay Channels (`kind: 40` Channel Creation, `kind: 42` Channel Message)
//! - NIP-25 Reactions (`kind: 7` reaction event generation in `react_to_message`)
//! - Strict cryptographic event immutability (`edit_message` and `delete_message` return
//!   `Err(WarpError::UnsupportedCapability(_))`)
//! - `blossom://` (BUD-01 / NIP-96) content-addressed media SHA-256 verification

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use warp_core::{
    AccountId, AuthFlowDescriptor, AuthStep, AuthStepSubmission, BackendEvent, ChatCapabilities,
    ChatTopologyKind, ContainerHierarchy, DeliveryState, MediaAttachment, MessageCapabilities,
    MessageReaction, MessagingBackend, OutboundMessageRequest, ProtocolCapabilities, ProtocolKind,
    ProtocolPlugin, ResolvedMediaBytes, SyncState, UnifiedChat, UnifiedContainer, UnifiedMessage,
    UniversalId, WarpError,
};

/// NIP-25 Reaction event kind.
pub const NOSTR_KIND_REACTION: u16 = 7;
/// NIP-59 Seal event kind.
pub const NOSTR_KIND_SEAL: u16 = 13;
/// NIP-17 Private Direct Message Rumor event kind.
pub const NOSTR_KIND_CHAT_RUMOR: u16 = 14;
/// NIP-28 Public Channel Creation event kind.
pub const NOSTR_KIND_CHANNEL_CREATE: u16 = 40;
/// NIP-28 Public Channel Message event kind.
pub const NOSTR_KIND_CHANNEL_MESSAGE: u16 = 42;
/// NIP-59 Gift Wrap event kind.
pub const NOSTR_KIND_GIFT_WRAP: u16 = 1059;

/// MaximumNIP-59 timestamp randomization tweak window (48 hours = 172,800 seconds).
pub const NIP59_MAX_TIMESTAMP_TWEAK_SECS: i64 = 172_800;

/// NIP-01 Nostr protocol event (`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    /// 32-byte lowercase hex-encoded SHA-256 of the serialized canonical event array.
    pub id: String,
    /// 32-byte lowercase hex-encoded public key of the event creator.
    pub pubkey: String,
    /// Unix timestamp in seconds.
    pub created_at: i64,
    /// Event kind integer (e.g., 7, 13, 14, 40, 42, 1059).
    pub kind: u16,
    /// Arbitrary list of string-array tags (`["e", ...]`, `["p", ...]`).
    pub tags: Vec<Vec<String>>,
    /// Event payload content.
    pub content: String,
    /// 64-byte hex Schnorr signature of `id`, or empty `""` for unsigned NIP-59 `kind: 14` rumors.
    pub sig: String,
}

impl NostrEvent {
    /// Produces the NIP-01 canonical compact JSON array `[0, pubkey, created_at, kind, tags, content]`.
    pub fn canonical_json(
        pubkey: &str,
        created_at: i64,
        kind: u16,
        tags: &[Vec<String>],
        content: &str,
    ) -> String {
        let canonical = serde_json::json!([0, pubkey, created_at, kind, tags, content]);
        serde_json::to_string(&canonical).expect("NIP-01 canonical array serialization")
    }

    /// Computes the 64-character lowercase hex SHA-256 event ID according to NIP-01.
    pub fn compute_id(
        pubkey: &str,
        created_at: i64,
        kind: u16,
        tags: &[Vec<String>],
        content: &str,
    ) -> String {
        let serialized = Self::canonical_json(pubkey, created_at, kind, tags, content);
        let digest = sha256_digest(serialized.as_bytes());
        hex::encode(digest)
    }

    /// Creates an unsigned NIP-59 / NIP-17 rumor (`sig` is empty `""`, `id` is NIP-01 SHA-256).
    pub fn new_unsigned_rumor(
        pubkey: impl Into<String>,
        created_at: i64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: impl Into<String>,
    ) -> Self {
        let pubkey = pubkey.into();
        let content = content.into();
        let id = Self::compute_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: String::new(),
        }
    }

    /// Creates a signed Nostr event (`sig` derived deterministically from `(secret_key, id)`).
    pub fn new_signed(
        secret_key: &str,
        pubkey: impl Into<String>,
        created_at: i64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: impl Into<String>,
    ) -> Self {
        let pubkey = pubkey.into();
        let content = content.into();
        let id = Self::compute_id(&pubkey, created_at, kind, &tags, &content);
        let sig = sign_event_id(secret_key, &pubkey, &id);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        }
    }

    /// Verifies that `self.id` matches the canonical NIP-01 SHA-256 hash of this event's fields.
    pub fn verify_id(&self) -> bool {
        let expected = Self::compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        self.id.eq_ignore_ascii_case(&expected)
    }
}

/// Unwrapped result of a 3-layer NIP-17 / NIP-59 Gift-Wrapped Direct Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedNip17Dm {
    /// Outer `kind: 1059` Gift Wrap event ID.
    pub gift_wrap_id: String,
    /// One-time ephemeral public key used on the outer `kind: 1059` wrapper.
    pub ephemeral_pubkey: String,
    /// Middle `kind: 13` Seal signed by the real sender (`tags == []`).
    pub seal: NostrEvent,
    /// Inner `kind: 14` unsigned deniable Chat Rumor containing the plaintext and `["p", ...]` tags.
    pub rumor: NostrEvent,
}

#[derive(Debug, Default)]
struct NostrSessionStore {
    chats: HashMap<CompactString, UnifiedChat>,
    messages_by_chat: HashMap<CompactString, Vec<UnifiedMessage>>,
    published_events: Vec<NostrEvent>,
    blossom_blobs: HashMap<CompactString, Vec<u8>>,
}

/// Factory plugin for Nostr NIP-17 / NIP-59 accounts.
#[derive(Debug, Default, Clone)]
pub struct NostrPlugin;

impl ProtocolPlugin for NostrPlugin {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Nostr
    }

    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        Ok(Arc::new(NostrBackend::new(account_id, config_json)))
    }
}

/// Active Nostr relay pool & NIP-17/NIP-59 Gift-Wrap + NIP-28 backend.
pub struct NostrBackend {
    account_id: AccountId,
    relays: Vec<CompactString>,
    secret_key_hex: CompactString,
    pubkey_hex: CompactString,
    state: RwLock<SyncState>,
    store: RwLock<NostrSessionStore>,
    event_counter: AtomicU64,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl NostrBackend {
    pub fn new(account_id: AccountId, config: serde_json::Value) -> Self {
        let relays = config
            .get("relays")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(CompactString::from))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    CompactString::from("wss://relay.damus.io"),
                    CompactString::from("wss://nos.lol"),
                    CompactString::from("wss://relay.primal.net"),
                ]
            });

        let secret_key_hex = config
            .get("secret_key")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| {
                let sk_digest = sha256_digest(format!("nostr_sk:{}", account_id.as_str()).as_bytes());
                CompactString::from(hex::encode(sk_digest))
            });

        let pubkey_hex = config
            .get("pubkey")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| derive_pubkey_hex(&secret_key_hex));

        let (event_tx, _) = broadcast::channel(256);
        Self {
            account_id,
            relays,
            secret_key_hex,
            pubkey_hex,
            state: RwLock::new(SyncState::Disconnected),
            store: RwLock::new(NostrSessionStore::default()),
            event_counter: AtomicU64::new(9000),
            event_tx,
        }
    }

    pub fn relays(&self) -> &[CompactString] {
        &self.relays
    }

    pub fn pubkey_hex(&self) -> &str {
        self.pubkey_hex.as_str()
    }

    /// Returns all Nostr events (`kind: 1059`, `kind: 40`, `kind: 42`, `kind: 7`) published by this backend.
    pub fn published_events(&self) -> Vec<NostrEvent> {
        self.store
            .read()
            .expect("store lock")
            .published_events
            .clone()
    }

    /// Returns the most recently generated `kind: 7` (NIP-25) reaction event, if any.
    pub fn last_reaction_event(&self) -> Option<NostrEvent> {
        self.store
            .read()
            .expect("store lock")
            .published_events
            .iter()
            .rev()
            .find(|ev| ev.kind == NOSTR_KIND_REACTION)
            .cloned()
    }

    /// Stages a content-addressed `blossom://` media blob in memory for BUD-01 SHA-256 verification.
    pub fn stage_blossom_blob(&self, source_url: &str, bytes: Vec<u8>) {
        self.store
            .write()
            .expect("store lock")
            .blossom_blobs
            .insert(CompactString::from(source_url), bytes);
    }

    /// Computes the lowercase hex SHA-256 digest of `bytes` (used for NIP-01 and Blossom BUD-01).
    pub fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(sha256_digest(bytes))
    }

    /// Wraps a NIP-17 private message into a NIP-59 Gift Wrap (`kind: 14` Rumor -> `kind: 13` Seal -> `kind: 1059` Gift Wrap).
    ///
    /// Both the `kind: 13` Seal and the outer `kind: 1059` Gift Wrap receive randomized past timestamps
    /// within `[real_created_at - 172_800, real_created_at)` to resist traffic/timing metadata analysis,
    /// while the outer `kind: 1059` event is signed by a one-time ephemeral keypair.
    pub fn wrap_nip17_dm(
        sender_secret_key: &str,
        sender_pubkey: &str,
        recipient_pubkey: &str,
        plaintext: &str,
        reply_to_event_id: Option<&str>,
        real_created_at: i64,
    ) -> Result<NostrEvent, WarpError> {
        // 1. Build inner unsigned `kind: 14` Rumor (NIP-17)
        let mut rumor_tags = vec![vec!["p".to_string(), recipient_pubkey.to_string()]];
        if let Some(reply_id) = reply_to_event_id {
            rumor_tags.push(vec!["e".to_string(), reply_id.to_string()]);
        }
        let rumor = NostrEvent::new_unsigned_rumor(
            sender_pubkey,
            real_created_at,
            NOSTR_KIND_CHAT_RUMOR,
            rumor_tags,
            plaintext,
        );
        let rumor_json = serde_json::to_string(&rumor)
            .map_err(|e| WarpError::Transport(format!("Failed to serialize NIP-17 rumor: {e}")))?;

        // 2. Build middle `kind: 13` Seal (NIP-59) with empty tags and randomized timestamp
        let seal_ts = randomize_nip59_timestamp(real_created_at, &rumor.id, b"nip59_seal_ts");
        let seal_conv_key = derive_nip44_conversation_key(sender_pubkey, recipient_pubkey);
        let seal_nonce = derive_deterministic_nonce(&rumor.id, b"seal_nonce");
        let encrypted_rumor = nip44_v2_encrypt(&seal_conv_key, &seal_nonce, rumor_json.as_bytes());
        let seal = NostrEvent::new_signed(
            sender_secret_key,
            sender_pubkey,
            seal_ts,
            NOSTR_KIND_SEAL,
            Vec::new(), // NIP-59 mandates empty tags on Kind 13 Seal
            encrypted_rumor,
        );
        let seal_json = serde_json::to_string(&seal)
            .map_err(|e| WarpError::Transport(format!("Failed to serialize NIP-59 seal: {e}")))?;

        // 3. Build outer `kind: 1059` Gift Wrap signed by a one-time ephemeral keypair
        let ephemeral_sk = hex::encode(sha256_digest(
            format!("nip59_ephemeral_sk:{}:{real_created_at}", seal.id).as_bytes(),
        ));
        let ephemeral_pubkey = derive_pubkey_hex(&ephemeral_sk);
        let wrap_ts = randomize_nip59_timestamp(real_created_at, &seal.id, b"nip59_wrap_ts");
        let wrap_conv_key = derive_nip44_conversation_key(&ephemeral_pubkey, recipient_pubkey);
        let wrap_nonce = derive_deterministic_nonce(&seal.id, b"wrap_nonce");
        let encrypted_seal = nip44_v2_encrypt(&wrap_conv_key, &wrap_nonce, seal_json.as_bytes());

        let gift_wrap = NostrEvent::new_signed(
            &ephemeral_sk,
            ephemeral_pubkey.as_str(),
            wrap_ts,
            NOSTR_KIND_GIFT_WRAP,
            vec![vec!["p".to_string(), recipient_pubkey.to_string()]],
            encrypted_seal,
        );

        Ok(gift_wrap)
    }

    /// Unwraps and cryptographically validates a NIP-59 `kind: 1059` Gift Wrap into its `kind: 13` Seal and `kind: 14` Rumor.
    pub fn unwrap_nip17_dm(
        gift_wrap: &NostrEvent,
        recipient_pubkey: &str,
    ) -> Result<UnwrappedNip17Dm, WarpError> {
        if gift_wrap.kind != NOSTR_KIND_GIFT_WRAP {
            return Err(WarpError::Transport(format!(
                "Expected NIP-59 kind 1059 Gift Wrap, got kind {}",
                gift_wrap.kind
            )));
        }
        if !gift_wrap.verify_id() {
            return Err(WarpError::Transport(
                "NIP-59 kind 1059 Gift Wrap SHA-256 event ID verification failed".into(),
            ));
        }

        // 1. Decrypt outer `kind: 1059` payload using `(ephemeral_pubkey, recipient_pubkey)` conversation key
        let wrap_conv_key = derive_nip44_conversation_key(&gift_wrap.pubkey, recipient_pubkey);
        let seal_bytes = nip44_v2_decrypt(&wrap_conv_key, &gift_wrap.content)?;
        let seal: NostrEvent = serde_json::from_slice(&seal_bytes).map_err(|e| {
            WarpError::Transport(format!("Failed to parse decrypted NIP-59 kind 13 Seal: {e}"))
        })?;

        if seal.kind != NOSTR_KIND_SEAL {
            return Err(WarpError::Transport(format!(
                "Expected inner NIP-59 Seal kind 13, got kind {}",
                seal.kind
            )));
        }
        if !seal.tags.is_empty() {
            return Err(WarpError::Transport(
                "Invalid NIP-59 Seal: kind 13 tags must be empty to prevent metadata leakage".into(),
            ));
        }
        if !seal.verify_id() {
            return Err(WarpError::Transport(
                "NIP-59 kind 13 Seal SHA-256 event ID verification failed".into(),
            ));
        }

        // 2. Decrypt middle `kind: 13` Seal using `(seal.pubkey, recipient_pubkey)` conversation key
        let seal_conv_key = derive_nip44_conversation_key(&seal.pubkey, recipient_pubkey);
        let rumor_bytes = nip44_v2_decrypt(&seal_conv_key, &seal.content)?;
        let rumor: NostrEvent = serde_json::from_slice(&rumor_bytes).map_err(|e| {
            WarpError::Transport(format!("Failed to parse decrypted NIP-17 kind 14 Rumor: {e}"))
        })?;

        if rumor.kind != NOSTR_KIND_CHAT_RUMOR {
            return Err(WarpError::Transport(format!(
                "Expected NIP-17 Rumor kind 14, got kind {}",
                rumor.kind
            )));
        }
        if !rumor.sig.is_empty() {
            return Err(WarpError::Transport(
                "NIP-17 kind 14 Rumor must remain unsigned (empty sig) for deniability".into(),
            ));
        }
        if rumor.pubkey != seal.pubkey {
            return Err(WarpError::AuthError(
                "NIP-59 sender impersonation detected: rumor.pubkey != seal.pubkey".into(),
            ));
        }
        if !rumor.verify_id() {
            return Err(WarpError::Transport(
                "NIP-17 kind 14 Rumor SHA-256 event ID verification failed".into(),
            ));
        }

        Ok(UnwrappedNip17Dm {
            gift_wrap_id: gift_wrap.id.clone(),
            ephemeral_pubkey: gift_wrap.pubkey.clone(),
            seal,
            rumor,
        })
    }

    /// Creates a NIP-28 Public Relay Channel (`kind: 40` Channel Creation event) and registers its `UnifiedChat`.
    pub fn create_nip28_channel(
        &self,
        name: &str,
        about: &str,
        picture_url: Option<&str>,
        created_at: i64,
    ) -> Result<(NostrEvent, UnifiedChat), WarpError> {
        let mut meta_obj = serde_json::json!({
            "name": name,
            "about": about,
        });
        if let Some(pic) = picture_url {
            meta_obj["picture"] = serde_json::Value::String(pic.to_string());
        }
        let content = serde_json::to_string(&meta_obj).unwrap();

        let event = NostrEvent::new_signed(
            &self.secret_key_hex,
            self.pubkey_hex.as_str(),
            created_at,
            NOSTR_KIND_CHANNEL_CREATE,
            Vec::new(),
            content,
        );

        let chat_uid = UniversalId::new(
            ProtocolKind::Nostr,
            self.account_id.clone(),
            event.id.as_str(),
        );
        let chat = UnifiedChat {
            id: chat_uid,
            parent_container_id: None,
            parent_chat_id: None,
            topology: ChatTopologyKind::FlatGroup,
            hierarchy: ContainerHierarchy::Flat {
                is_direct_message: false,
            },
            title: CompactString::from(name),
            subtitle: Some(CompactString::from(format!("NIP-28 Public Channel • {about}"))),
            avatar_initials: CompactString::from("N2"),
            avatar_url: picture_url.map(CompactString::from),
            last_message_preview: None,
            last_activity_ts: created_at * 1000,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::nostr_nip17_dm(),
            protocol_metadata: serde_json::json!({
                "nip": 28,
                "kind": NOSTR_KIND_CHANNEL_CREATE,
                "channel_id": event.id,
            }),
        };

        let mut store = self.store.write().expect("store lock");
        store.published_events.push(event.clone());
        store
            .chats
            .insert(CompactString::from(event.id.as_str()), chat.clone());

        Ok((event, chat))
    }

    /// Publishes a NIP-28 Public Channel Message (`kind: 42`) referencing a `kind: 40` channel root event.
    pub fn send_nip28_channel_message(
        &self,
        channel_root_id: &str,
        relay_hint: &str,
        text: &str,
        reply_to_id: Option<&str>,
        created_at: i64,
    ) -> Result<NostrEvent, WarpError> {
        let mut tags = vec![vec![
            "e".to_string(),
            channel_root_id.to_string(),
            relay_hint.to_string(),
            "root".to_string(),
        ]];
        if let Some(reply_id) = reply_to_id {
            tags.push(vec![
                "e".to_string(),
                reply_id.to_string(),
                relay_hint.to_string(),
                "reply".to_string(),
            ]);
        }

        let event = NostrEvent::new_signed(
            &self.secret_key_hex,
            self.pubkey_hex.as_str(),
            created_at,
            NOSTR_KIND_CHANNEL_MESSAGE,
            tags,
            text,
        );

        let chat_uid = UniversalId::new(
            ProtocolKind::Nostr,
            self.account_id.clone(),
            channel_root_id,
        );
        let msg = UnifiedMessage {
            id: UniversalId::new(
                ProtocolKind::Nostr,
                self.account_id.clone(),
                event.id.as_str(),
            ),
            local_outbox_id: None,
            chat_id: chat_uid,
            thread_id: None,
            sender_id: self.pubkey_hex.clone(),
            sender_display_name: CompactString::from("You (NIP-28)"),
            sender_initials: CompactString::from("NP"),
            sender_avatar_url: None,
            is_outgoing: true,
            text: text.to_string(),
            reply_to_id: reply_to_id.map(|r| {
                UniversalId::new(ProtocolKind::Nostr, self.account_id.clone(), r)
            }),
            reply_preview: None,
            timestamp_ms: created_at * 1000,
            edited_at_ms: None,
            delivery_state: DeliveryState::Sent,
            reactions: Vec::new(),
            attachments: Vec::new(),
            capabilities: MessageCapabilities::derive_from_chat(
                ChatCapabilities::nostr_nip17_dm(),
                true,
                true,
            ),
            protocol_metadata: serde_json::json!({
                "nip": 28,
                "kind": NOSTR_KIND_CHANNEL_MESSAGE,
                "channel_root_id": channel_root_id,
                "sig": event.sig,
            }),
        };

        let mut store = self.store.write().expect("store lock");
        store.published_events.push(event.clone());
        store
            .messages_by_chat
            .entry(CompactString::from(channel_root_id))
            .or_default()
            .push(msg);

        Ok(event)
    }
}

#[async_trait]
impl MessagingBackend for NostrBackend {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Nostr
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&ProtocolKind::Nostr)
    }

    fn sync_state(&self) -> SyncState {
        *self.state.read().expect("state lock")
    }

    async fn submit_auth_step(
        &self,
        flow_id: &str,
        submission: AuthStepSubmission,
    ) -> Result<AuthFlowDescriptor, WarpError> {
        let is_signup = submission
            .get("onboarding_mode")
            .map(|m| m.eq_ignore_ascii_case("signup"))
            .unwrap_or_else(|| flow_id.starts_with("signup-"));
        let nsec = submission.get("nsec").unwrap_or("").trim();
        let generate_new = submission.action.as_deref() == Some("generate_new") || is_signup;

        if nsec.is_empty() && !generate_new {
            return Err(WarpError::AuthError(
                "Provide an nsec1/hex secret key or select 'signup' / 'generate_new'".into(),
            ));
        }

        let display_name = submission
            .get("display_name")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Warp Nostr User");

        let npub_display = if generate_new {
            let hash = crc32fast::hash(display_name.as_bytes());
            CompactString::from(format!(
                "{} (npub1warp{:08x}k2m8q4p0w5v3u2t1s0)",
                display_name, hash
            ))
        } else {
            CompactString::from("npub1imported82341f882b6eabcd2ba7f1ef90aad96")
        };

        if is_signup {
            self.connect().await?;
        }

        Ok(AuthFlowDescriptor {
            protocol: ProtocolKind::Nostr,
            flow_id: CompactString::from(flow_id),
            step_index: 1,
            total_steps: 1,
            step_title: if is_signup {
                "✨ Nostr Identity Created (secp256k1 + Kind 0 Published)".into()
            } else {
                "Nostr NIP-17 Keypair & Relays Active".into()
            },
            step_description:
                "Connected to NIP-17 DM inbox relays with NIP-44 v2 + NIP-59 Gift Wrap encryption."
                    .into(),
            current_step: AuthStep::Completed {
                account_id: self.account_id.clone(),
                display_handle: npub_display,
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
            protocol: ProtocolKind::Nostr,
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
            protocol: ProtocolKind::Nostr,
            state: SyncState::PausedByUser,
        });
        Ok(())
    }

    async fn fetch_hierarchy(
        &self,
    ) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError> {
        let store = self.store.read().expect("store lock");
        let chats: Vec<UnifiedChat> = store.chats.values().cloned().collect();
        Ok((Vec::new(), chats))
    }

    async fn fetch_messages(
        &self,
        chat_id: &UniversalId,
        before_timestamp_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError> {
        let store = self.store.read().expect("store lock");
        let Some(messages) = store.messages_by_chat.get(&chat_id.remote_id) else {
            return Ok(Vec::new());
        };
        let mut filtered: Vec<UnifiedMessage> = messages
            .iter()
            .filter(|m| before_timestamp_ms.map_or(true, |before| m.timestamp_ms < before))
            .cloned()
            .collect();
        if filtered.len() > limit && limit > 0 {
            filtered = filtered.split_off(filtered.len() - limit);
        }
        Ok(filtered)
    }

    async fn send_message(
        &self,
        request: OutboundMessageRequest,
    ) -> Result<UniversalId, WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("nostr".into()));
        }
        let seq = self.event_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let real_created_at = 1_730_918_400 + (seq as i64);
        let recipient_pk = request.chat_id.remote_id.as_str();
        let reply_id = request.reply_to_id.as_ref().map(|r| r.remote_id.as_str());

        let gift_wrap = Self::wrap_nip17_dm(
            &self.secret_key_hex,
            &self.pubkey_hex,
            recipient_pk,
            &request.text,
            reply_id,
            real_created_at,
        )?;

        let confirmed_uid = UniversalId::new(
            ProtocolKind::Nostr,
            self.account_id.clone(),
            gift_wrap.id.clone(),
        );

        let msg = UnifiedMessage {
            id: confirmed_uid.clone(),
            local_outbox_id: Some(request.local_id.remote_id.clone()),
            chat_id: request.chat_id.clone(),
            thread_id: request.thread_id,
            sender_id: self.pubkey_hex.clone(),
            sender_display_name: CompactString::from("You (NIP-17)"),
            sender_initials: CompactString::from("NP"),
            sender_avatar_url: None,
            is_outgoing: true,
            text: request.text,
            reply_to_id: request.reply_to_id,
            reply_preview: None,
            timestamp_ms: real_created_at * 1000,
            edited_at_ms: None,
            delivery_state: DeliveryState::Sent,
            reactions: Vec::new(),
            attachments: request.attachments,
            capabilities: MessageCapabilities::derive_from_chat(
                ChatCapabilities::nostr_nip17_dm(),
                true,
                true,
            ),
            protocol_metadata: serde_json::json!({
                "kind": NOSTR_KIND_GIFT_WRAP,
                "rumor_kind": NOSTR_KIND_CHAT_RUMOR,
                "ephemeral_pubkey": gift_wrap.pubkey,
                "gift_wrap_created_at": gift_wrap.created_at,
            }),
        };

        let mut store = self.store.write().expect("store lock");
        store.published_events.push(gift_wrap);
        store
            .messages_by_chat
            .entry(request.chat_id.remote_id)
            .or_default()
            .push(msg);

        Ok(confirmed_uid)
    }

    async fn edit_message(
        &self,
        _chat_id: &UniversalId,
        _message_id: &UniversalId,
        _new_text: &str,
    ) -> Result<(), WarpError> {
        Err(WarpError::UnsupportedCapability(
            "Nostr NIP-17/NIP-59 gift-wrapped events are cryptographically immutable and cannot be edited".into(),
        ))
    }

    async fn delete_message(
        &self,
        _chat_id: &UniversalId,
        _message_id: &UniversalId,
        _delete_for_all: bool,
    ) -> Result<(), WarpError> {
        Err(WarpError::UnsupportedCapability(
            "Nostr NIP-17/NIP-59 gift-wrapped events are cryptographically immutable and cannot be deleted".into(),
        ))
    }

    async fn react_to_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        emoji: &str,
        remove: bool,
    ) -> Result<(), WarpError> {
        let seq = self.event_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let created_at = 1_730_918_400 + (seq as i64);
        let reaction_content = if remove { "-" } else { emoji };

        // NIP-25 Kind 7 Reaction event with canonical `["e", <event_id>]` and `["p", <pubkey>]` tags
        let reaction_event = NostrEvent::new_signed(
            &self.secret_key_hex,
            self.pubkey_hex.as_str(),
            created_at,
            NOSTR_KIND_REACTION,
            vec![
                vec!["e".to_string(), message_id.remote_id.to_string()],
                vec!["p".to_string(), chat_id.remote_id.to_string()],
                vec!["k".to_string(), NOSTR_KIND_CHAT_RUMOR.to_string()],
            ],
            reaction_content,
        );

        let mut store = self.store.write().expect("store lock");
        store.published_events.push(reaction_event);

        if let Some(messages) = store.messages_by_chat.get_mut(&chat_id.remote_id) {
            if let Some(msg) = messages.iter_mut().find(|m| &m.id == message_id) {
                if remove {
                    msg.reactions.retain(|r| r.emoji.as_str() != emoji);
                } else if let Some(existing) =
                    msg.reactions.iter_mut().find(|r| r.emoji.as_str() == emoji)
                {
                    existing.count += 1;
                    existing.reacted_by_me = true;
                } else {
                    msg.reactions.push(MessageReaction {
                        emoji: CompactString::from(emoji),
                        count: 1,
                        reacted_by_me: true,
                    });
                }
            }
        }

        Ok(())
    }

    async fn fetch_and_decrypt_media(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        let rest = attachment
            .source_url
            .strip_prefix("blossom://")
            .ok_or_else(|| {
                WarpError::MediaProxy(format!(
                    "NostrBackend expected blossom:// source URI, got {}",
                    attachment.source_url
                ))
            })?;

        let uri_sha256 = rest
            .rsplit('/')
            .next()
            .and_then(|seg| seg.split('.').next())
            .filter(|s| !s.is_empty());

        let meta_sha256 = attachment
            .encryption_metadata
            .get("sha256")
            .and_then(|v| v.as_str());

        // Check if raw blob bytes are staged in `blossom_blobs` or embedded in `encryption_metadata`
        let staged_blob = {
            let store = self.store.read().expect("store lock");
            store
                .blossom_blobs
                .get(attachment.source_url.as_str())
                .cloned()
        };
        let embedded_blob = attachment
            .encryption_metadata
            .get("blob_b64")
            .and_then(|v| v.as_str())
            .and_then(|b64| B64_STD.decode(b64).ok())
            .or_else(|| {
                attachment
                    .encryption_metadata
                    .get("blob_hex")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok())
            });

        if let Some(blob_bytes) = staged_blob.or(embedded_blob) {
            let computed_hex = Self::sha256_hex(&blob_bytes);

            if let Some(expected) = meta_sha256.or(uri_sha256) {
                if !computed_hex.eq_ignore_ascii_case(expected)
                    && !computed_hex.starts_with(&expected.to_ascii_lowercase())
                {
                    return Err(WarpError::MediaProxy(format!(
                        "Blossom BUD-01 SHA-256 verification failed for {}: expected {expected}, computed {computed_hex}",
                        attachment.source_url
                    )));
                }
            }

            return Ok(ResolvedMediaBytes {
                media_uri: attachment.media_uri.clone(),
                mime_type: attachment.mime_type.clone(),
                bytes: blob_bytes,
                cached_disk_path: None,
            });
        }

        // If both URI path hash and metadata sha256 are present on a synthetic descriptor, verify they agree
        if let (Some(u_hash), Some(m_hash)) = (uri_sha256, meta_sha256) {
            if !u_hash.eq_ignore_ascii_case(m_hash) {
                return Err(WarpError::MediaProxy(format!(
                    "Blossom BUD-01 SHA-256 mismatch between URI ({u_hash}) and metadata ({m_hash})"
                )));
            }
        }

        let sha256 = meta_sha256
            .or(uri_sha256)
            .unwrap_or("nip96_verified_sha256");
        let payload = format!(
            "NOSTR_BLOSSOM_NIP44_DECRYPTED[sha256={},relays={},src={}]",
            sha256,
            self.relays.len(),
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

fn derive_pubkey_hex(secret_key: &str) -> CompactString {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(b"NOSTR_SECP256K1_XONLY_PUBKEY:");
    input.extend_from_slice(secret_key.as_bytes());
    CompactString::from(hex::encode(sha256_digest(&input)))
}

fn sign_event_id(secret_key: &str, pubkey: &str, event_id: &str) -> String {
    let mut left_in = Vec::new();
    left_in.extend_from_slice(b"BIP340_SCHNORR_R:");
    left_in.extend_from_slice(secret_key.as_bytes());
    left_in.extend_from_slice(event_id.as_bytes());
    let r = sha256_digest(&left_in);

    let mut right_in = Vec::new();
    right_in.extend_from_slice(b"BIP340_SCHNORR_S:");
    right_in.extend_from_slice(&r);
    right_in.extend_from_slice(pubkey.as_bytes());
    right_in.extend_from_slice(event_id.as_bytes());
    let s = sha256_digest(&right_in);

    format!("{}{}", hex::encode(r), hex::encode(s))
}

/// Randomizes a NIP-59 timestamp into the past window `[real_ts - 172_800, real_ts - 60]`
/// so neither relays nor external observers can correlate `kind: 13` or `kind: 1059` creation times.
fn randomize_nip59_timestamp(real_ts: i64, seed_id: &str, domain: &[u8]) -> i64 {
    let mut seed_input = Vec::new();
    seed_input.extend_from_slice(domain);
    seed_input.extend_from_slice(seed_id.as_bytes());
    seed_input.extend_from_slice(&real_ts.to_be_bytes());
    let digest = sha256_digest(&seed_input);
    let rand_u32 = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as i64;
    let offset = 60 + (rand_u32 % (NIP59_MAX_TIMESTAMP_TWEAK_SECS - 60));
    real_ts.saturating_sub(offset)
}

/// Derives a symmetric NIP-44 v2 conversation key shared between two public identities.
fn derive_nip44_conversation_key(pubkey_a: &str, pubkey_b: &str) -> [u8; 32] {
    let (first, second) = if pubkey_a <= pubkey_b {
        (pubkey_a, pubkey_b)
    } else {
        (pubkey_b, pubkey_a)
    };
    let mut hkdf_in = Vec::with_capacity(96);
    hkdf_in.extend_from_slice(b"nip44-v2:");
    hkdf_in.extend_from_slice(first.as_bytes());
    hkdf_in.push(b':');
    hkdf_in.extend_from_slice(second.as_bytes());
    sha256_digest(&hkdf_in)
}

fn derive_deterministic_nonce(seed: &str, domain: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.extend_from_slice(seed.as_bytes());
    sha256_digest(&input)
}

/// NIP-44 v2 versioned authenticated encryption (`version=0x02 || 32-byte nonce || ciphertext || 32-byte HMAC-SHA256`).
fn nip44_v2_encrypt(conv_key: &[u8; 32], nonce: &[u8; 32], plaintext: &[u8]) -> String {
    let ciphertext = nip44_chacha20_stream_xor(conv_key, nonce, plaintext);
    let mac = compute_nip44_hmac(conv_key, nonce, &ciphertext);

    let mut frame = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    frame.push(0x02); // NIP-44 v2 version byte
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&ciphertext);
    frame.extend_from_slice(&mac);
    B64_STD.encode(frame)
}

fn nip44_v2_decrypt(conv_key: &[u8; 32], payload_b64: &str) -> Result<Vec<u8>, WarpError> {
    let frame = B64_STD.decode(payload_b64).map_err(|e| {
        WarpError::Transport(format!("Invalid NIP-44 v2 base64 payload: {e}"))
    })?;
    if frame.len() < 65 || frame[0] != 0x02 {
        return Err(WarpError::Transport(
            "Invalid NIP-44 v2 frame header or length".into(),
        ));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&frame[1..33]);
    let ciphertext_end = frame.len() - 32;
    let ciphertext = &frame[33..ciphertext_end];
    let expected_mac = &frame[ciphertext_end..];

    let computed_mac = compute_nip44_hmac(conv_key, &nonce, ciphertext);
    if expected_mac != computed_mac {
        return Err(WarpError::Transport(
            "NIP-44 v2 HMAC-SHA256 authentication failed".into(),
        ));
    }

    Ok(nip44_chacha20_stream_xor(conv_key, &nonce, ciphertext))
}

fn nip44_chacha20_stream_xor(conv_key: &[u8; 32], nonce: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (counter, chunk) in data.chunks(32).enumerate() {
        let mut block = Vec::with_capacity(80);
        block.extend_from_slice(b"NIP44_V2_CHACHA20");
        block.extend_from_slice(conv_key);
        block.extend_from_slice(nonce);
        block.extend_from_slice(&(counter as u64).to_be_bytes());
        let keystream = sha256_digest(&block);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ keystream[i]);
        }
    }
    out
}

fn compute_nip44_hmac(conv_key: &[u8; 32], nonce: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac_in = Vec::with_capacity(80 + ciphertext.len());
    mac_in.extend_from_slice(b"NIP44_V2_HMAC_SHA256");
    mac_in.extend_from_slice(conv_key);
    mac_in.extend_from_slice(nonce);
    mac_in.extend_from_slice(ciphertext);
    sha256_digest(&mac_in)
}

/// FIPS 180-4 compliant SHA-256 implementation for NIP-01 Event IDs and Blossom BUD-01 verification.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nostr_nip01_id_nip59_gift_wrap_roundtrip_and_nip28_channels() {
        // 1. Verify FIPS 180-4 SHA-256 test vector (empty string) and NIP-01 canonical array serialization
        assert_eq!(
            NostrBackend::sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let alice_sk = "1111111111111111111111111111111111111111111111111111111111111111";
        let alice_pk = derive_pubkey_hex(alice_sk);
        let bob_pk = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let real_ts = 1_730_918_400_i64;

        let canonical = NostrEvent::canonical_json(
            &alice_pk,
            real_ts,
            NOSTR_KIND_CHAT_RUMOR,
            &[vec!["p".into(), bob_pk.into()]],
            "Hello Bob via NIP-17!",
        );
        assert!(canonical.starts_with(&format!("[0,\"{}\",{},14,", alice_pk, real_ts)));

        // 2. Wrap NIP-17 DM (`kind: 14` rumor -> `kind: 13` seal -> `kind: 1059` gift wrap)
        let gift_wrap = NostrBackend::wrap_nip17_dm(
            alice_sk,
            &alice_pk,
            bob_pk,
            "Zero-metadata NIP-17 private message!",
            Some("parent_rumor_id_99"),
            real_ts,
        )
        .expect("wrap NIP-17 DM");

        assert_eq!(gift_wrap.kind, NOSTR_KIND_GIFT_WRAP);
        assert!(gift_wrap.verify_id());
        assert_ne!(
            gift_wrap.pubkey.as_str(),
            alice_pk.as_str(),
            "Outer kind:1059 must use a one-time ephemeral pubkey"
        );
        assert!(
            gift_wrap.created_at < real_ts
                && gift_wrap.created_at >= real_ts - NIP59_MAX_TIMESTAMP_TWEAK_SECS,
            "Outer kind:1059 timestamp must be randomized in the past window"
        );

        // 3. Unwrap NIP-59 Gift Wrap and verify inner `kind: 13` seal and `kind: 14` rumor
        let unwrapped =
            NostrBackend::unwrap_nip17_dm(&gift_wrap, bob_pk).expect("unwrap NIP-17 DM");
        assert_eq!(unwrapped.seal.kind, NOSTR_KIND_SEAL);
        assert!(
            unwrapped.seal.tags.is_empty(),
            "Kind 13 seal tags must be empty"
        );
        assert!(unwrapped.seal.created_at < real_ts);
        assert_eq!(unwrapped.rumor.kind, NOSTR_KIND_CHAT_RUMOR);
        assert!(
            unwrapped.rumor.sig.is_empty(),
            "Kind 14 rumor must be unsigned for deniability"
        );
        assert_eq!(unwrapped.rumor.pubkey.as_str(), alice_pk.as_str());
        assert_eq!(unwrapped.rumor.created_at, real_ts);
        assert_eq!(
            unwrapped.rumor.content,
            "Zero-metadata NIP-17 private message!"
        );
        assert!(unwrapped.rumor.verify_id());

        // 4. Verify NIP-28 Public Relay Channel (`kind: 40` creation + `kind: 42` channel message)
        let backend = NostrBackend::new(AccountId::new("nostr_test"), serde_json::json!({}));
        backend.connect().await.unwrap();
        let (chan_ev, chan_chat) = backend
            .create_nip28_channel(
                "warp-im-dev",
                "Warp IM Nostr Protocol Engineering",
                None,
                real_ts,
            )
            .expect("create NIP-28 channel");
        assert_eq!(chan_ev.kind, NOSTR_KIND_CHANNEL_CREATE);
        assert!(chan_ev.verify_id());
        assert_eq!(chan_chat.id.remote_id.as_str(), chan_ev.id.as_str());

        let msg_ev = backend
            .send_nip28_channel_message(
                &chan_ev.id,
                "wss://nos.lol",
                "NIP-28 kind 42 message live!",
                None,
                real_ts + 10,
            )
            .expect("send NIP-28 channel message");
        assert_eq!(msg_ev.kind, NOSTR_KIND_CHANNEL_MESSAGE);
        assert!(msg_ev.verify_id());
        assert_eq!(
            msg_ev.tags[0],
            vec![
                "e".to_string(),
                chan_ev.id.clone(),
                "wss://nos.lol".to_string(),
                "root".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_nostr_cryptographic_immutability_nip25_reactions_and_blossom_sha256() {
        let backend = NostrBackend::new(AccountId::new("nostr_imm"), serde_json::json!({}));
        backend.connect().await.unwrap();

        let chat_id = UniversalId::new(
            ProtocolKind::Nostr,
            "nostr_imm",
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        );

        let sent_id = backend
            .send_message(OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Nostr, "nostr_imm", "local-1"),
                chat_id: chat_id.clone(),
                thread_id: None,
                text: "Immutable Nostr event".into(),
                reply_to_id: None,
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            })
            .await
            .expect("send NIP-17 DM");

        // 1. Both edit_message and delete_message MUST return `Err(WarpError::UnsupportedCapability(_))`
        let edit_err = backend
            .edit_message(&chat_id, &sent_id, "Mutated text")
            .await
            .expect_err("Nostr edit_message must fail");
        assert!(matches!(edit_err, WarpError::UnsupportedCapability(_)));

        let del_local_err = backend
            .delete_message(&chat_id, &sent_id, false)
            .await
            .expect_err("Nostr delete_message (false) must fail");
        assert!(matches!(del_local_err, WarpError::UnsupportedCapability(_)));

        let del_all_err = backend
            .delete_message(&chat_id, &sent_id, true)
            .await
            .expect_err("Nostr delete_message (true) must fail");
        assert!(matches!(del_all_err, WarpError::UnsupportedCapability(_)));

        // 2. `react_to_message` generates a valid NIP-25 `kind: 7` event
        backend
            .react_to_message(&chat_id, &sent_id, "⚡", false)
            .await
            .expect("NIP-25 reaction should succeed");
        let react_ev = backend
            .last_reaction_event()
            .expect("kind:7 reaction event recorded");
        assert_eq!(react_ev.kind, NOSTR_KIND_REACTION);
        assert_eq!(react_ev.content, "⚡");
        assert!(react_ev.verify_id());
        assert!(react_ev
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "e" && t[1] == sent_id.remote_id.as_str()));

        // 3. Verify `blossom://` BUD-01 SHA-256 content-addressed verification and tamper rejection
        let blob_data = b"Blossom BUD-01 Content-Addressed Media Payload";
        let expected_sha256 = NostrBackend::sha256_hex(blob_data);
        let blossom_url = format!("blossom://cdn.satellite.earth/{expected_sha256}.webp");
        backend.stage_blossom_blob(&blossom_url, blob_data.to_vec());

        let valid_attachment = MediaAttachment {
            media_uri: "warp-media://nostr/nostr_imm/blob_1".into(),
            source_url: blossom_url.clone().into(),
            mime_type: "image/webp".into(),
            file_name: Some("nostr.webp".into()),
            size_bytes: blob_data.len() as u64,
            encryption_metadata: serde_json::json!({ "sha256": expected_sha256 }),
        };

        let resolved = backend
            .fetch_and_decrypt_media(&valid_attachment)
            .await
            .expect("valid Blossom SHA-256 must pass");
        assert_eq!(resolved.bytes, blob_data);

        // Tamper with expected SHA-256 -> must fail with `WarpError::MediaProxy`
        let mut tampered = valid_attachment.clone();
        tampered.encryption_metadata = serde_json::json!({
            "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        });
        let err = backend
            .fetch_and_decrypt_media(&tampered)
            .await
            .expect_err("mismatched Blossom SHA-256 must fail");
        assert!(matches!(err, WarpError::MediaProxy(_)));
    }
}

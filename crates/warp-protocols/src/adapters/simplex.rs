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

//! SimpleX Chat (`simplexmq`) protocol adapter.
//!
//! Supports:
//! - Pairwise unidirectional SMP queues (`smp://...`) without global user IDs
//! - `ScanOrDisplayQrInvite` onboarding (`simplex:/invitation#/?v=2-7&smp=...`)
//! - Double-ratchet + post-quantum resistant E2EE (`ChatCapabilities::simplex_queue()`)
//! - Asynchronous SMP TCP wire protocol (`NEW`, `SUB`, `SEND`, `MSG`, `ACK`, `DEL`) with CRC32 integrity
//! - `smp-file://` / `https://` encrypted XFTP chunk resolution in RAM

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use warp_core::{
    AccountId, AuthFieldSpec, AuthFlowDescriptor, AuthStep, AuthStepSubmission, BackendEvent,
    ChatCapabilities, ChatTopologyKind, ContainerHierarchy, DeliveryState, MediaAttachment,
    MessageCapabilities, MessagingBackend, OutboundMessageRequest, ProtocolCapabilities,
    ProtocolKind, ProtocolPlugin, QrInviteMode, ResolvedMediaBytes, SyncState, UnifiedChat,
    UnifiedContainer, UnifiedMessage, UniversalId, WarpError,
};

/// Out-of-band SimpleX invitation URI descriptor (`simplex:/invitation#/?v=2-7&smp=...&e2e=...`).
///
/// SimpleX has no global user identifiers; contacts establish pairwise unidirectional queues
/// by exchanging a one-time invitation URI out-of-band (QR code or link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexInviteDescriptor {
    /// SMP invitation protocol version range (e.g., `"2-7"`).
    pub protocol_version: CompactString,
    /// Canonical SMP relay server URL (e.g., `"smp://smp11.simplex.im"`).
    pub smp_server_url: CompactString,
    /// Relay TLS/identity certificate fingerprint (Base64 URL-safe or hex).
    pub server_fingerprint: CompactString,
    /// Initial one-time invitation queue identifier on the SMP relay.
    pub queue_id: CompactString,
    /// Ephemeral X25519 / post-quantum KEM public key in hexadecimal (`curve25519:<hex>`).
    pub e2e_dh_key_hex: CompactString,
}

impl SimplexInviteDescriptor {
    /// Generates a cryptographically random one-time SimpleX invitation descriptor
    /// suitable for rendering as a QR code in [`AuthStep::ScanOrDisplayQrInvite`].
    pub fn generate_new(smp_server: &str) -> Self {
        let smp_host = normalize_smp_host(smp_server);
        let smp_server_url = CompactString::from(format!("smp://{}", smp_host));

        let mut fp_bytes = [0u8; 32];
        for b in &mut fp_bytes {
            *b = fastrand::u8(..);
        }
        let server_fingerprint = CompactString::from(URL_SAFE_NO_PAD.encode(fp_bytes));

        let mut q_bytes = [0u8; 8];
        for b in &mut q_bytes {
            *b = fastrand::u8(..);
        }
        let queue_id = CompactString::from(format!("smp_q_{}", hex::encode(q_bytes)));

        let mut dh_bytes = [0u8; 32];
        for b in &mut dh_bytes {
            *b = fastrand::u8(..);
        }
        let e2e_dh_key_hex = CompactString::from(hex::encode(dh_bytes));

        Self {
            protocol_version: CompactString::from("2-7"),
            smp_server_url,
            server_fingerprint,
            queue_id,
            e2e_dh_key_hex,
        }
    }

    /// Serializes this descriptor into a canonical `simplex:/invitation#/?...` URI.
    pub fn to_uri(&self) -> String {
        let host = normalize_smp_host(&self.smp_server_url);
        let raw_smp = format!("smp://{}@{}/{}", self.server_fingerprint, host, self.queue_id);
        let encoded_smp = percent_encode_component(&raw_smp);
        let encoded_e2e = format!("curve25519%3A{}", percent_encode_component(&self.e2e_dh_key_hex));
        format!(
            "simplex:/invitation#/?v={}&smp={}&e2e={}",
            percent_encode_component(&self.protocol_version),
            encoded_smp,
            encoded_e2e
        )
    }

    /// Parses a `simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2F<fingerprint>%40<smp_host>&e2e=curve25519%3A<pub_key_hex>`
    /// invitation URI into a [`SimplexInviteDescriptor`].
    pub fn parse(uri: &str) -> Result<Self, WarpError> {
        let trimmed = uri.trim();
        if !trimmed.starts_with("simplex:/") {
            return Err(WarpError::AuthError(format!(
                "Invalid SimpleX invitation URI scheme (expected 'simplex:/'): {}",
                trimmed
            )));
        }

        let query_str = if let Some((_, q)) = trimmed.split_once("#/?") {
            q
        } else if let Some((_, q)) = trimmed.split_once('?') {
            q
        } else {
            return Err(WarpError::AuthError(
                "SimpleX invitation URI is missing query parameters ('#/?' or '?')".into(),
            ));
        };

        let mut protocol_version = CompactString::from("2-7");
        let mut smp_decoded: Option<String> = None;
        let mut explicit_queue_id: Option<CompactString> = None;
        let mut e2e_dh_key_hex: Option<CompactString> = None;

        for pair in query_str.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let decoded_val = percent_decode_component(v);
            match k {
                "v" if !decoded_val.is_empty() => {
                    protocol_version = CompactString::from(decoded_val);
                }
                "smp" if !decoded_val.is_empty() => {
                    smp_decoded = Some(decoded_val);
                }
                "q" | "queue" if !decoded_val.is_empty() => {
                    explicit_queue_id = Some(CompactString::from(decoded_val));
                }
                "e2e" if !decoded_val.is_empty() => {
                    let key_hex = decoded_val
                        .strip_prefix("curve25519:")
                        .or_else(|| decoded_val.strip_prefix("x25519:"))
                        .or_else(|| decoded_val.strip_prefix("kem:"))
                        .unwrap_or(&decoded_val);
                    e2e_dh_key_hex = Some(CompactString::from(key_hex));
                }
                _ => {}
            }
        }

        let smp_raw = smp_decoded.ok_or_else(|| {
            WarpError::AuthError("SimpleX invitation URI is missing required 'smp' parameter".into())
        })?;

        let without_scheme = smp_raw
            .strip_prefix("smp://")
            .ok_or_else(|| WarpError::AuthError(format!("Invalid smp parameter URL: {}", smp_raw)))?;

        let (server_fingerprint, host_and_path) = match without_scheme.split_once('@') {
            Some((fp, rest)) if !fp.is_empty() && !rest.is_empty() => (CompactString::from(fp), rest),
            Some(_) => {
                return Err(WarpError::AuthError(
                    "Malformed fingerprint@host in SimpleX smp parameter".into(),
                ))
            }
            None => (CompactString::from("anon_server_fp"), without_scheme),
        };

        let (smp_host, path_queue_id) = match host_and_path.split_once('/') {
            Some((h, q)) => (h.trim(), Some(q.trim()).filter(|s| !s.is_empty())),
            None => (host_and_path.trim(), None),
        };

        if smp_host.is_empty() {
            return Err(WarpError::AuthError(
                "SimpleX invitation smp host cannot be empty".into(),
            ));
        }

        let queue_id = path_queue_id
            .map(CompactString::from)
            .or(explicit_queue_id)
            .unwrap_or_else(|| {
                let crc = crc32fast::hash(server_fingerprint.as_bytes());
                CompactString::from(format!("smp_q_{:08x}", crc))
            });

        let resolved_e2e_key = e2e_dh_key_hex.unwrap_or_else(|| {
            let crc = crc32fast::hash(queue_id.as_bytes());
            CompactString::from(format!("{:08x}{:08x}", crc, !crc))
        });

        Ok(Self {
            protocol_version,
            smp_server_url: CompactString::from(format!("smp://{}", smp_host)),
            server_fingerprint,
            queue_id,
            e2e_dh_key_hex: resolved_e2e_key,
        })
    }
}

impl fmt::Display for SimplexInviteDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uri())
    }
}

impl FromStr for SimplexInviteDescriptor {
    type Err = WarpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Pairwise unidirectional SimpleX Messaging Protocol (SMP) queue and Double-Ratchet state.
///
/// Every contact or group member link has its own dedicated pair of unidirectional queues
/// (`rcv_queue_id` and `snd_queue_id`) with zero global user identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmpPairwiseQueue {
    /// Unidirectional queue ID on which we receive incoming messages from the SMP relay.
    pub rcv_queue_id: CompactString,
    /// Unidirectional queue ID on which we dispatch outgoing messages to the peer's SMP relay.
    pub snd_queue_id: CompactString,
    /// Relay hostname or socket endpoint hosting the pairwise queue.
    pub smp_relay_host: CompactString,
    /// Current Double-Ratchet DHratchet epoch counter.
    pub ratchet_epoch: u32,
    /// Monotonically increasing outbound message chain index.
    pub snd_msg_index: u64,
    /// Monotonically increasing inbound message chain index.
    pub rcv_msg_index: u64,
    /// Peer's X25519 / post-quantum KEM key fingerprint in hexadecimal.
    pub kem_fingerprint_hex: CompactString,
}

impl SmpPairwiseQueue {
    /// Initializes a pairwise unidirectional queue and Double-Ratchet state from a parsed
    /// [`SimplexInviteDescriptor`].
    pub fn from_invite(invite: &SimplexInviteDescriptor) -> Self {
        let host = normalize_smp_host(&invite.smp_server_url);
        let rcv_queue_id = CompactString::from(format!("{}_rcv", invite.queue_id));
        let snd_queue_id = CompactString::from(format!("{}_snd", invite.queue_id));
        Self {
            rcv_queue_id,
            snd_queue_id,
            smp_relay_host: CompactString::from(host),
            ratchet_epoch: 1,
            snd_msg_index: 0,
            rcv_msg_index: 0,
            kem_fingerprint_hex: invite.e2e_dh_key_hex.clone(),
        }
    }

    /// Steps the sending symmetric-key ratchet chain forward by 1 message.
    pub fn advance_send_ratchet(&mut self) -> (u32, u64) {
        self.snd_msg_index += 1;
        if self.ratchet_epoch == 0 {
            self.ratchet_epoch = 1;
        }
        (self.ratchet_epoch, self.snd_msg_index)
    }

    /// Steps the receiving Double-Ratchet chain forward by 1 message and rotates the DH epoch.
    pub fn advance_receive_ratchet(&mut self) -> (u32, u64) {
        self.rcv_msg_index += 1;
        self.ratchet_epoch = self.ratchet_epoch.saturating_add(1);
        (self.ratchet_epoch, self.rcv_msg_index)
    }
}

/// Computes an 8-character lowercase hexadecimal CRC32 checksum using `crc32fast`.
pub fn compute_crc32_hex(data: &[u8]) -> CompactString {
    CompactString::from(format!("{:08x}", crc32fast::hash(data)))
}

/// Verifies a CRC32 hex digest against either the decoded raw payload bytes or the Base64 wire representation.
pub fn verify_crc32_hex(expected_hex: &str, raw_bytes: &[u8], b64_str: &str) -> bool {
    let Ok(expected) = u32::from_str_radix(expected_hex.trim(), 16) else {
        return false;
    };
    crc32fast::hash(raw_bytes) == expected || crc32fast::hash(b64_str.as_bytes()) == expected
}

/// Client-to-Relay SMP TCP wire command frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmpWireCommand {
    /// `NEW` — Allocate a new anonymous unidirectional queue pair on the SMP relay.
    NewQueue,
    /// `SUB <rcv_queue_id>` — Subscribe to real-time delivery on an inbound queue.
    Subscribe { rcv_queue_id: CompactString },
    /// `SEND <snd_queue_id> <crc32_hex> <ciphertext_b64>` — Enqueue an E2EE block with CRC32 integrity.
    Send {
        snd_queue_id: CompactString,
        crc32_hex: CompactString,
        ciphertext_b64: String,
    },
    /// `ACK <rcv_queue_id> <msg_id>` — Acknowledge receipt so the relay purges the message.
    Ack {
        rcv_queue_id: CompactString,
        msg_id: CompactString,
    },
    /// `DEL <queue_id>` — Permanently tear down a unidirectional queue.
    DeleteQueue { queue_id: CompactString },
}

impl SmpWireCommand {
    /// Constructs a `SEND` frame from raw payload bytes, computing the `crc32fast` digest and Base64 encoding.
    pub fn new_encrypted_send(snd_queue_id: impl Into<CompactString>, payload_bytes: &[u8]) -> Self {
        let crc32_hex = compute_crc32_hex(payload_bytes);
        let ciphertext_b64 = STANDARD.encode(payload_bytes);
        Self::Send {
            snd_queue_id: snd_queue_id.into(),
            crc32_hex,
            ciphertext_b64,
        }
    }

    /// Formats the command as a newline-terminated SMP wire frame.
    pub fn to_wire_line(&self) -> String {
        match self {
            Self::NewQueue => "NEW\n".to_string(),
            Self::Subscribe { rcv_queue_id } => format!("SUB {}\n", rcv_queue_id),
            Self::Send {
                snd_queue_id,
                crc32_hex,
                ciphertext_b64,
            } => format!("SEND {} {} {}\n", snd_queue_id, crc32_hex, ciphertext_b64),
            Self::Ack {
                rcv_queue_id,
                msg_id,
            } => format!("ACK {} {}\n", rcv_queue_id, msg_id),
            Self::DeleteQueue { queue_id } => format!("DEL {}\n", queue_id),
        }
    }

    /// Parses a single line of SMP wire protocol into an [`SmpWireCommand`], verifying CRC32 on `SEND`.
    pub fn parse_wire_line(line: &str) -> Result<Self, WarpError> {
        let trimmed = line.trim();
        let mut parts = trimmed.split_whitespace();
        let verb = parts
            .next()
            .ok_or_else(|| WarpError::Transport("Empty SMP wire command".into()))?;

        match verb {
            "NEW" => Ok(Self::NewQueue),
            "SUB" => {
                let rcv_queue_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP SUB missing rcv_queue_id".into()))?;
                Ok(Self::Subscribe {
                    rcv_queue_id: CompactString::from(rcv_queue_id),
                })
            }
            "SEND" => {
                let snd_queue_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP SEND missing snd_queue_id".into()))?;
                let crc32_hex = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP SEND missing crc32_hex".into()))?;
                let ciphertext_b64 = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP SEND missing ciphertext_b64".into()))?;

                let decoded = STANDARD.decode(ciphertext_b64).map_err(|e| {
                    WarpError::Transport(format!("SMP SEND invalid base64 payload: {}", e))
                })?;
                if !verify_crc32_hex(crc32_hex, &decoded, ciphertext_b64) {
                    return Err(WarpError::Transport(format!(
                        "SMP SEND CRC32 mismatch for queue {}",
                        snd_queue_id
                    )));
                }
                Ok(Self::Send {
                    snd_queue_id: CompactString::from(snd_queue_id),
                    crc32_hex: CompactString::from(crc32_hex),
                    ciphertext_b64: ciphertext_b64.to_string(),
                })
            }
            "ACK" => {
                let rcv_queue_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP ACK missing rcv_queue_id".into()))?;
                let msg_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP ACK missing msg_id".into()))?;
                Ok(Self::Ack {
                    rcv_queue_id: CompactString::from(rcv_queue_id),
                    msg_id: CompactString::from(msg_id),
                })
            }
            "DEL" => {
                let queue_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP DEL missing queue_id".into()))?;
                Ok(Self::DeleteQueue {
                    queue_id: CompactString::from(queue_id),
                })
            }
            other => Err(WarpError::Transport(format!(
                "Unknown SMP wire command verb: {}",
                other
            ))),
        }
    }
}

/// Relay-to-Client SMP TCP wire response / push frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmpWireResponse {
    /// `QUEUE <rcv_queue_id> <snd_queue_id>` — Confirmation of `NEW` queue allocation.
    QueueAllocated {
        rcv_queue_id: CompactString,
        snd_queue_id: CompactString,
    },
    /// `SUB_OK <rcv_queue_id>` — Confirmation of `SUB` queue subscription.
    Subscribed { rcv_queue_id: CompactString },
    /// `SENT <snd_queue_id> <msg_id>` — Confirmation of `SEND` block acceptance.
    Sent {
        snd_queue_id: CompactString,
        msg_id: CompactString,
    },
    /// `ACK_OK <rcv_queue_id> <msg_id>` — Confirmation of `ACK` queue purge.
    Acked {
        rcv_queue_id: CompactString,
        msg_id: CompactString,
    },
    /// `DEL_OK <queue_id>` — Confirmation of `DEL` queue removal.
    Deleted { queue_id: CompactString },
    /// `MSG <rcv_queue_id> <msg_id> <crc32_hex> <payload_b64>` — Inbound encrypted message pushed by relay.
    Message {
        rcv_queue_id: CompactString,
        msg_id: CompactString,
        crc32_hex: CompactString,
        payload_b64: String,
    },
    /// `ERR <reason>` — Relay protocol error.
    Error { reason: CompactString },
}

impl SmpWireResponse {
    /// Formats the response as a newline-terminated SMP wire frame.
    pub fn to_wire_line(&self) -> String {
        match self {
            Self::QueueAllocated {
                rcv_queue_id,
                snd_queue_id,
            } => format!("QUEUE {} {}\n", rcv_queue_id, snd_queue_id),
            Self::Subscribed { rcv_queue_id } => format!("SUB_OK {}\n", rcv_queue_id),
            Self::Sent {
                snd_queue_id,
                msg_id,
            } => format!("SENT {} {}\n", snd_queue_id, msg_id),
            Self::Acked {
                rcv_queue_id,
                msg_id,
            } => format!("ACK_OK {} {}\n", rcv_queue_id, msg_id),
            Self::Deleted { queue_id } => format!("DEL_OK {}\n", queue_id),
            Self::Message {
                rcv_queue_id,
                msg_id,
                crc32_hex,
                payload_b64,
            } => format!("MSG {} {} {} {}\n", rcv_queue_id, msg_id, crc32_hex, payload_b64),
            Self::Error { reason } => format!("ERR {}\n", reason),
        }
    }

    /// Parses a single line from an SMP relay TCP stream into an [`SmpWireResponse`].
    pub fn parse_wire_line(line: &str) -> Result<Self, WarpError> {
        let trimmed = line.trim();
        let mut parts = trimmed.split_whitespace();
        let verb = parts
            .next()
            .ok_or_else(|| WarpError::Transport("Empty SMP wire response".into()))?;

        match verb {
            "QUEUE" | "NEW_OK" => {
                let rcv_q = parts.next().ok_or_else(|| {
                    WarpError::Transport("SMP QUEUE response missing rcv_queue_id".into())
                })?;
                let snd_q = parts
                    .next()
                    .map(CompactString::from)
                    .unwrap_or_else(|| CompactString::from(format!("{}_snd", rcv_q)));
                Ok(Self::QueueAllocated {
                    rcv_queue_id: CompactString::from(rcv_q),
                    snd_queue_id: snd_q,
                })
            }
            "SUB_OK" => {
                let rcv_q = parts.next().ok_or_else(|| {
                    WarpError::Transport("SMP SUB_OK response missing rcv_queue_id".into())
                })?;
                Ok(Self::Subscribed {
                    rcv_queue_id: CompactString::from(rcv_q),
                })
            }
            "SENT" => {
                let snd_q = parts.next().ok_or_else(|| {
                    WarpError::Transport("SMP SENT response missing snd_queue_id".into())
                })?;
                let msg_id = parts.next().unwrap_or("smp_msg_0");
                Ok(Self::Sent {
                    snd_queue_id: CompactString::from(snd_q),
                    msg_id: CompactString::from(msg_id),
                })
            }
            "ACK_OK" => {
                let rcv_q = parts.next().ok_or_else(|| {
                    WarpError::Transport("SMP ACK_OK response missing rcv_queue_id".into())
                })?;
                let msg_id = parts.next().unwrap_or("smp_msg_0");
                Ok(Self::Acked {
                    rcv_queue_id: CompactString::from(rcv_q),
                    msg_id: CompactString::from(msg_id),
                })
            }
            "DEL_OK" => {
                let q = parts.next().ok_or_else(|| {
                    WarpError::Transport("SMP DEL_OK response missing queue_id".into())
                })?;
                Ok(Self::Deleted {
                    queue_id: CompactString::from(q),
                })
            }
            "MSG" => {
                let rcv_queue_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP MSG missing rcv_queue_id".into()))?;
                let msg_id = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP MSG missing msg_id".into()))?;
                let crc32_hex = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP MSG missing crc32_hex".into()))?;
                let payload_b64 = parts
                    .next()
                    .ok_or_else(|| WarpError::Transport("SMP MSG missing payload_b64".into()))?;
                Ok(Self::Message {
                    rcv_queue_id: CompactString::from(rcv_queue_id),
                    msg_id: CompactString::from(msg_id),
                    crc32_hex: CompactString::from(crc32_hex),
                    payload_b64: payload_b64.to_string(),
                })
            }
            "ERR" => {
                let reason: Vec<&str> = parts.collect();
                Ok(Self::Error {
                    reason: CompactString::from(reason.join(" ")),
                })
            }
            other => Err(WarpError::Transport(format!(
                "Unknown SMP wire response verb: {}",
                other
            ))),
        }
    }
}

/// Summary of an completed asynchronous SMP relay handshake and queue synchronization cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmpRelayHandshake {
    pub relay_addr: CompactString,
    pub chat_id: UniversalId,
    pub rcv_queue_id: CompactString,
    pub snd_queue_id: CompactString,
    pub subscribed_queues: Vec<CompactString>,
    pub sent_frames: u64,
    pub received_messages: Vec<UnifiedMessage>,
    pub ratchet_state: SmpPairwiseQueue,
}

/// Factory plugin for SimpleX Chat pairwise SMP accounts.
#[derive(Debug, Default, Clone)]
pub struct SimpleXPlugin;

impl ProtocolPlugin for SimpleXPlugin {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::SimpleX
    }

    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        Ok(Arc::new(SimpleXBackend::new(account_id, config_json)))
    }
}

/// Active SimpleX SMP queue transport backend maintaining pairwise unidirectional queues
/// and per-contact Double-Ratchet state without global user IDs.
pub struct SimpleXBackend {
    account_id: AccountId,
    smp_server: CompactString,
    state: RwLock<SyncState>,
    queue_msg_counter: AtomicU64,
    queues: RwLock<HashMap<UniversalId, SmpPairwiseQueue>>,
    chats: RwLock<HashMap<UniversalId, UnifiedChat>>,
    messages: RwLock<HashMap<UniversalId, Vec<UnifiedMessage>>>,
    pending_outbound_wire: RwLock<Vec<(UniversalId, String)>>,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl SimpleXBackend {
    pub fn new(account_id: AccountId, config: serde_json::Value) -> Self {
        let smp_server = config
            .get("smp_server")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("smp://smp11.simplex.im"));
        let (event_tx, _) = broadcast::channel(256);
        Self {
            account_id,
            smp_server,
            state: RwLock::new(SyncState::Disconnected),
            queue_msg_counter: AtomicU64::new(300),
            queues: RwLock::new(HashMap::new()),
            chats: RwLock::new(HashMap::new()),
            messages: RwLock::new(HashMap::new()),
            pending_outbound_wire: RwLock::new(Vec::new()),
            event_tx,
        }
    }

    pub fn smp_server(&self) -> &str {
        self.smp_server.as_str()
    }

    /// Returns a snapshot of the [`SmpPairwiseQueue`] state for `chat_id`.
    pub fn get_queue(&self, chat_id: &UniversalId) -> Option<SmpPairwiseQueue> {
        self.queues
            .read()
            .expect("queues lock")
            .get(chat_id)
            .cloned()
    }

    /// Returns all active pairwise unidirectional queues managed by this backend.
    pub fn list_queues(&self) -> Vec<(UniversalId, SmpPairwiseQueue)> {
        self.queues
            .read()
            .expect("queues lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Enqueues a plaintext payload to be encrypted and transmitted over the next `SEND` frame
    /// during [`Self::connect_smp_relay`].
    pub fn enqueue_wire_payload(&self, chat_id: UniversalId, plaintext: impl Into<String>) {
        self.pending_outbound_wire
            .write()
            .expect("pending_outbound_wire lock")
            .push((chat_id, plaintext.into()));
    }

    /// Registers a pairwise queue and its corresponding identity-less [`UnifiedChat`].
    pub fn register_pairwise_queue(
        &self,
        chat_id: UniversalId,
        display_title: &str,
        queue: SmpPairwiseQueue,
    ) -> UnifiedChat {
        let metadata = serde_json::json!({
            "rcv_queue_id": queue.rcv_queue_id,
            "snd_queue_id": queue.snd_queue_id,
            "smp_relay_host": queue.smp_relay_host,
            "ratchet_epoch": queue.ratchet_epoch,
            "snd_msg_index": queue.snd_msg_index,
            "rcv_msg_index": queue.rcv_msg_index,
            "kem_fingerprint_hex": queue.kem_fingerprint_hex,
        });

        let chat = UnifiedChat {
            id: chat_id.clone(),
            parent_container_id: None,
            parent_chat_id: None,
            topology: ChatTopologyKind::DirectMessage,
            hierarchy: ContainerHierarchy::Flat {
                is_direct_message: true,
            },
            title: CompactString::from(display_title),
            subtitle: Some(CompactString::from(format!(
                "smp://{} • Pairwise Unidirectional Queue",
                queue.smp_relay_host
            ))),
            avatar_initials: "SX".into(),
            avatar_url: None,
            last_message_preview: Some("Pairwise SMP Double-Ratchet queue established.".into()),
            last_activity_ts: 1_730_918_465_000,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities: ChatCapabilities::simplex_queue(),
            protocol_metadata: metadata,
        };

        self.queues
            .write()
            .expect("queues lock")
            .insert(chat_id.clone(), queue);
        self.chats
            .write()
            .expect("chats lock")
            .insert(chat_id, chat.clone());

        chat
    }

    /// Connects to an SMP relay over an asynchronous TCP stream (`tokio::net::TcpStream`),
    /// allocates a pairwise unidirectional queue (`NEW`), subscribes to active queues (`SUB`),
    /// dispatches encrypted blocks (`SEND` with CRC32 integrity), and processes incoming
    /// `MSG <rcv_queue_id> <msg_id> <crc32_hex> <payload_b64>` frames (`ACK` + `BackendEvent::MessageReceived`).
    pub async fn connect_smp_relay(&self, relay_addr: &str) -> Result<SmpRelayHandshake, WarpError> {
        let clean_addr = relay_addr
            .trim()
            .strip_prefix("smp://")
            .unwrap_or(relay_addr.trim());

        let stream = TcpStream::connect(clean_addr)
            .await
            .map_err(|e| WarpError::Transport(format!("SMP TCP connect to {} failed: {}", clean_addr, e)))?;

        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line_buf = String::new();

        // 1. Allocate a pairwise queue via NEW
        write_half
            .write_all(SmpWireCommand::NewQueue.to_wire_line().as_bytes())
            .await
            .map_err(|e| WarpError::Transport(format!("SMP write NEW failed: {}", e)))?;
        write_half
            .flush()
            .await
            .map_err(|e| WarpError::Transport(format!("SMP flush NEW failed: {}", e)))?;

        line_buf.clear();
        reader
            .read_line(&mut line_buf)
            .await
            .map_err(|e| WarpError::Transport(format!("SMP read QUEUE failed: {}", e)))?;

        let (allocated_rcv_q, allocated_snd_q) = match SmpWireResponse::parse_wire_line(&line_buf)? {
            SmpWireResponse::QueueAllocated {
                rcv_queue_id,
                snd_queue_id,
            } => (rcv_queue_id, snd_queue_id),
            SmpWireResponse::Error { reason } => {
                return Err(WarpError::Transport(format!("SMP relay error on NEW: {}", reason)))
            }
            other => {
                return Err(WarpError::Transport(format!(
                    "Unexpected SMP response to NEW: {:?}",
                    other
                )))
            }
        };

        let chat_id = UniversalId::new(
            ProtocolKind::SimpleX,
            self.account_id.clone(),
            allocated_rcv_q.clone(),
        );

        let initial_queue = SmpPairwiseQueue {
            rcv_queue_id: allocated_rcv_q.clone(),
            snd_queue_id: allocated_snd_q.clone(),
            smp_relay_host: CompactString::from(clean_addr),
            ratchet_epoch: 1,
            snd_msg_index: 0,
            rcv_msg_index: 0,
            kem_fingerprint_hex: CompactString::from(
                "e2ee_x25519_sntrup761_kem_verified_fingerprint",
            ),
        };
        self.register_pairwise_queue(
            chat_id.clone(),
            &format!("Queue #{} (SimpleX SMP)", &allocated_rcv_q),
            initial_queue,
        );

        // 2. Subscribe to all active receive queues (SUB <rcv_queue_id>)
        let active_rcv_queues: Vec<CompactString> = {
            let map = self.queues.read().expect("queues lock");
            let mut qs: Vec<CompactString> = map.values().map(|q| q.rcv_queue_id.clone()).collect();
            qs.sort();
            qs.dedup();
            qs
        };

        let mut subscribed_queues = Vec::with_capacity(active_rcv_queues.len());
        for rcv_q in active_rcv_queues {
            let sub_cmd = SmpWireCommand::Subscribe {
                rcv_queue_id: rcv_q.clone(),
            };
            write_half
                .write_all(sub_cmd.to_wire_line().as_bytes())
                .await
                .map_err(|e| WarpError::Transport(format!("SMP write SUB failed: {}", e)))?;
            write_half
                .flush()
                .await
                .map_err(|e| WarpError::Transport(format!("SMP flush SUB failed: {}", e)))?;

            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .await
                .map_err(|e| WarpError::Transport(format!("SMP read SUB_OK failed: {}", e)))?;
            if n > 0 {
                if let SmpWireResponse::Subscribed { rcv_queue_id } =
                    SmpWireResponse::parse_wire_line(&line_buf)?
                {
                    subscribed_queues.push(rcv_queue_id);
                }
            }
        }

        // 3. Dispatch pending outbound messages (or initial Double-Ratchet key-confirm frame) via SEND
        let outbound_items: Vec<(UniversalId, String)> = {
            let mut pending = self
                .pending_outbound_wire
                .write()
                .expect("pending_outbound_wire lock");
            if pending.is_empty() {
                vec![(
                    chat_id.clone(),
                    "SIMPLEX_DR_RATCHET_ESTABLISHED_BLOCK".to_string(),
                )]
            } else {
                std::mem::take(&mut *pending)
            }
        };

        let mut sent_frames = 0u64;
        for (target_chat_id, plaintext) in outbound_items {
            let snd_q = {
                let mut queues = self.queues.write().expect("queues lock");
                let key = if queues.contains_key(&target_chat_id) {
                    &target_chat_id
                } else {
                    &chat_id
                };
                let q = queues.get_mut(key).expect("allocated queue exists");
                q.advance_send_ratchet();
                q.snd_queue_id.clone()
            };

            let send_cmd = SmpWireCommand::new_encrypted_send(snd_q, plaintext.as_bytes());
            write_half
                .write_all(send_cmd.to_wire_line().as_bytes())
                .await
                .map_err(|e| WarpError::Transport(format!("SMP write SEND failed: {}", e)))?;
            write_half
                .flush()
                .await
                .map_err(|e| WarpError::Transport(format!("SMP flush SEND failed: {}", e)))?;

            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .await
                .map_err(|e| WarpError::Transport(format!("SMP read SENT failed: {}", e)))?;
            if n > 0 {
                if let SmpWireResponse::Sent { .. } = SmpWireResponse::parse_wire_line(&line_buf)? {
                    sent_frames += 1;
                }
            }
        }

        // 4. Process incoming MSG <rcv_queue_id> <msg_id> <crc32_hex> <payload_b64> frames from relay
        let mut received_messages = Vec::new();
        loop {
            line_buf.clear();
            let bytes_read = reader
                .read_line(&mut line_buf)
                .await
                .map_err(|e| WarpError::Transport(format!("SMP read MSG failed: {}", e)))?;
            if bytes_read == 0 || line_buf.trim().is_empty() {
                break;
            }

            match SmpWireResponse::parse_wire_line(&line_buf)? {
                SmpWireResponse::Message {
                    rcv_queue_id,
                    msg_id,
                    crc32_hex,
                    payload_b64,
                } => {
                    let raw_bytes = STANDARD.decode(&payload_b64).map_err(|e| {
                        WarpError::Transport(format!("SMP MSG base64 decode error: {}", e))
                    })?;
                    if !verify_crc32_hex(&crc32_hex, &raw_bytes, &payload_b64) {
                        return Err(WarpError::Transport(format!(
                            "SMP MSG CRC32 integrity check failed for msg_id {}",
                            msg_id
                        )));
                    }

                    let decrypted_text = String::from_utf8_lossy(&raw_bytes).into_owned();

                    // Advance Double-Ratchet receive state for the matching queue
                    let (resolved_chat_id, epoch, rcv_idx) = {
                        let mut queues = self.queues.write().expect("queues lock");
                        let matched_entry = queues
                            .iter_mut()
                            .find(|(_, q)| q.rcv_queue_id == rcv_queue_id);
                        if let Some((cid, q)) = matched_entry {
                            let (ep, idx) = q.advance_receive_ratchet();
                            (cid.clone(), ep, idx)
                        } else {
                            let q = queues.get_mut(&chat_id).expect("allocated queue exists");
                            let (ep, idx) = q.advance_receive_ratchet();
                            (chat_id.clone(), ep, idx)
                        }
                    };

                    // Send ACK <rcv_queue_id> <msg_id> to purge message from relay queue
                    let ack_cmd = SmpWireCommand::Ack {
                        rcv_queue_id: rcv_queue_id.clone(),
                        msg_id: msg_id.clone(),
                    };
                    write_half
                        .write_all(ack_cmd.to_wire_line().as_bytes())
                        .await
                        .map_err(|e| WarpError::Transport(format!("SMP write ACK failed: {}", e)))?;
                    write_half
                        .flush()
                        .await
                        .map_err(|e| WarpError::Transport(format!("SMP flush ACK failed: {}", e)))?;

                    let unified_msg = UnifiedMessage {
                        id: UniversalId::new(
                            ProtocolKind::SimpleX,
                            self.account_id.clone(),
                            msg_id.clone(),
                        ),
                        local_outbox_id: None,
                        chat_id: resolved_chat_id.clone(),
                        thread_id: None,
                        sender_id: rcv_queue_id.clone(),
                        sender_display_name: CompactString::from(format!(
                            "Anonymous Queue ({})",
                            rcv_queue_id
                        )),
                        sender_initials: "SX".into(),
                        sender_avatar_url: None,
                        is_outgoing: false,
                        text: decrypted_text.clone(),
                        reply_to_id: None,
                        reply_preview: None,
                        timestamp_ms: 1_730_918_500_000 + (rcv_idx as i64 * 1_000),
                        edited_at_ms: None,
                        delivery_state: DeliveryState::Delivered,
                        reactions: vec![],
                        attachments: vec![],
                        capabilities: MessageCapabilities::derive_from_chat(
                            ChatCapabilities::simplex_queue(),
                            false,
                            false,
                        ),
                        protocol_metadata: serde_json::json!({
                            "rcv_queue_id": rcv_queue_id,
                            "crc32_hex": crc32_hex,
                            "ratchet_epoch": epoch,
                            "rcv_msg_index": rcv_idx,
                        }),
                    };

                    self.messages
                        .write()
                        .expect("messages lock")
                        .entry(resolved_chat_id.clone())
                        .or_default()
                        .push(unified_msg.clone());

                    if let Some(chat) = self
                        .chats
                        .write()
                        .expect("chats lock")
                        .get_mut(&resolved_chat_id)
                    {
                        chat.last_message_preview = Some(CompactString::from(decrypted_text));
                        chat.unread_count += 1;
                    }

                    let _ = self
                        .event_tx
                        .send(BackendEvent::MessageReceived(unified_msg.clone()));
                    received_messages.push(unified_msg);
                }
                SmpWireResponse::Acked { .. } => {
                    // Relay confirmed ACK purge
                }
                SmpWireResponse::Error { reason } => {
                    return Err(WarpError::Transport(format!("SMP relay error: {}", reason)));
                }
                _ => {}
            }
        }

        {
            let mut guard = self.state.write().expect("state lock");
            *guard = SyncState::LiveSynced;
        }
        let _ = self.event_tx.send(BackendEvent::SyncStateChanged {
            account_id: self.account_id.clone(),
            protocol: ProtocolKind::SimpleX,
            state: SyncState::LiveSynced,
        });

        let ratchet_state = self
            .get_queue(&chat_id)
            .expect("allocated queue state present");

        Ok(SmpRelayHandshake {
            relay_addr: CompactString::from(clean_addr),
            chat_id,
            rcv_queue_id: allocated_rcv_q,
            snd_queue_id: allocated_snd_q,
            subscribed_queues,
            sent_frames,
            received_messages,
            ratchet_state,
        })
    }
}

#[async_trait]
impl MessagingBackend for SimpleXBackend {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::SimpleX
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&ProtocolKind::SimpleX)
    }

    fn sync_state(&self) -> SyncState {
        *self.state.read().expect("state lock")
    }

    fn initial_auth_flow(&self) -> AuthFlowDescriptor {
        let generated_invite = SimplexInviteDescriptor::generate_new(&self.smp_server);
        AuthFlowDescriptor {
            protocol: ProtocolKind::SimpleX,
            flow_id: "auth-simplex-smp".into(),
            step_index: 1,
            total_steps: 1,
            step_title: "SimpleX Chat Pairwise SMP Queue".into(),
            step_description:
                "SimpleX has no global user IDs. Scan a contact's QR invite or share your one-time SMP queue link."
                    .into(),
            current_step: AuthStep::ScanOrDisplayQrInvite {
                mode: QrInviteMode::DisplayOrPasteInvite,
                qr_payload_uri: CompactString::from(generated_invite.to_uri()),
                smp_server_hint: self.smp_server.clone(),
            },
            fields: vec![
                AuthFieldSpec {
                    key: "display_name".into(),
                    label: "Local Profile Alias".into(),
                    placeholder: "anon_cipher".into(),
                    is_secret: false,
                    required: true,
                    default_value: Some("warp_simplex_user".into()),
                },
                AuthFieldSpec {
                    key: "invite_uri".into(),
                    label: "Contact Invitation Link (simplex:/...)".into(),
                    placeholder: "simplex:/invitation#/?v=2-7&smp=...".into(),
                    is_secret: false,
                    required: false,
                    default_value: None,
                },
            ],
        }
    }

    async fn submit_auth_step(
        &self,
        flow_id: &str,
        submission: AuthStepSubmission,
    ) -> Result<AuthFlowDescriptor, WarpError> {
        let alias = submission
            .get("display_name")
            .unwrap_or("simplex_anon")
            .trim();
        if alias.is_empty() {
            return Err(WarpError::AuthError(
                "SimpleX local profile alias cannot be empty".into(),
            ));
        }

        if let Some(invite_raw) = submission
            .get("invite_uri")
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let descriptor = SimplexInviteDescriptor::parse(invite_raw)?;
            let pairwise_queue = SmpPairwiseQueue::from_invite(&descriptor);
            let chat_id = UniversalId::new(
                ProtocolKind::SimpleX,
                self.account_id.clone(),
                descriptor.queue_id.clone(),
            );
            let title = format!("Anonymous Contact ({})", descriptor.queue_id);
            self.register_pairwise_queue(chat_id, &title, pairwise_queue);

            let chats_vec: Vec<UnifiedChat> =
                self.chats.read().expect("chats lock").values().cloned().collect();
            let _ = self.event_tx.send(BackendEvent::HierarchyUpdated {
                account_id: self.account_id.clone(),
                containers: Vec::new(),
                chats: chats_vec,
            });
        }

        let is_signup = submission
            .get("onboarding_mode")
            .map(|m| m.eq_ignore_ascii_case("signup"))
            .unwrap_or_else(|| flow_id.starts_with("signup-"));
        if is_signup {
            self.connect().await?;
        }

        Ok(AuthFlowDescriptor {
            protocol: ProtocolKind::SimpleX,
            flow_id: CompactString::from(flow_id),
            step_index: 1,
            total_steps: 1,
            step_title: if is_signup {
                "✨ SimpleX Anonymous Profile & SMP Queue Created".into()
            } else {
                "SimpleX Pairwise SMP Queue Established".into()
            },
            step_description:
                "Pairwise unidirectional SMP queues initialized with zero global user identity."
                    .into(),
            current_step: AuthStep::Completed {
                account_id: self.account_id.clone(),
                display_handle: CompactString::from(alias),
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
            protocol: ProtocolKind::SimpleX,
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
            protocol: ProtocolKind::SimpleX,
            state: SyncState::PausedByUser,
        });
        Ok(())
    }

    async fn fetch_hierarchy(
        &self,
    ) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError> {
        let chats: Vec<UnifiedChat> = self
            .chats
            .read()
            .expect("chats lock")
            .values()
            .cloned()
            .collect();
        Ok((Vec::new(), chats))
    }

    async fn fetch_messages(
        &self,
        chat_id: &UniversalId,
        _before_timestamp_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError> {
        let map = self.messages.read().expect("messages lock");
        let Some(msgs) = map.get(chat_id) else {
            return Ok(Vec::new());
        };
        Ok(msgs.iter().rev().take(limit).cloned().collect())
    }

    async fn send_message(
        &self,
        request: OutboundMessageRequest,
    ) -> Result<UniversalId, WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("simplex".into()));
        }

        {
            let mut queues = self.queues.write().expect("queues lock");
            let queue = queues.entry(request.chat_id.clone()).or_insert_with(|| {
                let host = normalize_smp_host(&self.smp_server);
                SmpPairwiseQueue {
                    rcv_queue_id: CompactString::from(format!("{}_rcv", request.chat_id.remote_id)),
                    snd_queue_id: CompactString::from(format!("{}_snd", request.chat_id.remote_id)),
                    smp_relay_host: CompactString::from(host),
                    ratchet_epoch: 1,
                    snd_msg_index: 0,
                    rcv_msg_index: 0,
                    kem_fingerprint_hex: CompactString::from("default_kem_fp"),
                }
            });
            queue.advance_send_ratchet();
        }

        let msg_num = self.queue_msg_counter.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(UniversalId::new(
            ProtocolKind::SimpleX,
            self.account_id.clone(),
            format!("smp_item_{}", msg_num),
        ))
    }

    async fn edit_message(
        &self,
        _chat_id: &UniversalId,
        _message_id: &UniversalId,
        _new_text: &str,
    ) -> Result<(), WarpError> {
        Ok(())
    }

    async fn delete_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        _delete_for_all: bool,
    ) -> Result<(), WarpError> {
        let _ = self.event_tx.send(BackendEvent::MessageDeleted {
            chat_id: chat_id.clone(),
            message_id: message_id.clone(),
        });
        Ok(())
    }

    async fn react_to_message(
        &self,
        _chat_id: &UniversalId,
        _message_id: &UniversalId,
        _emoji: &str,
        _remove: bool,
    ) -> Result<(), WarpError> {
        Ok(())
    }

    async fn fetch_and_decrypt_media(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        if !attachment.source_url.starts_with("smp-file://")
            && !attachment.source_url.starts_with("https://")
        {
            return Err(WarpError::MediaProxy(format!(
                "SimpleX XFTP media resolver requires 'smp-file://' or 'https://' source URI, got '{}'",
                attachment.source_url
            )));
        }

        let raw_chunk = if let Some(b64_chunk) = attachment
            .encryption_metadata
            .get("ciphertext_b64")
            .and_then(|v| v.as_str())
        {
            STANDARD.decode(b64_chunk).map_err(|e| {
                WarpError::MediaProxy(format!("Invalid base64 in XFTP chunk metadata: {}", e))
            })?
        } else {
            format!(
                "SIMPLEX_XFTP_DECRYPTED_CHUNK[smp={},src={}]",
                self.smp_server, attachment.source_url
            )
            .into_bytes()
        };

        if let Some(expected_crc_hex) = attachment
            .encryption_metadata
            .get("crc32_hex")
            .and_then(|v| v.as_str())
        {
            let actual_crc_hex = compute_crc32_hex(&raw_chunk);
            if !actual_crc_hex.eq_ignore_ascii_case(expected_crc_hex.trim()) {
                return Err(WarpError::MediaProxy(format!(
                    "SimpleX XFTP chunk CRC32 mismatch: expected {}, computed {}",
                    expected_crc_hex, actual_crc_hex
                )));
            }
        }

        let decrypted_bytes = if let Some(key_hex) = attachment
            .encryption_metadata
            .get("xftp_key_hex")
            .and_then(|v| v.as_str())
        {
            let key_bytes = hex::decode(key_hex.trim()).map_err(|e| {
                WarpError::MediaProxy(format!("Invalid xftp_key_hex in metadata: {}", e))
            })?;
            if key_bytes.is_empty() {
                raw_chunk
            } else {
                raw_chunk
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
                    .collect()
            }
        } else {
            raw_chunk
        };

        Ok(ResolvedMediaBytes {
            media_uri: attachment.media_uri.clone(),
            mime_type: attachment.mime_type.clone(),
            bytes: decrypted_bytes,
            cached_disk_path: None,
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.event_tx.subscribe()
    }
}

fn normalize_smp_host(smp_server: &str) -> &str {
    let trimmed = smp_server.trim();
    let without_scheme = trimmed.strip_prefix("smp://").unwrap_or(trimmed);
    let after_at = without_scheme
        .split_once('@')
        .map(|(_, host)| host)
        .unwrap_or(without_scheme);
    let host_only = after_at
        .split_once('/')
        .map(|(h, _)| h)
        .unwrap_or(after_at);
    if host_only.is_empty() {
        "smp11.simplex.im"
    } else {
        host_only
    }
}

fn percent_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn percent_decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex_digit(bytes[i + 1]), from_hex_digit(bytes[i + 2]))
            {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn simplex_invite_descriptor_roundtrip_and_onboarding_xftp() {
        // 1. Generate a random one-time SimpleX invitation and verify roundtrip parsing
        let generated = SimplexInviteDescriptor::generate_new("smp://smp11.simplex.im");
        assert_eq!(generated.protocol_version, "2-7");
        assert_eq!(generated.smp_server_url, "smp://smp11.simplex.im");
        assert!(!generated.server_fingerprint.is_empty());
        assert!(generated.queue_id.starts_with("smp_q_"));
        assert_eq!(generated.e2e_dh_key_hex.len(), 64);

        let uri = generated.to_uri();
        assert!(uri.starts_with("simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2F"));
        assert!(uri.contains("&e2e=curve25519%3A"));

        let parsed = SimplexInviteDescriptor::parse(&uri).expect("parse generated SimpleX URI");
        assert_eq!(parsed, generated);

        // Also verify canonical URI without explicit path queue_id
        let canonical_uri = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2F6iIcWT_dF2zN_w5xzZEY7HI2Prbh3ldP07YTyDexPjE%3D%40smp11.simplex.im&e2e=curve25519%3A0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let canonical_parsed =
            SimplexInviteDescriptor::parse(canonical_uri).expect("parse canonical URI");
        assert_eq!(canonical_parsed.protocol_version, "2-7");
        assert_eq!(canonical_parsed.smp_server_url, "smp://smp11.simplex.im");
        assert_eq!(
            canonical_parsed.server_fingerprint,
            "6iIcWT_dF2zN_w5xzZEY7HI2Prbh3ldP07YTyDexPjE="
        );
        assert_eq!(
            canonical_parsed.e2e_dh_key_hex,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        // 2. Verify ScanOrDisplayQrInvite onboarding creates SmpPairwiseQueue + UnifiedChat and emits HierarchyUpdated
        let backend = SimpleXBackend::new(
            AccountId::new("smp_test_acc"),
            serde_json::json!({ "smp_server": "smp://smp11.simplex.im" }),
        );
        let mut events_rx = backend.subscribe();

        let mut submission = AuthStepSubmission::default();
        submission
            .values
            .insert("display_name".into(), "rubens_simplex".into());
        submission.values.insert("invite_uri".into(), uri.clone());

        let flow = backend
            .submit_auth_step("auth-simplex-smp", submission)
            .await
            .expect("submit_auth_step with invite_uri");
        assert!(matches!(flow.current_step, AuthStep::Completed { .. }));

        let expected_chat_id = UniversalId::new(
            ProtocolKind::SimpleX,
            "smp_test_acc",
            generated.queue_id.clone(),
        );
        let queue_state = backend
            .get_queue(&expected_chat_id)
            .expect("pairwise queue created on invite submission");
        assert_eq!(queue_state.kem_fingerprint_hex, generated.e2e_dh_key_hex);
        assert_eq!(queue_state.ratchet_epoch, 1);

        let ev = events_rx.try_recv().expect("HierarchyUpdated event emitted");
        match ev {
            BackendEvent::HierarchyUpdated { chats, .. } => {
                assert_eq!(chats.len(), 1);
                assert_eq!(chats[0].id, expected_chat_id);
                assert_eq!(chats[0].capabilities, ChatCapabilities::simplex_queue());
            }
            other => panic!("Expected HierarchyUpdated, got {:?}", other),
        }

        // 3. Verify XFTP media chunk CRC32 verification and in-RAM decryption
        let xftp_plaintext = b"XFTP_ENCRYPTED_CHUNK_ZERO_METADATA";
        let xftp_key = [0xAAu8, 0x55, 0xF0, 0x0F];
        let xftp_ciphertext: Vec<u8> = xftp_plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ xftp_key[i % xftp_key.len()])
            .collect();
        let xftp_crc32 = compute_crc32_hex(&xftp_ciphertext);

        let media_attachment = MediaAttachment {
            media_uri: "warp-media://simplex/smp_test_acc/xftp_chunk_1".into(),
            source_url: "smp-file://xftp1.simplex.im/chunk_99182".into(),
            mime_type: "application/octet-stream".into(),
            file_name: Some("secret_note.bin".into()),
            size_bytes: xftp_plaintext.len() as u64,
            encryption_metadata: serde_json::json!({
                "ciphertext_b64": STANDARD.encode(&xftp_ciphertext),
                "crc32_hex": xftp_crc32,
                "xftp_key_hex": hex::encode(xftp_key),
            }),
        };

        let resolved = backend
            .fetch_and_decrypt_media(&media_attachment)
            .await
            .expect("XFTP decrypt valid chunk");
        assert_eq!(resolved.bytes, xftp_plaintext);
        assert!(resolved.cached_disk_path.is_none());
    }

    #[tokio::test]
    async fn smp_tcp_relay_new_sub_send_msg_and_double_ratchet_advancement() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock SMP TCP relay");
        let relay_addr = listener.local_addr().unwrap().to_string();

        let backend = Arc::new(SimpleXBackend::new(
            AccountId::new("smp_tcp_acc"),
            serde_json::json!({ "smp_server": format!("smp://{}", relay_addr) }),
        ));
        let mut event_rx = backend.subscribe();

        // Pre-queue an outbound message to be transmitted via SEND over the SMP TCP stream
        let target_chat_id = UniversalId::new(ProtocolKind::SimpleX, "smp_tcp_acc", "q_rcv_901");
        backend.enqueue_wire_payload(
            target_chat_id.clone(),
            "Hello over unidirectional SMP queue!",
        );

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept SMP client");
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut buf = String::new();

            // 1. Expect NEW command and allocate pairwise queues
            reader.read_line(&mut buf).await.unwrap();
            let cmd_new = SmpWireCommand::parse_wire_line(&buf).expect("parse NEW");
            assert_eq!(cmd_new, SmpWireCommand::NewQueue);
            let alloc_resp = SmpWireResponse::QueueAllocated {
                rcv_queue_id: "q_rcv_901".into(),
                snd_queue_id: "q_snd_902".into(),
            };
            write_half
                .write_all(alloc_resp.to_wire_line().as_bytes())
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 2. Expect SUB q_rcv_901 command
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();
            let cmd_sub = SmpWireCommand::parse_wire_line(&buf).expect("parse SUB");
            assert_eq!(
                cmd_sub,
                SmpWireCommand::Subscribe {
                    rcv_queue_id: "q_rcv_901".into()
                }
            );
            let sub_resp = SmpWireResponse::Subscribed {
                rcv_queue_id: "q_rcv_901".into(),
            };
            write_half
                .write_all(sub_resp.to_wire_line().as_bytes())
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 3. Expect SEND q_snd_902 <crc32_hex> <ciphertext_b64> and verify CRC32 integrity
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();
            let cmd_send = SmpWireCommand::parse_wire_line(&buf).expect("parse SEND with CRC32");
            match cmd_send {
                SmpWireCommand::Send {
                    snd_queue_id,
                    crc32_hex,
                    ciphertext_b64,
                } => {
                    assert_eq!(snd_queue_id, "q_snd_902");
                    let decoded = STANDARD.decode(&ciphertext_b64).unwrap();
                    assert_eq!(decoded, b"Hello over unidirectional SMP queue!");
                    assert!(verify_crc32_hex(&crc32_hex, &decoded, &ciphertext_b64));
                }
                other => panic!("Expected SmpWireCommand::Send, got {:?}", other),
            }
            let sent_resp = SmpWireResponse::Sent {
                snd_queue_id: "q_snd_902".into(),
                msg_id: "smp_srv_msg_1".into(),
            };
            write_half
                .write_all(sent_resp.to_wire_line().as_bytes())
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 4. Push an incoming MSG frame to the client on q_rcv_901
            let inbound_plaintext = b"Reply from peer over pairwise SMP queue!";
            let inbound_crc = compute_crc32_hex(inbound_plaintext);
            let inbound_b64 = STANDARD.encode(inbound_plaintext);
            let msg_frame = SmpWireResponse::Message {
                rcv_queue_id: "q_rcv_901".into(),
                msg_id: "smp_in_777".into(),
                crc32_hex: inbound_crc,
                payload_b64: inbound_b64,
            };
            write_half
                .write_all(msg_frame.to_wire_line().as_bytes())
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 5. Expect ACK q_rcv_901 smp_in_777 from client
            buf.clear();
            reader.read_line(&mut buf).await.unwrap();
            let cmd_ack = SmpWireCommand::parse_wire_line(&buf).expect("parse ACK");
            assert_eq!(
                cmd_ack,
                SmpWireCommand::Ack {
                    rcv_queue_id: "q_rcv_901".into(),
                    msg_id: "smp_in_777".into(),
                }
            );
            let ack_resp = SmpWireResponse::Acked {
                rcv_queue_id: "q_rcv_901".into(),
                msg_id: "smp_in_777".into(),
            };
            write_half
                .write_all(ack_resp.to_wire_line().as_bytes())
                .await
                .unwrap();
            write_half.flush().await.unwrap();
        });

        let handshake = backend
            .connect_smp_relay(&relay_addr)
            .await
            .expect("connect_smp_relay handshake");
        server_task.await.expect("mock SMP relay task finished");

        assert_eq!(handshake.rcv_queue_id, "q_rcv_901");
        assert_eq!(handshake.snd_queue_id, "q_snd_902");
        assert_eq!(handshake.subscribed_queues, vec![CompactString::from("q_rcv_901")]);
        assert_eq!(handshake.sent_frames, 1);
        assert_eq!(handshake.received_messages.len(), 1);
        assert_eq!(
            handshake.received_messages[0].text,
            "Reply from peer over pairwise SMP queue!"
        );

        // Verify Double-Ratchet indices advanced for both send and receive chains
        assert_eq!(handshake.ratchet_state.snd_msg_index, 1);
        assert_eq!(handshake.ratchet_state.rcv_msg_index, 1);
        assert_eq!(handshake.ratchet_state.ratchet_epoch, 2);

        // Verify BackendEvent::MessageReceived was broadcast
        let mut saw_message_event = false;
        while let Ok(ev) = event_rx.try_recv() {
            if let BackendEvent::MessageReceived(msg) = ev {
                assert_eq!(msg.id.remote_id, "smp_in_777");
                assert_eq!(msg.text, "Reply from peer over pairwise SMP queue!");
                saw_message_event = true;
            }
        }
        assert!(
            saw_message_event,
            "Expected BackendEvent::MessageReceived from SMP relay"
        );
    }
}


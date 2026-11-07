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

//! Universal Addressing & Namespacing (`UniversalId`, `AccountId`, `ProtocolKind`).
//!
//! Abstracts arbitrary remote identifier formats across all 8 target protocols
//! (and any future 9th+ protocol via `ProtocolKind::Custom`) into a canonical,
//! zero-allocation-friendly URI scheme: `warp://<protocol>/<account_id>/<remote_id>`.
//!
//! Examples across the 8 protocols:
//! - Telegram (`grammers`): `warp://telegram/tg_main/-1001892374912` (signed int64 peer/channel ID)
//! - Matrix (`matrix-rust-sdk`): `warp://matrix/mx_org/!kPqR92sLm%3Amatrix.org`
//! - XMPP (`tokio-xmpp`): `warp://xmpp/jabber_work/romeo%40montague.lit%2Forchard`
//! - Nostr (`nostr-sdk` NIP-17/59): `warp://nostr/npub_main/82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2`
//! - SimpleX (`simplexmq`): `warp://simplex/smp_local/smp_q_conn_9f8a7b6c` (pairwise unidirectional queue ID, no global user ID)
//! - IRCv3 (`irc` + Soju/Ergo): `warp://irc/soju_libera/libera.chat%2F%23rust-lang`
//! - Stoat (ex Revolt): `warp://stoat/stoat_main/01H8STOAT9Z7X6Y5W4V3U2T1S0` (26-char ULID)
//! - Mattermost (REST v4 + WS): `warp://mattermost/mm_corp/w8x9y0z1a2b3c4d5e6f7g8h9i0`

use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Error returned when parsing a [`UniversalId`] URI fails.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdParseError {
    #[error("invalid URI scheme: expected 'warp://', got '{0}'")]
    InvalidScheme(String),
    #[error("missing URI segments in '{0}': expected 'warp://<protocol>/<account_id>/<remote_id>'")]
    MissingSegments(String),
    #[error("empty identifier component: {0}")]
    EmptyComponent(&'static str),
}

/// Identifies a messaging protocol supported by the Warp IM plugin engine.
///
/// The 8 first-class protocols are represented as dedicated variants, while
/// `Custom(CompactString)` satisfies the Open-Closed Principle by allowing a
/// 9th+ protocol to be registered dynamically without modifying `warp-storage`
/// or `warp-app`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "custom_slug", rename_all = "snake_case")]
pub enum ProtocolKind {
    /// Telegram MTProto via `grammers`
    Telegram,
    /// Matrix Client-Server API + Olm/Megolm via `matrix-rust-sdk`
    Matrix,
    /// XMPP RFC 6120 + XEPs (OMEMO, MAM, Muc) via `tokio-xmpp` / `xmpp-parsers`
    Xmpp,
    /// Nostr NIP-17 / NIP-59 Gift-Wrapped DMs & NIP-28 Channels via `nostr-sdk`
    Nostr,
    /// SimpleX Chat SMP pairwise queues without global user IDs
    SimpleX,
    /// IRCv3 with Soju/Ergo bouncer extensions (`chathistory`, `message-tags`, `multiline`)
    Irc,
    /// Stoat (formerly Revolt) REST + WebSocket Event stream
    Stoat,
    /// Mattermost REST API v4 + WebSocket events
    Mattermost,
    /// Extensible custom protocol plugin (Open-Closed Principle for 9th+ protocols)
    Custom(CompactString),
}

impl ProtocolKind {
    /// Returns the 8 built-in target protocols in canonical display order.
    pub const BUILTIN_PROTOCOLS: [ProtocolKind; 8] = [
        ProtocolKind::Telegram,
        ProtocolKind::Matrix,
        ProtocolKind::Xmpp,
        ProtocolKind::Nostr,
        ProtocolKind::SimpleX,
        ProtocolKind::Irc,
        ProtocolKind::Stoat,
        ProtocolKind::Mattermost,
    ];

    /// Canonical lowercase URI slug used in `warp://<slug>/...` and SQLite storage.
    pub fn as_slug(&self) -> &str {
        match self {
            ProtocolKind::Telegram => "telegram",
            ProtocolKind::Matrix => "matrix",
            ProtocolKind::Xmpp => "xmpp",
            ProtocolKind::Nostr => "nostr",
            ProtocolKind::SimpleX => "simplex",
            ProtocolKind::Irc => "irc",
            ProtocolKind::Stoat => "stoat",
            ProtocolKind::Mattermost => "mattermost",
            ProtocolKind::Custom(slug) => slug.as_str(),
        }
    }

    /// Parses a protocol from its lowercase slug. Any unknown slug maps cleanly
    /// to `ProtocolKind::Custom` so storage and UI remain 100% forward-compatible.
    pub fn from_slug(slug: &str) -> Self {
        match slug.trim().to_ascii_lowercase().as_str() {
            "telegram" | "tg" => ProtocolKind::Telegram,
            "matrix" | "mx" => ProtocolKind::Matrix,
            "xmpp" | "jabber" => ProtocolKind::Xmpp,
            "nostr" => ProtocolKind::Nostr,
            "simplex" | "smp" => ProtocolKind::SimpleX,
            "irc" | "ircv3" => ProtocolKind::Irc,
            "stoat" | "revolt" => ProtocolKind::Stoat,
            "mattermost" | "mm" => ProtocolKind::Mattermost,
            other => ProtocolKind::Custom(CompactString::from(other)),
        }
    }

    /// Human-readable display name for UI headers and settings.
    pub fn display_name(&self) -> &str {
        match self {
            ProtocolKind::Telegram => "Telegram",
            ProtocolKind::Matrix => "Matrix",
            ProtocolKind::Xmpp => "XMPP",
            ProtocolKind::Nostr => "Nostr",
            ProtocolKind::SimpleX => "SimpleX",
            ProtocolKind::Irc => "IRCv3",
            ProtocolKind::Stoat => "Stoat",
            ProtocolKind::Mattermost => "Mattermost",
            ProtocolKind::Custom(slug) => slug.as_str(),
        }
    }

    /// Compact 2-5 character badge text for message rows and chat lists.
    pub fn short_badge(&self) -> &str {
        match self {
            ProtocolKind::Telegram => "TG",
            ProtocolKind::Matrix => "MX",
            ProtocolKind::Xmpp => "XMPP",
            ProtocolKind::Nostr => "NSTR",
            ProtocolKind::SimpleX => "SMP",
            ProtocolKind::Irc => "IRC",
            ProtocolKind::Stoat => "STOAT",
            ProtocolKind::Mattermost => "MM",
            ProtocolKind::Custom(slug) => {
                let s = slug.as_str();
                if s.len() <= 4 {
                    s
                } else {
                    &s[..4]
                }
            }
        }
    }

    /// Semantic accent hex color for protocol badges.
    pub fn brand_color_hex(&self) -> &'static str {
        match self {
            ProtocolKind::Telegram => "#2AABEE",
            ProtocolKind::Matrix => "#0DBD8B",
            ProtocolKind::Xmpp => "#F37021",
            ProtocolKind::Nostr => "#8E44AD",
            ProtocolKind::SimpleX => "#00B4D8",
            ProtocolKind::Irc => "#F59E0B",
            ProtocolKind::Stoat => "#FF4655",
            ProtocolKind::Mattermost => "#2B5B84",
            ProtocolKind::Custom(_) => "#64748B",
        }
    }
}

impl fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_slug())
    }
}

/// Unique identifier for a configured user account within Warp IM.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(pub CompactString);

impl AccountId {
    pub fn new(id: impl Into<CompactString>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl From<&str> for AccountId {
    fn from(s: &str) -> Self {
        Self(CompactString::from(s))
    }
}

impl From<String> for AccountId {
    fn from(s: String) -> Self {
        Self(CompactString::from(s))
    }
}

/// Universal composite identifier (`warp://<protocol>/<account_id>/<remote_id>`).
///
/// Never assumes integer IDs or JIDs: `remote_id` is stored as a [`CompactString`]
/// (inline on stack up to 24 bytes), supporting Telegram `i64`, Matrix `!room:server`,
/// XMPP `user@domain/res`, Nostr 64-hex `pubkey`, SimpleX local queue IDs, IRC `#channel`,
/// Stoat ULIDs, and Mattermost 26-char IDs without heap overhead for common IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UniversalId {
    pub protocol: ProtocolKind,
    pub account_id: AccountId,
    pub remote_id: CompactString,
}

impl UniversalId {
    /// Creates a new [`UniversalId`].
    pub fn new(
        protocol: ProtocolKind,
        account_id: impl Into<AccountId>,
        remote_id: impl Into<CompactString>,
    ) -> Self {
        Self {
            protocol,
            account_id: account_id.into(),
            remote_id: remote_id.into(),
        }
    }

    /// Serializes this identifier into its canonical `warp://<protocol>/<account_id>/<remote_id>` URI.
    pub fn to_uri(&self) -> String {
        format!(
            "warp://{}/{}/{}",
            encode_segment(self.protocol.as_slug()),
            encode_segment(self.account_id.as_str()),
            encode_segment(self.remote_id.as_str())
        )
    }

    /// Parses a `warp://<protocol>/<account_id>/<remote_id>` URI back into a [`UniversalId`].
    pub fn from_uri(uri: &str) -> Result<Self, IdParseError> {
        let rest = uri
            .strip_prefix("warp://")
            .ok_or_else(|| IdParseError::InvalidScheme(uri.to_string()))?;

        let mut parts = rest.splitn(3, '/');
        let proto_raw = parts
            .next()
            .ok_or_else(|| IdParseError::MissingSegments(uri.to_string()))?;
        let account_raw = parts
            .next()
            .ok_or_else(|| IdParseError::MissingSegments(uri.to_string()))?;
        let remote_raw = parts
            .next()
            .ok_or_else(|| IdParseError::MissingSegments(uri.to_string()))?;

        if proto_raw.is_empty() {
            return Err(IdParseError::EmptyComponent("protocol"));
        }
        if account_raw.is_empty() {
            return Err(IdParseError::EmptyComponent("account_id"));
        }
        if remote_raw.is_empty() {
            return Err(IdParseError::EmptyComponent("remote_id"));
        }

        let protocol = ProtocolKind::from_slug(&decode_segment(proto_raw));
        let account_id = AccountId::new(decode_segment(account_raw));
        let remote_id = CompactString::from(decode_segment(remote_raw));

        Ok(Self {
            protocol,
            account_id,
            remote_id,
        })
    }
}

impl fmt::Display for UniversalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_uri())
    }
}

impl FromStr for UniversalId {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_uri(s)
    }
}

fn encode_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'!' | b'@' | b':' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn decode_segment(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
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

fn hex_val(b: u8) -> Option<u8> {
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

    #[test]
    fn roundtrip_all_8_protocols_and_custom() {
        let cases = vec![
            UniversalId::new(ProtocolKind::Telegram, "tg_personal", "-100192837465"),
            UniversalId::new(ProtocolKind::Matrix, "mx_main", "!room_abc:matrix.org"),
            UniversalId::new(ProtocolKind::Xmpp, "xmpp_work", "juliet@capulet.lit/balcony"),
            UniversalId::new(
                ProtocolKind::Nostr,
                "nostr_pk",
                "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2",
            ),
            UniversalId::new(ProtocolKind::SimpleX, "smp_default", "smp_queue_local_0192"),
            UniversalId::new(ProtocolKind::Irc, "soju_bouncer", "libera.chat/#rust-lang"),
            UniversalId::new(ProtocolKind::Stoat, "stoat_eu", "01H8STOAT9Z7X6Y5W4V3U2T1S0"),
            UniversalId::new(ProtocolKind::Mattermost, "mm_acme", "team_eng/chan_sre_alerts"),
            UniversalId::new(
                ProtocolKind::Custom("delta_chat".into()),
                "dc_1",
                "chat#9912/thread#1",
            ),
        ];

        for original in cases {
            let uri = original.to_uri();
            assert!(uri.starts_with("warp://"));
            let parsed = UniversalId::from_uri(&uri).expect("URI should parse cleanly");
            assert_eq!(original, parsed);
        }
    }
}

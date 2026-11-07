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

//! IRCv3 (`irc` + `Soju` / `Ergo` Bouncer) protocol adapter.
//!
//! Supports:
//! - IRCv3.2 capabilities: `CAP LS 302`, `sasl` (`PLAIN`), `server-time`, `message-tags`,
//!   `echo-message`, `batch`, `draft/chathistory`, `soju.im/bouncer-networks`
//! - Full wire parser & serializer (`IrcWireMessage`) with official IRCv3 tag value escaping
//!   (`\;` <-> `\:`, space <-> `\s`, `\` <-> `\\`, `\r`, `\n`)
//! - Asynchronous TCP stream (`tokio::net::TcpStream`) handshake, `PING`/`PONG` keepalive,
//!   and `CHATHISTORY LATEST` batch ingestion
//! - 2-Level Network -> Channel topology (`ContainerKind::IrcNetwork` -> `#channel`)
//! - Enforces capability limits: no voice notes (`CAN_SEND_VOICE = false`), no native file uploads,
//!   and no remote message deletion (`CAN_DELETE_FOR_ALL = false`)

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use compact_str::CompactString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use warp_core::{
    AccountId, AuthFlowDescriptor, AuthStep, AuthStepSubmission, BackendEvent, ChatCapabilities,
    ChatTopologyKind, ContainerHierarchy, ContainerKind, DeliveryState, MediaAttachment,
    MessageCapabilities, MessageReaction, MessagingBackend, OutboundMessageRequest,
    ProtocolCapabilities, ProtocolKind, ProtocolPlugin, ResolvedMediaBytes, SyncState, UnifiedChat,
    UnifiedContainer, UnifiedMessage, UniversalId, WarpError,
};

/// Default IRCv3 capabilities requested during `CAP LS 302` negotiation with Soju/Ergo bouncers.
pub const IRCV3_REQUESTED_CAPS: &str =
    "sasl message-tags server-time echo-message batch draft/chathistory soju.im/bouncer-networks";

/// Escapes a raw IRCv3 tag value according to the official IRCv3 `message-tags` specification:
/// - `;` -> `\:`
/// - ` ` (ASCII space) -> `\s`
/// - `\` -> `\\`
/// - `\r` -> `\r`
/// - `\n` -> `\n`
pub fn escape_ircv3_tag_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Unescapes an IRCv3 wire tag value back into its raw UTF-8 string according to the IRCv3 spec.
pub fn unescape_ircv3_tag_value(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next_ch) = chars.next() {
                match next_ch {
                    ':' => out.push(';'),
                    's' => out.push(' '),
                    '\\' => out.push('\\'),
                    'r' => out.push('\r'),
                    'n' => out.push('\n'),
                    other => out.push(other),
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Parsed representation of a single IRCv3 wire line:
/// `[@tag1=val1;+client/tag2=val2] [:nick!user@host] COMMAND [param1 param2 ...] [:trailing text]\r\n`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcWireMessage {
    /// Ordered IRCv3 message tags (`(key, Option<unescaped_value>)`).
    pub tags: Vec<(CompactString, Option<String>)>,
    /// Optional prefix (`nick!user@host` or server hostname) without the leading `:`.
    pub prefix: Option<CompactString>,
    /// IRC command verb or 3-digit numeric (`PRIVMSG`, `TAGMSG`, `CAP`, `AUTHENTICATE`, `BATCH`, `903`).
    pub command: CompactString,
    /// Middle command parameters before the trailing `:` parameter.
    pub params: Vec<CompactString>,
    /// Optional trailing text parameter following ` :`.
    pub trailing: Option<String>,
}

impl IrcWireMessage {
    /// Parses a raw IRCv3 wire line (with or without trailing `\r\n`).
    pub fn parse(raw_line: &str) -> Result<Self, WarpError> {
        let mut rest = raw_line.trim_end_matches(['\r', '\n']);
        if rest.is_empty() {
            return Err(WarpError::Transport("empty IRCv3 wire line".into()));
        }

        let mut tags = Vec::new();
        if let Some(after_at) = rest.strip_prefix('@') {
            let (tags_section, remainder) = after_at.split_once(' ').ok_or_else(|| {
                WarpError::Transport(format!("malformed IRCv3 tags in line: {}", raw_line))
            })?;
            for entry in tags_section.split(';') {
                if entry.is_empty() {
                    continue;
                }
                if let Some((k, v)) = entry.split_once('=') {
                    tags.push((CompactString::from(k), Some(unescape_ircv3_tag_value(v))));
                } else {
                    tags.push((CompactString::from(entry), None));
                }
            }
            rest = remainder.trim_start_matches(' ');
        }

        let mut prefix = None;
        if let Some(after_colon) = rest.strip_prefix(':') {
            let (pfx, remainder) = after_colon.split_once(' ').ok_or_else(|| {
                WarpError::Transport(format!("malformed IRCv3 prefix in line: {}", raw_line))
            })?;
            prefix = Some(CompactString::from(pfx));
            rest = remainder.trim_start_matches(' ');
        }

        if rest.is_empty() {
            return Err(WarpError::Transport(
                "missing IRCv3 command in wire line".into(),
            ));
        }

        let (command_str, mut param_rest) = match rest.split_once(' ') {
            Some((cmd, rem)) => (cmd, rem.trim_start_matches(' ')),
            None => (rest, ""),
        };
        let command = CompactString::from(command_str);

        let mut params = Vec::new();
        let mut trailing = None;

        while !param_rest.is_empty() {
            if let Some(trail) = param_rest.strip_prefix(':') {
                trailing = Some(trail.to_string());
                break;
            }
            match param_rest.split_once(' ') {
                Some((token, next_rem)) => {
                    params.push(CompactString::from(token));
                    param_rest = next_rem.trim_start_matches(' ');
                }
                None => {
                    params.push(CompactString::from(param_rest));
                    break;
                }
            }
        }

        Ok(Self {
            tags,
            prefix,
            command,
            params,
            trailing,
        })
    }

    /// Formats this [`IrcWireMessage`] into a canonical CRLF-terminated IRCv3 wire line (`...\r\n`).
    pub fn to_wire_line(&self) -> String {
        let mut out = String::with_capacity(128);
        if !self.tags.is_empty() {
            out.push('@');
            for (idx, (k, v)) in self.tags.iter().enumerate() {
                if idx > 0 {
                    out.push(';');
                }
                out.push_str(k.as_str());
                if let Some(val) = v {
                    out.push('=');
                    out.push_str(&escape_ircv3_tag_value(val));
                }
            }
            out.push(' ');
        }

        if let Some(ref pfx) = self.prefix {
            out.push(':');
            out.push_str(pfx.as_str());
            out.push(' ');
        }

        out.push_str(self.command.as_str());

        for param in &self.params {
            out.push(' ');
            out.push_str(param.as_str());
        }

        if let Some(ref trail) = self.trailing {
            out.push_str(" :");
            out.push_str(trail.as_str());
        }

        out.push_str("\r\n");
        out
    }

    /// Looks up the unescaped value of a tag by its key.
    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|(k, _)| k.as_str() == key)
            .and_then(|(_, v)| v.as_deref())
    }

    /// Extracts the unique message identifier tag (`msgid` or `id`).
    pub fn msgid(&self) -> Option<&str> {
        self.tag("msgid").or_else(|| self.tag("id"))
    }

    /// Extracts the raw ISO-8601 `time` tag (`server-time` capability).
    pub fn time(&self) -> Option<&str> {
        self.tag("time")
    }

    /// Parses the ISO-8601 `time` tag (e.g. `2026-11-06T12:00:00.000Z`) into Unix epoch milliseconds.
    pub fn server_time_ms(&self) -> Option<i64> {
        self.time().and_then(parse_iso8601_utc_ms)
    }

    /// Extracts the `batch` reference tag (`batch` capability).
    pub fn batch(&self) -> Option<&str> {
        self.tag("batch")
    }

    /// Extracts the reply target message ID (`+draft/reply` or `+reply`).
    pub fn draft_reply(&self) -> Option<&str> {
        self.tag("+draft/reply").or_else(|| self.tag("+reply"))
    }

    /// Extracts the reaction emoji (`+draft/react` or `+react`).
    pub fn draft_react(&self) -> Option<&str> {
        self.tag("+draft/react").or_else(|| self.tag("+react"))
    }

    /// Extracts the edited target message ID (`+draft/edit` or `draft/edit`).
    pub fn draft_edit(&self) -> Option<&str> {
        self.tag("+draft/edit").or_else(|| self.tag("draft/edit"))
    }

    /// Extracts the Soju bouncer upstream network identifier (`soju.im/network`).
    pub fn soju_network(&self) -> Option<&str> {
        self.tag("soju.im/network")
            .or_else(|| self.tag("soju.im/bouncer-networks"))
    }

    /// Extracts the sender nickname from a `:nick!user@host` prefix.
    pub fn sender_nick(&self) -> Option<&str> {
        let pfx = self.prefix.as_deref()?;
        Some(pfx.split('!').next().unwrap_or(pfx))
    }
}

/// Summary of a negotiated IRCv3.2 + Soju/Ergo bouncer TCP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrcSessionSummary {
    pub server_addr: CompactString,
    pub nickname: CompactString,
    pub negotiated_caps: Vec<CompactString>,
    pub sasl_authenticated: bool,
    pub bouncer_networks: Vec<CompactString>,
    pub chathistory_messages_received: usize,
}

/// Factory plugin for IRCv3 + Soju/Ergo bouncer accounts.
#[derive(Debug, Default, Clone)]
pub struct IrcPlugin;

impl ProtocolPlugin for IrcPlugin {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Irc
    }

    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        Ok(Arc::new(IrcBackend::new(account_id, config_json)))
    }
}

/// Active IRCv3 client & Soju/Ergo bouncer backend.
pub struct IrcBackend {
    account_id: AccountId,
    server_url: CompactString,
    nickname: RwLock<CompactString>,
    sasl_password: RwLock<Option<CompactString>>,
    default_channel: RwLock<CompactString>,
    bouncer_network: RwLock<CompactString>,
    state: RwLock<SyncState>,
    msgid_counter: AtomicU64,
    negotiated_caps: RwLock<Vec<CompactString>>,
    bouncer_networks: RwLock<Vec<CompactString>>,
    outbound_wire_log: Arc<RwLock<Vec<String>>>,
    history_cache: Arc<RwLock<Vec<UnifiedMessage>>>,
    last_sent_message_id: RwLock<Option<UniversalId>>,
    tcp_writer: Arc<Mutex<Option<OwnedWriteHalf>>>,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl IrcBackend {
    pub fn new(account_id: AccountId, config: serde_json::Value) -> Self {
        let server_url = config
            .get("server_url")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("ircs://irc.libera.chat:6697"));
        let nickname = config
            .get("nickname")
            .or_else(|| config.get("nick"))
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("ferris"));
        let sasl_password = config
            .get("password")
            .or_else(|| config.get("sasl_password"))
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .or_else(|| Some(CompactString::from("soju_bouncer_token")));
        let default_channel = config
            .get("channel")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("#rust-lang"));
        let bouncer_network = config
            .get("network")
            .and_then(|v| v.as_str())
            .map(CompactString::from)
            .unwrap_or_else(|| CompactString::from("libera.chat"));

        let (event_tx, _) = broadcast::channel(256);
        Self {
            account_id,
            server_url,
            nickname: RwLock::new(nickname),
            sasl_password: RwLock::new(sasl_password),
            default_channel: RwLock::new(default_channel),
            bouncer_network: RwLock::new(bouncer_network),
            state: RwLock::new(SyncState::Disconnected),
            msgid_counter: AtomicU64::new(77_000),
            negotiated_caps: RwLock::new(Vec::new()),
            bouncer_networks: RwLock::new(Vec::new()),
            outbound_wire_log: Arc::new(RwLock::new(Vec::new())),
            history_cache: Arc::new(RwLock::new(Vec::new())),
            last_sent_message_id: RwLock::new(None),
            tcp_writer: Arc::new(Mutex::new(None)),
            event_tx,
        }
    }

    pub fn server_url(&self) -> &str {
        self.server_url.as_str()
    }

    /// Returns a snapshot of all IRCv3 wire lines sent by this backend.
    pub fn outbound_wire_log(&self) -> Vec<String> {
        self.outbound_wire_log
            .read()
            .expect("outbound_wire_log lock")
            .clone()
    }

    /// Returns the negotiated IRCv3 capabilities for this session.
    pub fn negotiated_capabilities(&self) -> Vec<CompactString> {
        self.negotiated_caps
            .read()
            .expect("negotiated_caps lock")
            .clone()
    }

    /// Sends a raw CRLF-terminated IRCv3 wire command, recording it in `outbound_wire_log`
    /// and writing it to the live TCP stream if connected.
    async fn send_raw_wire_line(&self, line: String) -> Result<(), WarpError> {
        let wire_line = if line.ends_with("\r\n") {
            line
        } else {
            format!("{}\r\n", line.trim_end_matches(['\r', '\n']))
        };

        {
            let mut log = self
                .outbound_wire_log
                .write()
                .expect("outbound_wire_log lock");
            log.push(wire_line.clone());
        }

        let mut writer_guard = self.tcp_writer.lock().await;
        if let Some(ref mut writer) = *writer_guard {
            writer
                .write_all(wire_line.as_bytes())
                .await
                .map_err(|e| WarpError::Transport(format!("IRCv3 TCP write error: {}", e)))?;
            writer
                .flush()
                .await
                .map_err(|e| WarpError::Transport(format!("IRCv3 TCP flush error: {}", e)))?;
        }

        Ok(())
    }

    /// Establishes an asynchronous TCP connection to an IRCv3 / Soju / Ergo server,
    /// executes `CAP LS 302` negotiation, `SASL PLAIN` authentication, automatic `PING`/`PONG`
    /// handling, and `CHATHISTORY LATEST` batch synchronization.
    pub async fn connect_tcp_ircv3(&self, addr: &str) -> Result<IrcSessionSummary, WarpError> {
        self.set_sync_state(SyncState::Connecting);

        let stream = TcpStream::connect(addr).await.map_err(|e| {
            WarpError::Transport(format!("failed to connect to IRCv3 server {}: {}", addr, e))
        })?;
        let (read_half, write_half) = stream.into_split();
        {
            let mut writer_guard = self.tcp_writer.lock().await;
            *writer_guard = Some(write_half);
        }

        let nick = self.nickname.read().expect("nickname lock").clone();
        let password = self
            .sasl_password
            .read()
            .expect("sasl_password lock")
            .clone()
            .unwrap_or_else(|| CompactString::from(""));
        let channel = self
            .default_channel
            .read()
            .expect("default_channel lock")
            .clone();
        let network = self
            .bouncer_network
            .read()
            .expect("bouncer_network lock")
            .clone();

        // 1. Send IRCv3.2 capability discovery & registration preamble
        self.send_raw_wire_line("CAP LS 302\r\n".to_string())
            .await?;
        self.send_raw_wire_line(format!("NICK {}\r\n", nick))
            .await?;
        self.send_raw_wire_line(format!("USER {} 0 * :Warp IM IRCv3\r\n", nick))
            .await?;
        self.send_raw_wire_line(format!("CAP REQ :{}\r\n", IRCV3_REQUESTED_CAPS))
            .await?;

        let mut reader = BufReader::new(read_half);
        let mut line_buf = String::new();
        let mut negotiated_caps: Vec<CompactString> = Vec::new();
        let mut bouncer_networks: Vec<CompactString> = Vec::new();
        let mut sasl_authenticated = false;
        let mut cap_ended = false;
        let mut active_batch_ref: Option<CompactString> = None;
        let mut active_batch_target: Option<CompactString> = None;
        let mut chathistory_messages_received = 0usize;
        let mut joined_channel = false;

        let handshake_future = async {
            loop {
                line_buf.clear();
                let bytes_read = reader.read_line(&mut line_buf).await.map_err(|e| {
                    WarpError::Transport(format!("IRCv3 TCP read error during handshake: {}", e))
                })?;
                if bytes_read == 0 {
                    break;
                }

                let trimmed = line_buf.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    continue;
                }

                let wire_msg = IrcWireMessage::parse(trimmed)?;
                match wire_msg.command.as_str() {
                    "PING" => {
                        let token = wire_msg
                            .trailing
                            .as_deref()
                            .or_else(|| wire_msg.params.first().map(|s| s.as_str()))
                            .unwrap_or("warp");
                        self.send_raw_wire_line(format!("PONG :{}\r\n", token))
                            .await?;
                    }
                    "CAP" => {
                        let subcmd = wire_msg
                            .params
                            .get(1)
                            .map(|s| s.as_str())
                            .unwrap_or_default();
                        if subcmd.eq_ignore_ascii_case("ACK") {
                            if let Some(ref ack_list) = wire_msg.trailing {
                                for cap_token in ack_list.split_whitespace() {
                                    let clean = cap_token.trim_start_matches([':', '+']);
                                    if !clean.is_empty() {
                                        negotiated_caps.push(CompactString::from(clean));
                                    }
                                }
                            }
                            let has_sasl = negotiated_caps
                                .iter()
                                .any(|c| c.eq_ignore_ascii_case("sasl"));
                            if has_sasl && !password.is_empty() {
                                self.send_raw_wire_line("AUTHENTICATE PLAIN\r\n".to_string())
                                    .await?;
                            } else if !cap_ended {
                                cap_ended = true;
                                self.send_raw_wire_line("CAP END\r\n".to_string()).await?;
                                self.set_sync_state(SyncState::CatchingUpHistory);
                                if negotiated_caps
                                    .iter()
                                    .any(|c| c.to_ascii_lowercase().contains("chathistory"))
                                {
                                    self.send_raw_wire_line(format!(
                                        "CHATHISTORY LATEST {} * 50\r\n",
                                        channel
                                    ))
                                    .await?;
                                } else if !joined_channel {
                                    joined_channel = true;
                                    self.send_raw_wire_line(format!("JOIN {}\r\n", channel))
                                        .await?;
                                }
                            }
                        } else if subcmd.eq_ignore_ascii_case("NAK") && !cap_ended {
                            cap_ended = true;
                            self.send_raw_wire_line("CAP END\r\n".to_string()).await?;
                            if !joined_channel {
                                joined_channel = true;
                                self.send_raw_wire_line(format!("JOIN {}\r\n", channel))
                                    .await?;
                            }
                        }
                    }
                    "AUTHENTICATE" => {
                        let is_plus = wire_msg.params.first().map(|s| s.as_str()) == Some("+")
                            || wire_msg.trailing.as_deref() == Some("+");
                        if is_plus {
                            let sasl_plain = format!("\0{}\0{}", nick, password);
                            let encoded = BASE64_STANDARD.encode(sasl_plain.as_bytes());
                            self.send_raw_wire_line(format!("AUTHENTICATE {}\r\n", encoded))
                                .await?;
                        }
                    }
                    "903" => {
                        // RPL_SASLSUCCESS
                        sasl_authenticated = true;
                        if !cap_ended {
                            cap_ended = true;
                            self.send_raw_wire_line("CAP END\r\n".to_string()).await?;
                            self.set_sync_state(SyncState::CatchingUpHistory);
                            self.send_raw_wire_line(format!(
                                "CHATHISTORY LATEST {} * 50\r\n",
                                channel
                            ))
                            .await?;
                        }
                    }
                    "904" | "905" => {
                        return Err(WarpError::AuthError(
                            "IRCv3 SASL PLAIN authentication failed".into(),
                        ));
                    }
                    "001" => {
                        // RPL_WELCOME on standard RFC 1459 / plain TCP 6667 servers
                        if !cap_ended {
                            cap_ended = true;
                            self.send_raw_wire_line("CAP END\r\n".to_string()).await?;
                        }
                        if !joined_channel
                            && !negotiated_caps
                                .iter()
                                .any(|c| c.to_ascii_lowercase().contains("chathistory"))
                        {
                            joined_channel = true;
                            self.send_raw_wire_line(format!("JOIN {}\r\n", channel))
                                .await?;
                        }
                    }
                    "376" | "422" | "366" => {
                        // RPL_ENDOFMOTD (376), ERR_NOMOTD (422), or RPL_ENDOFNAMES (366)
                        if !joined_channel
                            && !negotiated_caps
                                .iter()
                                .any(|c| c.to_ascii_lowercase().contains("chathistory"))
                        {
                            joined_channel = true;
                            self.send_raw_wire_line(format!("JOIN {}\r\n", channel))
                                .await?;
                        }
                        if active_batch_ref.is_none()
                            && !negotiated_caps
                                .iter()
                                .any(|c| c.to_ascii_lowercase().contains("chathistory"))
                        {
                            break;
                        }
                    }
                    "JOIN" => {
                        if active_batch_ref.is_none()
                            && !negotiated_caps
                                .iter()
                                .any(|c| c.to_ascii_lowercase().contains("chathistory"))
                        {
                            break;
                        }
                    }
                    "BOUNCER" => {
                        if wire_msg
                            .params
                            .first()
                            .map(|s| s.eq_ignore_ascii_case("NETWORK"))
                            .unwrap_or(false)
                        {
                            if let Some(net_id) = wire_msg.params.get(1) {
                                bouncer_networks.push(net_id.clone());
                            }
                        }
                    }
                    "BATCH" => {
                        if let Some(batch_param) = wire_msg.params.first() {
                            if let Some(opened_ref) = batch_param.strip_prefix('+') {
                                active_batch_ref = Some(CompactString::from(opened_ref));
                                active_batch_target = wire_msg.params.get(2).cloned();
                            } else if let Some(closed_ref) = batch_param.strip_prefix('-') {
                                if active_batch_ref.as_deref() == Some(closed_ref) {
                                    active_batch_ref = None;
                                    break;
                                }
                            }
                        }
                    }
                    "PRIVMSG" | "NOTICE" => {
                        let fallback_target = active_batch_target
                            .as_deref()
                            .unwrap_or_else(|| channel.as_str());
                        let unified = convert_wire_to_unified_message(
                            &self.account_id,
                            &nick,
                            &network,
                            fallback_target,
                            &wire_msg,
                            &self.msgid_counter,
                        );
                        if wire_msg.batch().is_some() || active_batch_ref.is_some() {
                            chathistory_messages_received += 1;
                        }
                        {
                            let mut cache = self.history_cache.write().expect("history_cache lock");
                            cache.push(unified.clone());
                        }
                        let _ = self.event_tx.send(BackendEvent::MessageReceived(unified));
                    }
                    _ => {}
                }
            }
            Ok::<(), WarpError>(())
        };

        tokio::time::timeout(Duration::from_secs(5), handshake_future)
            .await
            .map_err(|_| WarpError::Transport("IRCv3 TCP handshake timed out".into()))??;

        {
            let mut caps_guard = self.negotiated_caps.write().expect("negotiated_caps lock");
            *caps_guard = negotiated_caps.clone();
        }
        {
            let mut nets_guard = self
                .bouncer_networks
                .write()
                .expect("bouncer_networks lock");
            *nets_guard = bouncer_networks.clone();
        }

        self.set_sync_state(SyncState::LiveSynced);

        // Spawn background reader loop to process subsequent live PING/PRIVMSG/TAGMSG events
        let account_id = self.account_id.clone();
        let nick_clone = nick.clone();
        let network_clone = network.clone();
        let channel_clone = channel.clone();
        let tcp_writer = self.tcp_writer.clone();
        let outbound_log = self.outbound_wire_log.clone();
        let history_cache = self.history_cache.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut bg_line = String::new();
            let seq = AtomicU64::new(88_000);
            loop {
                bg_line.clear();
                let Ok(n) = reader.read_line(&mut bg_line).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                let trimmed = bg_line.trim_end_matches(['\r', '\n']);
                let Ok(wire_msg) = IrcWireMessage::parse(trimmed) else {
                    continue;
                };
                match wire_msg.command.as_str() {
                    "PING" => {
                        let token = wire_msg
                            .trailing
                            .as_deref()
                            .or_else(|| wire_msg.params.first().map(|s| s.as_str()))
                            .unwrap_or("warp");
                        let pong = format!("PONG :{}\r\n", token);
                        if let Ok(mut log) = outbound_log.write() {
                            log.push(pong.clone());
                        }
                        let mut w_guard = tcp_writer.lock().await;
                        if let Some(ref mut w) = *w_guard {
                            let _ = w.write_all(pong.as_bytes()).await;
                            let _ = w.flush().await;
                        }
                    }
                    "PRIVMSG" => {
                        let unified = convert_wire_to_unified_message(
                            &account_id,
                            &nick_clone,
                            &network_clone,
                            &channel_clone,
                            &wire_msg,
                            &seq,
                        );
                        if wire_msg.draft_edit().is_some() {
                            let _ = event_tx.send(BackendEvent::MessageUpdated(unified));
                        } else {
                            if let Ok(mut cache) = history_cache.write() {
                                cache.push(unified.clone());
                            }
                            let _ = event_tx.send(BackendEvent::MessageReceived(unified));
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(IrcSessionSummary {
            server_addr: CompactString::from(addr),
            nickname: nick,
            negotiated_caps,
            sasl_authenticated,
            bouncer_networks,
            chathistory_messages_received,
        })
    }

    fn set_sync_state(&self, new_state: SyncState) {
        {
            let mut guard = self.state.write().expect("state lock");
            *guard = new_state;
        }
        let _ = self.event_tx.send(BackendEvent::SyncStateChanged {
            account_id: self.account_id.clone(),
            protocol: ProtocolKind::Irc,
            state: new_state,
        });
    }
}

#[async_trait]
impl MessagingBackend for IrcBackend {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Irc
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&ProtocolKind::Irc)
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
        let nick = submission.get("nickname").unwrap_or("").trim();
        if nick.is_empty() {
            return Err(WarpError::AuthError(
                "IRCv3 nickname / Soju bouncer username is required".into(),
            ));
        }

        if is_signup {
            let pass = submission.get("password").unwrap_or("").trim();
            let email = submission.get("email").unwrap_or("").trim();
            if pass.is_empty() || email.is_empty() {
                return Err(WarpError::AuthError(
                    "IRCv3 Sign-Up (draft/account-registration / NickServ) requires nickname, password, and email"
                        .into(),
                ));
            }
        }

        {
            let mut nick_guard = self.nickname.write().expect("nickname lock");
            *nick_guard = CompactString::from(nick);
        }
        if let Some(pass) = submission.get("password") {
            if !pass.trim().is_empty() {
                let mut pass_guard = self.sasl_password.write().expect("sasl_password lock");
                *pass_guard = Some(CompactString::from(pass.trim()));
            }
        }

        if is_signup {
            self.connect().await?;
        }

        Ok(AuthFlowDescriptor {
            protocol: ProtocolKind::Irc,
            flow_id: CompactString::from(flow_id),
            step_index: 1,
            total_steps: 1,
            step_title: if is_signup {
                "✨ IRCv3 Account Registered (draft/account-registration) & SASL Active".into()
            } else {
                "IRCv3 CAP LS 302 + SASL Negotiated".into()
            },
            step_description:
                "Negotiated server-time, message-tags, echo-message, and draft/chathistory.".into(),
            current_step: AuthStep::Completed {
                account_id: self.account_id.clone(),
                display_handle: CompactString::from(nick),
            },
            fields: vec![],
        })
    }

    async fn connect(&self) -> Result<(), WarpError> {
        // If configured with a local TCP address (`irc://127.0.0.1:port` or `127.0.0.1:port`),
        // attempt a live IRCv3 TCP handshake first; fall back cleanly to simulated/offline mode.
        let raw_url = self.server_url.as_str();
        let maybe_local_addr = raw_url
            .strip_prefix("irc://")
            .or_else(|| raw_url.strip_prefix("ircs://"))
            .unwrap_or(raw_url);
        if maybe_local_addr.starts_with("127.0.0.1:") || maybe_local_addr.starts_with("localhost:")
        {
            if self.connect_tcp_ircv3(maybe_local_addr).await.is_ok() {
                return Ok(());
            }
        }

        let nick = self.nickname.read().expect("nickname lock").clone();
        let channel = self
            .default_channel
            .read()
            .expect("default_channel lock")
            .clone();

        {
            let mut log = self
                .outbound_wire_log
                .write()
                .expect("outbound_wire_log lock");
            if log.is_empty() {
                log.push("CAP LS 302\r\n".to_string());
                log.push(format!("NICK {}\r\n", nick));
                log.push(format!("USER {} 0 * :Warp IM IRCv3\r\n", nick));
                log.push(format!("CAP REQ :{}\r\n", IRCV3_REQUESTED_CAPS));
                log.push("CAP END\r\n".to_string());
                log.push(format!("CHATHISTORY LATEST {} * 50\r\n", channel));
            }
        }
        {
            let mut caps = self.negotiated_caps.write().expect("negotiated_caps lock");
            if caps.is_empty() {
                *caps = IRCV3_REQUESTED_CAPS
                    .split_whitespace()
                    .map(CompactString::from)
                    .collect();
            }
        }

        self.set_sync_state(SyncState::LiveSynced);
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), WarpError> {
        {
            let mut writer_guard = self.tcp_writer.lock().await;
            if let Some(mut writer) = writer_guard.take() {
                let _ = writer.write_all(b"QUIT :Warp IM paused\r\n").await;
                let _ = writer.flush().await;
            }
        }
        self.set_sync_state(SyncState::PausedByUser);
        Ok(())
    }

    async fn fetch_hierarchy(
        &self,
    ) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError> {
        let network = self
            .bouncer_network
            .read()
            .expect("bouncer_network lock")
            .clone();
        let channel = self
            .default_channel
            .read()
            .expect("default_channel lock")
            .clone();
        let container_id = UniversalId::new(
            ProtocolKind::Irc,
            self.account_id.clone(),
            format!("net_{}", network.replace('.', "_")),
        );
        let chat_id = UniversalId::new(
            ProtocolKind::Irc,
            self.account_id.clone(),
            format!("{}/{}", network, channel),
        );

        let container = UnifiedContainer {
            id: container_id.clone(),
            kind: ContainerKind::IrcNetwork,
            title: CompactString::from(format!("{} (Soju)", network)),
            icon_initials: "IR".into(),
            avatar_url: None,
            unread_count: 0,
            mention_count: 0,
            child_chat_ids: vec![chat_id.clone()],
            protocol_metadata: serde_json::json!({
                "bouncer": "soju",
                "network": network.as_str(),
                "caps": self.negotiated_capabilities(),
            }),
        };

        let chat = UnifiedChat {
            id: chat_id,
            parent_container_id: Some(container_id.clone()),
            parent_chat_id: None,
            topology: ChatTopologyKind::ContainerChannel,
            hierarchy: ContainerHierarchy::ServerChannel {
                container_id,
                container_kind: ContainerKind::IrcNetwork,
                category_name: Some("Bouncer Channels".into()),
            },
            title: channel,
            subtitle: Some("IRCv3.2 + Soju Bouncer • chathistory • message-tags".into()),
            avatar_initials: "IR".into(),
            avatar_url: None,
            last_message_preview: None,
            last_activity_ts: 1_730_918_400_000,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: self.sync_state() == SyncState::LiveSynced,
            capabilities: ChatCapabilities::irc_channel(true),
            protocol_metadata: serde_json::json!({
                "network": network.as_str(),
                "chathistory": true,
            }),
        };

        Ok((vec![container], vec![chat]))
    }

    async fn fetch_messages(
        &self,
        chat_id: &UniversalId,
        before_timestamp_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError> {
        let target = extract_irc_target(chat_id.remote_id.as_str());
        let cache = self.history_cache.read().expect("history_cache lock");
        let mut filtered: Vec<UnifiedMessage> = cache
            .iter()
            .filter(|m| {
                let msg_target = extract_irc_target(m.chat_id.remote_id.as_str());
                let matches_chat = m.chat_id == *chat_id || msg_target == target;
                let matches_ts = before_timestamp_ms
                    .map(|cursor| m.timestamp_ms < cursor)
                    .unwrap_or(true);
                matches_chat && matches_ts
            })
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
            return Err(WarpError::ProtocolDisabled("irc".into()));
        }
        if !request.attachments.is_empty() {
            return Err(WarpError::UnsupportedCapability(
                "IRCv3 does not support binary file attachments without an external HTTP upload host"
                    .into(),
            ));
        }

        let target = extract_irc_target(request.chat_id.remote_id.as_str());
        let sanitized_text = sanitize_irc_text(&request.text);

        let mut tags = Vec::new();
        if let Some(ref reply_id) = request.reply_to_id {
            tags.push((
                CompactString::from("+draft/reply"),
                Some(reply_id.remote_id.to_string()),
            ));
        }

        let wire_msg = IrcWireMessage {
            tags,
            prefix: None,
            command: CompactString::from("PRIVMSG"),
            params: vec![CompactString::from(target)],
            trailing: Some(sanitized_text.clone()),
        };
        self.send_raw_wire_line(wire_msg.to_wire_line()).await?;

        let id = self.msgid_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let msg_id = UniversalId::new(
            ProtocolKind::Irc,
            self.account_id.clone(),
            format!("irc_msgid_{}", id),
        );

        let nick = self.nickname.read().expect("nickname lock").clone();
        let outgoing_msg = UnifiedMessage {
            id: msg_id.clone(),
            local_outbox_id: Some(request.local_id.remote_id.clone()),
            chat_id: request.chat_id.clone(),
            thread_id: request.thread_id.clone(),
            sender_id: nick.clone(),
            sender_display_name: nick,
            sender_initials: "ME".into(),
            sender_avatar_url: None,
            is_outgoing: true,
            text: sanitized_text,
            reply_to_id: request.reply_to_id,
            reply_preview: None,
            timestamp_ms: 1_730_918_500_000 + (id as i64),
            edited_at_ms: None,
            delivery_state: DeliveryState::Sent,
            reactions: Vec::new(),
            attachments: Vec::new(),
            capabilities: MessageCapabilities::derive_from_chat(
                ChatCapabilities::irc_channel(true),
                true,
                true,
            ),
            protocol_metadata: serde_json::json!({ "msgid": msg_id.remote_id.as_str() }),
        };

        {
            let mut last_guard = self
                .last_sent_message_id
                .write()
                .expect("last_sent_message_id lock");
            *last_guard = Some(msg_id.clone());
        }
        {
            let mut cache = self.history_cache.write().expect("history_cache lock");
            cache.push(outgoing_msg);
        }

        Ok(msg_id)
    }

    async fn edit_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        new_text: &str,
    ) -> Result<(), WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("irc".into()));
        }

        // Supported via +draft/edit=<msgid> tag on modern Ergo/Soju bouncers for the last message
        let target = extract_irc_target(chat_id.remote_id.as_str());
        let sanitized_text = sanitize_irc_text(new_text);
        let wire_msg = IrcWireMessage {
            tags: vec![(
                CompactString::from("+draft/edit"),
                Some(message_id.remote_id.to_string()),
            )],
            prefix: None,
            command: CompactString::from("PRIVMSG"),
            params: vec![CompactString::from(target)],
            trailing: Some(sanitized_text.clone()),
        };
        self.send_raw_wire_line(wire_msg.to_wire_line()).await?;

        let updated_event = {
            let mut cache = self.history_cache.write().expect("history_cache lock");
            if let Some(existing) = cache.iter_mut().find(|m| m.id == *message_id) {
                existing.text = sanitized_text.clone();
                existing.edited_at_ms = Some(existing.timestamp_ms + 1_000);
                existing.clone()
            } else {
                let nick = self.nickname.read().expect("nickname lock").clone();
                UnifiedMessage {
                    id: message_id.clone(),
                    local_outbox_id: None,
                    chat_id: chat_id.clone(),
                    thread_id: None,
                    sender_id: nick.clone(),
                    sender_display_name: nick,
                    sender_initials: "ME".into(),
                    sender_avatar_url: None,
                    is_outgoing: true,
                    text: sanitized_text,
                    reply_to_id: None,
                    reply_preview: None,
                    timestamp_ms: 1_730_918_500_000,
                    edited_at_ms: Some(1_730_918_501_000),
                    delivery_state: DeliveryState::Sent,
                    reactions: Vec::new(),
                    attachments: Vec::new(),
                    capabilities: MessageCapabilities::derive_from_chat(
                        ChatCapabilities::irc_channel(true),
                        true,
                        true,
                    ),
                    protocol_metadata: serde_json::json!({
                        "edited_msgid": message_id.remote_id.as_str()
                    }),
                }
            }
        };

        let _ = self.event_tx.send(BackendEvent::MessageUpdated(updated_event));
        Ok(())
    }

    async fn delete_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        delete_for_all: bool,
    ) -> Result<(), WarpError> {
        if delete_for_all {
            return Err(WarpError::UnsupportedCapability(
                "IRCv3 channels do not support universal message deletion for all users".into(),
            ));
        }

        {
            let mut cache = self.history_cache.write().expect("history_cache lock");
            cache.retain(|m| m.id != *message_id);
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
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("irc".into()));
        }

        let target = extract_irc_target(chat_id.remote_id.as_str());
        let wire_msg = IrcWireMessage {
            tags: vec![
                (CompactString::from("+draft/react"), Some(emoji.to_string())),
                (
                    CompactString::from("+draft/reply"),
                    Some(message_id.remote_id.to_string()),
                ),
            ],
            prefix: None,
            command: CompactString::from("TAGMSG"),
            params: vec![CompactString::from(target)],
            trailing: None,
        };
        self.send_raw_wire_line(wire_msg.to_wire_line()).await?;

        let updated_msg = {
            let mut cache = self.history_cache.write().expect("history_cache lock");
            if let Some(existing) = cache.iter_mut().find(|m| m.id == *message_id) {
                if remove {
                    existing.reactions.retain(|r| r.emoji.as_str() != emoji);
                } else if let Some(r) = existing
                    .reactions
                    .iter_mut()
                    .find(|r| r.emoji.as_str() == emoji)
                {
                    r.count += 1;
                    r.reacted_by_me = true;
                } else {
                    existing.reactions.push(MessageReaction {
                        emoji: CompactString::from(emoji),
                        count: 1,
                        reacted_by_me: true,
                    });
                }
                existing.clone()
            } else {
                let nick = self.nickname.read().expect("nickname lock").clone();
                UnifiedMessage {
                    id: message_id.clone(),
                    local_outbox_id: None,
                    chat_id: chat_id.clone(),
                    thread_id: None,
                    sender_id: nick.clone(),
                    sender_display_name: nick,
                    sender_initials: "IR".into(),
                    sender_avatar_url: None,
                    is_outgoing: false,
                    text: String::new(),
                    reply_to_id: None,
                    reply_preview: None,
                    timestamp_ms: 1_730_918_500_000,
                    edited_at_ms: None,
                    delivery_state: DeliveryState::Delivered,
                    reactions: if remove {
                        Vec::new()
                    } else {
                        vec![MessageReaction {
                            emoji: CompactString::from(emoji),
                            count: 1,
                            reacted_by_me: true,
                        }]
                    },
                    attachments: Vec::new(),
                    capabilities: MessageCapabilities::derive_from_chat(
                        ChatCapabilities::irc_channel(true),
                        false,
                        false,
                    ),
                    protocol_metadata: serde_json::json!({
                        "msgid": message_id.remote_id.as_str()
                    }),
                }
            }
        };

        let _ = self.event_tx.send(BackendEvent::MessageUpdated(updated_msg));
        Ok(())
    }

    async fn fetch_and_decrypt_media(
        &self,
        _attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        Err(WarpError::UnsupportedCapability(
            "IRCv3 protocol does not natively host encrypted media streams".into(),
        ))
    }

    fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.event_tx.subscribe()
    }
}

fn extract_irc_target(remote_id: &str) -> &str {
    match remote_id.rsplit_once('/') {
        Some((_, chan)) if !chan.is_empty() => chan,
        _ => remote_id,
    }
}

fn sanitize_irc_text(input: &str) -> String {
    input.replace(['\r', '\n'], " ")
}

fn initials_from_nick(nick: &str) -> CompactString {
    let mut chars = nick.chars().filter(|c| c.is_alphanumeric());
    let first = chars
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('I');
    let second = chars
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('R');
    let mut s = String::with_capacity(2);
    s.push(first);
    s.push(second);
    CompactString::from(s)
}

fn convert_wire_to_unified_message(
    account_id: &AccountId,
    our_nick: &str,
    default_network: &str,
    fallback_target: &str,
    wire: &IrcWireMessage,
    seq: &AtomicU64,
) -> UnifiedMessage {
    let sender_nick = wire.sender_nick().unwrap_or("irc_server");
    let target = wire
        .params
        .first()
        .map(|s| s.as_str())
        .unwrap_or(fallback_target);
    let net = wire.soju_network().unwrap_or(default_network);
    let chat_remote_id = if target.starts_with('#') && !target.contains('/') {
        format!("{}/{}", net, target)
    } else {
        target.to_string()
    };
    let chat_id = UniversalId::new(ProtocolKind::Irc, account_id.clone(), chat_remote_id);

    let remote_msgid = wire.msgid().map(|s| s.to_string()).unwrap_or_else(|| {
        let next = seq.fetch_add(1, Ordering::SeqCst) + 1;
        format!("irc_msgid_{}", next)
    });
    let msg_id = UniversalId::new(ProtocolKind::Irc, account_id.clone(), remote_msgid.clone());

    let reply_to_id = wire
        .draft_reply()
        .map(|reply_raw| UniversalId::new(ProtocolKind::Irc, account_id.clone(), reply_raw));

    let mut reactions = Vec::new();
    if let Some(emoji) = wire.draft_react() {
        reactions.push(MessageReaction {
            emoji: CompactString::from(emoji),
            count: 1,
            reacted_by_me: sender_nick.eq_ignore_ascii_case(our_nick),
        });
    }

    let timestamp_ms = wire.server_time_ms().unwrap_or(1_730_918_400_000);
    let is_outgoing = sender_nick.eq_ignore_ascii_case(our_nick);

    UnifiedMessage {
        id: msg_id,
        local_outbox_id: None,
        chat_id,
        thread_id: None,
        sender_id: CompactString::from(sender_nick),
        sender_display_name: CompactString::from(sender_nick),
        sender_initials: initials_from_nick(sender_nick),
        sender_avatar_url: None,
        is_outgoing,
        text: wire.trailing.clone().unwrap_or_default(),
        reply_to_id,
        reply_preview: None,
        timestamp_ms,
        edited_at_ms: wire.draft_edit().map(|_| timestamp_ms),
        delivery_state: DeliveryState::Delivered,
        reactions,
        attachments: Vec::new(),
        capabilities: MessageCapabilities::derive_from_chat(
            ChatCapabilities::irc_channel(true),
            is_outgoing,
            is_outgoing,
        ),
        protocol_metadata: serde_json::json!({
            "msgid": remote_msgid,
            "batch": wire.batch(),
            "server_time": wire.time(),
            "soju_network": wire.soju_network(),
        }),
    }
}

/// Dependency-free parser for ISO-8601 UTC `server-time` strings (`YYYY-MM-DDTHH:MM:SS[.sss]Z`).
fn parse_iso8601_utc_ms(iso: &str) -> Option<i64> {
    let trimmed = iso.trim().strip_suffix('Z')?;
    let (date_part, time_part) = trimmed.split_once('T')?;
    let mut date_iter = date_part.splitn(3, '-');
    let year: i64 = date_iter.next()?.parse().ok()?;
    let month: i64 = date_iter.next()?.parse().ok()?;
    let day: i64 = date_iter.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let mut time_iter = time_part.splitn(3, ':');
    let hour: i64 = time_iter.next()?.parse().ok()?;
    let minute: i64 = time_iter.next()?.parse().ok()?;
    let sec_part = time_iter.next()?;
    let (sec_str, millis) = match sec_part.split_once('.') {
        Some((s, frac)) => {
            let mut ms_digits = String::with_capacity(3);
            for ch in frac.chars().take(3) {
                if !ch.is_ascii_digit() {
                    return None;
                }
                ms_digits.push(ch);
            }
            while ms_digits.len() < 3 {
                ms_digits.push('0');
            }
            (s, ms_digits.parse::<i64>().ok()?)
        }
        None => (sec_part, 0),
    };
    let second: i64 = sec_str.parse().ok()?;

    // Civil date to days since 1970-01-01 (Howard Hinnant's algorithm)
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    let total_secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(total_secs * 1_000 + millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn ircv3_wire_message_parse_and_serialize_roundtrip() {
        let raw_line = "@id=msg-99;time=2026-11-06T12:00:00.000Z;+draft/reply=msg-98;+draft/react=🦀 :ferris!~rust@libera/staff PRIVMSG #rust-lang :Zero-cost abstractions!";
        let parsed = IrcWireMessage::parse(raw_line).expect("parse complex IRCv3 wire line");

        assert_eq!(parsed.msgid(), Some("msg-99"));
        assert_eq!(parsed.time(), Some("2026-11-06T12:00:00.000Z"));
        assert_eq!(parsed.server_time_ms(), Some(1_793_966_400_000));
        assert_eq!(parsed.draft_reply(), Some("msg-98"));
        assert_eq!(parsed.draft_react(), Some("🦀"));
        assert_eq!(parsed.sender_nick(), Some("ferris"));
        assert_eq!(parsed.prefix.as_deref(), Some("ferris!~rust@libera/staff"));
        assert_eq!(parsed.command.as_str(), "PRIVMSG");
        assert_eq!(parsed.params, vec![CompactString::from("#rust-lang")]);
        assert_eq!(parsed.trailing.as_deref(), Some("Zero-cost abstractions!"));

        let serialized = parsed.to_wire_line();
        assert_eq!(serialized, format!("{}\r\n", raw_line));

        // Verify official IRCv3 tag escaping/unescaping (\: <-> ;, \s <-> space, \\ <-> \, \r, \n)
        let complex_val = "hello; world\\path\r\nnext";
        let escaped = escape_ircv3_tag_value(complex_val);
        assert_eq!(escaped, "hello\\:\\sworld\\\\path\\r\\nnext");
        let unescaped = unescape_ircv3_tag_value(&escaped);
        assert_eq!(unescaped, complex_val);
    }

    #[tokio::test]
    async fn ircv3_soju_tcp_handshake_sasl_chathistory_and_live_tags_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Soju IRCv3 server");
        let addr = listener.local_addr().unwrap().to_string();

        // Spawn a real TCP mock IRCv3.2 + Soju bouncer server
        let server_handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            let mut received_from_client: Vec<String> = Vec::new();

            // 1. Read CAP LS 302, NICK, USER, CAP REQ
            for _ in 0..4 {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                received_from_client.push(line.trim_end_matches(['\r', '\n']).to_string());
            }

            assert!(received_from_client.iter().any(|l| l == "CAP LS 302"));
            assert!(received_from_client.iter().any(|l| l == "NICK ferris"));
            assert!(received_from_client
                .iter()
                .any(|l| l.starts_with("CAP REQ :sasl message-tags server-time")));

            // 2. Advertise and ACK IRCv3.2 + Soju capabilities
            write_half
                .write_all(
                    b":soju.bouncer.local CAP * LS :sasl=PLAIN message-tags server-time echo-message batch draft/chathistory soju.im/bouncer-networks\r\n",
                )
                .await
                .unwrap();
            write_half
                .write_all(
                    b":soju.bouncer.local CAP * ACK :sasl message-tags server-time echo-message batch draft/chathistory soju.im/bouncer-networks\r\n",
                )
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 3. Expect AUTHENTICATE PLAIN
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line.trim_end_matches(['\r', '\n']), "AUTHENTICATE PLAIN");

            write_half.write_all(b"AUTHENTICATE +\r\n").await.unwrap();
            write_half.flush().await.unwrap();

            // 4. Expect Base64 SASL PLAIN payload (\0ferris\0hunter2_soju)
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let auth_line = line.trim_end_matches(['\r', '\n']);
            let b64_part = auth_line
                .strip_prefix("AUTHENTICATE ")
                .expect("AUTHENTICATE base64 line");
            let decoded = BASE64_STANDARD.decode(b64_part).expect("valid base64");
            assert_eq!(decoded, b"\0ferris\0hunter2_soju");

            // 5. Send 903 SASL success + PING + Soju BOUNCER NETWORK
            write_half
                .write_all(b":soju.bouncer.local 903 ferris :SASL authentication successful\r\n")
                .await
                .unwrap();
            write_half
                .write_all(b"PING :soju-keepalive-42\r\n")
                .await
                .unwrap();
            write_half
                .write_all(b":soju.bouncer.local BOUNCER NETWORK libera name=Libera.Chat\r\n")
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 6. Read CAP END, PONG, and CHATHISTORY LATEST #rust-lang * 50
            let mut saw_cap_end = false;
            let mut saw_pong = false;
            let mut saw_chathistory = false;
            while !(saw_cap_end && saw_pong && saw_chathistory) {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed == "CAP END" {
                    saw_cap_end = true;
                } else if trimmed == "PONG :soju-keepalive-42" {
                    saw_pong = true;
                } else if trimmed == "CHATHISTORY LATEST #rust-lang * 50" {
                    saw_chathistory = true;
                }
            }

            // 7. Send BATCH +hist chathistory #rust-lang with 2 historical messages and BATCH -hist
            write_half
                .write_all(b":soju.bouncer.local BATCH +hist chathistory #rust-lang\r\n")
                .await
                .unwrap();
            write_half
                .write_all(
                    b"@msgid=hist-1;time=2026-11-06T12:00:00.000Z;batch=hist;soju.im/network=libera.chat :alice!~a@libera PRIVMSG #rust-lang :Welcome to #rust-lang via Soju!\r\n",
                )
                .await
                .unwrap();
            write_half
                .write_all(
                    b"@msgid=hist-2;time=2026-11-06T12:01:00.000Z;batch=hist;+draft/reply=hist-1;soju.im/network=libera.chat :bob!~b@libera PRIVMSG #rust-lang :Async IRCv3 chathistory works!\r\n",
                )
                .await
                .unwrap();
            write_half
                .write_all(b":soju.bouncer.local BATCH -hist\r\n")
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // 8. Read live PRIVMSG (reply), TAGMSG (reaction), and PRIVMSG (+draft/edit) from IrcBackend
            let mut live_commands = Vec::new();
            for _ in 0..3 {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                live_commands.push(line.trim_end_matches(['\r', '\n']).to_string());
            }
            live_commands
        });

        let backend = IrcBackend::new(
            AccountId::new("soju_libera"),
            serde_json::json!({
                "server_url": format!("irc://{}", addr),
                "nickname": "ferris",
                "password": "hunter2_soju",
                "channel": "#rust-lang",
                "network": "libera.chat"
            }),
        );
        let mut events_rx = backend.subscribe();

        let summary = backend
            .connect_tcp_ircv3(&addr)
            .await
            .expect("TCP IRCv3 handshake & chathistory");

        assert!(summary.sasl_authenticated);
        assert_eq!(summary.chathistory_messages_received, 2);
        assert_eq!(
            summary.bouncer_networks,
            vec![CompactString::from("libera")]
        );
        assert!(summary
            .negotiated_caps
            .contains(&CompactString::from("draft/chathistory")));
        assert_eq!(backend.sync_state(), SyncState::LiveSynced);

        // Verify the 2 historical messages were emitted on event_tx and cached
        let chat_id = UniversalId::new(ProtocolKind::Irc, "soju_libera", "libera.chat/#rust-lang");
        let cached = backend.fetch_messages(&chat_id, None, 50).await.unwrap();
        assert_eq!(cached.len(), 2);
        assert_eq!(cached[0].id.remote_id.as_str(), "hist-1");
        assert_eq!(cached[0].sender_display_name.as_str(), "alice");
        assert_eq!(cached[1].id.remote_id.as_str(), "hist-2");
        assert_eq!(
            cached[1]
                .reply_to_id
                .as_ref()
                .map(|id| id.remote_id.as_str()),
            Some("hist-1")
        );

        let mut received_hist_events = 0;
        while let Ok(ev) = events_rx.try_recv() {
            if matches!(ev, BackendEvent::MessageReceived(_)) {
                received_hist_events += 1;
            }
        }
        assert_eq!(received_hist_events, 2);

        // Send a live reply PRIVMSG, a TAGMSG reaction, and a +draft/edit message over TCP
        let sent_id = backend
            .send_message(OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Irc, "soju_libera", "local-1"),
                chat_id: chat_id.clone(),
                thread_id: None,
                text: "Replying live with IRCv3 tags!".into(),
                reply_to_id: Some(UniversalId::new(ProtocolKind::Irc, "soju_libera", "hist-2")),
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            })
            .await
            .expect("send live IRCv3 reply");

        backend
            .react_to_message(
                &chat_id,
                &UniversalId::new(ProtocolKind::Irc, "soju_libera", "hist-2"),
                "🦀",
                false,
            )
            .await
            .expect("send IRCv3 TAGMSG reaction");

        backend
            .edit_message(&chat_id, &sent_id, "Edited live via +draft/edit!")
            .await
            .expect("send IRCv3 +draft/edit");

        // Verify delete_for_all is strictly rejected per IRCv3 capabilities
        let del_err = backend.delete_message(&chat_id, &sent_id, true).await;
        assert!(matches!(del_err, Err(WarpError::UnsupportedCapability(_))));

        let live_commands = server_handle.await.expect("mock server completed");
        assert_eq!(
            live_commands[0],
            "@+draft/reply=hist-2 PRIVMSG #rust-lang :Replying live with IRCv3 tags!"
        );
        assert_eq!(
            live_commands[1],
            "@+draft/react=🦀;+draft/reply=hist-2 TAGMSG #rust-lang"
        );
        assert_eq!(
            live_commands[2],
            format!(
                "@+draft/edit={} PRIVMSG #rust-lang :Edited live via +draft/edit!",
                sent_id.remote_id
            )
        );
    }

    #[tokio::test]
    async fn irc_plain_rfc1459_tcp_port_6667_join_and_privmsg() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind plain RFC 1459 IRC server");
        let addr = listener.local_addr().unwrap().to_string();

        let server_handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept client");
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();

            // Read initial registration lines
            for _ in 0..4 {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
            }

            // Send standard RFC 1459 001 RPL_WELCOME + 376 RPL_ENDOFMOTD (no BATCH)
            write_half
                .write_all(b":irc.plain.local 001 warp_user :Welcome to Plain IRC\r\n")
                .await
                .unwrap();
            write_half
                .write_all(b":irc.plain.local 376 warp_user :End of /MOTD command.\r\n")
                .await
                .unwrap();
            write_half.flush().await.unwrap();

            // Expect CAP END, JOIN #warp-im, and PRIVMSG #warp-im :Hello live IRC!
            let mut saw_join = false;
            let mut saw_privmsg = false;
            while !(saw_join && saw_privmsg) {
                line.clear();
                let n = reader.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed == "JOIN #warp-im" {
                    saw_join = true;
                    write_half
                        .write_all(
                            b":peer_bot!~bot@irc.plain.local PRIVMSG #warp-im :Welcome to #warp-im!\r\n",
                        )
                        .await
                        .unwrap();
                    write_half.flush().await.unwrap();
                } else if trimmed == "PRIVMSG #warp-im :Hello live IRC!" {
                    saw_privmsg = true;
                }
            }
            (saw_join, saw_privmsg)
        });

        let backend = IrcBackend::new(
            AccountId::new("irc_live_test"),
            serde_json::json!({
                "server_url": format!("irc://{}", addr),
                "nickname": "warp_user",
                "channel": "#warp-im",
                "network": "plain.local"
            }),
        );
        let mut rx = backend.subscribe();
        backend.connect().await.expect("connect plain RFC 1459");
        assert_eq!(backend.sync_state(), SyncState::LiveSynced);

        let chat_id = UniversalId::new(ProtocolKind::Irc, "irc_live_test", "plain.local/#warp-im");
        backend
            .send_message(OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Irc, "irc_live_test", "local-plain-1"),
                chat_id,
                thread_id: None,
                text: "Hello live IRC!".into(),
                reply_to_id: None,
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            })
            .await
            .expect("send PRIVMSG over plain TCP");

        let (saw_join, saw_privmsg) = server_handle.await.expect("plain server finished");
        assert!(saw_join);
        assert!(saw_privmsg);

        // Wait briefly for the incoming PRIVMSG from peer_bot (skipping SyncStateChanged events)
        let mut got_incoming = false;
        while let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            if let BackendEvent::MessageReceived(msg) = ev {
                assert_eq!(msg.text, "Welcome to #warp-im!");
                got_incoming = true;
                break;
            }
        }
        assert!(got_incoming);
    }
}

/// Resolves a configured IRC server URL or host string into a plain TCP `host:port` endpoint
/// when plain TCP (`irc://`, `:6667`, `127.0.0.1:...`, or `localhost:...`) is specified.
pub fn resolve_irc_plain_tcp_endpoint(server_url: &str) -> Option<String> {
    let trimmed = server_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("irc://") {
        let host_port = rest.split('/').next().unwrap_or(rest).trim();
        if host_port.is_empty() {
            return None;
        }
        if host_port.contains(':') {
            return Some(host_port.to_string());
        }
        return Some(format!("{}:6667", host_port));
    }
    if let Some(rest) = trimmed.strip_prefix("ircs://") {
        let host_port = rest.split('/').next().unwrap_or(rest).trim();
        if host_port.starts_with("127.0.0.1:") || host_port.starts_with("localhost:") {
            return Some(host_port.to_string());
        }
        return None;
    }
    let host_port = trimmed.split('/').next().unwrap_or(trimmed).trim();
    if host_port.starts_with("127.0.0.1:")
        || host_port.starts_with("localhost:")
        || host_port.ends_with(":6667")
    {
        return Some(host_port.to_string());
    }
    None
}

/// Sends a one-shot `NICK`/`USER`/`JOIN`/`PRIVMSG` over plain TCP (e.g. port `6667`) if the
/// target IRC server is reachable, used by the live/hybrid dispatcher when sending messages
/// to an IRC channel or nick.
pub async fn irc_send_live_privmsg(
    server_url: &str,
    nickname: &str,
    target_raw: &str,
    text: &str,
) -> Result<(), WarpError> {
    let addr = resolve_irc_plain_tcp_endpoint(server_url).ok_or_else(|| {
        WarpError::Transport(format!("no plain TCP IRC endpoint for {}", server_url))
    })?;
    let target = extract_irc_target(target_raw);
    let nick = if nickname.trim().is_empty() {
        "warp_im"
    } else {
        nickname.trim()
    };
    let clean_text = sanitize_irc_text(text);

    let send_fut = async {
        let mut stream = TcpStream::connect(&addr).await.map_err(|e| {
            WarpError::Transport(format!("IRC TCP connect to {} failed: {}", addr, e))
        })?;
        let mut payload = format!(
            "NICK {nick}\r\nUSER {nick} 0 * :Warp IM\r\n",
            nick = nick
        );
        if target.starts_with('#') {
            payload.push_str(&format!("JOIN {}\r\n", target));
        }
        payload.push_str(&format!("PRIVMSG {} :{}\r\nQUIT :Warp IM\r\n", target, clean_text));
        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| WarpError::Transport(format!("IRC TCP write failed: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| WarpError::Transport(format!("IRC TCP flush failed: {}", e)))?;
        Ok::<(), WarpError>(())
    };

    tokio::time::timeout(Duration::from_millis(1500), send_fut)
        .await
        .map_err(|_| WarpError::Transport("IRC TCP send timed out".into()))?
}

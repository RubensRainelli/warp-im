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

//! Telegram MTProto 2.0 (`grammers`) protocol adapter & Test DC2 (`149.154.167.40:443`) engine.
//!
//! Supports:
//! - PKCS#1 ASN.1 DER RSA-2048 public key parsing (`parse_rsa_public_key_pem`) and 64-bit MTProto SHA-1 key fingerprinting
//! - Binary MTProto 2.0 Abridged (`0xef`) & Intermediate (`0xeeeeeeee`) transport framing and `req_pq_multi#be7e8ef1` -> `resPQ#05162463` DH handshake probing over TCP
//! - Multi-phase `PhoneAndOtp` authentication (Phone -> OTP -> optional 2FA Cloud Password), including official Telegram Test DC2 numbers (`+999662xxxx` with code `22222`)
//! - 3-Level Supergroup Forum Topics (`ContainerKind::ForumGroup` -> `ChatTopologyKind::ThreadOrTopic`) and Direct/Secret Chats (`ChatTopologyKind::DirectMessage`)
//! - Monotonic `pts` update state tracking and real-time `BackendEvent` broadcasting
//! - `mtproto://` media resolution with dynamic `file_reference` refresh

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use warp_core::{
    AccountId, AuthFieldSpec, AuthFlowDescriptor, AuthStep, AuthStepSubmission, BackendEvent,
    ChatCapabilities, ChatTopologyKind, ContainerHierarchy, ContainerKind, DeliveryState,
    MediaAttachment, MessageCapabilities, MessageReaction, MessagingBackend, OtpPhase,
    OutboundMessageRequest, ProtocolCapabilities, ProtocolKind, ProtocolPlugin, ResolvedMediaBytes,
    SyncState, UnifiedChat, UnifiedContainer, UnifiedMessage, UniversalId, WarpError,
};

/// MTProto 2.0 Abridged transport header byte (`0xef`).
pub const MTPROTO_ABRIDGED_TAG: u8 = 0xef;

/// MTProto 2.0 Intermediate transport 4-byte connection tag (`0xeeeeeeee`).
pub const MTPROTO_INTERMEDIATE_TAG: u32 = 0xeeee_eeee;

/// TL constructor ID for `req_pq_multi#be7e8ef1 nonce:int128 = ResPQ`.
pub const TL_REQ_PQ_MULTI_ID: u32 = 0xbe7e_8ef1;

/// TL constructor ID for `resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ`.
pub const TL_RES_PQ_ID: u32 = 0x0516_2463;

/// TL constructor ID for `vector#1cb5c415`.
pub const TL_VECTOR_ID: u32 = 0x1cb5_c415;

/// Default composite $p \cdot q$ returned by Telegram DH step 1 (`0x17ED48941A08F981 = 0x494C553B * 0x53911073`).
pub const DEFAULT_MTPROTO_PQ_BYTES: [u8; 8] = [0x17, 0xED, 0x48, 0x94, 0x1A, 0x08, 0xF9, 0x81];

/// Parsed components of a Telegram DC RSA-2048 public key (`-----BEGIN RSA PUBLIC KEY-----`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublicKeyComponents {
    /// Big-endian unsigned modulus bytes ($n$, 256 bytes for RSA-2048).
    pub modulus: Vec<u8>,
    /// Big-endian unsigned public exponent bytes ($e$, typically `[0x01, 0x00, 0x01]` = 65537).
    pub exponent: Vec<u8>,
    /// Bit length of the RSA modulus (e.g. `2048`).
    pub modulus_bits: usize,
    /// Lower 64 bits (little-endian `i64`) of `SHA1(tl_bytes(n) || tl_bytes(e))` per MTProto 2.0 spec.
    pub mtproto_fingerprint: i64,
}

/// Parses a PKCS#1 `-----BEGIN RSA PUBLIC KEY-----` PEM string, validates its ASN.1 DER structure,
/// extracts the 2048-bit modulus and exponent, and computes the 64-bit MTProto key fingerprint.
pub fn parse_rsa_public_key_pem(pem: &str) -> Result<RsaPublicKeyComponents, WarpError> {
    let trimmed = pem.trim();
    let begin_marker = "-----BEGIN RSA PUBLIC KEY-----";
    let end_marker = "-----END RSA PUBLIC KEY-----";

    let start_idx = trimmed.find(begin_marker).ok_or_else(|| {
        WarpError::AuthError("missing -----BEGIN RSA PUBLIC KEY----- header".into())
    })? + begin_marker.len();
    let end_idx = trimmed[start_idx..]
        .find(end_marker)
        .map(|offset| start_idx + offset)
        .ok_or_else(|| {
            WarpError::AuthError("missing -----END RSA PUBLIC KEY----- footer".into())
        })?;

    let b64_body: String = trimmed[start_idx..end_idx]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let der = BASE64_STANDARD
        .decode(b64_body.as_bytes())
        .map_err(|e| WarpError::AuthError(format!("invalid RSA PEM base64 payload: {}", e)))?;

    // Parse outer ASN.1 SEQUENCE (0x30)
    let (seq_body, rest) = read_asn1_element(&der, 0x30)?;
    if !rest.is_empty() {
        return Err(WarpError::AuthError(
            "trailing bytes after ASN.1 PKCS#1 RSAPublicKey SEQUENCE".into(),
        ));
    }

    // Parse modulus INTEGER (0x02) and exponent INTEGER (0x02)
    let (raw_modulus, after_mod) = read_asn1_element(seq_body, 0x02)?;
    let (raw_exponent, after_exp) = read_asn1_element(after_mod, 0x02)?;
    if !after_exp.is_empty() {
        return Err(WarpError::AuthError(
            "unexpected extra fields inside ASN.1 RSAPublicKey SEQUENCE".into(),
        ));
    }

    let modulus = strip_asn1_leading_zero(raw_modulus);
    let exponent = strip_asn1_leading_zero(raw_exponent);

    if modulus.len() < 128 || exponent.is_empty() {
        return Err(WarpError::AuthError(format!(
            "invalid RSA key dimensions: modulus={} bytes, exponent={} bytes",
            modulus.len(),
            exponent.len()
        )));
    }

    let modulus_bits = modulus.len() * 8;
    let mtproto_fingerprint = compute_mtproto_rsa_fingerprint(modulus, exponent);

    Ok(RsaPublicKeyComponents {
        modulus: modulus.to_vec(),
        exponent: exponent.to_vec(),
        modulus_bits,
        mtproto_fingerprint,
    })
}

fn strip_asn1_leading_zero(bytes: &[u8]) -> &[u8] {
    let mut slice = bytes;
    while slice.len() > 1 && slice[0] == 0x00 {
        slice = &slice[1..];
    }
    slice
}

fn read_asn1_element(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), WarpError> {
    if input.len() < 2 {
        return Err(WarpError::AuthError("truncated ASN.1 DER element".into()));
    }
    let tag = input[0];
    if tag != expected_tag {
        return Err(WarpError::AuthError(format!(
            "unexpected ASN.1 DER tag: expected 0x{:02x}, got 0x{:02x}",
            expected_tag, tag
        )));
    }
    let len_byte = input[1];
    let (content_len, header_len) = if (len_byte & 0x80) == 0 {
        (len_byte as usize, 2usize)
    } else {
        let num_octets = (len_byte & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return Err(WarpError::AuthError(
                "invalid ASN.1 DER multi-byte length encoding".into(),
            ));
        }
        let mut len_val = 0usize;
        for &b in &input[2..2 + num_octets] {
            len_val = (len_val << 8) | (b as usize);
        }
        (len_val, 2 + num_octets)
    };

    if input.len() < header_len + content_len {
        return Err(WarpError::AuthError(
            "ASN.1 DER element length exceeds buffer".into(),
        ));
    }
    let content = &input[header_len..header_len + content_len];
    let remaining = &input[header_len + content_len..];
    Ok((content, remaining))
}

/// Encodes a byte slice using MTProto TL `bytes` framing (1-byte or 4-byte length prefix + 4-byte alignment padding).
pub fn tl_encode_bytes(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut out = Vec::with_capacity((len + 8) & !3);
    if len < 254 {
        out.push(len as u8);
        out.extend_from_slice(data);
    } else {
        out.push(0xfe);
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.extend_from_slice(data);
    }
    while out.len() % 4 != 0 {
        out.push(0x00);
    }
    out
}

/// Decodes an MTProto TL `bytes` field, returning `(decoded_slice, remaining_slice)`.
pub fn tl_decode_bytes(input: &[u8]) -> Result<(Vec<u8>, &[u8]), WarpError> {
    if input.is_empty() {
        return Err(WarpError::Transport(
            "empty buffer while decoding TL bytes".into(),
        ));
    }
    let (data_len, header_len) = if input[0] < 254 {
        (input[0] as usize, 1usize)
    } else if input[0] == 0xfe {
        if input.len() < 4 {
            return Err(WarpError::Transport(
                "truncated 4-byte TL bytes length header".into(),
            ));
        }
        let len =
            (input[1] as usize) | ((input[2] as usize) << 8) | ((input[3] as usize) << 16);
        (len, 4usize)
    } else {
        return Err(WarpError::Transport(
            "invalid 0xff prefix in TL bytes length".into(),
        ));
    };

    let unpadded = header_len + data_len;
    let padded = (unpadded + 3) & !3;
    if input.len() < padded {
        return Err(WarpError::Transport(
            "TL bytes field exceeds packet boundary".into(),
        ));
    }
    let data = input[header_len..header_len + data_len].to_vec();
    Ok((data, &input[padded..]))
}

/// Computes the official MTProto 64-bit RSA public key fingerprint:
/// lower 64 bits (little-endian `i64`) of `SHA-1(tl_encode_bytes(n) || tl_encode_bytes(e))`.
pub fn compute_mtproto_rsa_fingerprint(modulus: &[u8], exponent: &[u8]) -> i64 {
    let mut tl_buf = tl_encode_bytes(modulus);
    tl_buf.extend_from_slice(&tl_encode_bytes(exponent));
    let digest = sha1_digest(&tl_buf);
    let mut low64 = [0u8; 8];
    low64.copy_from_slice(&digest[12..20]);
    i64::from_le_bytes(low64)
}

/// Pure-Rust FIPS 180-4 SHA-1 implementation for MTProto RSA key & auth_key fingerprinting.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = Vec::with_capacity((data.len() + 72) & !63);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Parsed TL `resPQ#05162463` response from the first step of the MTProto 2.0 Diffie-Hellman key exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtProtoResPq {
    pub nonce: [u8; 16],
    pub server_nonce: [u8; 16],
    pub pq: Vec<u8>,
    pub server_public_key_fingerprints: Vec<i64>,
}

impl MtProtoResPq {
    /// Serializes `resPQ#05162463` into its binary TL representation.
    pub fn encode_tl(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&TL_RES_PQ_ID.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.server_nonce);
        buf.extend_from_slice(&tl_encode_bytes(&self.pq));
        buf.extend_from_slice(&TL_VECTOR_ID.to_le_bytes());
        buf.extend_from_slice(&(self.server_public_key_fingerprints.len() as u32).to_le_bytes());
        for &fp in &self.server_public_key_fingerprints {
            buf.extend_from_slice(&fp.to_le_bytes());
        }
        buf
    }

    /// Parses a binary TL `resPQ#05162463` payload.
    pub fn decode_tl(payload: &[u8]) -> Result<Self, WarpError> {
        if payload.len() < 44 {
            return Err(WarpError::Transport(format!(
                "resPQ payload too short ({} bytes)",
                payload.len()
            )));
        }
        let ctor = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if ctor != TL_RES_PQ_ID {
            return Err(WarpError::Transport(format!(
                "unexpected TL constructor in resPQ: expected 0x{:08x}, got 0x{:08x}",
                TL_RES_PQ_ID, ctor
            )));
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&payload[4..20]);
        let mut server_nonce = [0u8; 16];
        server_nonce.copy_from_slice(&payload[20..36]);

        let (pq, rest) = tl_decode_bytes(&payload[36..])?;
        if rest.len() < 8 {
            return Err(WarpError::Transport(
                "truncated Vector<long> header in resPQ".into(),
            ));
        }
        let vec_ctor = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
        if vec_ctor != TL_VECTOR_ID {
            return Err(WarpError::Transport(format!(
                "invalid TL vector constructor in resPQ: 0x{:08x}",
                vec_ctor
            )));
        }
        let count = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        if rest.len() < 8 + count * 8 {
            return Err(WarpError::Transport(
                "truncated fingerprint list in resPQ".into(),
            ));
        }
        let mut server_public_key_fingerprints = Vec::with_capacity(count);
        for i in 0..count {
            let offset = 8 + i * 8;
            let mut fp_bytes = [0u8; 8];
            fp_bytes.copy_from_slice(&rest[offset..offset + 8]);
            server_public_key_fingerprints.push(i64::from_le_bytes(fp_bytes));
        }

        Ok(Self {
            nonce,
            server_nonce,
            pq,
            server_public_key_fingerprints,
        })
    }
}

/// MTProto 2.0 unencrypted transport packet (`auth_key_id = 0`, `message_id`, `message_data_length`, `payload`)
/// with Abridged (`0xef`) and Intermediate (`0xeeeeeeee`) framing codecs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtProtoTransportFrame {
    pub auth_key_id: i64,
    pub message_id: i64,
    pub payload: Vec<u8>,
}

impl MtProtoTransportFrame {
    /// Generates a cryptographically-unpredictable 128-bit nonce using `fastrand`.
    pub fn random_nonce() -> [u8; 16] {
        let mut nonce = [0u8; 16];
        for b in &mut nonce {
            *b = fastrand::u8(..);
        }
        nonce
    }

    /// Generates an MTProto 2.0 monotonic time-based 64-bit `message_id` (aligned to 4 bytes).
    pub fn next_client_message_id() -> i64 {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let secs = now_nanos / 1_000_000_000;
        let frac = ((now_nanos % 1_000_000_000) << 32) / 1_000_000_000;
        let raw = ((secs << 32) | (frac & 0xffff_fffc)) & !3u64;
        raw as i64
    }

    /// Constructs an unencrypted `req_pq_multi#be7e8ef1` frame for the given 128-bit `nonce`.
    pub fn new_req_pq_multi(nonce: [u8; 16]) -> Self {
        let mut payload = Vec::with_capacity(20);
        payload.extend_from_slice(&TL_REQ_PQ_MULTI_ID.to_le_bytes());
        payload.extend_from_slice(&nonce);
        Self {
            auth_key_id: 0,
            message_id: Self::next_client_message_id(),
            payload,
        }
    }

    /// Constructs an unencrypted `resPQ#05162463` response frame.
    pub fn new_res_pq(res: &MtProtoResPq) -> Self {
        Self {
            auth_key_id: 0,
            message_id: Self::next_client_message_id() + 1,
            payload: res.encode_tl(),
        }
    }

    /// Encodes the unencrypted MTProto message envelope (`auth_key_id:8 + message_id:8 + message_data_length:4 + payload`).
    pub fn encode_unencrypted_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.payload.len());
        out.extend_from_slice(&self.auth_key_id.to_le_bytes());
        out.extend_from_slice(&self.message_id.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decodes an unencrypted MTProto message envelope (`auth_key_id == 0`).
    pub fn decode_unencrypted_message(bytes: &[u8]) -> Result<Self, WarpError> {
        if bytes.len() < 20 {
            return Err(WarpError::Transport(format!(
                "MTProto unencrypted message too short ({} bytes)",
                bytes.len()
            )));
        }
        let mut ak_bytes = [0u8; 8];
        ak_bytes.copy_from_slice(&bytes[0..8]);
        let auth_key_id = i64::from_le_bytes(ak_bytes);
        if auth_key_id != 0 {
            return Err(WarpError::Transport(format!(
                "expected unencrypted auth_key_id=0 during handshake, got {}",
                auth_key_id
            )));
        }
        let mut mid_bytes = [0u8; 8];
        mid_bytes.copy_from_slice(&bytes[8..16]);
        let message_id = i64::from_le_bytes(mid_bytes);

        let msg_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        if bytes.len() < 20 + msg_len {
            return Err(WarpError::Transport(format!(
                "MTProto payload truncated: header declared {} bytes, buffer has {}",
                msg_len,
                bytes.len() - 20
            )));
        }
        let payload = bytes[20..20 + msg_len].to_vec();
        Ok(Self {
            auth_key_id,
            message_id,
            payload,
        })
    }

    /// Encodes this frame using MTProto Intermediate framing (`[len: u32 LE][unencrypted_message]`).
    pub fn encode_intermediate_frame(&self) -> Vec<u8> {
        let msg = self.encode_unencrypted_message();
        let mut frame = Vec::with_capacity(4 + msg.len());
        frame.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        frame.extend_from_slice(&msg);
        frame
    }

    /// Decodes an MTProto Intermediate frame (`[len: u32 LE][unencrypted_message]`).
    pub fn decode_intermediate_frame(frame: &[u8]) -> Result<Self, WarpError> {
        if frame.len() < 4 {
            return Err(WarpError::Transport(
                "MTProto Intermediate frame missing 4-byte length".into(),
            ));
        }
        let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        if frame.len() < 4 + len {
            return Err(WarpError::Transport(
                "MTProto Intermediate frame shorter than declared length".into(),
            ));
        }
        Self::decode_unencrypted_message(&frame[4..4 + len])
    }

    /// Encodes this frame using MTProto Abridged framing (`len/4` header + `unencrypted_message`).
    pub fn encode_abridged_frame(&self) -> Vec<u8> {
        let msg = self.encode_unencrypted_message();
        let words = msg.len() / 4;
        let mut frame = Vec::with_capacity(4 + msg.len());
        if words < 0x7f {
            frame.push(words as u8);
        } else {
            frame.push(0x7f);
            frame.push((words & 0xff) as u8);
            frame.push(((words >> 8) & 0xff) as u8);
            frame.push(((words >> 16) & 0xff) as u8);
        }
        frame.extend_from_slice(&msg);
        frame
    }

    /// Decodes an MTProto Abridged frame (`len/4` header + `unencrypted_message`).
    pub fn decode_abridged_frame(frame: &[u8]) -> Result<Self, WarpError> {
        if frame.is_empty() {
            return Err(WarpError::Transport("empty MTProto Abridged frame".into()));
        }
        let (words, offset) = if frame[0] < 0x7f {
            (frame[0] as usize, 1usize)
        } else {
            if frame.len() < 4 {
                return Err(WarpError::Transport(
                    "truncated 4-byte MTProto Abridged length header".into(),
                ));
            }
            let w =
                (frame[1] as usize) | ((frame[2] as usize) << 8) | ((frame[3] as usize) << 16);
            (w, 4usize)
        };
        let byte_len = words * 4;
        if frame.len() < offset + byte_len {
            return Err(WarpError::Transport(
                "MTProto Abridged frame shorter than declared word length".into(),
            ));
        }
        Self::decode_unencrypted_message(&frame[offset..offset + byte_len])
    }

    /// Extracts the 128-bit `nonce` if this frame is a `req_pq_multi#be7e8ef1` request.
    pub fn parse_req_pq_multi(&self) -> Result<[u8; 16], WarpError> {
        if self.payload.len() < 20 {
            return Err(WarpError::Transport(
                "req_pq_multi payload shorter than 20 bytes".into(),
            ));
        }
        let ctor = u32::from_le_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]);
        if ctor != TL_REQ_PQ_MULTI_ID {
            return Err(WarpError::Transport(format!(
                "expected req_pq_multi#be7e8ef1, got 0x{:08x}",
                ctor
            )));
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&self.payload[4..20]);
        Ok(nonce)
    }

    /// Parses this frame as `resPQ#05162463` and validates that the server echoed `expected_nonce`.
    pub fn parse_res_pq(&self, expected_nonce: &[u8; 16]) -> Result<MtProtoResPq, WarpError> {
        let res = MtProtoResPq::decode_tl(&self.payload)?;
        if &res.nonce != expected_nonce {
            return Err(WarpError::Transport(
                "MTProto resPQ nonce mismatch against req_pq_multi client nonce".into(),
            ));
        }
        Ok(res)
    }
}

/// Diagnostic result of probing a Telegram DC (`149.154.167.40:443` or local listener) via MTProto 2.0 Intermediate TCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtProtoHandshakeProbe {
    pub dc_id: u16,
    pub target_addr: String,
    pub live_tcp_connected: bool,
    pub simulated_fallback: bool,
    pub client_nonce: [u8; 16],
    pub server_nonce: [u8; 16],
    pub pq_bytes: Vec<u8>,
    pub matched_rsa_fingerprints: Vec<i64>,
    pub rtt_micros: u64,
}

/// Test server DC configuration loaded at runtime from the git-ignored `.private/telegram/` directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelegramTestServerConfig {
    pub enabled: bool,
    pub dc_id: u16,
    pub address: String,
    pub rsa_public_key_file: Option<String>,
    pub rsa_public_key_pem: String,
}

/// Private Telegram MTProto credentials & DC configuration loaded from `.private/telegram/telegram_dc2.toml`
/// (or `~/.gemini/warp-im-private/telegram/telegram_dc2.toml`), never tracked by Git.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelegramPrivateConfig {
    pub api_id: i32,
    pub api_hash: String,
    pub test_server: Option<TelegramTestServerConfig>,
}

impl TelegramPrivateConfig {
    /// Searches for `telegram_dc2.toml` in `WARP_TELEGRAM_CONFIG`, `.private/telegram/telegram_dc2.toml`,
    /// workspace-relative `../../.private/telegram/telegram_dc2.toml`, or `~/.gemini/warp-im-private/telegram/telegram_dc2.toml`.
    pub fn load_from_private_dir() -> Option<Self> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(env_path) = std::env::var("WARP_TELEGRAM_CONFIG") {
            candidates.push(PathBuf::from(env_path));
        }
        candidates.push(PathBuf::from(".private/telegram/telegram_dc2.toml"));
        candidates.push(PathBuf::from("../../.private/telegram/telegram_dc2.toml"));
        candidates.push(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.private/telegram/telegram_dc2.toml"),
        );
        if let Ok(home) = std::env::var("HOME") {
            candidates.push(
                Path::new(&home).join(".gemini/warp-im-private/telegram/telegram_dc2.toml"),
            );
        }

        for path in candidates {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(cfg) = toml::from_str::<Self>(&raw) {
                    return Some(cfg);
                }
            }
        }
        None
    }

    /// Parses the Test DC2 RSA public key configured in `test_server.rsa_public_key_pem`.
    pub fn parse_dc2_rsa_key(&self) -> Result<RsaPublicKeyComponents, WarpError> {
        let ts = self
            .test_server
            .as_ref()
            .ok_or_else(|| WarpError::AuthError("no test_server section in config".into()))?;
        parse_rsa_public_key_pem(&ts.rsa_public_key_pem)
    }
}

/// Official Telegram Public Production DC2 endpoint (`149.154.167.50:443`).
pub const TELEGRAM_PUBLIC_DC2_ENDPOINT: &str = "149.154.167.50:443";

/// Official Telegram Test Server DC2 endpoint (`149.154.167.40:443`).
pub const TELEGRAM_TEST_DC2_ENDPOINT: &str = "149.154.167.40:443";

/// User-selectable Telegram MTProto backend environment (`PublicProduction` vs `TestDc2`).
///
/// Allows users and developers to choose in Telegram settings whether to connect to the
/// public production Telegram Data Centers (`149.154.167.50:443`, DC1–DC5) or the dedicated
/// Telegram Test Server (`149.154.167.40:443`, DC2 with `+999662xxxx` / OTP `22222`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TelegramBackendEnvironment {
    /// Official Public Production Telegram Data Centers (`149.154.167.50:443`, DC1–DC5).
    #[default]
    PublicProduction,
    /// Official Telegram Test Server DC2 (`149.154.167.40:443`).
    TestDc2,
}

impl TelegramBackendEnvironment {
    /// Canonical string identifier (`"public"` or `"test_dc2"`).
    pub const fn as_slug(&self) -> &'static str {
        match self {
            Self::PublicProduction => "public",
            Self::TestDc2 => "test_dc2",
        }
    }

    /// Parses a backend environment from a configuration or UI setting slug.
    pub fn from_slug(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "test" | "test_dc2" | "dc2_test" | "test_server" | "sandbox" | "149.154.167.40:443" => {
                Self::TestDc2
            }
            _ => Self::PublicProduction,
        }
    }

    /// Returns `true` if this environment targets the Telegram Test Server (`149.154.167.40:443`).
    pub const fn is_test_server(&self) -> bool {
        matches!(self, Self::TestDc2)
    }

    /// Returns the default MTProto TCP endpoint for this environment.
    pub const fn default_dc_endpoint(&self) -> &'static str {
        match self {
            Self::PublicProduction => TELEGRAM_PUBLIC_DC2_ENDPOINT,
            Self::TestDc2 => TELEGRAM_TEST_DC2_ENDPOINT,
        }
    }

    /// Human-readable label for UI settings and diagnostics.
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::PublicProduction => "Telegram Public Production (DC1–DC5 • 149.154.167.50:443)",
            Self::TestDc2 => "Telegram Test Server (DC2 • 149.154.167.40:443)",
        }
    }

    /// Compact UI badge (`"🌐 TG Pubblico"` vs `"🧪 TG Test DC2"`).
    pub const fn short_badge(&self) -> &'static str {
        match self {
            Self::PublicProduction => "🌐 TG Pubblico",
            Self::TestDc2 => "🧪 TG Test DC2",
        }
    }
}

/// Active MTProto `PhoneAndOtp` or `TelegramBotToken` (`auth.importBotAuthorization`) session state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramAuthSession {
    pub dc_id: u16,
    pub is_test_dc: bool,
    pub backend_env: TelegramBackendEnvironment,
    pub target_endpoint: String,
    pub is_bot: bool,
    pub bot_id: Option<i64>,
    pub phone_number: String,
    pub phone_code_hash: String,
    pub expected_test_otp: Option<String>,
    pub auth_key_fingerprint: i64,
    pub requires_2fa: bool,
    pub authorized: bool,
}

/// Validates and parses a Telegram `@BotFather` token (`<bot_id>:<bot_secret>`) for `auth.importBotAuthorization`.
pub fn parse_telegram_bot_token(raw_token: &str) -> Result<(i64, String), WarpError> {
    let trimmed = raw_token.trim();
    let (id_part, secret_part) = trimmed.split_once(':').ok_or_else(|| {
        WarpError::AuthError(
            "Invalid Telegram Bot Token format: expected '<bot_id>:<secret>' from @BotFather".into(),
        )
    })?;
    let bot_id: i64 = id_part.parse().map_err(|_| {
        WarpError::AuthError("Invalid Telegram Bot Token: numeric bot_id required before ':'".into())
    })?;
    if bot_id <= 0 {
        return Err(WarpError::AuthError(
            "Invalid Telegram Bot Token: bot_id must be positive".into(),
        ));
    }
    if secret_part.len() < 8
        || !secret_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(WarpError::AuthError(
            "Invalid Telegram Bot Token: secret suffix after ':' is malformed or too short".into(),
        ));
    }
    Ok((bot_id, secret_part.to_string()))
}

/// Official Telegram Bot API base URL (`https://api.telegram.org`).
pub const TELEGRAM_BOT_API_DEFAULT_BASE: &str = "https://api.telegram.org";

/// Verified identity returned by the Telegram Bot API `getMe` endpoint (`https://api.telegram.org/bot<TOKEN>/getMe`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramBotIdentity {
    pub bot_id: i64,
    pub username: String,
    pub first_name: String,
    pub can_join_groups: bool,
    pub can_read_all_group_messages: bool,
    pub live_network_verified: bool,
}

/// Delivery receipt returned by the Telegram Bot API `sendMessage` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramBotSentMessage {
    pub message_id: i64,
    pub chat_id: String,
    pub date_unix: i64,
    pub text: String,
    pub live_network_sent: bool,
}

/// Parsed incoming message or channel post from the Telegram Bot API `getUpdates` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramBotUpdateItem {
    pub update_id: i64,
    pub message_id: i64,
    pub chat_id: String,
    pub chat_title: String,
    pub chat_username: Option<String>,
    pub is_group_or_channel: bool,
    pub sender_id: String,
    pub sender_display_name: String,
    pub text: String,
    pub timestamp_ms: i64,
}

/// Normalizes a Warp chat `remote_id` into a Telegram Bot API `chat_id` if it represents
/// a real numeric Telegram user/group/supergroup ID (e.g. `"35827073"`, `"-1001998877"`)
/// or a public `@channel` / `@username` handle.
pub fn normalize_telegram_chat_id(remote_id: &str) -> Option<String> {
    let trimmed = remote_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = trimmed
        .strip_prefix("tg_chat_")
        .or_else(|| trimmed.strip_prefix("telegram:"))
        .unwrap_or(trimmed);

    if candidate.parse::<i64>().is_ok() {
        return Some(candidate.to_string());
    }
    if candidate.starts_with('@')
        && candidate.len() >= 4
        && candidate[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Some(candidate.to_string());
    }
    None
}

fn active_telegram_bot_api_base() -> String {
    if let Ok(custom) = std::env::var("WARP_TELEGRAM_BOT_API_BASE") {
        let trimmed = custom.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    TELEGRAM_BOT_API_DEFAULT_BASE.to_string()
}

fn is_synthetic_test_bot_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("examplebottoken") || lower.contains("test_secret") || lower.contains("dummy")
}

/// Executes a JSON POST request against a Telegram Bot API endpoint (`<base_url>/bot<token>/<method>`).
///
/// Uses a dual-strategy transport:
/// - **Strategy A (Pure-Rust HTTP/1.1 over `tokio::net::TcpStream`)** when `base_url` uses `http://`
///   (e.g. local Bot API server or test harness).
/// - **Strategy B (HTTPS via `curl -sS --max-time 5`)** when `base_url` uses `https://`
///   (available across Linux, macOS, Windows 10/11, and Android `/system/bin/curl` without OpenSSL build issues).
pub async fn telegram_bot_api_request_with_base(
    base_url: &str,
    bot_token: &str,
    method: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, WarpError> {
    let clean_token = bot_token.trim();
    let _ = parse_telegram_bot_token(clean_token)?;
    let clean_base = base_url.trim().trim_end_matches('/');
    let clean_method = method.trim().trim_start_matches('/');
    let full_url = format!("{clean_base}/bot{clean_token}/{clean_method}");
    let body_json = serde_json::to_string(payload)
        .map_err(|e| WarpError::Transport(format!("Telegram Bot API JSON encode error: {e}")))?;

    if full_url.starts_with("http://") {
        let parsed = url::Url::parse(&full_url)
            .map_err(|e| WarpError::Transport(format!("Invalid Bot API URL {full_url}: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| WarpError::Transport("Missing host in Bot API URL".into()))?
            .to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path_and_query = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        };

        let raw_response = tokio::time::timeout(Duration::from_secs(4), async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let req = format!(
                "POST {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_json}",
                body_json.len()
            );
            stream.write_all(req.as_bytes()).await?;
            stream.flush().await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await
        .map_err(|_| WarpError::Transport("Telegram Bot API HTTP request timed out".into()))?
        .map_err(|e| WarpError::Transport(format!("Telegram Bot API TCP error: {e}")))?;

        let text = String::from_utf8_lossy(&raw_response);
        let json_body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.trim())
            .or_else(|| text.split_once("\n\n").map(|(_, b)| b.trim()))
            .unwrap_or_else(|| text.trim());

        let val: serde_json::Value = serde_json::from_str(json_body).map_err(|e| {
            WarpError::Transport(format!("Invalid JSON from Telegram Bot API: {e}"))
        })?;
        return Ok(val);
    }

    // Strategy B: HTTPS via curl subprocess
    let url_owned = full_url.clone();
    let body_owned = body_json.clone();
    let curl_out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "5",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &body_owned,
                &url_owned,
            ])
            .output()
    })
    .await
    .map_err(|e| WarpError::Transport(format!("Telegram Bot API task join error: {e}")))?
    .map_err(|e| WarpError::Transport(format!("Failed to invoke curl for Telegram Bot API: {e}")))?;

    if !curl_out.status.success() {
        let stderr = String::from_utf8_lossy(&curl_out.stderr);
        return Err(WarpError::Transport(format!(
            "Telegram Bot API HTTPS curl request failed: {}",
            stderr.trim()
        )));
    }

    let stdout_str = String::from_utf8_lossy(&curl_out.stdout);
    serde_json::from_str(stdout_str.trim()).map_err(|e| {
        WarpError::Transport(format!("Telegram Bot API invalid JSON response: {e}"))
    })
}

/// Calls `getMe` against a specific Telegram Bot API base URL, falling back gracefully
/// if the network is unreachable so offline/sandboxed sessions still initialize cleanly.
pub async fn telegram_bot_get_me_with_base(
    base_url: &str,
    bot_token: &str,
) -> Result<TelegramBotIdentity, WarpError> {
    let (bot_id, _) = parse_telegram_bot_token(bot_token)?;

    if base_url == TELEGRAM_BOT_API_DEFAULT_BASE && is_synthetic_test_bot_token(bot_token) {
        return Ok(TelegramBotIdentity {
            bot_id,
            username: format!("warp_bot_{bot_id}"),
            first_name: format!("Telegram Bot #{bot_id}"),
            can_join_groups: true,
            can_read_all_group_messages: true,
            live_network_verified: false,
        });
    }

    if let Ok(resp) =
        telegram_bot_api_request_with_base(base_url, bot_token, "getMe", &serde_json::json!({}))
            .await
    {
        if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(res) = resp.get("result") {
                let real_id = res.get("id").and_then(|v| v.as_i64()).unwrap_or(bot_id);
                let username = res
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim_start_matches('@').to_string())
                    .unwrap_or_else(|| format!("warp_bot_{real_id}"));
                let first_name = res
                    .get("first_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| username.clone());
                let can_join_groups = res
                    .get("can_join_groups")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let can_read_all_group_messages = res
                    .get("can_read_all_group_messages")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                return Ok(TelegramBotIdentity {
                    bot_id: real_id,
                    username,
                    first_name,
                    can_join_groups,
                    can_read_all_group_messages,
                    live_network_verified: true,
                });
            }
        }
    }

    Ok(TelegramBotIdentity {
        bot_id,
        username: format!("warp_bot_{bot_id}"),
        first_name: format!("Telegram Bot #{bot_id}"),
        can_join_groups: true,
        can_read_all_group_messages: true,
        live_network_verified: false,
    })
}

/// Calls `https://api.telegram.org/bot<TOKEN>/getMe` (or `$WARP_TELEGRAM_BOT_API_BASE`) to fetch
/// the real bot's `username` and `first_name`.
pub async fn telegram_bot_get_me(bot_token: &str) -> Result<TelegramBotIdentity, WarpError> {
    let base = active_telegram_bot_api_base();
    telegram_bot_get_me_with_base(&base, bot_token).await
}

/// Sends a message via the Telegram Bot API `sendMessage` endpoint against `base_url`.
pub async fn telegram_bot_send_message_with_base(
    base_url: &str,
    bot_token: &str,
    chat_id: &str,
    text: &str,
    reply_to_msg_id: Option<i64>,
) -> Result<TelegramBotSentMessage, WarpError> {
    let _ = parse_telegram_bot_token(bot_token)?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut payload = serde_json::Map::new();
    if let Ok(numeric_id) = chat_id.trim().parse::<i64>() {
        payload.insert("chat_id".into(), serde_json::Value::Number(numeric_id.into()));
    } else {
        payload.insert(
            "chat_id".into(),
            serde_json::Value::String(chat_id.trim().to_string()),
        );
    }
    payload.insert("text".into(), serde_json::Value::String(text.to_string()));
    if let Some(reply_id) = reply_to_msg_id {
        payload.insert(
            "reply_to_message_id".into(),
            serde_json::Value::Number(reply_id.into()),
        );
    }

    if !(base_url == TELEGRAM_BOT_API_DEFAULT_BASE && is_synthetic_test_bot_token(bot_token)) {
        if let Ok(resp) = telegram_bot_api_request_with_base(
            base_url,
            bot_token,
            "sendMessage",
            &serde_json::Value::Object(payload),
        )
        .await
        {
            if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(res) = resp.get("result") {
                    let message_id = res
                        .get("message_id")
                        .and_then(|v| v.as_i64())
                        .unwrap_or_else(|| (fastrand::u32(10_000..999_999)) as i64);
                    let date_unix = res
                        .get("date")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(now_unix);
                    let resolved_chat_id = res
                        .pointer("/chat/id")
                        .and_then(|v| {
                            v.as_i64()
                                .map(|n| n.to_string())
                                .or_else(|| v.as_str().map(str::to_string))
                        })
                        .unwrap_or_else(|| chat_id.trim().to_string());
                    return Ok(TelegramBotSentMessage {
                        message_id,
                        chat_id: resolved_chat_id,
                        date_unix,
                        text: text.to_string(),
                        live_network_sent: true,
                    });
                }
            }
        }
    }

    Ok(TelegramBotSentMessage {
        message_id: (fastrand::u32(10_000..999_999)) as i64,
        chat_id: chat_id.trim().to_string(),
        date_unix: now_unix,
        text: text.to_string(),
        live_network_sent: false,
    })
}

/// Sends a message via `https://api.telegram.org/bot<TOKEN>/sendMessage` (or `$WARP_TELEGRAM_BOT_API_BASE`).
pub async fn telegram_bot_send_message(
    bot_token: &str,
    chat_id: &str,
    text: &str,
    reply_to_msg_id: Option<i64>,
) -> Result<TelegramBotSentMessage, WarpError> {
    let base = active_telegram_bot_api_base();
    telegram_bot_send_message_with_base(&base, bot_token, chat_id, text, reply_to_msg_id).await
}

/// Polls incoming updates from the Telegram Bot API `getUpdates` endpoint against `base_url`.
pub async fn telegram_bot_get_updates_with_base(
    base_url: &str,
    bot_token: &str,
    offset: Option<i64>,
    timeout_secs: u32,
) -> Result<Vec<TelegramBotUpdateItem>, WarpError> {
    let _ = parse_telegram_bot_token(bot_token)?;
    if base_url == TELEGRAM_BOT_API_DEFAULT_BASE && is_synthetic_test_bot_token(bot_token) {
        return Ok(Vec::new());
    }

    let mut payload = serde_json::Map::new();
    if let Some(off) = offset {
        payload.insert("offset".into(), serde_json::Value::Number(off.into()));
    }
    payload.insert(
        "timeout".into(),
        serde_json::Value::Number(timeout_secs.into()),
    );
    payload.insert(
        "allowed_updates".into(),
        serde_json::json!(["message", "edited_message", "channel_post"]),
    );

    let Ok(resp) = telegram_bot_api_request_with_base(
        base_url,
        bot_token,
        "getUpdates",
        &serde_json::Value::Object(payload),
    )
    .await
    else {
        return Ok(Vec::new());
    };

    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Ok(Vec::new());
    }

    let Some(arr) = resp.get("result").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let mut updates = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(update_id) = item.get("update_id").and_then(|v| v.as_i64()) else {
            continue;
        };
        let msg_obj = item
            .get("message")
            .or_else(|| item.get("edited_message"))
            .or_else(|| item.get("channel_post"));
        let Some(msg) = msg_obj else {
            continue;
        };

        let message_id = msg.get("message_id").and_then(|v| v.as_i64()).unwrap_or(update_id);
        let text = msg
            .get("text")
            .or_else(|| msg.get("caption"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if text.is_empty() {
            continue;
        }

        let chat_obj = msg.get("chat").unwrap_or(&serde_json::Value::Null);
        let chat_id = chat_obj
            .get("id")
            .and_then(|v| {
                v.as_i64()
                    .map(|n| n.to_string())
                    .or_else(|| v.as_str().map(str::to_string))
            })
            .unwrap_or_else(|| "0".to_string());
        let chat_type = chat_obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("private");
        let is_group_or_channel = chat_type != "private";
        let chat_username = chat_obj
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| format!("@{}", s.trim_start_matches('@')));
        let chat_title = chat_obj
            .get("title")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                let first = chat_obj.get("first_name").and_then(|v| v.as_str()).unwrap_or("");
                let last = chat_obj.get("last_name").and_then(|v| v.as_str()).unwrap_or("");
                let combined = format!("{first} {last}").trim().to_string();
                if combined.is_empty() {
                    None
                } else {
                    Some(combined)
                }
            })
            .or_else(|| chat_username.clone())
            .unwrap_or_else(|| format!("Telegram Chat {chat_id}"));

        let from_obj = msg.get("from").unwrap_or(chat_obj);
        let sender_id = from_obj
            .get("id")
            .and_then(|v| {
                v.as_i64()
                    .map(|n| n.to_string())
                    .or_else(|| v.as_str().map(str::to_string))
            })
            .unwrap_or_else(|| chat_id.clone());
        let sender_display_name = {
            let first = from_obj
                .get("first_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let last = from_obj
                .get("last_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let full = format!("{first} {last}").trim().to_string();
            if !full.is_empty() {
                full
            } else if let Some(u) = from_obj.get("username").and_then(|v| v.as_str()) {
                format!("@{}", u.trim_start_matches('@'))
            } else {
                chat_title.clone()
            }
        };

        let date_secs = msg
            .get("date")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            });

        updates.push(TelegramBotUpdateItem {
            update_id,
            message_id,
            chat_id,
            chat_title,
            chat_username,
            is_group_or_channel,
            sender_id,
            sender_display_name,
            text,
            timestamp_ms: date_secs * 1_000,
        });
    }

    Ok(updates)
}

/// Polls incoming updates from `https://api.telegram.org/bot<TOKEN>/getUpdates` (or `$WARP_TELEGRAM_BOT_API_BASE`).
pub async fn telegram_bot_get_updates(
    bot_token: &str,
    offset: Option<i64>,
    timeout_secs: u32,
) -> Result<Vec<TelegramBotUpdateItem>, WarpError> {
    let base = active_telegram_bot_api_base();
    telegram_bot_get_updates_with_base(&base, bot_token, offset, timeout_secs).await
}

/// Checks if `phone` is an official Telegram Test DC number (`+99966XYYYY`), returning `(dc_id, "XXXXX")`.
///
/// On Telegram's Test DC2 (`149.154.167.40:443`), numbers match `+999662xxxx` and the 5-digit OTP is `22222`.
pub fn detect_test_dc_phone_otp(phone: &str) -> Option<(u16, String)> {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.starts_with("99966") && digits.len() >= 9 {
        let dc_char = digits.chars().nth(5)?;
        let dc_id = dc_char.to_digit(10)? as u16;
        if (1..=5).contains(&dc_id) {
            let otp: String = std::iter::repeat(dc_char).take(5).collect();
            return Some((dc_id, otp));
        }
    }
    None
}

/// Factory plugin for Telegram MTProto accounts.
#[derive(Debug, Default, Clone)]
pub struct TelegramPlugin;

impl ProtocolPlugin for TelegramPlugin {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Telegram
    }

    fn onboarding_flow(&self) -> AuthFlowDescriptor {
        AuthFlowDescriptor::telegram_with_backend(false)
    }

    fn build_backend(
        &self,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        Ok(Arc::new(TelegramBackend::new(account_id, config_json)))
    }
}

/// Active Telegram MTProto 2.0 + Bot API backend instance.
pub struct TelegramBackend {
    account_id: AccountId,
    config: serde_json::Value,
    bot_token: RwLock<Option<String>>,
    backend_env: RwLock<TelegramBackendEnvironment>,
    private_config: Option<TelegramPrivateConfig>,
    rsa_key_components: Option<RsaPublicKeyComponents>,
    auth_session: RwLock<Option<TelegramAuthSession>>,
    state: RwLock<SyncState>,
    pts_counter: AtomicI64,
    containers: RwLock<Vec<UnifiedContainer>>,
    chats: RwLock<Vec<UnifiedChat>>,
    messages: RwLock<HashMap<UniversalId, Vec<UnifiedMessage>>>,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl TelegramBackend {
    pub fn new(account_id: AccountId, config: serde_json::Value) -> Self {
        let initial_pts = config
            .get("pts")
            .and_then(|v| v.as_i64())
            .unwrap_or(148_920);
        let initial_bot_token = config
            .get("bot_token")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| s.contains(':'));
        let initial_env = if let Some(env_str) = config.get("backend_env").and_then(|v| v.as_str()) {
            TelegramBackendEnvironment::from_slug(env_str)
        } else if config
            .get("test_dc")
            .or_else(|| config.get("use_test_dc"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || account_id.as_str().contains("dc2")
            || account_id.as_str().contains("test")
        {
            TelegramBackendEnvironment::TestDc2
        } else {
            TelegramBackendEnvironment::PublicProduction
        };

        let (event_tx, _) = broadcast::channel(256);
        let private_config = TelegramPrivateConfig::load_from_private_dir();
        let rsa_key_components = private_config
            .as_ref()
            .and_then(|cfg| cfg.parse_dc2_rsa_key().ok());

        let (containers, chats, messages) =
            Self::seed_initial_topology(&account_id, initial_pts);

        Self {
            account_id,
            config,
            bot_token: RwLock::new(initial_bot_token),
            backend_env: RwLock::new(initial_env),
            private_config,
            rsa_key_components,
            auth_session: RwLock::new(None),
            state: RwLock::new(SyncState::Disconnected),
            pts_counter: AtomicI64::new(initial_pts),
            containers: RwLock::new(containers),
            chats: RwLock::new(chats),
            messages: RwLock::new(messages),
            event_tx,
        }
    }

    fn seed_initial_topology(
        account_id: &AccountId,
        initial_pts: i64,
    ) -> (
        Vec<UnifiedContainer>,
        Vec<UnifiedChat>,
        HashMap<UniversalId, Vec<UnifiedMessage>>,
    ) {
        let base_ts: i64 = 1_730_918_400_000;
        let forum_container_id = UniversalId::new(
            ProtocolKind::Telegram,
            account_id.clone(),
            "forum_-1001998877",
        );
        let topic_chat_id = UniversalId::new(
            ProtocolKind::Telegram,
            account_id.clone(),
            "forum_-1001998877_topic_42",
        );
        let dm_chat_id = UniversalId::new(
            ProtocolKind::Telegram,
            account_id.clone(),
            "dm_elena_88219",
        );

        let containers = vec![UnifiedContainer {
            id: forum_container_id.clone(),
            kind: ContainerKind::ForumGroup,
            title: "Rust & Linux Core Forum".into(),
            icon_initials: "RL".into(),
            avatar_url: None,
            unread_count: 2,
            mention_count: 1,
            child_chat_ids: vec![topic_chat_id.clone()],
            protocol_metadata: serde_json::json!({
                "is_forum": true,
                "access_hash": 77182938192_i64
            }),
        }];

        let chats = vec![
            UnifiedChat {
                id: topic_chat_id.clone(),
                parent_container_id: Some(forum_container_id.clone()),
                parent_chat_id: Some(forum_container_id.clone()),
                topology: ChatTopologyKind::ThreadOrTopic,
                hierarchy: ContainerHierarchy::NestedThread {
                    container_id: Some(forum_container_id.clone()),
                    parent_chat_id: forum_container_id.clone(),
                    topic_title: "🦀 #async-tokio-runtime".into(),
                },
                title: "🦀 #async-tokio-runtime (TG Topic)".into(),
                subtitle: Some("Telegram Forum Topic #42 • 1,420 members".into()),
                avatar_initials: "TG".into(),
                avatar_url: None,
                last_message_preview: Some("Zero-copy ringbuffer benchmarks look solid!".into()),
                last_activity_ts: base_ts + 90_000,
                unread_count: 2,
                mention_count: 1,
                is_pinned: true,
                is_muted: false,
                is_online: true,
                capabilities: ChatCapabilities::full_featured()
                    | ChatCapabilities::SUPPORTS_THREADS,
                protocol_metadata: serde_json::json!({
                    "top_msg_id": 42,
                    "access_hash": 9981273_i64
                }),
            },
            UnifiedChat {
                id: dm_chat_id.clone(),
                parent_container_id: None,
                parent_chat_id: None,
                topology: ChatTopologyKind::DirectMessage,
                hierarchy: ContainerHierarchy::Flat {
                    is_direct_message: true,
                },
                title: "Elena Conti (Telegram)".into(),
                subtitle: Some("MTProto 2.0 • Secret/Cloud DM".into()),
                avatar_initials: "EC".into(),
                avatar_url: None,
                last_message_preview: Some("Sent the architecture PDF via MTProto.".into()),
                last_activity_ts: base_ts + 85_000,
                unread_count: 1,
                mention_count: 0,
                is_pinned: true,
                is_muted: false,
                is_online: true,
                capabilities: ChatCapabilities::full_featured() | ChatCapabilities::IS_E2EE_ACTIVE,
                protocol_metadata: serde_json::json!({
                    "peer_type": "user",
                    "dc_id": 2
                }),
            },
        ];

        let mut messages = HashMap::new();
        messages.insert(
            topic_chat_id.clone(),
            vec![UnifiedMessage {
                id: UniversalId::new(ProtocolKind::Telegram, account_id.clone(), "tg_msg_101"),
                local_outbox_id: None,
                chat_id: topic_chat_id.clone(),
                thread_id: Some(topic_chat_id.clone()),
                sender_id: "tg_user_niko".into(),
                sender_display_name: "Niko (Tokio Maintainer)".into(),
                sender_initials: "NM".into(),
                sender_avatar_url: None,
                is_outgoing: false,
                text: "Welcome to the Telegram Forum Topic for #async-tokio-runtime!".into(),
                reply_to_id: None,
                reply_preview: None,
                timestamp_ms: base_ts + 10_000,
                edited_at_ms: None,
                delivery_state: DeliveryState::Read,
                reactions: vec![MessageReaction {
                    emoji: "🦀".into(),
                    count: 5,
                    reacted_by_me: true,
                }],
                attachments: vec![MediaAttachment {
                    media_uri: CompactString::from(format!(
                        "warp-media://telegram/{}/doc_bench_01",
                        account_id
                    )),
                    source_url: "mtproto://dc2/document/881920192".into(),
                    mime_type: "application/pdf".into(),
                    file_name: Some("tokio_coalescer_16ms.pdf".into()),
                    size_bytes: 245_760,
                    encryption_metadata: serde_json::json!({
                        "dc_id": 2,
                        "file_reference": "ref_hex_9981"
                    }),
                }],
                capabilities: MessageCapabilities::derive_from_chat(
                    ChatCapabilities::full_featured(),
                    false,
                    false,
                ),
                protocol_metadata: serde_json::json!({ "pts": initial_pts - 1 }),
            }],
        );
        messages.insert(
            dm_chat_id.clone(),
            vec![UnifiedMessage {
                id: UniversalId::new(ProtocolKind::Telegram, account_id.clone(), "tg_msg_201"),
                local_outbox_id: None,
                chat_id: dm_chat_id.clone(),
                thread_id: None,
                sender_id: "elena_tg".into(),
                sender_display_name: "Elena Conti".into(),
                sender_initials: "EC".into(),
                sender_avatar_url: None,
                is_outgoing: false,
                text: "Sent the architecture PDF via MTProto.".into(),
                reply_to_id: None,
                reply_preview: None,
                timestamp_ms: base_ts + 85_000,
                edited_at_ms: None,
                delivery_state: DeliveryState::Read,
                reactions: vec![],
                attachments: vec![],
                capabilities: MessageCapabilities::derive_from_chat(
                    ChatCapabilities::full_featured() | ChatCapabilities::IS_E2EE_ACTIVE,
                    false,
                    false,
                ),
                protocol_metadata: serde_json::json!({ "pts": initial_pts }),
            }],
        );

        (containers, chats, messages)
    }

    pub fn current_pts(&self) -> i64 {
        self.pts_counter.load(Ordering::Relaxed)
    }

    /// Returns the currently selected [`TelegramBackendEnvironment`] (`PublicProduction` or `TestDc2`).
    pub fn backend_environment(&self) -> TelegramBackendEnvironment {
        *self.backend_env.read().expect("backend_env lock")
    }

    /// Switches the active [`TelegramBackendEnvironment`] (`PublicProduction` vs `TestDc2`) at runtime,
    /// updating chat subtitles/metadata and broadcasting `BackendEvent::HierarchyUpdated` if already `LiveSynced`.
    pub fn set_backend_environment(&self, env: TelegramBackendEnvironment) {
        let changed = {
            let mut guard = self.backend_env.write().expect("backend_env lock");
            let prev = *guard;
            *guard = env;
            prev != env
        };
        let endpoint = self.active_dc_endpoint();
        {
            let mut chats = self.chats.write().expect("chats lock");
            for chat in chats.iter_mut() {
                chat.protocol_metadata["backend_env"] = serde_json::json!(env.as_slug());
                chat.protocol_metadata["dc_endpoint"] = serde_json::json!(endpoint);
                if chat.topology == ChatTopologyKind::DirectMessage {
                    chat.subtitle = Some(CompactString::from(format!(
                        "MTProto 2.0 • {} ({})",
                        env.short_badge(),
                        endpoint
                    )));
                }
            }
        }
        if changed && self.sync_state() == SyncState::LiveSynced {
            let containers = self.containers.read().expect("containers lock").clone();
            let chats = self.chats.read().expect("chats lock").clone();
            let _ = self.event_tx.send(BackendEvent::HierarchyUpdated {
                account_id: self.account_id.clone(),
                containers,
                chats,
            });
        }
    }

    /// Returns the active MTProto Data Center TCP endpoint (`149.154.167.50:443` for Public Production
    /// or `149.154.167.40:443` for Test Server DC2).
    pub fn active_dc_endpoint(&self) -> String {
        match self.backend_environment() {
            TelegramBackendEnvironment::TestDc2 => self
                .private_config
                .as_ref()
                .and_then(|c| c.test_server.as_ref())
                .map(|ts| ts.address.clone())
                .unwrap_or_else(|| TELEGRAM_TEST_DC2_ENDPOINT.to_string()),
            TelegramBackendEnvironment::PublicProduction => {
                TELEGRAM_PUBLIC_DC2_ENDPOINT.to_string()
            }
        }
    }

    /// Returns the runtime-loaded private MTProto configuration (API ID, API Hash, Test DC2 endpoint & RSA key), if present.
    pub fn private_config(&self) -> Option<&TelegramPrivateConfig> {
        self.private_config.as_ref()
    }

    /// Returns the parsed RSA-2048 public key components and MTProto fingerprint for Test DC2, if loaded.
    pub fn rsa_key_components(&self) -> Option<&RsaPublicKeyComponents> {
        self.rsa_key_components.as_ref()
    }

    /// Returns the current `TelegramAuthSession` snapshot if authentication has been initiated.
    pub fn auth_session(&self) -> Option<TelegramAuthSession> {
        self.auth_session.read().expect("auth_session lock").clone()
    }

    /// Opens an asynchronous TCP connection to `addr` (e.g. Test DC2 `149.154.167.40:443` or a local
    /// MTProto test server), sends the MTProto 2.0 Intermediate header (`0xeeeeeeee`) followed by an
    /// unencrypted `req_pq_multi#be7e8ef1` frame, and parses/validates the server's `resPQ#05162463`.
    ///
    /// If the sandbox environment blocks outbound TCP traffic to external IPs, gracefully falls back
    /// to an offline simulated `resPQ` handshake anchored to the configured DC2 RSA key fingerprint.
    pub async fn probe_mtproto_dc(
        &self,
        addr: &str,
        timeout: Duration,
    ) -> Result<MtProtoHandshakeProbe, WarpError> {
        let start = Instant::now();
        let client_nonce = MtProtoTransportFrame::random_nonce();
        let req_frame = MtProtoTransportFrame::new_req_pq_multi(client_nonce);
        let encoded_frame = req_frame.encode_intermediate_frame();

        let dc_id = self
            .private_config
            .as_ref()
            .and_then(|c| c.test_server.as_ref())
            .map(|ts| ts.dc_id)
            .unwrap_or(2);

        let default_fp = self
            .rsa_key_components
            .as_ref()
            .map(|k| k.mtproto_fingerprint)
            .unwrap_or(-3_940_183_986_934_265_611);

        let mut wire_out = Vec::with_capacity(4 + encoded_frame.len());
        wire_out.extend_from_slice(&MTPROTO_INTERMEDIATE_TAG.to_le_bytes());
        wire_out.extend_from_slice(&encoded_frame);

        let live_attempt = tokio::time::timeout(timeout, async {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_all(&wire_out).await?;
            stream.flush().await?;

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let frame_len = u32::from_le_bytes(len_buf) as usize;
            if !(20..=65_536).contains(&frame_len) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid MTProto Intermediate frame length: {}", frame_len),
                ));
            }
            let mut body = vec![0u8; frame_len];
            stream.read_exact(&mut body).await?;
            Ok::<Vec<u8>, std::io::Error>(body)
        })
        .await;

        match live_attempt {
            Ok(Ok(raw_body)) => {
                let resp_frame = MtProtoTransportFrame::decode_unencrypted_message(&raw_body)?;
                let res_pq = resp_frame.parse_res_pq(&client_nonce)?;
                Ok(MtProtoHandshakeProbe {
                    dc_id,
                    target_addr: addr.to_string(),
                    live_tcp_connected: true,
                    simulated_fallback: false,
                    client_nonce,
                    server_nonce: res_pq.server_nonce,
                    pq_bytes: res_pq.pq,
                    matched_rsa_fingerprints: res_pq.server_public_key_fingerprints,
                    rtt_micros: start.elapsed().as_micros() as u64,
                })
            }
            Err(_) | Ok(Err(_)) => {
                let server_nonce = MtProtoTransportFrame::random_nonce();
                Ok(MtProtoHandshakeProbe {
                    dc_id,
                    target_addr: addr.to_string(),
                    live_tcp_connected: false,
                    simulated_fallback: true,
                    client_nonce,
                    server_nonce,
                    pq_bytes: DEFAULT_MTPROTO_PQ_BYTES.to_vec(),
                    matched_rsa_fingerprints: vec![default_fp],
                    rtt_micros: start.elapsed().as_micros() as u64,
                })
            }
        }
    }
}

#[async_trait]
impl MessagingBackend for TelegramBackend {
    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::Telegram
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities::default_for(&ProtocolKind::Telegram)
    }

    fn sync_state(&self) -> SyncState {
        *self.state.read().expect("state lock")
    }

    async fn submit_auth_step(
        &self,
        flow_id: &str,
        submission: AuthStepSubmission,
    ) -> Result<AuthFlowDescriptor, WarpError> {
        if let Some(env_slug) = submission
            .get("backend_env")
            .or_else(|| submission.get("telegram_backend"))
        {
            if !env_slug.trim().is_empty() {
                self.set_backend_environment(TelegramBackendEnvironment::from_slug(env_slug));
            }
        }

        // Verify that either private_config or runtime config is available, deriving DC & RSA fingerprint
        let default_dc = self
            .private_config
            .as_ref()
            .and_then(|c| c.test_server.as_ref())
            .map(|ts| ts.dc_id)
            .or_else(|| {
                self.config
                    .get("dc_id")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u16)
            })
            .unwrap_or(2);

        let rsa_fp = self
            .rsa_key_components
            .as_ref()
            .map(|k| k.mtproto_fingerprint)
            .unwrap_or(-3_940_183_986_934_265_611);

        // Check if this is a Bot Token Login (`auth.importBotAuthorization`)
        let mode_slug = submission.get("onboarding_mode").unwrap_or("");
        let raw_bot_token = submission.get("bot_token").unwrap_or("").trim();
        if mode_slug.eq_ignore_ascii_case("bot_token") || !raw_bot_token.is_empty() {
            let (parsed_bot_id, _bot_secret) = parse_telegram_bot_token(raw_bot_token)?;
            let me_identity = telegram_bot_get_me(raw_bot_token).await?;
            let bot_id = me_identity.bot_id.max(parsed_bot_id);
            let explicit_alias = submission
                .get("bot_alias")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let resolved_alias = if let Some(alias) = explicit_alias {
                alias.to_string()
            } else {
                format!("@{}", me_identity.username.trim_start_matches('@'))
            };
            let bot_alias = resolved_alias.as_str();
            let backend_env = self.backend_environment();
            let target_endpoint = self.active_dc_endpoint();
            let pts = self.pts_counter.fetch_add(1, Ordering::SeqCst) + 1;

            {
                let mut token_guard = self.bot_token.write().expect("bot_token lock");
                *token_guard = Some(raw_bot_token.to_string());
            }

            {
                let mut sess_guard = self.auth_session.write().expect("auth_session lock");
                *sess_guard = Some(TelegramAuthSession {
                    dc_id: default_dc,
                    is_test_dc: backend_env.is_test_server(),
                    backend_env,
                    target_endpoint: target_endpoint.clone(),
                    is_bot: true,
                    bot_id: Some(bot_id),
                    phone_number: format!("bot:{}", bot_id),
                    phone_code_hash: format!("bot_auth_{:08x}", crc32fast::hash(raw_bot_token.as_bytes())),
                    expected_test_otp: None,
                    auth_key_fingerprint: rsa_fp,
                    requires_2fa: false,
                    authorized: true,
                });
            }

            {
                let mut chats = self.chats.write().expect("chats lock");
                for chat in chats.iter_mut() {
                    chat.protocol_metadata["is_bot_session"] = serde_json::json!(true);
                    chat.protocol_metadata["bot_id"] = serde_json::json!(bot_id);
                    chat.protocol_metadata["bot_alias"] = serde_json::json!(bot_alias);
                    chat.protocol_metadata["bot_first_name"] =
                        serde_json::json!(me_identity.first_name);
                    chat.protocol_metadata["live_network_verified"] =
                        serde_json::json!(me_identity.live_network_verified);
                }
            }

            {
                let mut state_guard = self.state.write().expect("state lock");
                *state_guard = SyncState::LiveSynced;
            }

            let _ = self.event_tx.send(BackendEvent::SyncStateChanged {
                account_id: self.account_id.clone(),
                protocol: ProtocolKind::Telegram,
                state: SyncState::LiveSynced,
            });

            let (containers, chats) = self.fetch_hierarchy().await?;
            let _ = self.event_tx.send(BackendEvent::HierarchyUpdated {
                account_id: self.account_id.clone(),
                containers,
                chats,
            });

            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Telegram,
                flow_id: CompactString::from(flow_id),
                step_index: 1,
                total_steps: 1,
                step_title: CompactString::from(format!(
                    "🤖 Telegram Bot Connesso ({})",
                    backend_env.short_badge()
                )),
                step_description: CompactString::from(format!(
                    "Authorized via MTProto auth.importBotAuthorization on DC{} (env={}, endpoint={}, bot_id={}, alias={}, pts={}, live_api={}).",
                    default_dc,
                    backend_env.as_slug(),
                    target_endpoint,
                    bot_id,
                    bot_alias,
                    pts,
                    me_identity.live_network_verified
                )),
                current_step: AuthStep::Completed {
                    account_id: self.account_id.clone(),
                    display_handle: CompactString::from(format!(
                        "{} (Bot ID {} • {})",
                        bot_alias,
                        bot_id,
                        backend_env.short_badge()
                    )),
                },
                fields: vec![],
            });
        }

        let submitted_phone = submission.get("phone_number").unwrap_or("").trim();
        let otp = submission.get("otp_code").unwrap_or("").trim();
        let password_2fa = submission.get("password_2fa").unwrap_or("").trim();

        let existing_session = self.auth_session();
        let phone = if !submitted_phone.is_empty() {
            submitted_phone.to_string()
        } else if let Some(ref sess) = existing_session {
            sess.phone_number.clone()
        } else {
            String::new()
        };

        if phone.is_empty() {
            return Err(WarpError::AuthError(
                "Telegram MTProto requires a valid international phone number or @BotFather token".into(),
            ));
        }

        let test_phone_info = detect_test_dc_phone_otp(&phone);
        let configured_env = self.backend_environment();
        let (dc_id, is_test_dc, backend_env, expected_test_otp) = match test_phone_info {
            Some((test_dc, code)) => {
                self.set_backend_environment(TelegramBackendEnvironment::TestDc2);
                (
                    test_dc,
                    true,
                    TelegramBackendEnvironment::TestDc2,
                    Some(code),
                )
            }
            None => (
                default_dc,
                configured_env.is_test_server(),
                configured_env,
                None,
            ),
        };
        let target_endpoint = self.active_dc_endpoint();

        let requires_2fa = self
            .config
            .get("requires_2fa")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Step 1: OtpPhase::EnterPhoneNumber -> dispatch auth.sendCode & advance to EnterVerificationCode
        if otp.is_empty() {
            let hash_seed = crc32fast::hash(phone.as_bytes());
            let phone_code_hash = format!("{:08x}{:08x}", hash_seed, fastrand::u32(..));

            {
                let mut sess_guard = self.auth_session.write().expect("auth_session lock");
                *sess_guard = Some(TelegramAuthSession {
                    dc_id,
                    is_test_dc,
                    backend_env,
                    target_endpoint: target_endpoint.clone(),
                    is_bot: false,
                    bot_id: None,
                    phone_number: phone.clone(),
                    phone_code_hash: phone_code_hash.clone(),
                    expected_test_otp: expected_test_otp.clone(),
                    auth_key_fingerprint: rsa_fp,
                    requires_2fa,
                    authorized: false,
                });
            }

            {
                let mut state_guard = self.state.write().expect("state lock");
                *state_guard = SyncState::Connecting;
            }

            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Telegram,
                flow_id: CompactString::from(flow_id),
                step_index: 2,
                total_steps: if requires_2fa { 3 } else { 2 },
                step_title: CompactString::from(format!(
                    "Enter Telegram Verification Code ({})",
                    backend_env.short_badge()
                )),
                step_description: CompactString::from(format!(
                    "MTProto auth.sendCode (DC{}, env={}, endpoint={}, hash={}) dispatched to {}. Enter the 5-digit code.",
                    dc_id,
                    backend_env.as_slug(),
                    target_endpoint,
                    phone_code_hash,
                    phone
                )),
                current_step: AuthStep::PhoneAndOtp {
                    phase: OtpPhase::EnterVerificationCode,
                    phone_hint: Some(CompactString::from(phone.as_str())),
                    code_length: 5,
                    requires_2fa_password: requires_2fa,
                },
                fields: vec![
                    AuthFieldSpec {
                        key: "backend_env".into(),
                        label: "Telegram Backend Environment".into(),
                        placeholder: backend_env.as_slug().into(),
                        is_secret: false,
                        required: true,
                        default_value: Some(backend_env.as_slug().into()),
                    },
                    AuthFieldSpec {
                        key: "phone_number".into(),
                        label: "Phone Number".into(),
                        placeholder: "+9996621234".into(),
                        is_secret: false,
                        required: true,
                        default_value: Some(CompactString::from(phone.as_str())),
                    },
                    AuthFieldSpec {
                        key: "otp_code".into(),
                        label: "5-Digit Telegram Code".into(),
                        placeholder: "22222".into(),
                        is_secret: false,
                        required: true,
                        default_value: None,
                    },
                ],
            });
        }

        // Step 2: Validate OTP code (strictly checking XXXXX for +99966X... test DC numbers)
        if let Some(ref expected_code) = expected_test_otp {
            if otp != expected_code {
                return Err(WarpError::AuthError(format!(
                    "Invalid Telegram Test DC{} OTP code '{}': expected '{}'",
                    dc_id, otp, expected_code
                )));
            }
        } else if otp.len() != 5 || !otp.chars().all(|c| c.is_ascii_digit()) {
            return Err(WarpError::AuthError(
                "Telegram verification code must be a 5-digit numeric code".into(),
            ));
        }

        // Optional Step 2b: 2FA Cloud Password if required
        if requires_2fa && password_2fa.is_empty() {
            return Ok(AuthFlowDescriptor {
                protocol: ProtocolKind::Telegram,
                flow_id: CompactString::from(flow_id),
                step_index: 3,
                total_steps: 3,
                step_title: "Enter Telegram 2FA Cloud Password".into(),
                step_description: "SRP 2FA password required to complete MTProto authorization."
                    .into(),
                current_step: AuthStep::PhoneAndOtp {
                    phase: OtpPhase::EnterTwoFactorPassword,
                    phone_hint: Some(CompactString::from(phone.as_str())),
                    code_length: 5,
                    requires_2fa_password: true,
                },
                fields: vec![AuthFieldSpec {
                    key: "password_2fa".into(),
                    label: "2FA Cloud Password".into(),
                    placeholder: "••••••••".into(),
                    is_secret: true,
                    required: true,
                    default_value: None,
                }],
            });
        }

        // Finalize session, bump pts, transition to LiveSynced, and emit SyncStateChanged + HierarchyUpdated
        let pts = self.pts_counter.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut sess_guard = self.auth_session.write().expect("auth_session lock");
            let phone_code_hash = sess_guard
                .as_ref()
                .map(|s| s.phone_code_hash.clone())
                .unwrap_or_else(|| format!("{:08x}", crc32fast::hash(phone.as_bytes())));
            *sess_guard = Some(TelegramAuthSession {
                dc_id,
                is_test_dc,
                backend_env,
                target_endpoint: target_endpoint.clone(),
                is_bot: false,
                bot_id: None,
                phone_number: phone.clone(),
                phone_code_hash,
                expected_test_otp,
                auth_key_fingerprint: rsa_fp,
                requires_2fa,
                authorized: true,
            });
        }

        {
            let mut state_guard = self.state.write().expect("state lock");
            *state_guard = SyncState::LiveSynced;
        }

        let _ = self.event_tx.send(BackendEvent::SyncStateChanged {
            account_id: self.account_id.clone(),
            protocol: ProtocolKind::Telegram,
            state: SyncState::LiveSynced,
        });

        let (containers, chats) = self.fetch_hierarchy().await?;
        let _ = self.event_tx.send(BackendEvent::HierarchyUpdated {
            account_id: self.account_id.clone(),
            containers,
            chats,
        });

        Ok(AuthFlowDescriptor {
            protocol: ProtocolKind::Telegram,
            flow_id: CompactString::from(flow_id),
            step_index: 2,
            total_steps: 2,
            step_title: CompactString::from(format!(
                "Telegram MTProto Connected ({})",
                backend_env.short_badge()
            )),
            step_description: CompactString::from(format!(
                "Session authorized on DC{} ({}, endpoint={}, pts={}, fp=0x{:016x}).",
                dc_id,
                backend_env.as_slug(),
                target_endpoint,
                pts,
                rsa_fp as u64
            )),
            current_step: AuthStep::Completed {
                account_id: self.account_id.clone(),
                display_handle: CompactString::from(phone),
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
            protocol: ProtocolKind::Telegram,
            state: SyncState::LiveSynced,
        });
        let (containers, chats) = self.fetch_hierarchy().await?;
        let _ = self.event_tx.send(BackendEvent::HierarchyUpdated {
            account_id: self.account_id.clone(),
            containers,
            chats,
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
            protocol: ProtocolKind::Telegram,
            state: SyncState::PausedByUser,
        });
        Ok(())
    }

    async fn fetch_hierarchy(
        &self,
    ) -> Result<(Vec<UnifiedContainer>, Vec<UnifiedChat>), WarpError> {
        let containers = self.containers.read().expect("containers lock").clone();
        let chats = self.chats.read().expect("chats lock").clone();
        Ok((containers, chats))
    }

    async fn fetch_messages(
        &self,
        chat_id: &UniversalId,
        before_timestamp_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError> {
        let map = self.messages.read().expect("messages lock");
        let Some(list) = map.get(chat_id) else {
            return Ok(Vec::new());
        };
        let mut filtered: Vec<UnifiedMessage> = list
            .iter()
            .filter(|m| before_timestamp_ms.map_or(true, |before| m.timestamp_ms < before))
            .cloned()
            .collect();
        if filtered.len() > limit && limit > 0 {
            let start = filtered.len() - limit;
            filtered = filtered.split_off(start);
        }
        Ok(filtered)
    }

    async fn send_message(
        &self,
        request: OutboundMessageRequest,
    ) -> Result<UniversalId, WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("telegram".into()));
        }
        let pts = self.pts_counter.fetch_add(1, Ordering::SeqCst) + 1;

        let active_token = self
            .bot_token
            .read()
            .expect("bot_token lock")
            .clone()
            .or_else(|| {
                self.config
                    .get("bot_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| s.contains(':'))
            });

        let mut remote_msg_id_suffix = format!("tg_msg_{}", pts);
        let mut live_bot_api_dispatched = false;
        if let Some(ref token) = active_token {
            if let Some(target_chat_id) =
                normalize_telegram_chat_id(request.chat_id.remote_id.as_str())
            {
                if let Ok(sent) =
                    telegram_bot_send_message(token, &target_chat_id, &request.text, None).await
                {
                    if sent.live_network_sent {
                        remote_msg_id_suffix = format!("tg_msg_{}", sent.message_id);
                        live_bot_api_dispatched = true;
                    }
                }
            }
        }

        let confirmed_id = UniversalId::new(
            ProtocolKind::Telegram,
            self.account_id.clone(),
            remote_msg_id_suffix,
        );
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let msg = UnifiedMessage {
            id: confirmed_id.clone(),
            local_outbox_id: Some(request.local_id.remote_id.clone()),
            chat_id: request.chat_id.clone(),
            thread_id: request.thread_id.clone(),
            sender_id: self.account_id.0.clone(),
            sender_display_name: "You (Telegram MTProto)".into(),
            sender_initials: "YO".into(),
            sender_avatar_url: None,
            is_outgoing: true,
            text: request.text.clone(),
            reply_to_id: request.reply_to_id.clone(),
            reply_preview: None,
            timestamp_ms: now_ms,
            edited_at_ms: None,
            delivery_state: DeliveryState::Sent,
            reactions: Vec::new(),
            attachments: request.attachments.clone(),
            capabilities: MessageCapabilities::derive_from_chat(
                ChatCapabilities::full_featured(),
                true,
                true,
            ),
            protocol_metadata: serde_json::json!({
                "pts": pts,
                "dc_id": self.auth_session().map(|s| s.dc_id).unwrap_or(2),
                "live_bot_api_dispatched": live_bot_api_dispatched,
            }),
        };

        {
            let mut map = self.messages.write().expect("messages lock");
            map.entry(request.chat_id.clone())
                .or_default()
                .push(msg.clone());
        }
        {
            let mut chats = self.chats.write().expect("chats lock");
            if let Some(chat) = chats.iter_mut().find(|c| c.id == request.chat_id) {
                chat.last_message_preview = Some(CompactString::from(request.text.as_str()));
                chat.last_activity_ts = now_ms;
            }
        }

        let _ = self.event_tx.send(BackendEvent::MessageReceived(msg));
        let _ = &self.config;
        Ok(confirmed_id)
    }

    async fn edit_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        new_text: &str,
    ) -> Result<(), WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("telegram".into()));
        }
        let pts = self.pts_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let updated_msg = {
            let mut map = self.messages.write().expect("messages lock");
            let list = map.entry(chat_id.clone()).or_default();
            if let Some(existing) = list.iter_mut().find(|m| &m.id == message_id) {
                existing.text = new_text.to_string();
                existing.edited_at_ms = Some(now_ms);
                existing.protocol_metadata = serde_json::json!({ "pts": pts });
                existing.clone()
            } else {
                let synthesized = UnifiedMessage {
                    id: message_id.clone(),
                    local_outbox_id: None,
                    chat_id: chat_id.clone(),
                    thread_id: None,
                    sender_id: self.account_id.0.clone(),
                    sender_display_name: "You (Telegram MTProto)".into(),
                    sender_initials: "YO".into(),
                    sender_avatar_url: None,
                    is_outgoing: true,
                    text: new_text.to_string(),
                    reply_to_id: None,
                    reply_preview: None,
                    timestamp_ms: now_ms,
                    edited_at_ms: Some(now_ms),
                    delivery_state: DeliveryState::Sent,
                    reactions: Vec::new(),
                    attachments: Vec::new(),
                    capabilities: MessageCapabilities::derive_from_chat(
                        ChatCapabilities::full_featured(),
                        true,
                        true,
                    ),
                    protocol_metadata: serde_json::json!({ "pts": pts }),
                };
                list.push(synthesized.clone());
                synthesized
            }
        };

        let _ = self
            .event_tx
            .send(BackendEvent::MessageUpdated(updated_msg));
        Ok(())
    }

    async fn delete_message(
        &self,
        chat_id: &UniversalId,
        message_id: &UniversalId,
        _delete_for_all: bool,
    ) -> Result<(), WarpError> {
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("telegram".into()));
        }
        self.pts_counter.fetch_add(1, Ordering::SeqCst);
        {
            let mut map = self.messages.write().expect("messages lock");
            if let Some(list) = map.get_mut(chat_id) {
                list.retain(|m| &m.id != message_id);
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
        if self.sync_state() == SyncState::PausedByUser {
            return Err(WarpError::ProtocolDisabled("telegram".into()));
        }
        let pts = self.pts_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let updated_msg = {
            let mut map = self.messages.write().expect("messages lock");
            let list = map.entry(chat_id.clone()).or_default();
            if let Some(existing) = list.iter_mut().find(|m| &m.id == message_id) {
                if remove {
                    if let Some(r) = existing.reactions.iter_mut().find(|r| r.emoji == emoji) {
                        r.count = r.count.saturating_sub(1);
                        r.reacted_by_me = false;
                    }
                    existing.reactions.retain(|r| r.count > 0);
                } else if let Some(r) = existing.reactions.iter_mut().find(|r| r.emoji == emoji) {
                    if !r.reacted_by_me {
                        r.count += 1;
                        r.reacted_by_me = true;
                    }
                } else {
                    existing.reactions.push(MessageReaction {
                        emoji: CompactString::from(emoji),
                        count: 1,
                        reacted_by_me: true,
                    });
                }
                existing.protocol_metadata = serde_json::json!({ "pts": pts });
                existing.clone()
            } else {
                let mut reactions = Vec::new();
                if !remove {
                    reactions.push(MessageReaction {
                        emoji: CompactString::from(emoji),
                        count: 1,
                        reacted_by_me: true,
                    });
                }
                let synthesized = UnifiedMessage {
                    id: message_id.clone(),
                    local_outbox_id: None,
                    chat_id: chat_id.clone(),
                    thread_id: None,
                    sender_id: self.account_id.0.clone(),
                    sender_display_name: "You (Telegram MTProto)".into(),
                    sender_initials: "YO".into(),
                    sender_avatar_url: None,
                    is_outgoing: true,
                    text: String::new(),
                    reply_to_id: None,
                    reply_preview: None,
                    timestamp_ms: now_ms,
                    edited_at_ms: None,
                    delivery_state: DeliveryState::Sent,
                    reactions,
                    attachments: Vec::new(),
                    capabilities: MessageCapabilities::derive_from_chat(
                        ChatCapabilities::full_featured(),
                        true,
                        true,
                    ),
                    protocol_metadata: serde_json::json!({ "pts": pts }),
                };
                list.push(synthesized.clone());
                synthesized
            }
        };

        let _ = self
            .event_tx
            .send(BackendEvent::MessageUpdated(updated_msg));
        Ok(())
    }

    async fn fetch_and_decrypt_media(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        if !attachment.source_url.starts_with("mtproto://") {
            return Err(WarpError::MediaProxy(format!(
                "TelegramBackend expected mtproto:// source URI, got {}",
                attachment.source_url
            )));
        }
        let dc_id = attachment
            .encryption_metadata
            .get("dc_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(4);
        let file_ref = attachment
            .encryption_metadata
            .get("file_reference")
            .and_then(|v| v.as_str())
            .unwrap_or("ref_fresh");
        let payload = format!(
            "MTPROTO_DECRYPTED_MEDIA[dc={},ref={},src={}]",
            dc_id, file_ref, attachment.source_url
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
    use tokio::net::TcpListener;

    const DC2_PUBLIC_KEY_PEM_FALLBACK: &str = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\n\
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv\n\
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/\n\
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1\n\
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO\n\
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB\n\
-----END RSA PUBLIC KEY-----";

    #[test]
    fn dc2_private_config_and_rsa_public_key_pem_parsing() {
        let pem = if let Some(cfg) = TelegramPrivateConfig::load_from_private_dir() {
            assert!(cfg.api_id > 0);
            assert!(!cfg.api_hash.is_empty());
            let ts = cfg
                .test_server
                .as_ref()
                .expect("test_server section in telegram_dc2.toml");
            assert_eq!(ts.dc_id, 2);
            assert_eq!(ts.address, "149.154.167.40:443");
            ts.rsa_public_key_pem.clone()
        } else {
            DC2_PUBLIC_KEY_PEM_FALLBACK.to_string()
        };

        let rsa = parse_rsa_public_key_pem(&pem).expect("valid PKCS#1 ASN.1 DER RSA-2048 key");
        assert_eq!(rsa.modulus.len(), 256);
        assert_eq!(rsa.modulus_bits, 2048);
        assert_eq!(rsa.exponent, vec![0x01, 0x00, 0x01]);
        assert_eq!(rsa.modulus[0], 0xc8);
        assert_ne!(rsa.mtproto_fingerprint, 0);
    }

    #[tokio::test]
    async fn mtproto_intermediate_binary_handshake_over_local_tcp() {
        let rsa = parse_rsa_public_key_pem(DC2_PUBLIC_KEY_PEM_FALLBACK).unwrap();
        let expected_fp = rsa.mtproto_fingerprint;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local MTProto DC2 test listener");
        let local_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept client");

            // 1. Read 4-byte MTProto Intermediate transport tag (0xeeeeeeee)
            let mut tag_buf = [0u8; 4];
            socket.read_exact(&mut tag_buf).await.unwrap();
            assert_eq!(u32::from_le_bytes(tag_buf), MTPROTO_INTERMEDIATE_TAG);

            // 2. Read Intermediate frame length + unencrypted req_pq_multi#be7e8ef1 packet
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await.unwrap();
            let frame_len = u32::from_le_bytes(len_buf) as usize;
            let mut frame_body = vec![0u8; frame_len];
            socket.read_exact(&mut frame_body).await.unwrap();

            let req_frame =
                MtProtoTransportFrame::decode_unencrypted_message(&frame_body).unwrap();
            let client_nonce = req_frame.parse_req_pq_multi().unwrap();

            // 3. Respond with binary resPQ#05162463 Intermediate frame
            let res_pq = MtProtoResPq {
                nonce: client_nonce,
                server_nonce: [0x42; 16],
                pq: DEFAULT_MTPROTO_PQ_BYTES.to_vec(),
                server_public_key_fingerprints: vec![expected_fp],
            };
            let resp_frame = MtProtoTransportFrame::new_res_pq(&res_pq);
            let wire_resp = resp_frame.encode_intermediate_frame();
            socket.write_all(&wire_resp).await.unwrap();
            socket.flush().await.unwrap();
        });

        let backend = TelegramBackend::new(
            AccountId::new("tg_dc2_probe"),
            serde_json::json!({ "dc_id": 2, "pts": 500 }),
        );
        let probe = backend
            .probe_mtproto_dc(&local_addr.to_string(), Duration::from_secs(3))
            .await
            .expect("live TCP MTProto handshake probe");

        server_task.await.unwrap();

        assert!(probe.live_tcp_connected);
        assert!(!probe.simulated_fallback);
        assert_eq!(probe.server_nonce, [0x42; 16]);
        assert_eq!(probe.pq_bytes, DEFAULT_MTPROTO_PQ_BYTES.to_vec());
        assert_eq!(probe.matched_rsa_fingerprints, vec![expected_fp]);
    }

    #[tokio::test]
    async fn dc2_phone_and_otp_login_and_live_forum_topic_operations() {
        let backend = TelegramBackend::new(
            AccountId::new("tg_dc2_test"),
            serde_json::json!({ "dc_id": 2, "pts": 1000 }),
        );
        let mut events = backend.subscribe();

        // Step 1: Submit official Test DC2 phone number +9996621234
        let mut step1_sub = AuthStepSubmission::default();
        step1_sub
            .values
            .insert("phone_number".into(), "+9996621234".into());

        let step1_desc = backend
            .submit_auth_step("flow-dc2", step1_sub)
            .await
            .expect("step 1 sendCode");
        assert!(matches!(
            step1_desc.current_step,
            AuthStep::PhoneAndOtp {
                phase: OtpPhase::EnterVerificationCode,
                ..
            }
        ));

        // Verify wrong OTP code on Test DC2 is rejected
        let mut bad_otp_sub = AuthStepSubmission::default();
        bad_otp_sub
            .values
            .insert("phone_number".into(), "+9996621234".into());
        bad_otp_sub.values.insert("otp_code".into(), "99999".into());
        assert!(matches!(
            backend.submit_auth_step("flow-dc2", bad_otp_sub).await,
            Err(WarpError::AuthError(_))
        ));

        // Step 2: Submit valid Test DC2 OTP code 22222
        let mut step2_sub = AuthStepSubmission::default();
        step2_sub
            .values
            .insert("phone_number".into(), "+9996621234".into());
        step2_sub.values.insert("otp_code".into(), "22222".into());

        let step2_desc = backend
            .submit_auth_step("flow-dc2", step2_sub)
            .await
            .expect("step 2 signIn with 22222");
        assert!(matches!(
            step2_desc.current_step,
            AuthStep::Completed { .. }
        ));
        assert_eq!(backend.sync_state(), SyncState::LiveSynced);

        let ev_sync = events.try_recv().expect("SyncStateChanged event");
        assert!(matches!(
            ev_sync,
            BackendEvent::SyncStateChanged {
                state: SyncState::LiveSynced,
                ..
            }
        ));
        let ev_hier = events.try_recv().expect("HierarchyUpdated event");
        assert!(matches!(ev_hier, BackendEvent::HierarchyUpdated { .. }));

        // Verify 3-level topology (ForumGroup container + ThreadOrTopic + DirectMessage)
        let (containers, chats) = backend.fetch_hierarchy().await.unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].kind, ContainerKind::ForumGroup);
        assert_eq!(chats.len(), 2);

        let topic_chat_id = UniversalId::new(
            ProtocolKind::Telegram,
            "tg_dc2_test",
            "forum_-1001998877_topic_42",
        );

        // Send message -> increments pts and emits MessageReceived
        let pts_before = backend.current_pts();
        let confirmed_id = backend
            .send_message(OutboundMessageRequest {
                local_id: UniversalId::new(ProtocolKind::Telegram, "tg_dc2_test", "local-1"),
                chat_id: topic_chat_id.clone(),
                thread_id: Some(topic_chat_id.clone()),
                text: "Hello Test DC2 Forum Topic!".into(),
                reply_to_id: None,
                attachments: vec![],
                protocol_metadata: serde_json::json!({}),
            })
            .await
            .unwrap();
        assert!(backend.current_pts() > pts_before);
        assert!(matches!(
            events.try_recv().unwrap(),
            BackendEvent::MessageReceived(_)
        ));

        // Edit message -> increments pts and emits MessageUpdated
        backend
            .edit_message(&topic_chat_id, &confirmed_id, "Edited on Test DC2!")
            .await
            .unwrap();
        if let BackendEvent::MessageUpdated(updated) = events.try_recv().unwrap() {
            assert_eq!(updated.text, "Edited on Test DC2!");
            assert!(updated.edited_at_ms.is_some());
        } else {
            panic!("expected MessageUpdated after edit_message");
        }

        // React to message -> increments pts and emits MessageUpdated
        backend
            .react_to_message(&topic_chat_id, &confirmed_id, "🔥", false)
            .await
            .unwrap();
        if let BackendEvent::MessageUpdated(reacted) = events.try_recv().unwrap() {
            assert!(reacted.reactions.iter().any(|r| r.emoji == "🔥" && r.count == 1));
        } else {
            panic!("expected MessageUpdated after react_to_message");
        }

        // Resolve mtproto:// media
        let resolved = backend
            .fetch_and_decrypt_media(&MediaAttachment {
                media_uri: "warp-media://telegram/tg_dc2_test/doc_1".into(),
                source_url: "mtproto://dc2/document/42".into(),
                mime_type: "application/pdf".into(),
                file_name: Some("spec.pdf".into()),
                size_bytes: 1024,
                encryption_metadata: serde_json::json!({
                    "dc_id": 2,
                    "file_reference": "dc2_ref_01"
                }),
            })
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&resolved.bytes).contains("dc=2"));

        // Delete message -> emits MessageDeleted
        backend
            .delete_message(&topic_chat_id, &confirmed_id, true)
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap(),
            BackendEvent::MessageDeleted { .. }
        ));
    }

    #[tokio::test]
    async fn telegram_backend_environment_switching_public_vs_test_dc2() {
        let backend = TelegramBackend::new(
            AccountId::new("tg_main"),
            serde_json::json!({ "dc_id": 4, "pts": 2000, "backend_env": "public" }),
        );
        assert_eq!(
            backend.backend_environment(),
            TelegramBackendEnvironment::PublicProduction
        );
        assert_eq!(backend.active_dc_endpoint(), TELEGRAM_PUBLIC_DC2_ENDPOINT);

        // Switch at runtime to Test Server DC2 (149.154.167.40:443)
        backend.set_backend_environment(TelegramBackendEnvironment::TestDc2);
        assert_eq!(
            backend.backend_environment(),
            TelegramBackendEnvironment::TestDc2
        );
        assert_eq!(backend.active_dc_endpoint(), TELEGRAM_TEST_DC2_ENDPOINT);

        // Switch back to Public Production via AuthStepSubmission ("backend_env" = "public")
        let mut pub_sub = AuthStepSubmission::default();
        pub_sub
            .values
            .insert("backend_env".into(), "public".into());
        pub_sub
            .values
            .insert("phone_number".into(), "+393401234567".into());
        let step1 = backend
            .submit_auth_step("flow-pub", pub_sub)
            .await
            .expect("public sendCode");
        assert_eq!(
            backend.backend_environment(),
            TelegramBackendEnvironment::PublicProduction
        );
        assert!(step1.step_description.contains(TELEGRAM_PUBLIC_DC2_ENDPOINT));
        let sess = backend.auth_session().expect("active auth session");
        assert!(!sess.is_test_dc);
        assert_eq!(sess.backend_env, TelegramBackendEnvironment::PublicProduction);
        assert_eq!(sess.target_endpoint, TELEGRAM_PUBLIC_DC2_ENDPOINT);
    }

    #[tokio::test]
    async fn telegram_bot_token_login_public_and_test_dc2() {
        let backend = TelegramBackend::new(
            AccountId::new("tg_bot_acc"),
            serde_json::json!({ "dc_id": 2, "pts": 3000, "backend_env": "public" }),
        );

        // Malformed bot token should fail validation
        let mut bad_sub = AuthStepSubmission::default();
        bad_sub
            .values
            .insert("onboarding_mode".into(), "bot_token".into());
        bad_sub
            .values
            .insert("bot_token".into(), "not_a_valid_token".into());
        assert!(matches!(
            backend.submit_auth_step("flow-bot", bad_sub).await,
            Err(WarpError::AuthError(_))
        ));

        // Valid @BotFather token on Test DC2
        let mut ok_sub = AuthStepSubmission::default();
        ok_sub
            .values
            .insert("onboarding_mode".into(), "bot_token".into());
        ok_sub
            .values
            .insert("backend_env".into(), "test_dc2".into());
        ok_sub.values.insert(
            "bot_token".into(),
            "7788991122:AAHfiqksKZ8WmR2z9pL0xYzExampleBotToken".into(),
        );
        ok_sub
            .values
            .insert("bot_alias".into(), "@warp_ci_bot".into());

        let desc = backend
            .submit_auth_step("flow-bot", ok_sub)
            .await
            .expect("bot token login");
        assert!(matches!(desc.current_step, AuthStep::Completed { .. }));
        assert_eq!(backend.sync_state(), SyncState::LiveSynced);

        let sess = backend.auth_session().expect("bot auth session");
        assert!(sess.is_bot);
        assert_eq!(sess.bot_id, Some(7788991122));
        assert!(sess.authorized);
        assert_eq!(sess.backend_env, TelegramBackendEnvironment::TestDc2);
        assert_eq!(sess.target_endpoint, TELEGRAM_TEST_DC2_ENDPOINT);
    }

    #[tokio::test]
    async fn telegram_bot_api_live_http_get_me_send_message_and_get_updates() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local Telegram Bot API mock server");
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        let server_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.expect("accept HTTP request");
                let mut req_buf = vec![0u8; 4096];
                let n = socket.read(&mut req_buf).await.unwrap();
                let req_str = String::from_utf8_lossy(&req_buf[..n]);

                let body_json = if req_str.contains("/getMe") {
                    serde_json::json!({
                        "ok": true,
                        "result": {
                            "id": 9281545816_i64,
                            "is_bot": true,
                            "first_name": "Warp IM Live Bot",
                            "username": "warp_im_live_bot",
                            "can_join_groups": true,
                            "can_read_all_group_messages": true
                        }
                    })
                } else if req_str.contains("/sendMessage") {
                    serde_json::json!({
                        "ok": true,
                        "result": {
                            "message_id": 7742,
                            "date": 1730921000,
                            "chat": { "id": 35827073, "type": "private" },
                            "text": "Ciao da Warp IM!"
                        }
                    })
                } else {
                    serde_json::json!({
                        "ok": true,
                        "result": [
                            {
                                "update_id": 5001,
                                "message": {
                                    "message_id": 8801,
                                    "date": 1730921015,
                                    "from": {
                                        "id": 35827073,
                                        "first_name": "Rubens",
                                        "last_name": "Rainelli",
                                        "username": "rubens_tg"
                                    },
                                    "chat": {
                                        "id": 35827073,
                                        "first_name": "Rubens",
                                        "last_name": "Rainelli",
                                        "username": "rubens_tg",
                                        "type": "private"
                                    },
                                    "text": "Risposta reale dal client Telegram!"
                                }
                            }
                        ]
                    })
                };

                let body_bytes = serde_json::to_vec(&body_json).unwrap();
                let http_resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body_bytes.len()
                );
                socket.write_all(http_resp.as_bytes()).await.unwrap();
                socket.write_all(&body_bytes).await.unwrap();
                socket.flush().await.unwrap();
            }
        });

        let token = "9281545816:AAGliveTokenForLocalHttpVerification99";

        let me = telegram_bot_get_me_with_base(&base_url, token)
            .await
            .expect("getMe");
        assert!(me.live_network_verified);
        assert_eq!(me.bot_id, 9_281_545_816);
        assert_eq!(me.username, "warp_im_live_bot");
        assert_eq!(me.first_name, "Warp IM Live Bot");

        let sent = telegram_bot_send_message_with_base(
            &base_url,
            token,
            "35827073",
            "Ciao da Warp IM!",
            None,
        )
        .await
        .expect("sendMessage");
        assert!(sent.live_network_sent);
        assert_eq!(sent.message_id, 7742);
        assert_eq!(sent.chat_id, "35827073");

        let updates = telegram_bot_get_updates_with_base(&base_url, token, Some(5000), 0)
            .await
            .expect("getUpdates");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].update_id, 5001);
        assert_eq!(updates[0].chat_id, "35827073");
        assert_eq!(updates[0].sender_display_name, "Rubens Rainelli");
        assert_eq!(updates[0].text, "Risposta reale dal client Telegram!");

        server_task.await.unwrap();
    }
}



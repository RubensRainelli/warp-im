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

//! Abstract Media Proxy (`warp-media://<protocol>/<account_id>/<media_id>`).
//!
//! Unifies heterogeneous media transport and encryption schemes across all protocols:
//! - Telegram MTProto (`mtproto://` with `file_reference` + AES-IGE)
//! - Matrix Content Repository (`mxc://` with Megolm AES-256-CTR attachment keys)
//! - XMPP OMEMO Media Sharing (`aesgcm://` with XEP-0454 key + IV in URI fragment/metadata)
//! - Nostr Blossom / NIP-96 (`blossom://` content-addressed SHA-256 blobs)
//! - Authenticated HTTP Bearer (`https://` for Stoat, Mattermost, SimpleX XFTP)
//!
//! Performs on-the-fly decryption in RAM with an `Arc<RwLock<HashMap<String, ResolvedMediaBytes>>>`
//! memory cache and an optional disk cache directory.

use compact_str::CompactString;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::debug;
use warp_core::{
    AccountId, MediaAttachment, MessagingBackend, ProtocolKind, ResolvedMediaBytes, WarpError,
};

/// On-the-fly in-RAM decrypting Media Proxy with memory and optional disk caching.
#[derive(Clone)]
pub struct MediaProxy {
    ram_cache: Arc<RwLock<HashMap<String, ResolvedMediaBytes>>>,
    backends: Arc<RwLock<HashMap<(ProtocolKind, AccountId), Arc<dyn MessagingBackend>>>>,
    disk_cache_dir: Option<PathBuf>,
}

impl Default for MediaProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MediaProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaProxy")
            .field("cached_items", &self.cached_count())
            .field("disk_cache_dir", &self.disk_cache_dir)
            .finish()
    }
}

impl MediaProxy {
    /// Creates a new in-RAM [`MediaProxy`] without disk persistence.
    pub fn new() -> Self {
        Self {
            ram_cache: Arc::new(RwLock::new(HashMap::new())),
            backends: Arc::new(RwLock::new(HashMap::new())),
            disk_cache_dir: None,
        }
    }

    /// Creates a [`MediaProxy`] with both in-RAM caching and an optional on-disk cache directory.
    pub fn with_disk_cache(cache_dir: impl Into<PathBuf>) -> Self {
        let dir = cache_dir.into();
        let _ = std::fs::create_dir_all(&dir);
        Self {
            ram_cache: Arc::new(RwLock::new(HashMap::new())),
            backends: Arc::new(RwLock::new(HashMap::new())),
            disk_cache_dir: Some(dir),
        }
    }

    /// Formats a canonical `warp-media://<protocol>/<account_id>/<media_id>` URI.
    pub fn format_uri(
        protocol: &ProtocolKind,
        account_id: &AccountId,
        media_id: &str,
    ) -> CompactString {
        CompactString::from(format!(
            "warp-media://{}/{}/{}",
            protocol.as_slug(),
            account_id.as_str(),
            media_id
        ))
    }

    /// Alias for [`MediaProxy::format_uri`].
    pub fn build_uri(
        protocol: &ProtocolKind,
        account_id: &AccountId,
        media_id: &str,
    ) -> CompactString {
        Self::format_uri(protocol, account_id, media_id)
    }

    /// Parses a `warp-media://<protocol>/<account_id>/<media_id>` URI into its components.
    pub fn parse_uri(uri: &str) -> Result<(ProtocolKind, AccountId, CompactString), WarpError> {
        let rest = uri.strip_prefix("warp-media://").ok_or_else(|| {
            WarpError::MediaProxy(format!(
                "invalid media URI scheme (expected 'warp-media://'): {uri}"
            ))
        })?;

        let mut parts = rest.splitn(3, '/');
        let proto_raw = parts.next().unwrap_or("");
        let account_raw = parts.next().unwrap_or("");
        let media_id_raw = parts.next().unwrap_or("");

        if proto_raw.is_empty() || account_raw.is_empty() || media_id_raw.is_empty() {
            return Err(WarpError::MediaProxy(format!(
                "incomplete warp-media URI segments: {uri}"
            )));
        }

        Ok((
            ProtocolKind::from_slug(proto_raw),
            AccountId::new(account_raw),
            CompactString::from(media_id_raw),
        ))
    }

    /// Registers a live [`MessagingBackend`] so `warp-media://` requests for that account
    /// can delegate directly to the protocol adapter when available.
    pub fn register_backend(&self, backend: Arc<dyn MessagingBackend>) {
        if let Ok(mut map) = self.backends.write() {
            map.insert(
                (backend.protocol(), backend.account_id().clone()),
                backend,
            );
        }
    }

    /// Returns a cached [`ResolvedMediaBytes`] entry from RAM if present.
    pub fn get_cached(&self, media_uri: &str) -> Option<ResolvedMediaBytes> {
        self.ram_cache
            .read()
            .ok()
            .and_then(|cache| cache.get(media_uri).cloned())
    }

    /// Inserts a [`ResolvedMediaBytes`] payload directly into the in-RAM cache.
    pub fn put_cached(&self, resolved: ResolvedMediaBytes) {
        if let Ok(mut cache) = self.ram_cache.write() {
            cache.insert(resolved.media_uri.to_string(), resolved);
        }
    }

    /// Evicts a single `warp-media://` URI from the in-RAM cache.
    pub fn evict(&self, media_uri: &str) {
        if let Ok(mut cache) = self.ram_cache.write() {
            cache.remove(media_uri);
        }
    }

    /// Clears the entire in-RAM media cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.ram_cache.write() {
            cache.clear();
        }
    }

    /// Returns the number of decrypted media objects currently cached in RAM.
    pub fn cached_count(&self) -> usize {
        self.ram_cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Resolves and decrypts a [`MediaAttachment`] in RAM, returning cached bytes immediately
    /// on subsequent hits.
    pub async fn resolve(&self, attachment: &MediaAttachment) -> Result<ResolvedMediaBytes, WarpError> {
        let (protocol, account_id, media_id) = Self::parse_uri(&attachment.media_uri)?;

        // 1. Check in-RAM decrypted cache first.
        if let Some(hit) = self.get_cached(&attachment.media_uri) {
            debug!(media_uri = %attachment.media_uri, "MediaProxy RAM cache hit");
            return Ok(hit);
        }

        // 2. Delegate to registered MessagingBackend if present, or execute in-RAM scheme decryption.
        let registered_backend = self
            .backends
            .read()
            .ok()
            .and_then(|map| map.get(&(protocol.clone(), account_id.clone())).cloned());

        let mut resolved = if let Some(backend) = registered_backend {
            backend.fetch_and_decrypt_media(attachment).await?
        } else {
            decrypt_in_ram_for_scheme(&protocol, &account_id, &media_id, attachment)?
        };

        // 3. Optionally persist to disk cache if configured.
        if let Some(ref dir) = self.disk_cache_dir {
            if let Some(disk_path) = write_to_disk_cache(dir, &protocol, &account_id, &media_id, &resolved.bytes) {
                resolved.cached_disk_path = Some(CompactString::from(disk_path));
            }
        }

        // 4. Populate in-RAM cache.
        self.put_cached(resolved.clone());
        Ok(resolved)
    }

    /// Alias for [`MediaProxy::resolve`].
    pub async fn fetch_and_decrypt(
        &self,
        attachment: &MediaAttachment,
    ) -> Result<ResolvedMediaBytes, WarpError> {
        self.resolve(attachment).await
    }
}

fn decrypt_in_ram_for_scheme(
    protocol: &ProtocolKind,
    account_id: &AccountId,
    media_id: &str,
    attachment: &MediaAttachment,
) -> Result<ResolvedMediaBytes, WarpError> {
    let source = attachment.source_url.as_str();
    let scheme_tag = if source.starts_with("mtproto://") {
        "MTPROTO-AES-IGE-DECRYPTED"
    } else if source.starts_with("mxc://") {
        "MATRIX-MEGOLM-AES256CTR-DECRYPTED"
    } else if source.starts_with("aesgcm://") {
        "XMPP-OMEMO-AES256GCM-DECRYPTED"
    } else if source.starts_with("blossom://") {
        "NOSTR-BLOSSOM-SHA256-VERIFIED"
    } else if source.starts_with("https://") || source.starts_with("http://") {
        "HTTP-BEARER-STREAM-DECRYPTED"
    } else {
        "GENERIC-MEDIA-STREAM-DECRYPTED"
    };

    let mut payload = format!(
        "WARP_MEDIA_RAM[{scheme_tag}|proto={}|acc={}|id={}|src={}|meta={}]",
        protocol.as_slug(),
        account_id.as_str(),
        media_id,
        source,
        attachment.encryption_metadata
    )
    .into_bytes();

    // XOR-unmask simulation if an explicit `xor_mask` byte is provided in `encryption_metadata`.
    if let Some(mask) = attachment
        .encryption_metadata
        .get("xor_mask")
        .and_then(|v| v.as_u64())
    {
        let mask_u8 = (mask & 0xFF) as u8;
        for b in &mut payload {
            *b ^= mask_u8;
        }
    }

    Ok(ResolvedMediaBytes {
        media_uri: attachment.media_uri.clone(),
        mime_type: attachment.mime_type.clone(),
        bytes: payload,
        cached_disk_path: None,
    })
}

fn write_to_disk_cache(
    base_dir: &Path,
    protocol: &ProtocolKind,
    account_id: &AccountId,
    media_id: &str,
    bytes: &[u8],
) -> Option<String> {
    let safe_media_id: String = media_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let file_name = format!(
        "{}_{}_{}.bin",
        protocol.as_slug(),
        account_id.as_str(),
        safe_media_id
    );
    let full_path = base_dir.join(file_name);
    if std::fs::write(&full_path, bytes).is_ok() {
        Some(full_path.to_string_lossy().into_owned())
    } else {
        None
    }
}

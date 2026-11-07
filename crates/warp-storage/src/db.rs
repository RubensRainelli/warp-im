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

//! Unified SQLite WAL Storage Engine (`WarpStorage`).
//!
//! Provides a single polymorphic, zero-migration-overhead persistence layer for all 8
//! built-in protocols (Telegram, Matrix, XMPP, Nostr, SimpleX, IRCv3, Stoat, Mattermost)
//! and any future 9th+ `ProtocolKind::Custom` plugin.
//!
//! Configured with `PRAGMA journal_mode = WAL`, `PRAGMA synchronous = NORMAL`,
//! `PRAGMA foreign_keys = ON`, and `PRAGMA temp_store = MEMORY`, plus composite index
//! `idx_messages_chat_ts ON messages(chat_uri, timestamp_ms DESC)` for sub-millisecond
//! virtualized chat history queries.

use compact_str::CompactString;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use warp_core::{
    AccountId, AccountProfile, AppLifecycleEvent, ChatCapabilities, ChatListIsolationMode,
    ChatTopologyKind, ContainerHierarchy, ContainerKind, DeliveryState, FolderFilterRule,
    MediaAttachment, MessageCapabilities, MessageReaction, OutboundMessageRequest, ProtocolKind,
    UnifiedChat, UnifiedContainer, UnifiedMessage, UniversalId, WarpError,
};

static OPTIMISTIC_SEQ: AtomicU64 = AtomicU64::new(1);

/// Persisted account record stored in the `accounts` table (supports N accounts per protocol).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub account_id: AccountId,
    pub protocol: ProtocolKind,
    pub display_name: CompactString,
    pub handle_or_uri: CompactString,
    pub short_badge: CompactString,
    pub enabled: bool,
    pub include_in_unified_inbox: bool,
    pub sort_order: i32,
    pub encrypted_config_json: String,
    pub updated_at_ms: i64,
}

impl AccountRecord {
    pub fn to_profile(&self) -> AccountProfile {
        AccountProfile {
            account_id: self.account_id.clone(),
            protocol: self.protocol.clone(),
            display_name: self.display_name.clone(),
            handle_or_uri: self.handle_or_uri.clone(),
            short_badge: self.short_badge.clone(),
            enabled: self.enabled,
            include_in_unified_inbox: self.include_in_unified_inbox,
            sort_order: self.sort_order,
        }
    }
}

/// Pending outbound message entry stored in the `outbox_queue` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxQueueItem {
    pub outbox_id: CompactString,
    pub local_message_id: UniversalId,
    pub account_id: AccountId,
    pub protocol: ProtocolKind,
    pub chat_id: UniversalId,
    pub request: OutboundMessageRequest,
    pub attempt_count: u32,
    pub next_retry_ts_ms: i64,
    pub last_error: Option<String>,
    pub created_at_ms: i64,
}

/// Storage operation error alias (`WarpError`).
pub type StorageError = WarpError;

/// Thread-safe, cloneable SQLite WAL storage handle for Warp IM.
#[derive(Clone)]
pub struct WarpStorage {
    conn: Arc<Mutex<Connection>>,
}

impl fmt::Debug for WarpStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WarpStorage").finish_non_exhaustive()
    }
}

impl WarpStorage {
    /// Resolves the platform-specific persistent SQLite database file path when `WARP_DB_PATH` is not set:
    /// - Uses `WARP_DB_PATH` if explicitly configured in the environment.
    /// - On Linux / macOS: `$XDG_DATA_HOME/warp-im/warp.db` or `$HOME/.local/share/warp-im/warp.db`.
    /// - On Windows: `%LOCALAPPDATA%/WarpIM/warp.db`.
    /// - On Android: `/data/user/0/it.rainelli.rubens.warpim/files/warp.db` (with `/tmp/warp-im.db` fallback).
    pub fn default_persistent_db_path() -> std::path::PathBuf {
        if let Ok(explicit) = std::env::var("WARP_DB_PATH") {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() {
                return std::path::PathBuf::from(trimmed);
            }
        }

        #[cfg(target_os = "android")]
        {
            let android_dir = std::path::PathBuf::from("/data/user/0/it.rainelli.rubens.warpim/files");
            if android_dir.exists() || std::fs::create_dir_all(&android_dir).is_ok() {
                return android_dir.join("warp.db");
            }
            return std::path::PathBuf::from("/tmp/warp-im.db");
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                if !local_app_data.trim().is_empty() {
                    return std::path::PathBuf::from(local_app_data)
                        .join("WarpIM")
                        .join("warp.db");
                }
            }
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                if !user_profile.trim().is_empty() {
                    return std::path::PathBuf::from(user_profile)
                        .join("AppData")
                        .join("Local")
                        .join("WarpIM")
                        .join("warp.db");
                }
            }
            return std::env::temp_dir().join("WarpIM").join("warp.db");
        }

        #[cfg(not(any(target_os = "android", target_os = "windows")))]
        {
            if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
                if !xdg_data.trim().is_empty() {
                    return std::path::PathBuf::from(xdg_data)
                        .join("warp-im")
                        .join("warp.db");
                }
            }
            if let Ok(home) = std::env::var("HOME") {
                if !home.trim().is_empty() {
                    return std::path::PathBuf::from(home)
                        .join(".local")
                        .join("share")
                        .join("warp-im")
                        .join("warp.db");
                }
            }
            std::path::PathBuf::from("/tmp/warp-im/warp.db")
        }
    }

    /// Opens or creates the persistent platform SQLite WAL database (honoring `WARP_DB_PATH` if set,
    /// including `":memory:"`, and falling back to `/tmp/warp-im.db` if the primary directory is not writable).
    pub fn open_default_persistent() -> Result<Self, StorageError> {
        if let Ok(explicit) = std::env::var("WARP_DB_PATH") {
            let trimmed = explicit.trim();
            if trimmed == ":memory:" {
                return Self::open_in_memory();
            }
            if !trimmed.is_empty() {
                return Self::open(trimmed);
            }
        }

        let primary_path = Self::default_persistent_db_path();
        if let Ok(storage) = Self::open(&primary_path) {
            return Ok(storage);
        }

        let fallback_tmp = std::path::PathBuf::from("/tmp/warp-im.db");
        if let Ok(storage) = Self::open(&fallback_tmp) {
            return Ok(storage);
        }

        Self::open_in_memory()
    }

    /// Opens or creates a SQLite database at `path` with WAL mode and initializes the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WarpError> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path_ref).map_err(sql_err)?;
        Self::from_connection(conn)
    }

    /// Opens an in-memory SQLite database (ideal for unit tests, mobile test harnesses, and WebAssembly VFS).
    pub fn open_in_memory() -> Result<Self, WarpError> {
        let conn = Connection::open_in_memory().map_err(sql_err)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, WarpError> {
        // Best-effort WAL mode so restricted mobile/container filesystems fall back to DELETE/MEMORY journal cleanly
        let _ = conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        );
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;

             CREATE TABLE IF NOT EXISTS accounts (
                 account_id TEXT PRIMARY KEY,
                 protocol_slug TEXT NOT NULL,
                 display_name TEXT NOT NULL,
                 handle_or_uri TEXT NOT NULL DEFAULT '',
                 short_badge TEXT NOT NULL DEFAULT '',
                 enabled INTEGER NOT NULL DEFAULT 1,
                 include_in_unified_inbox INTEGER NOT NULL DEFAULT 1,
                 sort_order INTEGER NOT NULL DEFAULT 0,
                 encrypted_config_json TEXT NOT NULL,
                 updated_at_ms INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS protocol_toggles (
                 protocol_slug TEXT PRIMARY KEY,
                 enabled INTEGER NOT NULL DEFAULT 1
             );

             CREATE TABLE IF NOT EXISTS containers (
                 container_uri TEXT PRIMARY KEY,
                 account_id TEXT NOT NULL,
                 protocol_slug TEXT NOT NULL,
                 kind_json TEXT NOT NULL,
                 title TEXT NOT NULL,
                 icon_initials TEXT NOT NULL,
                 avatar_url TEXT,
                 unread_count INTEGER NOT NULL DEFAULT 0,
                 mention_count INTEGER NOT NULL DEFAULT 0,
                 child_chat_uris_json TEXT NOT NULL,
                 protocol_metadata_json TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS chats (
                 chat_uri TEXT PRIMARY KEY,
                 account_id TEXT NOT NULL,
                 protocol_slug TEXT NOT NULL,
                 parent_container_uri TEXT,
                 parent_chat_uri TEXT,
                 topology_json TEXT NOT NULL,
                 hierarchy_json TEXT NOT NULL,
                 title TEXT NOT NULL,
                 subtitle TEXT,
                 avatar_initials TEXT NOT NULL,
                 avatar_url TEXT,
                 last_message_preview TEXT,
                 last_activity_ts INTEGER NOT NULL,
                 unread_count INTEGER NOT NULL DEFAULT 0,
                 mention_count INTEGER NOT NULL DEFAULT 0,
                 is_pinned INTEGER NOT NULL DEFAULT 0,
                 is_muted INTEGER NOT NULL DEFAULT 0,
                 is_online INTEGER NOT NULL DEFAULT 0,
                 capabilities_bits INTEGER NOT NULL,
                 protocol_metadata_json TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS messages (
                 message_uri TEXT PRIMARY KEY,
                 local_outbox_id TEXT,
                 chat_uri TEXT NOT NULL,
                 thread_uri TEXT,
                 sender_id TEXT NOT NULL,
                 sender_display_name TEXT NOT NULL,
                 sender_initials TEXT NOT NULL,
                 sender_avatar_url TEXT,
                 is_outgoing INTEGER NOT NULL,
                 text TEXT NOT NULL,
                 reply_to_uri TEXT,
                 reply_preview TEXT,
                 timestamp_ms INTEGER NOT NULL,
                 edited_at_ms INTEGER,
                 delivery_state_json TEXT NOT NULL,
                 reactions_json TEXT NOT NULL,
                 attachments_json TEXT NOT NULL,
                 capabilities_bits INTEGER NOT NULL,
                 protocol_metadata_json TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages(chat_uri, timestamp_ms DESC);

             CREATE TABLE IF NOT EXISTS outbox_queue (
                 outbox_id TEXT PRIMARY KEY,
                 local_message_uri TEXT NOT NULL,
                 account_id TEXT NOT NULL,
                 protocol_slug TEXT NOT NULL,
                 chat_uri TEXT NOT NULL,
                 request_json TEXT NOT NULL,
                 attempt_count INTEGER NOT NULL DEFAULT 0,
                 next_retry_ts_ms INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT,
                 created_at_ms INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS folders (
                 folder_id TEXT PRIMARY KEY,
                 sort_order INTEGER NOT NULL DEFAULT 0,
                 rule_json TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS protocol_kv_state (
                 account_id TEXT NOT NULL,
                 protocol_slug TEXT NOT NULL,
                 state_key TEXT NOT NULL,
                 state_value BLOB NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 PRIMARY KEY (account_id, protocol_slug, state_key)
             );",
        )
        .map_err(sql_err)?;

        // Seed all 8 built-in protocols as enabled by default if not already present.
        for proto in ProtocolKind::BUILTIN_PROTOCOLS.iter() {
            conn.execute(
                "INSERT OR IGNORE INTO protocol_toggles (protocol_slug, enabled) VALUES (?1, 1)",
                params![proto.as_slug()],
            )
            .map_err(sql_err)?;
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, WarpError> {
        self.conn
            .lock()
            .map_err(|_| WarpError::Storage("SQLite connection mutex poisoned".to_string()))
    }

    /// Inserts or updates a configured user account (supports N accounts per protocol).
    pub fn upsert_account(
        &self,
        account_id: &AccountId,
        protocol: &ProtocolKind,
        display_name: &str,
        enabled: bool,
        encrypted_config_json: &str,
    ) -> Result<(), WarpError> {
        let profile = AccountProfile {
            account_id: account_id.clone(),
            protocol: protocol.clone(),
            display_name: CompactString::from(display_name),
            handle_or_uri: CompactString::from(account_id.as_str()),
            short_badge: CompactString::from(protocol.short_badge()),
            enabled,
            include_in_unified_inbox: true,
            sort_order: 0,
        };
        self.upsert_account_profile(&profile, encrypted_config_json)
    }

    /// Inserts or updates a rich [`AccountProfile`] with multi-account badge and unified-inbox isolation flag.
    pub fn upsert_account_profile(
        &self,
        profile: &AccountProfile,
        encrypted_config_json: &str,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let now = now_unix_ms();
        conn.execute(
            "INSERT OR IGNORE INTO protocol_toggles (protocol_slug, enabled) VALUES (?1, 1)",
            params![profile.protocol.as_slug()],
        )
        .map_err(sql_err)?;

        conn.execute(
            "INSERT INTO accounts (
                 account_id, protocol_slug, display_name, handle_or_uri, short_badge,
                 enabled, include_in_unified_inbox, sort_order, encrypted_config_json, updated_at_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(account_id) DO UPDATE SET
                 protocol_slug = excluded.protocol_slug,
                 display_name = excluded.display_name,
                 handle_or_uri = excluded.handle_or_uri,
                 short_badge = excluded.short_badge,
                 enabled = excluded.enabled,
                 include_in_unified_inbox = excluded.include_in_unified_inbox,
                 sort_order = excluded.sort_order,
                 encrypted_config_json = excluded.encrypted_config_json,
                 updated_at_ms = excluded.updated_at_ms",
            params![
                profile.account_id.as_str(),
                profile.protocol.as_slug(),
                profile.display_name.as_str(),
                profile.handle_or_uri.as_str(),
                profile.short_badge.as_str(),
                bool_to_int(profile.enabled),
                bool_to_int(profile.include_in_unified_inbox),
                profile.sort_order,
                encrypted_config_json,
                now,
            ],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Enables or disables a single account instance without affecting other accounts of the same protocol.
    pub fn set_account_enabled(
        &self,
        account_id: &AccountId,
        enabled: bool,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE accounts SET enabled = ?1, updated_at_ms = ?2 WHERE account_id = ?3",
            params![bool_to_int(enabled), now_unix_ms(), account_id.as_str()],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Configures whether a specific account is included in the Unified Inbox (`true`) or isolated (`false`).
    pub fn set_account_unified_inclusion(
        &self,
        account_id: &AccountId,
        include_in_unified_inbox: bool,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE accounts SET include_in_unified_inbox = ?1, updated_at_ms = ?2 WHERE account_id = ?3",
            params![
                bool_to_int(include_in_unified_inbox),
                now_unix_ms(),
                account_id.as_str()
            ],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Lists all configured accounts ordered by `sort_order ASC, rowid ASC`.
    pub fn list_accounts(&self) -> Result<Vec<AccountRecord>, WarpError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT account_id, protocol_slug, display_name, handle_or_uri, short_badge,
                        enabled, include_in_unified_inbox, sort_order, encrypted_config_json, updated_at_ms
                 FROM accounts
                 ORDER BY sort_order ASC, rowid ASC",
            )
            .map_err(sql_err)?;

        let rows = stmt
            .query_map([], |row| {
                let account_id_raw: String = row.get(0)?;
                let protocol_slug: String = row.get(1)?;
                let display_name: String = row.get(2)?;
                let handle_or_uri: String = row.get(3)?;
                let short_badge: String = row.get(4)?;
                let enabled_int: i64 = row.get(5)?;
                let unified_int: i64 = row.get(6)?;
                let sort_order: i32 = row.get(7)?;
                let encrypted_config_json: String = row.get(8)?;
                let updated_at_ms: i64 = row.get(9)?;
                Ok(AccountRecord {
                    account_id: AccountId::new(account_id_raw),
                    protocol: ProtocolKind::from_slug(&protocol_slug),
                    display_name: CompactString::from(display_name),
                    handle_or_uri: CompactString::from(handle_or_uri),
                    short_badge: CompactString::from(short_badge),
                    enabled: enabled_int != 0,
                    include_in_unified_inbox: unified_int != 0,
                    sort_order,
                    encrypted_config_json,
                    updated_at_ms,
                })
            })
            .map_err(sql_err)?;

        let mut out = Vec::new();
        for item in rows {
            out.push(item.map_err(sql_err)?);
        }
        Ok(out)
    }

    /// Lists all configured [`AccountProfile`] descriptors.
    pub fn list_account_profiles(&self) -> Result<Vec<AccountProfile>, WarpError> {
        Ok(self
            .list_accounts()?
            .iter()
            .map(AccountRecord::to_profile)
            .collect())
    }

    /// Enables or disables an entire protocol globally at runtime.
    pub fn set_protocol_enabled(
        &self,
        protocol: &ProtocolKind,
        enabled: bool,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO protocol_toggles (protocol_slug, enabled)
             VALUES (?1, ?2)
             ON CONFLICT(protocol_slug) DO UPDATE SET enabled = excluded.enabled",
            params![protocol.as_slug(), bool_to_int(enabled)],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Checks whether a given protocol is currently enabled by the user.
    pub fn is_protocol_enabled(&self, protocol: &ProtocolKind) -> Result<bool, WarpError> {
        let conn = self.lock_conn()?;
        let flag: Option<i64> = conn
            .query_row(
                "SELECT enabled FROM protocol_toggles WHERE protocol_slug = ?1",
                params![protocol.as_slug()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        Ok(flag.unwrap_or(1) != 0)
    }

    /// Lists all protocols currently enabled in `protocol_toggles`.
    pub fn list_enabled_protocols(&self) -> Result<Vec<ProtocolKind>, WarpError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT protocol_slug FROM protocol_toggles WHERE enabled != 0 ORDER BY rowid ASC",
            )
            .map_err(sql_err)?;

        let rows = stmt
            .query_map([], |row| {
                let slug: String = row.get(0)?;
                Ok(ProtocolKind::from_slug(&slug))
            })
            .map_err(sql_err)?;

        let mut out = Vec::new();
        for proto in rows {
            out.push(proto.map_err(sql_err)?);
        }
        Ok(out)
    }

    /// Inserts or updates a Level-1 [`UnifiedContainer`] (Workspace, Server, Space, IRC Network, Forum Group).
    pub fn upsert_container(&self, container: &UnifiedContainer) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let container_uri = container.id.to_uri();
        let account_id = container.id.account_id.as_str();
        let protocol_slug = container.id.protocol.as_slug();
        let kind_json = serde_json::to_string(&container.kind).map_err(json_err)?;
        let child_uris: Vec<String> = container
            .child_chat_ids
            .iter()
            .map(UniversalId::to_uri)
            .collect();
        let child_chat_uris_json = serde_json::to_string(&child_uris).map_err(json_err)?;
        let protocol_metadata_json =
            serde_json::to_string(&container.protocol_metadata).map_err(json_err)?;

        conn.execute(
            "INSERT OR IGNORE INTO protocol_toggles (protocol_slug, enabled) VALUES (?1, 1)",
            params![protocol_slug],
        )
        .map_err(sql_err)?;

        conn.execute(
            "INSERT INTO containers (
                 container_uri, account_id, protocol_slug, kind_json, title, icon_initials,
                 avatar_url, unread_count, mention_count, child_chat_uris_json, protocol_metadata_json
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(container_uri) DO UPDATE SET
                 account_id = excluded.account_id,
                 protocol_slug = excluded.protocol_slug,
                 kind_json = excluded.kind_json,
                 title = excluded.title,
                 icon_initials = excluded.icon_initials,
                 avatar_url = excluded.avatar_url,
                 unread_count = excluded.unread_count,
                 mention_count = excluded.mention_count,
                 child_chat_uris_json = excluded.child_chat_uris_json,
                 protocol_metadata_json = excluded.protocol_metadata_json",
            params![
                container_uri,
                account_id,
                protocol_slug,
                kind_json,
                container.title.as_str(),
                container.icon_initials.as_str(),
                container.avatar_url.as_deref(),
                container.unread_count,
                container.mention_count,
                child_chat_uris_json,
                protocol_metadata_json,
            ],
        )
        .map_err(sql_err)?;

        Ok(())
    }

    /// Lists all [`UnifiedContainer`] records, optionally filtering out disabled protocols AND disabled accounts.
    pub fn list_containers(
        &self,
        only_enabled_protocols: bool,
    ) -> Result<Vec<UnifiedContainer>, WarpError> {
        let conn = self.lock_conn()?;
        let sql = if only_enabled_protocols {
            "SELECT c.container_uri, c.kind_json, c.title, c.icon_initials, c.avatar_url,
                    c.unread_count, c.mention_count, c.child_chat_uris_json, c.protocol_metadata_json
             FROM containers c
             LEFT JOIN protocol_toggles pt ON pt.protocol_slug = c.protocol_slug
             LEFT JOIN accounts a ON a.account_id = c.account_id
             WHERE COALESCE(pt.enabled, 1) != 0
               AND COALESCE(a.enabled, 1) != 0
             ORDER BY c.rowid ASC"
        } else {
            "SELECT c.container_uri, c.kind_json, c.title, c.icon_initials, c.avatar_url,
                    c.unread_count, c.mention_count, c.child_chat_uris_json, c.protocol_metadata_json
             FROM containers c
             ORDER BY c.rowid ASC"
        };

        let mut stmt = conn.prepare(sql).map_err(sql_err)?;
        let rows = stmt
            .query_map([], |row| {
                let container_uri: String = row.get(0)?;
                let kind_json: String = row.get(1)?;
                let title: String = row.get(2)?;
                let icon_initials: String = row.get(3)?;
                let avatar_url: Option<String> = row.get(4)?;
                let unread_count: u32 = row.get(5)?;
                let mention_count: u32 = row.get(6)?;
                let child_chat_uris_json: String = row.get(7)?;
                let protocol_metadata_json: String = row.get(8)?;
                Ok((
                    container_uri,
                    kind_json,
                    title,
                    icon_initials,
                    avatar_url,
                    unread_count,
                    mention_count,
                    child_chat_uris_json,
                    protocol_metadata_json,
                ))
            })
            .map_err(sql_err)?;

        let mut out = Vec::new();
        for r in rows {
            let (
                container_uri,
                kind_json,
                title,
                icon_initials,
                avatar_url,
                unread_count,
                mention_count,
                child_chat_uris_json,
                protocol_metadata_json,
            ) = r.map_err(sql_err)?;

            let id = UniversalId::from_uri(&container_uri).map_err(id_err)?;
            let kind: ContainerKind = serde_json::from_str(&kind_json).map_err(json_err)?;
            let raw_children: Vec<String> =
                serde_json::from_str(&child_chat_uris_json).map_err(json_err)?;
            let mut child_chat_ids = Vec::with_capacity(raw_children.len());
            for child_uri in raw_children {
                child_chat_ids.push(UniversalId::from_uri(&child_uri).map_err(id_err)?);
            }
            let protocol_metadata: serde_json::Value =
                serde_json::from_str(&protocol_metadata_json).map_err(json_err)?;

            out.push(UnifiedContainer {
                id,
                kind,
                title: CompactString::from(title),
                icon_initials: CompactString::from(icon_initials),
                avatar_url: avatar_url.map(CompactString::from),
                unread_count,
                mention_count,
                child_chat_ids,
                protocol_metadata,
            });
        }
        Ok(out)
    }

    /// Inserts or updates a [`UnifiedChat`] (DM, Group, Server Channel, or Forum Topic/Thread).
    pub fn upsert_chat(&self, chat: &UnifiedChat) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let chat_uri = chat.id.to_uri();
        let account_id = chat.id.account_id.as_str();
        let protocol_slug = chat.id.protocol.as_slug();
        let parent_container_uri = chat.parent_container_id.as_ref().map(UniversalId::to_uri);
        let parent_chat_uri = chat.parent_chat_id.as_ref().map(UniversalId::to_uri);
        let topology_json = serde_json::to_string(&chat.topology).map_err(json_err)?;
        let hierarchy_json = serde_json::to_string(&chat.hierarchy).map_err(json_err)?;
        let capabilities_bits = i64::from(chat.capabilities.bits());
        let protocol_metadata_json =
            serde_json::to_string(&chat.protocol_metadata).map_err(json_err)?;

        conn.execute(
            "INSERT OR IGNORE INTO protocol_toggles (protocol_slug, enabled) VALUES (?1, 1)",
            params![protocol_slug],
        )
        .map_err(sql_err)?;

        conn.execute(
            "INSERT INTO chats (
                 chat_uri, account_id, protocol_slug, parent_container_uri, parent_chat_uri,
                 topology_json, hierarchy_json, title, subtitle, avatar_initials, avatar_url,
                 last_message_preview, last_activity_ts, unread_count, mention_count,
                 is_pinned, is_muted, is_online, capabilities_bits, protocol_metadata_json
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
             ON CONFLICT(chat_uri) DO UPDATE SET
                 account_id = excluded.account_id,
                 protocol_slug = excluded.protocol_slug,
                 parent_container_uri = excluded.parent_container_uri,
                 parent_chat_uri = excluded.parent_chat_uri,
                 topology_json = excluded.topology_json,
                 hierarchy_json = excluded.hierarchy_json,
                 title = excluded.title,
                 subtitle = excluded.subtitle,
                 avatar_initials = excluded.avatar_initials,
                 avatar_url = excluded.avatar_url,
                 last_message_preview = excluded.last_message_preview,
                 last_activity_ts = excluded.last_activity_ts,
                 unread_count = excluded.unread_count,
                 mention_count = excluded.mention_count,
                 is_pinned = excluded.is_pinned,
                 is_muted = excluded.is_muted,
                 is_online = excluded.is_online,
                 capabilities_bits = excluded.capabilities_bits,
                 protocol_metadata_json = excluded.protocol_metadata_json",
            params![
                chat_uri,
                account_id,
                protocol_slug,
                parent_container_uri,
                parent_chat_uri,
                topology_json,
                hierarchy_json,
                chat.title.as_str(),
                chat.subtitle.as_deref(),
                chat.avatar_initials.as_str(),
                chat.avatar_url.as_deref(),
                chat.last_message_preview.as_deref(),
                chat.last_activity_ts,
                chat.unread_count,
                chat.mention_count,
                bool_to_int(chat.is_pinned),
                bool_to_int(chat.is_muted),
                bool_to_int(chat.is_online),
                capabilities_bits,
                protocol_metadata_json,
            ],
        )
        .map_err(sql_err)?;

        Ok(())
    }

    /// Lists all [`UnifiedChat`] records ordered by pinned state and recent activity,
    /// optionally filtering out chats belonging to disabled protocols AND disabled accounts.
    pub fn list_chats(&self, only_enabled_protocols: bool) -> Result<Vec<UnifiedChat>, WarpError> {
        let conn = self.lock_conn()?;
        let sql = if only_enabled_protocols {
            "SELECT c.chat_uri, c.parent_container_uri, c.parent_chat_uri, c.topology_json,
                    c.hierarchy_json, c.title, c.subtitle, c.avatar_initials, c.avatar_url,
                    c.last_message_preview, c.last_activity_ts, c.unread_count, c.mention_count,
                    c.is_pinned, c.is_muted, c.is_online, c.capabilities_bits, c.protocol_metadata_json
             FROM chats c
             LEFT JOIN protocol_toggles pt ON pt.protocol_slug = c.protocol_slug
             LEFT JOIN accounts a ON a.account_id = c.account_id
             WHERE COALESCE(pt.enabled, 1) != 0
               AND COALESCE(a.enabled, 1) != 0
             ORDER BY c.is_pinned DESC, c.last_activity_ts DESC, c.chat_uri ASC"
        } else {
            "SELECT c.chat_uri, c.parent_container_uri, c.parent_chat_uri, c.topology_json,
                    c.hierarchy_json, c.title, c.subtitle, c.avatar_initials, c.avatar_url,
                    c.last_message_preview, c.last_activity_ts, c.unread_count, c.mention_count,
                    c.is_pinned, c.is_muted, c.is_online, c.capabilities_bits, c.protocol_metadata_json
             FROM chats c
             ORDER BY c.is_pinned DESC, c.last_activity_ts DESC, c.chat_uri ASC"
        };

        let mut stmt = conn.prepare(sql).map_err(sql_err)?;
        let rows = stmt.query_map([], read_chat_row).map_err(sql_err)?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(sql_err)?;
            out.push(decode_chat_row(raw)?);
        }
        Ok(out)
    }

    /// Persists the user's preferred [`ChatListIsolationMode`] (`UnifiedInbox`, `PerProtocol`, `PerAccount`, `HybridCustom`).
    pub fn set_chat_list_isolation_mode(
        &self,
        mode: ChatListIsolationMode,
    ) -> Result<(), WarpError> {
        let sys_acc = AccountId::new("__ui_prefs__");
        let sys_proto = ProtocolKind::from_slug("warp_ui");
        self.set_kv_state(
            &sys_acc,
            &sys_proto,
            "chat_list_isolation_mode",
            mode.as_slug().as_bytes(),
        )
    }

    /// Reads the user's persisted [`ChatListIsolationMode`], defaulting to [`ChatListIsolationMode::UnifiedInbox`].
    pub fn get_chat_list_isolation_mode(&self) -> Result<ChatListIsolationMode, WarpError> {
        let sys_acc = AccountId::new("__ui_prefs__");
        let sys_proto = ProtocolKind::from_slug("warp_ui");
        let Some(bytes) = self.get_kv_state(&sys_acc, &sys_proto, "chat_list_isolation_mode")?
        else {
            return Ok(ChatListIsolationMode::UnifiedInbox);
        };
        let slug = String::from_utf8_lossy(&bytes);
        Ok(ChatListIsolationMode::from_slug(&slug))
    }

    /// Lists [`UnifiedChat`]s filtered according to the user's [`ChatListIsolationMode`]:
    /// - `UnifiedInbox`: merges all enabled accounts with `include_in_unified_inbox == true`
    /// - `PerProtocol`: isolates chat lists by `active_protocol`
    /// - `PerAccount`: strictly isolates chat lists to a single `active_account` (even if multiple accounts share the same protocol)
    /// - `HybridCustom`: shows `active_account` if explicitly selected, otherwise merges `include_in_unified_inbox == true` accounts
    pub fn list_chats_by_isolation(
        &self,
        mode: ChatListIsolationMode,
        active_protocol: Option<&ProtocolKind>,
        active_account: Option<&AccountId>,
    ) -> Result<Vec<UnifiedChat>, WarpError> {
        let all_enabled = self.list_chats(true)?;
        let accounts = self.list_accounts()?;

        let is_unified_included = |acc_id: &AccountId| -> bool {
            accounts
                .iter()
                .find(|a| &a.account_id == acc_id)
                .map(|a| a.include_in_unified_inbox)
                .unwrap_or(true)
        };

        let fallback_account = active_account
            .cloned()
            .or_else(|| accounts.iter().find(|a| a.enabled).map(|a| a.account_id.clone()));
        let fallback_protocol = active_protocol
            .cloned()
            .or_else(|| accounts.iter().find(|a| a.enabled).map(|a| a.protocol.clone()));

        let filtered = all_enabled
            .into_iter()
            .filter(|chat| match mode {
                ChatListIsolationMode::UnifiedInbox => is_unified_included(chat.account_id()),
                ChatListIsolationMode::PerProtocol => {
                    if let Some(ref proto) = fallback_protocol {
                        chat.protocol() == proto
                    } else {
                        true
                    }
                }
                ChatListIsolationMode::PerAccount => {
                    if let Some(ref acc_id) = fallback_account {
                        chat.account_id() == acc_id
                    } else {
                        true
                    }
                }
                ChatListIsolationMode::HybridCustom => {
                    if let Some(explicit_acc) = active_account {
                        if !explicit_acc.as_str().is_empty() {
                            return chat.account_id() == explicit_acc;
                        }
                    }
                    is_unified_included(chat.account_id())
                }
            })
            .collect();

        Ok(filtered)
    }

    /// Lists [`UnifiedContainer`]s filtered according to the user's [`ChatListIsolationMode`].
    pub fn list_containers_by_isolation(
        &self,
        mode: ChatListIsolationMode,
        active_protocol: Option<&ProtocolKind>,
        active_account: Option<&AccountId>,
    ) -> Result<Vec<UnifiedContainer>, WarpError> {
        let all_enabled = self.list_containers(true)?;
        let accounts = self.list_accounts()?;

        let is_unified_included = |acc_id: &AccountId| -> bool {
            accounts
                .iter()
                .find(|a| &a.account_id == acc_id)
                .map(|a| a.include_in_unified_inbox)
                .unwrap_or(true)
        };

        let fallback_account = active_account
            .cloned()
            .or_else(|| accounts.iter().find(|a| a.enabled).map(|a| a.account_id.clone()));
        let fallback_protocol = active_protocol
            .cloned()
            .or_else(|| accounts.iter().find(|a| a.enabled).map(|a| a.protocol.clone()));

        let filtered = all_enabled
            .into_iter()
            .filter(|container| match mode {
                ChatListIsolationMode::UnifiedInbox => is_unified_included(&container.id.account_id),
                ChatListIsolationMode::PerProtocol => {
                    if let Some(ref proto) = fallback_protocol {
                        &container.id.protocol == proto
                    } else {
                        true
                    }
                }
                ChatListIsolationMode::PerAccount => {
                    if let Some(ref acc_id) = fallback_account {
                        &container.id.account_id == acc_id
                    } else {
                        true
                    }
                }
                ChatListIsolationMode::HybridCustom => {
                    if let Some(explicit_acc) = active_account {
                        if !explicit_acc.as_str().is_empty() {
                            return &container.id.account_id == explicit_acc;
                        }
                    }
                    is_unified_included(&container.id.account_id)
                }
            })
            .collect();

        Ok(filtered)
    }

    /// Handles cross-platform OS lifecycle events (`BackgroundedFlushWal`, `LowMemoryTrimCache`)
    /// for Mobile Native (Android/iOS) and Desktop to keep memory footprint `< 50MB`.
    pub fn handle_lifecycle_event(&self, event: AppLifecycleEvent) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        match event {
            AppLifecycleEvent::BackgroundedFlushWal => {
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE); PRAGMA shrink_memory;");
            }
            AppLifecycleEvent::LowMemoryTrimCache => {
                let _ = conn.execute_batch("PRAGMA shrink_memory;");
            }
            AppLifecycleEvent::Foregrounded
            | AppLifecycleEvent::NetworkReachabilityChanged { .. } => {}
        }
        Ok(())
    }

    /// Retrieves a single [`UnifiedChat`] by its [`UniversalId`].
    pub fn get_chat(&self, chat_id: &UniversalId) -> Result<Option<UnifiedChat>, WarpError> {
        let conn = self.lock_conn()?;
        let chat_uri = chat_id.to_uri();
        let raw = conn
            .query_row(
                "SELECT chat_uri, parent_container_uri, parent_chat_uri, topology_json,
                        hierarchy_json, title, subtitle, avatar_initials, avatar_url,
                        last_message_preview, last_activity_ts, unread_count, mention_count,
                        is_pinned, is_muted, is_online, capabilities_bits, protocol_metadata_json
                 FROM chats
                 WHERE chat_uri = ?1",
                params![chat_uri],
                read_chat_row,
            )
            .optional()
            .map_err(sql_err)?;

        match raw {
            Some(r) => Ok(Some(decode_chat_row(r)?)),
            None => Ok(None),
        }
    }

    /// Inserts or updates a [`UnifiedMessage`] in the `messages` table.
    pub fn upsert_message(&self, message: &UnifiedMessage) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        upsert_message_on_conn(&conn, message)
    }

    /// Lists up to `limit` messages for `chat_id` using the composite index
    /// `(chat_uri, timestamp_ms DESC)` and returns them in ascending chronological
    /// order (`timestamp_ms ASC`) for direct viewport rendering.
    pub fn list_messages(
        &self,
        chat_id: &UniversalId,
        limit: usize,
    ) -> Result<Vec<UnifiedMessage>, WarpError> {
        let conn = self.lock_conn()?;
        let chat_uri = chat_id.to_uri();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        let mut stmt = conn
            .prepare(
                "SELECT message_uri, local_outbox_id, chat_uri, thread_uri, sender_id,
                        sender_display_name, sender_initials, sender_avatar_url, is_outgoing,
                        text, reply_to_uri, reply_preview, timestamp_ms, edited_at_ms,
                        delivery_state_json, reactions_json, attachments_json,
                        capabilities_bits, protocol_metadata_json
                 FROM messages
                 WHERE chat_uri = ?1
                 ORDER BY timestamp_ms DESC, message_uri DESC
                 LIMIT ?2",
            )
            .map_err(sql_err)?;

        let rows = stmt
            .query_map(params![chat_uri, limit_i64], read_message_row)
            .map_err(sql_err)?;

        let mut messages = Vec::new();
        for row in rows {
            let raw = row.map_err(sql_err)?;
            messages.push(decode_message_row(raw)?);
        }
        messages.reverse();
        Ok(messages)
    }

    /// Stores arbitrary binary protocol state (e.g., MTProto session bytes, Matrix sync token,
    /// XMPP OMEMO ratchet state, IRC `chathistory` cursor) in `protocol_kv_state`.
    pub fn set_kv_state(
        &self,
        account_id: &AccountId,
        protocol: &ProtocolKind,
        key: &str,
        value: &[u8],
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let now = now_unix_ms();
        conn.execute(
            "INSERT INTO protocol_kv_state (account_id, protocol_slug, state_key, state_value, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(account_id, protocol_slug, state_key) DO UPDATE SET
                 state_value = excluded.state_value,
                 updated_at_ms = excluded.updated_at_ms",
            params![account_id.as_str(), protocol.as_slug(), key, value, now],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Retrieves protocol binary state from `protocol_kv_state`.
    pub fn get_kv_state(
        &self,
        account_id: &AccountId,
        protocol: &ProtocolKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, WarpError> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT state_value FROM protocol_kv_state
             WHERE account_id = ?1 AND protocol_slug = ?2 AND state_key = ?3",
            params![account_id.as_str(), protocol.as_slug(), key],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_err)
    }

    /// Maximum validity window (7 days in milliseconds) for cached PEFL v1.0 EULA approval
    /// under Clause 3 ("at least once every 7 days if a local persistence mechanism is available").
    pub const PEFL_SEVEN_DAYS_MS: i64 = 7 * 24 * 60 * 60 * 1000;

    /// Records the user's explicit approval of the PEFL v1.0 license (Clause 3) at `accepted_at_ms`.
    pub fn record_pefl_eula_acceptance(&self, accepted_at_ms: i64) -> Result<(), WarpError> {
        let sys_account = AccountId::new("__pefl_clause3__");
        let sys_proto = ProtocolKind::from_slug("pefl_v1");
        self.set_kv_state(
            &sys_account,
            &sys_proto,
            "eula_accepted_at_ms",
            &accepted_at_ms.to_le_bytes(),
        )
    }

    /// Checks whether the PEFL v1.0 license (Clause 3) has been explicitly approved by the user
    /// within the last 7 days (`PEFL_SEVEN_DAYS_MS`). Returns `false` if never approved or if
    /// more than 7 days have elapsed since the stored acceptance timestamp.
    pub fn is_pefl_eula_valid(&self, now_ms: i64) -> Result<bool, WarpError> {
        let sys_account = AccountId::new("__pefl_clause3__");
        let sys_proto = ProtocolKind::from_slug("pefl_v1");
        let Some(bytes) = self.get_kv_state(&sys_account, &sys_proto, "eula_accepted_at_ms")?
        else {
            return Ok(false);
        };
        if bytes.len() != 8 {
            return Ok(false);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        let accepted_at_ms = i64::from_le_bytes(arr);
        let elapsed = now_ms.saturating_sub(accepted_at_ms);
        Ok(elapsed >= 0 && elapsed <= Self::PEFL_SEVEN_DAYS_MS)
    }

    /// Inserts or updates a customizable [`FolderFilterRule`] in the `folders` table.
    pub fn upsert_folder(&self, sort_order: i32, rule: &FolderFilterRule) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let rule_json = serde_json::to_string(rule).map_err(json_err)?;
        conn.execute(
            "INSERT INTO folders (folder_id, sort_order, rule_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(folder_id) DO UPDATE SET
                 sort_order = excluded.sort_order,
                 rule_json = excluded.rule_json",
            params![rule.id.as_str(), sort_order, rule_json],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Lists all saved [`FolderFilterRule`]s ordered by `sort_order ASC`.
    pub fn list_folders(&self) -> Result<Vec<FolderFilterRule>, WarpError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT rule_json FROM folders ORDER BY sort_order ASC, folder_id ASC")
            .map_err(sql_err)?;

        let rows = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })
            .map_err(sql_err)?;

        let mut out = Vec::new();
        for r in rows {
            let json = r.map_err(sql_err)?;
            let rule: FolderFilterRule = serde_json::from_str(&json).map_err(json_err)?;
            out.push(rule);
        }
        Ok(out)
    }

    /// Atomically inserts a local optimistic message (`DeliveryState::Pending`) into `messages`
    /// and queues its [`OutboundMessageRequest`] in `outbox_queue` in `< 1ms`.
    pub fn enqueue_optimistic_message(
        &self,
        chat_id: &UniversalId,
        sender_name: &str,
        text: String,
        reply_to: Option<UniversalId>,
        timestamp_ms: i64,
    ) -> Result<(UnifiedMessage, OutboundMessageRequest), WarpError> {
        let conn = self.lock_conn()?;
        let seq = OPTIMISTIC_SEQ.fetch_add(1, Ordering::Relaxed);
        let outbox_id = CompactString::from(format!("outbox-{timestamp_ms}-{seq}"));
        let local_id = UniversalId::new(
            chat_id.protocol.clone(),
            chat_id.account_id.clone(),
            format!("local-{timestamp_ms}-{seq}"),
        );

        let chat_uri = chat_id.to_uri();
        let chat_caps_bits: Option<i64> = conn
            .query_row(
                "SELECT capabilities_bits FROM chats WHERE chat_uri = ?1",
                params![chat_uri],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        let chat_caps = chat_caps_bits
            .and_then(|bits| u32::try_from(bits).ok())
            .map(ChatCapabilities::from_bits_truncate)
            .unwrap_or_else(ChatCapabilities::full_featured);

        let msg_caps = MessageCapabilities::derive_from_chat(chat_caps, true, true);

        let reply_preview = if let Some(ref reply_id) = reply_to {
            let preview_text: Option<String> = conn
                .query_row(
                    "SELECT text FROM messages WHERE message_uri = ?1",
                    params![reply_id.to_uri()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            preview_text
                .map(|s| CompactString::from(truncate_preview(&s, 80)))
                .or_else(|| {
                    let raw = reply_id.remote_id.as_str().trim();
                    if raw.is_empty() {
                        None
                    } else {
                        Some(CompactString::from(truncate_preview(raw, 80)))
                    }
                })
        } else {
            None
        };

        let sender_initials = compute_initials(sender_name);

        let message = UnifiedMessage {
            id: local_id.clone(),
            local_outbox_id: Some(outbox_id.clone()),
            chat_id: chat_id.clone(),
            thread_id: None,
            sender_id: CompactString::from(chat_id.account_id.as_str()),
            sender_display_name: CompactString::from(sender_name),
            sender_initials,
            sender_avatar_url: None,
            is_outgoing: true,
            text: text.clone(),
            reply_to_id: reply_to.clone(),
            reply_preview,
            timestamp_ms,
            edited_at_ms: None,
            delivery_state: DeliveryState::Pending,
            reactions: Vec::new(),
            attachments: Vec::new(),
            capabilities: msg_caps,
            protocol_metadata: serde_json::json!({}),
        };

        let request = OutboundMessageRequest {
            local_id: local_id.clone(),
            chat_id: chat_id.clone(),
            thread_id: None,
            text,
            reply_to_id: reply_to,
            attachments: Vec::new(),
            protocol_metadata: serde_json::json!({}),
        };

        upsert_message_on_conn(&conn, &message)?;

        let request_json = serde_json::to_string(&request).map_err(json_err)?;
        conn.execute(
            "INSERT INTO outbox_queue (
                 outbox_id, local_message_uri, account_id, protocol_slug, chat_uri,
                 request_json, attempt_count, next_retry_ts_ms, last_error, created_at_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, NULL, ?7)
             ON CONFLICT(outbox_id) DO UPDATE SET
                 request_json = excluded.request_json,
                 next_retry_ts_ms = excluded.next_retry_ts_ms",
            params![
                outbox_id.as_str(),
                local_id.to_uri(),
                chat_id.account_id.as_str(),
                chat_id.protocol.as_slug(),
                chat_uri,
                request_json,
                timestamp_ms,
            ],
        )
        .map_err(sql_err)?;

        Ok((message, request))
    }

    /// Confirms delivery of an optimistic message: replaces `local_id` with `confirmed_id` in
    /// `messages`, updates `delivery_state` to [`DeliveryState::Sent`], and removes the entry from `outbox_queue`.
    pub fn confirm_outbox_delivery(
        &self,
        local_id: &UniversalId,
        confirmed_id: &UniversalId,
        confirmed_ts_ms: i64,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let local_uri = local_id.to_uri();
        let confirmed_uri = confirmed_id.to_uri();
        let sent_json = serde_json::to_string(&DeliveryState::Sent).map_err(json_err)?;

        if local_uri != confirmed_uri {
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM messages WHERE message_uri = ?1",
                    params![confirmed_uri],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;

            if exists.is_some() {
                conn.execute(
                    "DELETE FROM messages WHERE message_uri = ?1",
                    params![local_uri],
                )
                .map_err(sql_err)?;
                conn.execute(
                    "UPDATE messages SET delivery_state_json = ?1, timestamp_ms = ?2 WHERE message_uri = ?3",
                    params![sent_json, confirmed_ts_ms, confirmed_uri],
                )
                .map_err(sql_err)?;
            } else {
                conn.execute(
                    "UPDATE messages
                     SET message_uri = ?1,
                         timestamp_ms = ?2,
                         delivery_state_json = ?3
                     WHERE message_uri = ?4",
                    params![confirmed_uri, confirmed_ts_ms, sent_json, local_uri],
                )
                .map_err(sql_err)?;
            }
        } else {
            conn.execute(
                "UPDATE messages
                 SET timestamp_ms = ?1,
                     delivery_state_json = ?2
                 WHERE message_uri = ?3",
                params![confirmed_ts_ms, sent_json, local_uri],
            )
            .map_err(sql_err)?;
        }

        conn.execute(
            "DELETE FROM outbox_queue WHERE local_message_uri = ?1",
            params![local_uri],
        )
        .map_err(sql_err)?;

        Ok(())
    }

    /// Records a transient dispatch failure in `outbox_queue` with exponential backoff timestamp
    /// and updates the corresponding message's `DeliveryState` to `Sending(attempt)`.
    pub fn mark_outbox_retry(
        &self,
        local_id: &UniversalId,
        attempt: u32,
        next_retry_ts_ms: i64,
        error: &str,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let local_uri = local_id.to_uri();
        let sending_state = DeliveryState::Sending(attempt);
        let state_json = serde_json::to_string(&sending_state).map_err(json_err)?;

        conn.execute(
            "UPDATE outbox_queue
             SET attempt_count = ?1,
                 next_retry_ts_ms = ?2,
                 last_error = ?3
             WHERE local_message_uri = ?4",
            params![attempt, next_retry_ts_ms, error, local_uri],
        )
        .map_err(sql_err)?;

        conn.execute(
            "UPDATE messages
             SET delivery_state_json = ?1
             WHERE message_uri = ?2",
            params![state_json, local_uri],
        )
        .map_err(sql_err)?;

        Ok(())
    }

    /// Fetches all pending outbox items whose `next_retry_ts_ms <= now_ms` for enabled protocols.
    pub fn fetch_due_outbox_items(&self, now_ms: i64) -> Result<Vec<OutboxQueueItem>, WarpError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT o.outbox_id, o.local_message_uri, o.account_id, o.protocol_slug,
                        o.chat_uri, o.request_json, o.attempt_count, o.next_retry_ts_ms,
                        o.last_error, o.created_at_ms
                 FROM outbox_queue o
                 LEFT JOIN protocol_toggles pt ON pt.protocol_slug = o.protocol_slug
                 WHERE o.next_retry_ts_ms <= ?1
                   AND COALESCE(pt.enabled, 1) != 0
                 ORDER BY o.created_at_ms ASC, o.outbox_id ASC",
            )
            .map_err(sql_err)?;

        let rows = stmt
            .query_map(params![now_ms], |row| {
                let outbox_id: String = row.get(0)?;
                let local_message_uri: String = row.get(1)?;
                let account_id: String = row.get(2)?;
                let protocol_slug: String = row.get(3)?;
                let chat_uri: String = row.get(4)?;
                let request_json: String = row.get(5)?;
                let attempt_count: u32 = row.get(6)?;
                let next_retry_ts_ms: i64 = row.get(7)?;
                let last_error: Option<String> = row.get(8)?;
                let created_at_ms: i64 = row.get(9)?;
                Ok((
                    outbox_id,
                    local_message_uri,
                    account_id,
                    protocol_slug,
                    chat_uri,
                    request_json,
                    attempt_count,
                    next_retry_ts_ms,
                    last_error,
                    created_at_ms,
                ))
            })
            .map_err(sql_err)?;

        let mut out = Vec::new();
        for r in rows {
            let (
                outbox_id,
                local_message_uri,
                account_id,
                protocol_slug,
                chat_uri,
                request_json,
                attempt_count,
                next_retry_ts_ms,
                last_error,
                created_at_ms,
            ) = r.map_err(sql_err)?;

            let local_message_id = UniversalId::from_uri(&local_message_uri).map_err(id_err)?;
            let chat_id = UniversalId::from_uri(&chat_uri).map_err(id_err)?;
            let request: OutboundMessageRequest =
                serde_json::from_str(&request_json).map_err(json_err)?;

            out.push(OutboxQueueItem {
                outbox_id: CompactString::from(outbox_id),
                local_message_id,
                account_id: AccountId::new(account_id),
                protocol: ProtocolKind::from_slug(&protocol_slug),
                chat_id,
                request,
                attempt_count,
                next_retry_ts_ms,
                last_error,
                created_at_ms,
            });
        }
        Ok(out)
    }

    /// Reads an application-level persistent setting from `protocol_kv_state` (`account_id = "__app_settings__"`).
    ///
    /// Used for settings such as `"send_shortcut_mode"` (`"enter"` vs `"ctrl_enter"`)
    /// and `"demo_mode_active"` (`"true"` vs `"false"`).
    pub fn get_app_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let conn = self.lock_conn()?;
        let raw: Option<Vec<u8>> = conn
            .query_row(
                "SELECT state_value FROM protocol_kv_state
                 WHERE account_id = '__app_settings__' AND state_key = ?1
                 ORDER BY updated_at_ms DESC
                 LIMIT 1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        Ok(raw.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Persists an application-level setting into `protocol_kv_state` (`account_id = "__app_settings__"`).
    pub fn set_app_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let sys_acc = AccountId::new("__app_settings__");
        let sys_proto = ProtocolKind::from_slug("warp_settings");
        self.set_kv_state(&sys_acc, &sys_proto, key, value.as_bytes())
    }

    /// Ensures default folder filter tabs (`all`, `unread`, `work`, `groups`) exist in `folders`
    /// if the table is currently empty.
    pub fn ensure_default_folders(&self) -> Result<(), StorageError> {
        if !self.list_folders()?.is_empty() {
            return Ok(());
        }
        let defaults = [
            (
                0,
                FolderFilterRule {
                    id: "all".into(),
                    name: "All Chats".into(),
                    icon: "📥".into(),
                    included_protocols: vec![],
                    included_accounts: vec![],
                    included_topologies: vec![],
                    container_filter: None,
                    pinned_chat_ids: vec![],
                    excluded_chat_ids: vec![],
                    unread_only: false,
                },
            ),
            (
                1,
                FolderFilterRule {
                    id: "unread".into(),
                    name: "Unread".into(),
                    icon: "🔔".into(),
                    included_protocols: vec![],
                    included_accounts: vec![],
                    included_topologies: vec![],
                    container_filter: None,
                    pinned_chat_ids: vec![],
                    excluded_chat_ids: vec![],
                    unread_only: true,
                },
            ),
            (
                2,
                FolderFilterRule {
                    id: "work".into(),
                    name: "Work & Servers".into(),
                    icon: "🏢".into(),
                    included_protocols: vec![
                        ProtocolKind::Mattermost,
                        ProtocolKind::Stoat,
                        ProtocolKind::Matrix,
                        ProtocolKind::Telegram,
                        ProtocolKind::Xmpp,
                    ],
                    included_accounts: vec![],
                    included_topologies: vec![
                        ChatTopologyKind::ContainerChannel,
                        ChatTopologyKind::ThreadOrTopic,
                    ],
                    container_filter: None,
                    pinned_chat_ids: vec![],
                    excluded_chat_ids: vec![],
                    unread_only: false,
                },
            ),
            (
                3,
                FolderFilterRule {
                    id: "groups".into(),
                    name: "Groups & Channels".into(),
                    icon: "💬".into(),
                    included_protocols: vec![],
                    included_accounts: vec![],
                    included_topologies: vec![
                        ChatTopologyKind::FlatGroup,
                        ChatTopologyKind::ContainerChannel,
                        ChatTopologyKind::ThreadOrTopic,
                    ],
                    container_filter: None,
                    pinned_chat_ids: vec![],
                    excluded_chat_ids: vec![],
                    unread_only: false,
                },
            ),
        ];

        for (order, folder) in &defaults {
            self.upsert_folder(*order, folder)?;
        }
        Ok(())
    }

    /// Clears all user and demo accounts, containers, chats, messages, outbox queue entries,
    /// and folders, and resets `"demo_mode_active"` to `"false"`.
    pub fn clear_all_user_and_demo_data(&self) -> Result<(), StorageError> {
        {
            let conn = self.lock_conn()?;
            conn.execute_batch(
                "DELETE FROM outbox_queue;
                 DELETE FROM messages;
                 DELETE FROM chats;
                 DELETE FROM containers;
                 DELETE FROM accounts;
                 DELETE FROM folders;
                 DELETE FROM protocol_kv_state
                  WHERE account_id NOT IN ('__app_settings__', '__pefl_clause3__', '__ui_prefs__');
                 UPDATE protocol_toggles SET enabled = 1;",
            )
            .map_err(sql_err)?;
        }
        self.set_app_setting("demo_mode_active", "false")?;
        Ok(())
    }

    /// Deletes a specific user account and all of its containers, chats, messages, KV cursors,
    /// and outbox queue entries.
    pub fn delete_account(&self, account_id: &AccountId) -> Result<(), StorageError> {
        let conn = self.lock_conn()?;
        let acc_str = account_id.as_str();
        let probe_uri = UniversalId::new(ProtocolKind::Telegram, account_id.clone(), "__probe__").to_uri();
        let encoded_acc = probe_uri
            .strip_prefix("warp://telegram/")
            .and_then(|s| s.strip_suffix("/__probe__"))
            .unwrap_or(acc_str);
        let uri_pattern = format!("warp://%/{encoded_acc}/%");

        conn.execute(
            "DELETE FROM outbox_queue WHERE account_id = ?1",
            params![acc_str],
        )
        .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM messages
             WHERE chat_uri IN (SELECT chat_uri FROM chats WHERE account_id = ?1)
                OR message_uri LIKE ?2
                OR chat_uri LIKE ?2",
            params![acc_str, uri_pattern],
        )
        .map_err(sql_err)?;

        conn.execute("DELETE FROM chats WHERE account_id = ?1", params![acc_str])
            .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM containers WHERE account_id = ?1",
            params![acc_str],
        )
        .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM protocol_kv_state WHERE account_id = ?1",
            params![acc_str],
        )
        .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM accounts WHERE account_id = ?1",
            params![acc_str],
        )
        .map_err(sql_err)?;

        Ok(())
    }

    /// Creates and persists a new user conversation or channel for `account_id` on `protocol`
    /// with protocol-accurate [`ChatCapabilities`], and seeds an initial system/welcome
    /// [`UnifiedMessage`] so the chat appears immediately at the top of the chat list.
    pub fn create_user_chat(
        &self,
        account_id: &AccountId,
        protocol: ProtocolKind,
        title: &str,
        remote_target: &str,
        is_group_or_channel: bool,
    ) -> Result<UnifiedChat, StorageError> {
        let now_ms = now_unix_ms();
        let seq = OPTIMISTIC_SEQ.fetch_add(1, Ordering::Relaxed);

        let clean_target = remote_target.trim();
        let clean_title = if !title.trim().is_empty() {
            title.trim().to_string()
        } else if !clean_target.is_empty() {
            clean_target.to_string()
        } else if is_group_or_channel {
            format!("#canale-{seq}")
        } else {
            format!("Chat #{seq}")
        };

        let remote_id_str = if !clean_target.is_empty() {
            clean_target.to_string()
        } else {
            let slug: String = clean_title
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '#' || c == '@' || c == '-' || c == '_' {
                        c.to_ascii_lowercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            let trimmed_slug = slug.trim_matches('_');
            if trimmed_slug.is_empty() {
                format!("user_chat_{now_ms}_{seq}")
            } else {
                format!("{trimmed_slug}_{seq}")
            }
        };

        let chat_id = UniversalId::new(protocol.clone(), account_id.clone(), remote_id_str.clone());

        let capabilities = match protocol {
            ProtocolKind::Telegram => {
                if is_group_or_channel {
                    ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS
                } else {
                    ChatCapabilities::full_featured() | ChatCapabilities::IS_E2EE_ACTIVE
                }
            }
            ProtocolKind::Matrix => {
                ChatCapabilities::full_featured()
                    | ChatCapabilities::IS_E2EE_ACTIVE
                    | ChatCapabilities::SUPPORTS_THREADS
            }
            ProtocolKind::Xmpp => ChatCapabilities::xmpp_omemo_dm(),
            ProtocolKind::Nostr => ChatCapabilities::nostr_nip17_dm(),
            ProtocolKind::SimpleX => ChatCapabilities::simplex_queue(),
            ProtocolKind::Irc => ChatCapabilities::irc_channel(true),
            ProtocolKind::Stoat => ChatCapabilities::full_featured(),
            ProtocolKind::Mattermost => {
                ChatCapabilities::full_featured() | ChatCapabilities::SUPPORTS_THREADS
            }
            ProtocolKind::Custom(_) => ChatCapabilities::full_featured(),
        };

        let existing_container = if is_group_or_channel {
            self.list_containers(false)?
                .into_iter()
                .find(|c| &c.id.account_id == account_id)
        } else {
            None
        };

        let (parent_container_id, topology, hierarchy) = if is_group_or_channel {
            if let Some(mut container) = existing_container {
                let c_id = container.id.clone();
                let c_kind = container.kind;
                if !container.child_chat_ids.contains(&chat_id) {
                    container.child_chat_ids.push(chat_id.clone());
                    self.upsert_container(&container)?;
                }
                (
                    Some(c_id.clone()),
                    ChatTopologyKind::ContainerChannel,
                    ContainerHierarchy::ServerChannel {
                        container_id: c_id,
                        container_kind: c_kind,
                        category_name: Some("Canali".into()),
                    },
                )
            } else {
                (
                    None,
                    ChatTopologyKind::FlatGroup,
                    ContainerHierarchy::Flat {
                        is_direct_message: false,
                    },
                )
            }
        } else {
            (
                None,
                ChatTopologyKind::DirectMessage,
                ContainerHierarchy::Flat {
                    is_direct_message: true,
                },
            )
        };

        let kind_label = if is_group_or_channel {
            "Canale / Gruppo"
        } else {
            "Messaggio Diretto"
        };
        let subtitle = CompactString::from(format!(
            "{} • {} ({})",
            protocol.display_name(),
            kind_label,
            remote_id_str
        ));

        let welcome_text = format!(
            "Conversazione \"{}\" avviata su {} ({}). Puoi inviare messaggi, rispondere, reagire con emoji o modificare i messaggi supportati dal protocollo.",
            clean_title,
            protocol.display_name(),
            remote_id_str
        );

        let chat = UnifiedChat {
            id: chat_id.clone(),
            parent_container_id,
            parent_chat_id: None,
            topology,
            hierarchy,
            title: CompactString::from(clean_title.as_str()),
            subtitle: Some(subtitle),
            avatar_initials: compute_initials(&clean_title),
            avatar_url: None,
            last_message_preview: Some(CompactString::from(truncate_preview(&welcome_text, 96))),
            last_activity_ts: now_ms,
            unread_count: 0,
            mention_count: 0,
            is_pinned: false,
            is_muted: false,
            is_online: true,
            capabilities,
            protocol_metadata: serde_json::json!({
                "remote_target": remote_id_str,
                "is_group_or_channel": is_group_or_channel,
                "user_created": true,
            }),
        };

        self.upsert_chat(&chat)?;

        let welcome_msg = UnifiedMessage {
            id: UniversalId::new(
                protocol,
                account_id.clone(),
                format!("welcome_{now_ms}_{seq}"),
            ),
            local_outbox_id: None,
            chat_id: chat_id.clone(),
            thread_id: None,
            sender_id: CompactString::from("system"),
            sender_display_name: CompactString::from(clean_title.as_str()),
            sender_initials: compute_initials(&clean_title),
            sender_avatar_url: None,
            is_outgoing: false,
            text: welcome_text,
            reply_to_id: None,
            reply_preview: None,
            timestamp_ms: now_ms,
            edited_at_ms: None,
            delivery_state: DeliveryState::Read,
            reactions: Vec::new(),
            attachments: Vec::new(),
            capabilities: MessageCapabilities::derive_from_chat(capabilities, false, false),
            protocol_metadata: serde_json::json!({ "system_welcome": true }),
        };

        self.upsert_message(&welcome_msg)?;

        Ok(self.get_chat(&chat_id)?.unwrap_or(chat))
    }

    /// Retrieves a single [`UnifiedMessage`] by its [`UniversalId`].
    pub fn get_message(
        &self,
        message_id: &UniversalId,
    ) -> Result<Option<UnifiedMessage>, StorageError> {
        let conn = self.lock_conn()?;
        let msg_uri = message_id.to_uri();
        let raw = conn
            .query_row(
                "SELECT message_uri, local_outbox_id, chat_uri, thread_uri, sender_id,
                        sender_display_name, sender_initials, sender_avatar_url, is_outgoing,
                        text, reply_to_uri, reply_preview, timestamp_ms, edited_at_ms,
                        delivery_state_json, reactions_json, attachments_json,
                        capabilities_bits, protocol_metadata_json
                 FROM messages
                 WHERE message_uri = ?1",
                params![msg_uri],
                read_message_row,
            )
            .optional()
            .map_err(sql_err)?;

        match raw {
            Some(r) => Ok(Some(decode_message_row(r)?)),
            None => Ok(None),
        }
    }

    /// Updates the text body and sets `edited_at_ms` on an existing message in SQLite,
    /// and refreshes the parent chat's `last_message_preview`.
    pub fn update_message_text(
        &self,
        message_id: &UniversalId,
        new_text: &str,
    ) -> Result<(), StorageError> {
        let conn = self.lock_conn()?;
        let msg_uri = message_id.to_uri();
        let now_ms = now_unix_ms();

        let chat_uri: Option<String> = conn
            .query_row(
                "SELECT chat_uri FROM messages WHERE message_uri = ?1",
                params![msg_uri],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        conn.execute(
            "UPDATE messages SET text = ?1, edited_at_ms = ?2 WHERE message_uri = ?3",
            params![new_text, now_ms, msg_uri],
        )
        .map_err(sql_err)?;

        let reply_preview = truncate_preview(new_text, 80);
        conn.execute(
            "UPDATE messages SET reply_preview = ?1 WHERE reply_to_uri = ?2",
            params![reply_preview, msg_uri],
        )
        .map_err(sql_err)?;

        if let Some(c_uri) = chat_uri {
            refresh_chat_last_preview(&conn, &c_uri)?;
        }

        Ok(())
    }

    /// Deletes a message from SQLite (and from `outbox_queue` if pending) and updates the parent
    /// chat's `last_message_preview`.
    pub fn delete_message(&self, message_id: &UniversalId) -> Result<(), StorageError> {
        let conn = self.lock_conn()?;
        let msg_uri = message_id.to_uri();

        let chat_uri: Option<String> = conn
            .query_row(
                "SELECT chat_uri FROM messages WHERE message_uri = ?1",
                params![msg_uri],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM outbox_queue WHERE local_message_uri = ?1",
            params![msg_uri],
        )
        .map_err(sql_err)?;

        conn.execute("DELETE FROM messages WHERE message_uri = ?1", params![msg_uri])
            .map_err(sql_err)?;

        if let Some(c_uri) = chat_uri {
            refresh_chat_last_preview(&conn, &c_uri)?;
        }

        Ok(())
    }

    /// Toggles an emoji reaction for `actor` on a message's `reactions_json` in SQLite.
    pub fn toggle_message_reaction(
        &self,
        message_id: &UniversalId,
        emoji: &str,
        actor: &str,
    ) -> Result<(), StorageError> {
        let _ = actor;
        let conn = self.lock_conn()?;
        let msg_uri = message_id.to_uri();
        let clean_emoji = emoji.trim();
        if clean_emoji.is_empty() {
            return Ok(());
        }

        let reactions_json: Option<String> = conn
            .query_row(
                "SELECT reactions_json FROM messages WHERE message_uri = ?1",
                params![msg_uri],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        let Some(raw_json) = reactions_json else {
            return Ok(());
        };

        let mut reactions: Vec<MessageReaction> =
            serde_json::from_str(&raw_json).map_err(json_err)?;

        if let Some(pos) = reactions.iter().position(|r| r.emoji.as_str() == clean_emoji) {
            if reactions[pos].reacted_by_me {
                reactions[pos].count = reactions[pos].count.saturating_sub(1);
                reactions[pos].reacted_by_me = false;
                if reactions[pos].count == 0 {
                    reactions.remove(pos);
                }
            } else {
                reactions[pos].count = reactions[pos].count.saturating_add(1);
                reactions[pos].reacted_by_me = true;
            }
        } else {
            reactions.push(MessageReaction {
                emoji: CompactString::from(clean_emoji),
                count: 1,
                reacted_by_me: true,
            });
        }

        let updated_json = serde_json::to_string(&reactions).map_err(json_err)?;
        conn.execute(
            "UPDATE messages SET reactions_json = ?1 WHERE message_uri = ?2",
            params![updated_json, msg_uri],
        )
        .map_err(sql_err)?;

        Ok(())
    }

    /// Marks a chat as read by setting `unread_count = 0` and `mention_count = 0`.
    pub fn mark_chat_read(&self, chat_id: &UniversalId) -> Result<(), StorageError> {
        let conn = self.lock_conn()?;
        let chat_uri = chat_id.to_uri();

        let parent_container_uri: Option<String> = conn
            .query_row(
                "SELECT parent_container_uri FROM chats WHERE chat_uri = ?1",
                params![chat_uri],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(sql_err)?
            .flatten();

        conn.execute(
            "UPDATE chats SET unread_count = 0, mention_count = 0 WHERE chat_uri = ?1",
            params![chat_uri],
        )
        .map_err(sql_err)?;

        if let Some(container_uri) = parent_container_uri {
            let (total_unread, total_mentions): (i64, i64) = conn
                .query_row(
                    "SELECT COALESCE(SUM(unread_count), 0), COALESCE(SUM(mention_count), 0)
                     FROM chats
                     WHERE parent_container_uri = ?1",
                    params![container_uri],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap_or((0, 0));

            let _ = conn.execute(
                "UPDATE containers SET unread_count = ?1, mention_count = ?2 WHERE container_uri = ?3",
                params![total_unread, total_mentions, container_uri],
            );
        }

        Ok(())
    }

    /// Toggles `is_pinned` on a chat and returns the new pinned state (`true` if now pinned).
    pub fn toggle_chat_pinned(&self, chat_id: &UniversalId) -> Result<bool, StorageError> {
        let conn = self.lock_conn()?;
        let chat_uri = chat_id.to_uri();

        let current_pinned: Option<i64> = conn
            .query_row(
                "SELECT is_pinned FROM chats WHERE chat_uri = ?1",
                params![chat_uri],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        let new_pinned = current_pinned.unwrap_or(0) == 0;
        conn.execute(
            "UPDATE chats SET is_pinned = ?1 WHERE chat_uri = ?2",
            params![bool_to_int(new_pinned), chat_uri],
        )
        .map_err(sql_err)?;

        Ok(new_pinned)
    }

    /// Reads and parses `encrypted_config_json` for `account_id` from the `accounts` table.
    ///
    /// Allows protocol adapters, background sync tasks, and the UI bridge to retrieve stored
    /// credentials and parameters such as `bot_token`, `server_host`, `backend_env`, etc.
    pub fn get_account_config_json(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<serde_json::Value>, WarpError> {
        let conn = self.lock_conn()?;
        let raw_json: Option<String> = conn
            .query_row(
                "SELECT encrypted_config_json FROM accounts WHERE account_id = ?1",
                params![account_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        let Some(raw) = raw_json else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Some(serde_json::json!({})));
        }
        let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(json_err)?;
        Ok(Some(parsed))
    }

    /// Deletes all messages and pending outbox items for `chat_uri` and sets the chat's
    /// `last_message_preview` to `"Nessun messaggio"`, resetting `unread_count` and `mention_count` to `0`.
    pub fn clear_chat_history(&self, chat_uri: &str) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let normalized_uri = UniversalId::from_uri(chat_uri)
            .map(|id| id.to_uri())
            .unwrap_or_else(|_| chat_uri.trim().to_string());

        let parent_container_uri: Option<String> = conn
            .query_row(
                "SELECT parent_container_uri FROM chats WHERE chat_uri = ?1",
                params![normalized_uri],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(sql_err)?
            .flatten();

        conn.execute(
            "DELETE FROM outbox_queue WHERE chat_uri = ?1",
            params![normalized_uri],
        )
        .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM messages WHERE chat_uri = ?1",
            params![normalized_uri],
        )
        .map_err(sql_err)?;

        conn.execute(
            "UPDATE chats
             SET last_message_preview = 'Nessun messaggio',
                 unread_count = 0,
                 mention_count = 0
             WHERE chat_uri = ?1",
            params![normalized_uri],
        )
        .map_err(sql_err)?;

        if let Some(container_uri) = parent_container_uri {
            let (total_unread, total_mentions): (i64, i64) = conn
                .query_row(
                    "SELECT COALESCE(SUM(unread_count), 0), COALESCE(SUM(mention_count), 0)
                     FROM chats
                     WHERE parent_container_uri = ?1",
                    params![container_uri],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap_or((0, 0));

            let _ = conn.execute(
                "UPDATE containers SET unread_count = ?1, mention_count = ?2 WHERE container_uri = ?3",
                params![total_unread, total_mentions, container_uri],
            );
        }

        Ok(())
    }

    /// Deletes a chat and all of its messages (and any child thread chats) from `chats`,
    /// `messages`, and `outbox_queue`, and detaches it from any parent container.
    pub fn delete_chat(&self, chat_uri: &str) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        let normalized_uri = UniversalId::from_uri(chat_uri)
            .map(|id| id.to_uri())
            .unwrap_or_else(|_| chat_uri.trim().to_string());

        let parent_container_uri: Option<String> = conn
            .query_row(
                "SELECT parent_container_uri FROM chats WHERE chat_uri = ?1",
                params![normalized_uri],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(sql_err)?
            .flatten();

        conn.execute(
            "DELETE FROM outbox_queue
             WHERE chat_uri = ?1
                OR chat_uri IN (SELECT chat_uri FROM chats WHERE parent_chat_uri = ?1)",
            params![normalized_uri],
        )
        .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM messages
             WHERE chat_uri = ?1
                OR thread_uri = ?1
                OR chat_uri IN (SELECT chat_uri FROM chats WHERE parent_chat_uri = ?1)",
            params![normalized_uri],
        )
        .map_err(sql_err)?;

        conn.execute(
            "DELETE FROM chats WHERE chat_uri = ?1 OR parent_chat_uri = ?1",
            params![normalized_uri],
        )
        .map_err(sql_err)?;

        if let Some(container_uri) = parent_container_uri {
            let child_json_opt: Option<String> = conn
                .query_row(
                    "SELECT child_chat_uris_json FROM containers WHERE container_uri = ?1",
                    params![container_uri],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;

            if let Some(raw_children) = child_json_opt {
                if let Ok(mut children) = serde_json::from_str::<Vec<String>>(&raw_children) {
                    children.retain(|u| u != &normalized_uri);
                    if let Ok(updated_json) = serde_json::to_string(&children) {
                        let _ = conn.execute(
                            "UPDATE containers SET child_chat_uris_json = ?1 WHERE container_uri = ?2",
                            params![updated_json, container_uri],
                        );
                    }
                }
            }

            let (total_unread, total_mentions): (i64, i64) = conn
                .query_row(
                    "SELECT COALESCE(SUM(unread_count), 0), COALESCE(SUM(mention_count), 0)
                     FROM chats
                     WHERE parent_container_uri = ?1",
                    params![container_uri],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap_or((0, 0));

            let _ = conn.execute(
                "UPDATE containers SET unread_count = ?1, mention_count = ?2 WHERE container_uri = ?3",
                params![total_unread, total_mentions, container_uri],
            );
        }

        Ok(())
    }

    /// Creates and persists a rich outgoing [`UnifiedMessage`] with a media/file/voice attachment
    /// (`📎 Allegato`, `🎤 Nota Vocale`, `🖼️ Immagine`) so that the attachment (`📎`) and voice (`🎤`)
    /// composer actions work across all supported protocols.
    pub fn send_media_attachment_message(
        &self,
        chat_id: &UniversalId,
        sender_name: &str,
        attachment_kind: &str,
        file_name: &str,
        caption: &str,
        timestamp_ms: i64,
    ) -> Result<UnifiedMessage, WarpError> {
        let conn = self.lock_conn()?;
        let ts = if timestamp_ms > 0 {
            timestamp_ms
        } else {
            now_unix_ms()
        };
        let seq = OPTIMISTIC_SEQ.fetch_add(1, Ordering::Relaxed);
        let chat_uri = chat_id.to_uri();

        let chat_caps_bits: Option<i64> = conn
            .query_row(
                "SELECT capabilities_bits FROM chats WHERE chat_uri = ?1",
                params![chat_uri],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;

        let chat_caps = chat_caps_bits
            .and_then(|bits| u32::try_from(bits).ok())
            .map(ChatCapabilities::from_bits_truncate)
            .unwrap_or_else(ChatCapabilities::full_featured);

        let kind_lower = attachment_kind.trim().to_ascii_lowercase();
        let raw_name = file_name.trim();
        let name_lower = raw_name.to_ascii_lowercase();

        let is_voice = kind_lower.contains("voice")
            || kind_lower.contains("audio")
            || kind_lower.contains("vocal")
            || name_lower.ends_with(".ogg")
            || name_lower.ends_with(".opus")
            || name_lower.ends_with(".mp3")
            || name_lower.ends_with(".wav");

        let is_image = !is_voice
            && (kind_lower.contains("image")
                || kind_lower.contains("photo")
                || kind_lower.contains("immagin")
                || name_lower.ends_with(".png")
                || name_lower.ends_with(".jpg")
                || name_lower.ends_with(".jpeg")
                || name_lower.ends_with(".webp")
                || name_lower.ends_with(".gif"));

        let (prefix_badge, default_file_name, mime_type, size_bytes) = if is_voice {
            (
                "🎤 Nota Vocale",
                format!("nota_vocale_{seq}.ogg"),
                "audio/ogg; codecs=opus",
                38_400_u64,
            )
        } else if is_image {
            (
                "🖼️ Immagine",
                format!("immagine_{seq}.png"),
                "image/png",
                142_800_u64,
            )
        } else {
            let inferred_mime = if name_lower.ends_with(".pdf") {
                "application/pdf"
            } else if name_lower.ends_with(".zip") || name_lower.ends_with(".tar.gz") {
                "application/zip"
            } else if name_lower.ends_with(".txt") || name_lower.ends_with(".md") || name_lower.ends_with(".rs") {
                "text/plain; charset=utf-8"
            } else {
                "application/octet-stream"
            };
            (
                "📎 Allegato",
                format!("allegato_{seq}.pdf"),
                inferred_mime,
                256_000_u64,
            )
        };

        let resolved_file_name = if raw_name.is_empty() {
            default_file_name
        } else {
            raw_name.to_string()
        };

        let clean_caption = caption.trim();
        let text = if clean_caption.is_empty() {
            format!("{prefix_badge}: {resolved_file_name}")
        } else {
            format!("{prefix_badge}: {resolved_file_name} — {clean_caption}")
        };

        let media_id = format!("media_{ts}_{seq}");
        let media_uri = CompactString::from(format!(
            "warp-media://{}/{}/{}",
            chat_id.protocol.as_slug(),
            chat_id.account_id.as_str(),
            media_id
        ));

        let (source_url, encryption_metadata) = match &chat_id.protocol {
            ProtocolKind::Telegram => (
                CompactString::from(format!("mtproto://dc2/document/{ts}{seq}")),
                serde_json::json!({
                    "dc_id": 2,
                    "file_reference": format!("ref_hex_{ts}_{seq}"),
                    "kind": if is_voice { "voice" } else if is_image { "photo" } else { "document" },
                }),
            ),
            ProtocolKind::Matrix => (
                CompactString::from(format!("mxc://matrix.org/WarpMedia{ts}{seq}")),
                serde_json::json!({
                    "v": "v2",
                    "iv": "YWVzX2N0cl9pdg==",
                    "kind": if is_voice { "m.audio" } else if is_image { "m.image" } else { "m.file" },
                }),
            ),
            ProtocolKind::Xmpp => (
                CompactString::from(format!(
                    "aesgcm://upload.conversations.im/{ts}{seq}#00112233445566778899aabbccddeeff"
                )),
                serde_json::json!({ "cipher": "AES-256-GCM", "xep": "0454" }),
            ),
            ProtocolKind::Nostr => (
                CompactString::from(format!(
                    "blossom://cdn.satellite.earth/e3b0c44298fc1c149afbf4c8996fb924{seq}"
                )),
                serde_json::json!({ "nip": 94, "blossom": true }),
            ),
            ProtocolKind::SimpleX => (
                CompactString::from(format!("smp://smp11.simplex.im/file/{ts}_{seq}")),
                serde_json::json!({ "smp_file_transfer": true }),
            ),
            _ => (
                CompactString::from(format!(
                    "https://cdn.warp.im/attachments/{}/{}/{}",
                    chat_id.protocol.as_slug(),
                    chat_id.account_id.as_str(),
                    resolved_file_name
                )),
                serde_json::json!({ "transport": "https" }),
            ),
        };

        let attachment = MediaAttachment {
            media_uri,
            source_url,
            mime_type: CompactString::from(mime_type),
            file_name: Some(CompactString::from(resolved_file_name.as_str())),
            size_bytes,
            encryption_metadata,
        };

        let resolved_sender = if sender_name.trim().is_empty() {
            "Tu (Warp IM)"
        } else {
            sender_name.trim()
        };

        let message = UnifiedMessage {
            id: UniversalId::new(
                chat_id.protocol.clone(),
                chat_id.account_id.clone(),
                format!("media_msg_{ts}_{seq}"),
            ),
            local_outbox_id: None,
            chat_id: chat_id.clone(),
            thread_id: None,
            sender_id: CompactString::from(chat_id.account_id.as_str()),
            sender_display_name: CompactString::from(resolved_sender),
            sender_initials: compute_initials(resolved_sender),
            sender_avatar_url: None,
            is_outgoing: true,
            text,
            reply_to_id: None,
            reply_preview: None,
            timestamp_ms: ts,
            edited_at_ms: None,
            delivery_state: DeliveryState::Sent,
            reactions: Vec::new(),
            attachments: vec![attachment],
            capabilities: MessageCapabilities::derive_from_chat(chat_caps, true, true),
            protocol_metadata: serde_json::json!({
                "attachment_kind": if is_voice { "voice" } else if is_image { "image" } else { "file" },
                "file_name": resolved_file_name,
            }),
        };

        upsert_message_on_conn(&conn, &message)?;
        Ok(message)
    }

    /// Inserts or updates an incoming [`UnifiedMessage`] and optionally increments `unread_count`
    /// on the target chat (and its parent container, if any).
    pub fn ingest_incoming_message(
        &self,
        message: &UnifiedMessage,
        increment_unread: bool,
    ) -> Result<(), WarpError> {
        let conn = self.lock_conn()?;
        upsert_message_on_conn(&conn, message)?;

        if increment_unread && !message.is_outgoing {
            let chat_uri = message.chat_id.to_uri();
            conn.execute(
                "UPDATE chats SET unread_count = unread_count + 1 WHERE chat_uri = ?1",
                params![chat_uri],
            )
            .map_err(sql_err)?;

            let parent_container_uri: Option<String> = conn
                .query_row(
                    "SELECT parent_container_uri FROM chats WHERE chat_uri = ?1",
                    params![chat_uri],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(sql_err)?
                .flatten();

            if let Some(container_uri) = parent_container_uri {
                let (total_unread, total_mentions): (i64, i64) = conn
                    .query_row(
                        "SELECT COALESCE(SUM(unread_count), 0), COALESCE(SUM(mention_count), 0)
                         FROM chats
                         WHERE parent_container_uri = ?1",
                        params![container_uri],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap_or((0, 0));

                let _ = conn.execute(
                    "UPDATE containers SET unread_count = ?1, mention_count = ?2 WHERE container_uri = ?3",
                    params![total_unread, total_mentions, container_uri],
                );
            }
        }
        Ok(())
    }
}

fn refresh_chat_last_preview(conn: &Connection, chat_uri: &str) -> Result<(), WarpError> {
    let latest: Option<(String, i64)> = conn
        .query_row(
            "SELECT text, timestamp_ms
             FROM messages
             WHERE chat_uri = ?1
             ORDER BY timestamp_ms DESC, message_uri DESC
             LIMIT 1",
            params![chat_uri],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql_err)?;

    match latest {
        Some((text, ts_ms)) => {
            let preview = truncate_preview(&text, 96);
            conn.execute(
                "UPDATE chats
                 SET last_message_preview = ?1,
                     last_activity_ts = ?2
                 WHERE chat_uri = ?3",
                params![preview, ts_ms, chat_uri],
            )
            .map_err(sql_err)?;
        }
        None => {
            conn.execute(
                "UPDATE chats SET last_message_preview = NULL WHERE chat_uri = ?1",
                params![chat_uri],
            )
            .map_err(sql_err)?;
        }
    }
    Ok(())
}

fn upsert_message_on_conn(conn: &Connection, message: &UnifiedMessage) -> Result<(), WarpError> {
    let message_uri = message.id.to_uri();
    let chat_uri = message.chat_id.to_uri();
    let thread_uri = message.thread_id.as_ref().map(UniversalId::to_uri);
    let reply_to_uri = message.reply_to_id.as_ref().map(UniversalId::to_uri);
    let delivery_state_json = serde_json::to_string(&message.delivery_state).map_err(json_err)?;
    let reactions_json = serde_json::to_string(&message.reactions).map_err(json_err)?;
    let attachments_json = serde_json::to_string(&message.attachments).map_err(json_err)?;
    let capabilities_bits = i64::from(message.capabilities.bits());
    let protocol_metadata_json =
        serde_json::to_string(&message.protocol_metadata).map_err(json_err)?;

    conn.execute(
        "INSERT INTO messages (
             message_uri, local_outbox_id, chat_uri, thread_uri, sender_id,
             sender_display_name, sender_initials, sender_avatar_url, is_outgoing,
             text, reply_to_uri, reply_preview, timestamp_ms, edited_at_ms,
             delivery_state_json, reactions_json, attachments_json,
             capabilities_bits, protocol_metadata_json
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
         ON CONFLICT(message_uri) DO UPDATE SET
             local_outbox_id = COALESCE(excluded.local_outbox_id, messages.local_outbox_id),
             chat_uri = excluded.chat_uri,
             thread_uri = excluded.thread_uri,
             sender_id = excluded.sender_id,
             sender_display_name = excluded.sender_display_name,
             sender_initials = excluded.sender_initials,
             sender_avatar_url = excluded.sender_avatar_url,
             is_outgoing = excluded.is_outgoing,
             text = excluded.text,
             reply_to_uri = excluded.reply_to_uri,
             reply_preview = excluded.reply_preview,
             timestamp_ms = excluded.timestamp_ms,
             edited_at_ms = excluded.edited_at_ms,
             delivery_state_json = excluded.delivery_state_json,
             reactions_json = excluded.reactions_json,
             attachments_json = excluded.attachments_json,
             capabilities_bits = excluded.capabilities_bits,
             protocol_metadata_json = excluded.protocol_metadata_json",
        params![
            message_uri,
            message.local_outbox_id.as_deref(),
            chat_uri,
            thread_uri,
            message.sender_id.as_str(),
            message.sender_display_name.as_str(),
            message.sender_initials.as_str(),
            message.sender_avatar_url.as_deref(),
            bool_to_int(message.is_outgoing),
            message.text.as_str(),
            reply_to_uri,
            message.reply_preview.as_deref(),
            message.timestamp_ms,
            message.edited_at_ms,
            delivery_state_json,
            reactions_json,
            attachments_json,
            capabilities_bits,
            protocol_metadata_json,
        ],
    )
    .map_err(sql_err)?;

    let preview = truncate_preview(&message.text, 96);
    conn.execute(
        "UPDATE chats
         SET last_message_preview = ?1,
             last_activity_ts = MAX(last_activity_ts, ?2)
         WHERE chat_uri = ?3",
        params![preview, message.timestamp_ms, chat_uri],
    )
    .map_err(sql_err)?;

    Ok(())
}

type RawChatRow = (
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    i64,
    u32,
    u32,
    i64,
    i64,
    i64,
    i64,
    String,
);

fn read_chat_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawChatRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
    ))
}

fn decode_chat_row(raw: RawChatRow) -> Result<UnifiedChat, WarpError> {
    let (
        chat_uri,
        parent_container_uri,
        parent_chat_uri,
        topology_json,
        hierarchy_json,
        title,
        subtitle,
        avatar_initials,
        avatar_url,
        last_message_preview,
        last_activity_ts,
        unread_count,
        mention_count,
        is_pinned,
        is_muted,
        is_online,
        capabilities_bits,
        protocol_metadata_json,
    ) = raw;

    let id = UniversalId::from_uri(&chat_uri).map_err(id_err)?;
    let parent_container_id = match parent_container_uri {
        Some(uri) => Some(UniversalId::from_uri(&uri).map_err(id_err)?),
        None => None,
    };
    let parent_chat_id = match parent_chat_uri {
        Some(uri) => Some(UniversalId::from_uri(&uri).map_err(id_err)?),
        None => None,
    };
    let topology: ChatTopologyKind = serde_json::from_str(&topology_json).map_err(json_err)?;
    let hierarchy: ContainerHierarchy = serde_json::from_str(&hierarchy_json).map_err(json_err)?;
    let caps_u32 = u32::try_from(capabilities_bits).unwrap_or(0);
    let capabilities = ChatCapabilities::from_bits_truncate(caps_u32);
    let protocol_metadata: serde_json::Value =
        serde_json::from_str(&protocol_metadata_json).map_err(json_err)?;

    Ok(UnifiedChat {
        id,
        parent_container_id,
        parent_chat_id,
        topology,
        hierarchy,
        title: CompactString::from(title),
        subtitle: subtitle.map(CompactString::from),
        avatar_initials: CompactString::from(avatar_initials),
        avatar_url: avatar_url.map(CompactString::from),
        last_message_preview: last_message_preview.map(CompactString::from),
        last_activity_ts,
        unread_count,
        mention_count,
        is_pinned: is_pinned != 0,
        is_muted: is_muted != 0,
        is_online: is_online != 0,
        capabilities,
        protocol_metadata,
    })
}

type RawMessageRow = (
    String,
    Option<String>,
    String,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    Option<String>,
    Option<String>,
    i64,
    Option<i64>,
    String,
    String,
    String,
    i64,
    String,
);

fn read_message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMessageRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
    ))
}

fn decode_message_row(raw: RawMessageRow) -> Result<UnifiedMessage, WarpError> {
    let (
        message_uri,
        local_outbox_id,
        chat_uri,
        thread_uri,
        sender_id,
        sender_display_name,
        sender_initials,
        sender_avatar_url,
        is_outgoing,
        text,
        reply_to_uri,
        reply_preview,
        timestamp_ms,
        edited_at_ms,
        delivery_state_json,
        reactions_json,
        attachments_json,
        capabilities_bits,
        protocol_metadata_json,
    ) = raw;

    let id = UniversalId::from_uri(&message_uri).map_err(id_err)?;
    let chat_id = UniversalId::from_uri(&chat_uri).map_err(id_err)?;
    let thread_id = match thread_uri {
        Some(uri) => Some(UniversalId::from_uri(&uri).map_err(id_err)?),
        None => None,
    };
    let reply_to_id = match reply_to_uri {
        Some(uri) => Some(UniversalId::from_uri(&uri).map_err(id_err)?),
        None => None,
    };
    let delivery_state: DeliveryState =
        serde_json::from_str(&delivery_state_json).map_err(json_err)?;
    let reactions: Vec<MessageReaction> =
        serde_json::from_str(&reactions_json).map_err(json_err)?;
    let attachments: Vec<MediaAttachment> =
        serde_json::from_str(&attachments_json).map_err(json_err)?;
    let caps_u32 = u32::try_from(capabilities_bits).unwrap_or(0);
    let capabilities = MessageCapabilities::from_bits_truncate(caps_u32);
    let protocol_metadata: serde_json::Value =
        serde_json::from_str(&protocol_metadata_json).map_err(json_err)?;

    Ok(UnifiedMessage {
        id,
        local_outbox_id: local_outbox_id.map(CompactString::from),
        chat_id,
        thread_id,
        sender_id: CompactString::from(sender_id),
        sender_display_name: CompactString::from(sender_display_name),
        sender_initials: CompactString::from(sender_initials),
        sender_avatar_url: sender_avatar_url.map(CompactString::from),
        is_outgoing: is_outgoing != 0,
        text,
        reply_to_id,
        reply_preview: reply_preview.map(CompactString::from),
        timestamp_ms,
        edited_at_ms,
        delivery_state,
        reactions,
        attachments,
        capabilities,
        protocol_metadata,
    })
}

fn bool_to_int(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

pub(crate) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn compute_initials(name: &str) -> CompactString {
    let mut initials = String::with_capacity(2);
    for word in name.split_whitespace().take(2) {
        if let Some(ch) = word.chars().find(|c| c.is_alphanumeric()) {
            for upper in ch.to_uppercase() {
                initials.push(upper);
            }
        }
    }
    if initials.is_empty() {
        CompactString::from("ME")
    } else {
        CompactString::from(initials)
    }
}

fn truncate_preview(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in text.chars().enumerate() {
        if idx >= max_chars {
            out.push('…');
            break;
        }
        out.push(if ch == '\n' || ch == '\r' { ' ' } else { ch });
    }
    out
}

fn sql_err(err: rusqlite::Error) -> WarpError {
    WarpError::Storage(err.to_string())
}

fn json_err(err: serde_json::Error) -> WarpError {
    WarpError::Storage(format!("JSON serialization error: {err}"))
}

fn id_err(err: warp_core::IdParseError) -> WarpError {
    WarpError::Storage(format!("Invalid UniversalId URI in SQLite: {err}"))
}

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

//! Dynamic Protocol Plugin & Runtime Backend Registry (`ProtocolRegistry`).
//!
//! Satisfies the **Open-Closed Principle**:
//! - Adding a 9th protocol requires implementing [`ProtocolPlugin`] and [`MessagingBackend`]
//!   and calling `registry.register_plugin(Box::new(NewProtocolPlugin))`.
//! - Supports compile-time feature gating (`#[cfg(feature = "proto-*")]`) AND runtime
//!   activation/deactivation (`set_protocol_enabled`) with live `BackendEvent::ProtocolToggled`
//!   notifications.
//! - Implements [`warp_storage::MessageDispatcher`] so `Arc<ProtocolRegistry>` can be passed
//!   directly into [`warp_storage::OutboxEngine::new`].

use crate::adapters::*;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tracing::debug;
use warp_core::{
    AccountId, AuthFlowDescriptor, BackendEvent, MessagingBackend, OutboundMessageRequest,
    ProtocolKind, ProtocolPlugin, UniversalId, WarpError,
};
use warp_storage::MessageDispatcher;

/// Central multi-protocol plugin & account backend registry.
pub struct ProtocolRegistry {
    plugins: RwLock<HashMap<String, Box<dyn ProtocolPlugin>>>,
    backends: RwLock<HashMap<AccountId, Arc<dyn MessagingBackend>>>,
    enabled_protocols: RwLock<HashSet<ProtocolKind>>,
    disabled_accounts: RwLock<HashSet<AccountId>>,
    event_tx: broadcast::Sender<BackendEvent>,
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProtocolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolRegistry")
            .field("registered_protocols", &self.list_registered_protocols())
            .field("enabled_protocols", &self.enabled_protocols())
            .finish()
    }
}

impl ProtocolRegistry {
    /// Creates an empty [`ProtocolRegistry`].
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            plugins: RwLock::new(HashMap::new()),
            backends: RwLock::new(HashMap::new()),
            enabled_protocols: RwLock::new(HashSet::new()),
            disabled_accounts: RwLock::new(HashSet::new()),
            event_tx,
        }
    }

    /// Creates a [`ProtocolRegistry`] pre-populated with all protocol plugins enabled via
    /// Cargo feature flags (`proto-telegram`, `proto-matrix`, `proto-xmpp`, `proto-nostr`,
    /// `proto-simplex`, `proto-irc`, `proto-stoat`, `proto-mattermost`).
    pub fn with_compiled_plugins() -> Self {
        let registry = Self::new();

        #[cfg(feature = "proto-telegram")]
        registry.register_plugin(Box::new(TelegramPlugin));

        #[cfg(feature = "proto-matrix")]
        registry.register_plugin(Box::new(MatrixPlugin));

        #[cfg(feature = "proto-xmpp")]
        registry.register_plugin(Box::new(XmppPlugin));

        #[cfg(feature = "proto-nostr")]
        registry.register_plugin(Box::new(NostrPlugin));

        #[cfg(feature = "proto-simplex")]
        registry.register_plugin(Box::new(SimpleXPlugin));

        #[cfg(feature = "proto-irc")]
        registry.register_plugin(Box::new(IrcPlugin));

        #[cfg(feature = "proto-stoat")]
        registry.register_plugin(Box::new(StoatPlugin));

        #[cfg(feature = "proto-mattermost")]
        registry.register_plugin(Box::new(MattermostPlugin));

        registry
    }

    /// Registers a [`ProtocolPlugin`] factory and enables its [`ProtocolKind`] by default.
    ///
    /// Adding a 9th protocol at runtime is literally:
    /// `registry.register_plugin(Box::new(MyCustomPlugin));`
    pub fn register_plugin(&self, plugin: Box<dyn ProtocolPlugin>) {
        let proto = plugin.protocol();
        let slug = proto.as_slug().to_string();
        if let Ok(mut enabled) = self.enabled_protocols.write() {
            enabled.insert(proto);
        }
        if let Ok(mut plugins) = self.plugins.write() {
            plugins.insert(slug, plugin);
        }
    }

    /// Instantiates a [`MessagingBackend`] via the registered [`ProtocolPlugin`] for `protocol`
    /// and registers it under `account_id`.
    pub fn build_and_register_backend(
        &self,
        protocol: &ProtocolKind,
        account_id: AccountId,
        config_json: serde_json::Value,
    ) -> Result<Arc<dyn MessagingBackend>, WarpError> {
        let backend = {
            let plugins = self
                .plugins
                .read()
                .map_err(|_| WarpError::Storage("plugins lock poisoned".into()))?;
            let plugin = plugins
                .get(protocol.as_slug())
                .ok_or_else(|| WarpError::PluginNotRegistered(protocol.as_slug().to_string()))?;
            plugin.build_backend(account_id, config_json)?
        };
        self.register_backend(backend.clone());
        Ok(backend)
    }

    /// Registers an active account [`MessagingBackend`] and forwards its live events into the
    /// global registry event bus.
    pub fn register_backend(&self, backend: Arc<dyn MessagingBackend>) {
        let account_id = backend.account_id().clone();
        let proto = backend.protocol();

        if let Ok(mut enabled) = self.enabled_protocols.write() {
            enabled.insert(proto);
        }

        if tokio::runtime::Handle::try_current().is_ok() {
            let mut rx = backend.subscribe();
            let tx = self.event_tx.clone();
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    let _ = tx.send(ev);
                }
            });
        }

        if let Ok(mut backends) = self.backends.write() {
            backends.insert(account_id, backend);
        }
    }

    /// Looks up a registered [`MessagingBackend`] by its [`AccountId`].
    pub fn get_backend(&self, account_id: &AccountId) -> Option<Arc<dyn MessagingBackend>> {
        self.backends
            .read()
            .ok()
            .and_then(|map| map.get(account_id).cloned())
    }

    /// Returns the declarative onboarding flow descriptor for `protocol`.
    pub fn onboarding_flow_for(&self, protocol: &ProtocolKind) -> AuthFlowDescriptor {
        if let Ok(plugins) = self.plugins.read() {
            if let Some(plugin) = plugins.get(protocol.as_slug()) {
                return plugin.onboarding_flow();
            }
        }
        AuthFlowDescriptor::initial_for(protocol.clone())
    }

    /// Lists all registered [`ProtocolKind`]s in deterministic order.
    pub fn list_registered_protocols(&self) -> Vec<ProtocolKind> {
        let Ok(plugins) = self.plugins.read() else {
            return Vec::new();
        };
        let mut out: Vec<ProtocolKind> = plugins.values().map(|p| p.protocol()).collect();
        out.sort();
        out
    }

    /// Returns `true` if `protocol` is currently enabled by the user.
    pub fn is_protocol_enabled(&self, protocol: &ProtocolKind) -> bool {
        self.enabled_protocols
            .read()
            .map(|set| set.contains(protocol))
            .unwrap_or(false)
    }

    /// Returns all currently enabled [`ProtocolKind`]s in deterministic order.
    pub fn enabled_protocols(&self) -> Vec<ProtocolKind> {
        let Ok(set) = self.enabled_protocols.read() else {
            return Vec::new();
        };
        let mut out: Vec<ProtocolKind> = set.iter().cloned().collect();
        out.sort();
        out
    }

    /// Dynamically enables or disables a protocol at runtime:
    /// 1. Updates `enabled_protocols`.
    /// 2. Calls `connect()` or `disconnect()` on all registered backends for that protocol.
    /// 3. Broadcasts [`BackendEvent::ProtocolToggled`] to the 16ms UI coalescer.
    pub async fn set_protocol_enabled(
        &self,
        protocol: ProtocolKind,
        enabled: bool,
    ) -> Result<(), WarpError> {
        {
            let mut set = self
                .enabled_protocols
                .write()
                .map_err(|_| WarpError::Storage("enabled_protocols lock poisoned".into()))?;
            if enabled {
                set.insert(protocol.clone());
            } else {
                set.remove(&protocol);
            }
        }

        let matching_backends: Vec<Arc<dyn MessagingBackend>> = {
            let map = self
                .backends
                .read()
                .map_err(|_| WarpError::Storage("backends lock poisoned".into()))?;
            map.values()
                .filter(|b| b.protocol() == protocol)
                .cloned()
                .collect()
        };

        for backend in matching_backends {
            if enabled {
                backend.connect().await?;
            } else {
                backend.disconnect().await?;
            }
        }

        debug!(protocol = %protocol, enabled, "Protocol runtime state toggled");
        self.emit_event(BackendEvent::ProtocolToggled { protocol, enabled });
        Ok(())
    }

    /// Lists all registered [`AccountId`]s belonging to `protocol` (supports N accounts per protocol).
    pub fn accounts_for_protocol(&self, protocol: &ProtocolKind) -> Vec<AccountId> {
        let Ok(map) = self.backends.read() else {
            return Vec::new();
        };
        let mut out: Vec<AccountId> = map
            .iter()
            .filter(|(_, b)| &b.protocol() == protocol)
            .map(|(acc_id, _)| acc_id.clone())
            .collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        out
    }

    /// Lists all `(AccountId, ProtocolKind)` pairs registered across all protocols.
    pub fn list_all_accounts(&self) -> Vec<(AccountId, ProtocolKind)> {
        let Ok(map) = self.backends.read() else {
            return Vec::new();
        };
        let mut out: Vec<(AccountId, ProtocolKind)> = map
            .iter()
            .map(|(acc_id, b)| (acc_id.clone(), b.protocol()))
            .collect();
        out.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        out
    }

    /// Returns `true` if the specific account instance is enabled (and its protocol is also enabled).
    pub fn is_account_enabled(&self, account_id: &AccountId) -> bool {
        let disabled = self
            .disabled_accounts
            .read()
            .map(|s| s.contains(account_id))
            .unwrap_or(false);
        if disabled {
            return false;
        }
        if let Some(backend) = self.get_backend(account_id) {
            return self.is_protocol_enabled(&backend.protocol());
        }
        true
    }

    /// Enables or disables a single account instance at runtime without affecting other accounts of the same protocol.
    pub async fn set_account_enabled(
        &self,
        account_id: AccountId,
        enabled: bool,
    ) -> Result<(), WarpError> {
        {
            let mut set = self
                .disabled_accounts
                .write()
                .map_err(|_| WarpError::Storage("disabled_accounts lock poisoned".into()))?;
            if enabled {
                set.remove(&account_id);
            } else {
                set.insert(account_id.clone());
            }
        }

        if let Some(backend) = self.get_backend(&account_id) {
            let protocol = backend.protocol();
            if enabled && self.is_protocol_enabled(&protocol) {
                backend.connect().await?;
            } else {
                backend.disconnect().await?;
            }
            self.emit_event(BackendEvent::AccountToggled {
                account_id,
                protocol,
                enabled,
            });
        }
        Ok(())
    }

    /// Broadcasts a [`BackendEvent`] to all subscribers (e.g., the 16ms UI coalescer).
    pub fn emit_event(&self, event: BackendEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Subscribes to the global [`BackendEvent`] broadcast stream.
    pub fn subscribe(&self) -> broadcast::Receiver<BackendEvent> {
        self.event_tx.subscribe()
    }
}

#[async_trait]
impl MessageDispatcher for ProtocolRegistry {
    async fn dispatch(&self, req: OutboundMessageRequest) -> Result<UniversalId, WarpError> {
        let protocol = &req.chat_id.protocol;
        if !self.is_protocol_enabled(protocol) {
            return Err(WarpError::ProtocolDisabled(protocol.as_slug().to_string()));
        }
        if !self.is_account_enabled(&req.chat_id.account_id) {
            return Err(WarpError::ProtocolDisabled(format!(
                "account:{}",
                req.chat_id.account_id
            )));
        }

        let backend = self.get_backend(&req.chat_id.account_id).ok_or_else(|| {
            WarpError::AccountNotFound(req.chat_id.account_id.as_str().to_string())
        })?;

        backend.send_message(req).await
    }
}

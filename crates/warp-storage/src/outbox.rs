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

//! Transactional Outbox Engine & Optimistic UI (`OutboxEngine`, `MessageDispatcher`).
//!
//! Guarantees `< 1ms` local echo when sending a message on any of the 8 protocols:
//! 1. `send_optimistic` writes the message immediately to SQLite (`DeliveryState::Pending`)
//!    and appends an entry to `outbox_queue`.
//! 2. `flush_once` / `spawn_worker` asynchronously dispatches due items through
//!    [`MessageDispatcher`].
//! 3. On confirmation, `confirm_outbox_delivery` atomically swaps the temporary
//!    `local-*` `UniversalId` with the authoritative remote `UniversalId` and updates
//!    `DeliveryState` to `DeliveryState::Sent`.
//! 4. On transient network failure, exponential backoff (`500ms * 2^attempt`) is scheduled
//!    via `mark_outbox_retry`.

use crate::db::{now_unix_ms, WarpStorage};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use warp_core::{OutboundMessageRequest, UnifiedMessage, UniversalId, WarpError};

/// Asynchronous dispatcher bridge implemented by the protocol registry / router
/// to forward queued [`OutboundMessageRequest`] payloads to the appropriate [`warp_core::MessagingBackend`].
#[async_trait]
pub trait MessageDispatcher: Send + Sync {
    /// Dispatches `req` to the target protocol backend and returns the confirmed remote [`UniversalId`].
    async fn dispatch(&self, req: OutboundMessageRequest) -> Result<UniversalId, WarpError>;
}

/// Transactional Outbox Engine driving Optimistic UI (`< 1ms` local echo) and resilient retries.
#[derive(Clone)]
pub struct OutboxEngine {
    storage: WarpStorage,
    dispatcher: Arc<dyn MessageDispatcher>,
}

impl OutboxEngine {
    /// Creates a new [`OutboxEngine`] backed by `storage` and `dispatcher`.
    pub fn new(storage: WarpStorage, dispatcher: Arc<dyn MessageDispatcher>) -> Self {
        Self {
            storage,
            dispatcher,
        }
    }

    /// Returns a reference to the underlying [`WarpStorage`].
    pub fn storage(&self) -> &WarpStorage {
        &self.storage
    }

    /// Synchronously persists an outgoing message with [`warp_core::DeliveryState::Pending`]
    /// in `< 1ms` and enqueues it in `outbox_queue` for asynchronous background delivery.
    pub fn send_optimistic(
        &self,
        chat_id: &UniversalId,
        sender_name: &str,
        text: String,
        reply_to: Option<UniversalId>,
    ) -> Result<UnifiedMessage, WarpError> {
        let now_ms = now_unix_ms();
        let (message, _req) =
            self.storage
                .enqueue_optimistic_message(chat_id, sender_name, text, reply_to, now_ms)?;
        Ok(message)
    }

    /// Processes all currently due entries in `outbox_queue` once.
    ///
    /// Returns the number of messages successfully confirmed during this pass.
    pub async fn flush_once(&self) -> Result<usize, WarpError> {
        self.flush_due_at(now_unix_ms()).await
    }

    /// Processes all entries in `outbox_queue` whose `next_retry_ts_ms <= now_ms`.
    pub async fn flush_due_at(&self, now_ms: i64) -> Result<usize, WarpError> {
        let due_items = self.storage.fetch_due_outbox_items(now_ms)?;
        let mut confirmed_count = 0usize;

        for item in due_items {
            match self.dispatcher.dispatch(item.request.clone()).await {
                Ok(confirmed_id) => {
                    let confirmed_ts = now_unix_ms().max(item.created_at_ms);
                    self.storage.confirm_outbox_delivery(
                        &item.local_message_id,
                        &confirmed_id,
                        confirmed_ts,
                    )?;
                    debug!(
                        local_id = %item.local_message_id,
                        confirmed_id = %confirmed_id,
                        "Outbox message confirmed and reconciled"
                    );
                    confirmed_count += 1;
                }
                Err(err) => {
                    let next_attempt = item.attempt_count.saturating_add(1);
                    let shift = item.attempt_count.min(16);
                    let backoff_ms = 500_i64.saturating_mul(1_i64 << shift);
                    let next_retry_ts_ms = now_ms.saturating_add(backoff_ms);
                    let err_msg = err.to_string();

                    self.storage.mark_outbox_retry(
                        &item.local_message_id,
                        next_attempt,
                        next_retry_ts_ms,
                        &err_msg,
                    )?;
                    warn!(
                        local_id = %item.local_message_id,
                        attempt = next_attempt,
                        backoff_ms,
                        error = %err_msg,
                        "Outbox delivery failed; scheduled exponential backoff retry"
                    );
                }
            }
        }

        Ok(confirmed_count)
    }

    /// Spawns a background Tokio worker that periodically flushes the transactional outbox.
    pub fn spawn_worker(self: Arc<Self>, poll_interval: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll_interval);
            loop {
                ticker.tick().await;
                if let Err(err) = self.flush_once().await {
                    warn!(error = %err, "Outbox worker flush pass encountered an error");
                }
            }
        })
    }
}

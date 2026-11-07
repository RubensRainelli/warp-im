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

//! Integration test demonstrating how a new 9th protocol (`dummy_mesh`) can be
//! defined and dispatched through the Transactional `OutboxEngine` in < 50 lines
//! without modifying a single line of `warp-core` or `warp-storage`.

use async_trait::async_trait;
use std::sync::Arc;
use warp_core::{
    DeliveryState, OutboundMessageRequest, ProtocolKind, UniversalId, WarpError,
};
use warp_storage::{MessageDispatcher, OutboxEngine, WarpStorage};

struct DummyMeshProtocolDispatcher;

#[async_trait]
impl MessageDispatcher for DummyMeshProtocolDispatcher {
    async fn dispatch(&self, req: OutboundMessageRequest) -> Result<UniversalId, WarpError> {
        Ok(UniversalId::new(
            req.chat_id.protocol.clone(),
            req.chat_id.account_id.clone(),
            format!("mesh-ack-{}", req.text.len()),
        ))
    }
}

#[tokio::test]
async fn register_dummy_9th_protocol_and_send_via_outbox_in_under_50_lines() {
    let storage = WarpStorage::open_in_memory().unwrap();
    let outbox = OutboxEngine::new(storage.clone(), Arc::new(DummyMeshProtocolDispatcher));

    let proto = ProtocolKind::from_slug("dummy_mesh");
    let chat_id = UniversalId::new(proto, "mesh_acc_1", "room_alpha");

    // 1. Optimistic local insert (< 1ms) -> DeliveryState::Pending
    let pending = outbox
        .send_optimistic(&chat_id, "Alice", "Hello 9th Protocol!".into(), None)
        .unwrap();
    assert_eq!(pending.delivery_state, DeliveryState::Pending);

    // 2. Flush Outbox -> Dispatches to DummyMeshProtocolDispatcher & reconciles remote_id
    let confirmed = outbox.flush_once().await.unwrap();
    assert_eq!(confirmed, 1);

    let messages = storage.list_messages(&chat_id, 10).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].delivery_state, DeliveryState::Sent);
    assert_eq!(messages[0].id.remote_id.as_str(), "mesh-ack-19");
}

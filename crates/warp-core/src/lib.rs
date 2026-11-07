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

//! # `warp-core` — Core Protocol SDK & Topology Architecture
//!
//! Foundational protocol-agnostic crate for **Warp IM** (Universal Native Multi-Protocol Messenger).
//! Designed around the **Open-Closed Principle**: adding a 9th protocol requires implementing
//! [`plugin::ProtocolPlugin`] and [`plugin::MessagingBackend`] with **ZERO** changes to
//! `warp-storage` or `warp-app`.

pub mod auth;
pub mod capabilities;
pub mod ids;
pub mod models;
pub mod platform;
pub mod plugin;

pub use auth::{
    AuthFieldSpec, AuthFlowDescriptor, AuthStep, AuthStepSubmission, OnboardingMode, OtpPhase,
    QrInviteMode,
};
pub use capabilities::{ChatCapabilities, MessageCapabilities, ProtocolCapabilities};
pub use ids::{AccountId, IdParseError, ProtocolKind, UniversalId};
pub use models::{
    AccountProfile, ChatListIsolationMode, ChatTopologyKind, ContainerHierarchy, ContainerKind,
    DeliveryState, FolderFilterRule, MediaAttachment, MessageReaction, UnifiedChat,
    UnifiedContainer, UnifiedMessage,
};
pub use platform::{
    AppLifecycleEvent, FormFactorMode, PlatformTarget, TransportCapabilities,
};
pub use plugin::{
    BackendEvent, MessagingBackend, OutboundMessageRequest, ProtocolPlugin, ResolvedMediaBytes,
    SyncState, WarpError,
};

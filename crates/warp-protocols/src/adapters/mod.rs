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

//! Protocol adapters for all 8 first-class protocols in Warp IM.
//!
//! Each adapter is gated behind its corresponding Cargo feature flag (`proto-*`)
//! and implements [`warp_core::ProtocolPlugin`] and [`warp_core::MessagingBackend`].

#[cfg(feature = "proto-telegram")]
pub mod telegram;

#[cfg(feature = "proto-matrix")]
pub mod matrix;

#[cfg(feature = "proto-xmpp")]
pub mod xmpp;

#[cfg(feature = "proto-nostr")]
pub mod nostr;

#[cfg(feature = "proto-simplex")]
pub mod simplex;

#[cfg(feature = "proto-irc")]
pub mod irc;

#[cfg(feature = "proto-stoat")]
pub mod stoat;

#[cfg(feature = "proto-mattermost")]
pub mod mattermost;

#[cfg(feature = "proto-telegram")]
pub use telegram::{TelegramBackend, TelegramBackendEnvironment, TelegramPlugin};

#[cfg(feature = "proto-matrix")]
pub use matrix::{MatrixBackend, MatrixPlugin};

#[cfg(feature = "proto-xmpp")]
pub use xmpp::{XmppBackend, XmppPlugin};

#[cfg(feature = "proto-nostr")]
pub use nostr::{NostrBackend, NostrPlugin};

#[cfg(feature = "proto-simplex")]
pub use simplex::{SimpleXBackend, SimpleXPlugin};

#[cfg(feature = "proto-irc")]
pub use irc::{IrcBackend, IrcPlugin};

#[cfg(feature = "proto-stoat")]
pub use stoat::{StoatBackend, StoatPlugin};

#[cfg(feature = "proto-mattermost")]
pub use mattermost::{MattermostBackend, MattermostPlugin};

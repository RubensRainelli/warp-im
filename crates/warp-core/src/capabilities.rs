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

//! Granular Capability Bitmasks (`ProtocolCapabilities`, `ChatCapabilities`, `MessageCapabilities`).
//!
//! Enables the Slint UI and storage engine to adapt dynamically to the exact
//! capabilities of any protocol, room, or individual message without hardcoding
//! `if protocol == ProtocolKind::Irc` checks in the presentation layer.

use crate::ids::ProtocolKind;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    /// Capabilities advertised at the protocol adapter level.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ProtocolCapabilities: u32 {
        /// Supports 2-level containers (Workspaces, Servers, Matrix Spaces, IRC Networks).
        const SUPPORTS_WORKSPACES         = 1 << 0;
        /// Supports 3rd-level nested threads or forum topics (Telegram Topics, Matrix/Mattermost Threads).
        const SUPPORTS_THREADS            = 1 << 1;
        /// Supports end-to-end encryption (Matrix Megolm, XMPP OMEMO, Nostr NIP-17/59, SimpleX, TG Secret).
        const SUPPORTS_E2EE               = 1 << 2;
        /// Supports user online/offline/away presence notifications.
        const SUPPORTS_PRESENCE           = 1 << 3;
        /// Supports custom server/pack emojis.
        const SUPPORTS_CUSTOM_EMOJI       = 1 << 4;
        /// Supports server-side full-text message search.
        const SUPPORTS_SERVER_SEARCH      = 1 << 5;
        /// Requires a persistent background socket (MTProto, IRC TCP, XMPP stream, SimpleX SMP).
        const REQUIRES_PERSISTENT_SOCKET  = 1 << 6;
        /// Supports typing indicator events.
        const SUPPORTS_TYPING_INDICATORS  = 1 << 7;
        /// Supports message reactions (emoji responses).
        const SUPPORTS_REACTIONS          = 1 << 8;
        /// Supports voice note recording and playback.
        const SUPPORTS_VOICE_NOTES        = 1 << 9;
        /// Supports rich binary file/media uploads.
        const SUPPORTS_FILE_Uploads       = 1 << 10;
        /// Supports QR-code based out-of-band pairing or invite queues (SimpleX, Matrix, Telegram).
        const SUPPORTS_QR_INVITES         = 1 << 11;
        /// Supports bouncer/relay history backfill (IRCv3 `chathistory`, XMPP MAM, Nostr relays).
        const SUPPORTS_HISTORY_BACKFILL   = 1 << 12;
    }
}

impl ProtocolCapabilities {
    /// Returns the canonical capability bitmask for each of the 8 target protocols.
    pub fn default_for(protocol: &ProtocolKind) -> Self {
        match protocol {
            ProtocolKind::Telegram => {
                Self::SUPPORTS_THREADS
                    | Self::SUPPORTS_E2EE
                    | Self::SUPPORTS_PRESENCE
                    | Self::SUPPORTS_CUSTOM_EMOJI
                    | Self::SUPPORTS_SERVER_SEARCH
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_VOICE_NOTES
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_QR_INVITES
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::Matrix => {
                Self::SUPPORTS_WORKSPACES
                    | Self::SUPPORTS_THREADS
                    | Self::SUPPORTS_E2EE
                    | Self::SUPPORTS_PRESENCE
                    | Self::SUPPORTS_CUSTOM_EMOJI
                    | Self::SUPPORTS_SERVER_SEARCH
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_VOICE_NOTES
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_QR_INVITES
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::Xmpp => {
                Self::SUPPORTS_E2EE
                    | Self::SUPPORTS_PRESENCE
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_VOICE_NOTES
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::Nostr => {
                Self::SUPPORTS_E2EE
                    | Self::SUPPORTS_CUSTOM_EMOJI
                    | Self::SUPPORTS_SERVER_SEARCH
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::SimpleX => {
                Self::SUPPORTS_E2EE
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_VOICE_NOTES
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_QR_INVITES
            }
            ProtocolKind::Irc => {
                Self::SUPPORTS_WORKSPACES
                    | Self::SUPPORTS_PRESENCE
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::Stoat => {
                Self::SUPPORTS_WORKSPACES
                    | Self::SUPPORTS_THREADS
                    | Self::SUPPORTS_PRESENCE
                    | Self::SUPPORTS_CUSTOM_EMOJI
                    | Self::SUPPORTS_SERVER_SEARCH
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_VOICE_NOTES
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::Mattermost => {
                Self::SUPPORTS_WORKSPACES
                    | Self::SUPPORTS_THREADS
                    | Self::SUPPORTS_PRESENCE
                    | Self::SUPPORTS_CUSTOM_EMOJI
                    | Self::SUPPORTS_SERVER_SEARCH
                    | Self::REQUIRES_PERSISTENT_SOCKET
                    | Self::SUPPORTS_TYPING_INDICATORS
                    | Self::SUPPORTS_REACTIONS
                    | Self::SUPPORTS_VOICE_NOTES
                    | Self::SUPPORTS_FILE_Uploads
                    | Self::SUPPORTS_HISTORY_BACKFILL
            }
            ProtocolKind::Custom(_) => {
                Self::REQUIRES_PERSISTENT_SOCKET | Self::SUPPORTS_FILE_Uploads
            }
        }
    }
}

bitflags! {
    /// Fine-grained capabilities for a specific [`crate::models::UnifiedChat`].
    ///
    /// Directly drives the Slint chat viewport input bar and header controls:
    /// e.g. on a basic IRC channel, `CAN_SEND_VOICE` and `CAN_EDIT` are unset,
    /// so the microphone button and arbitrary message editing are automatically hidden.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ChatCapabilities: u32 {
        /// User is allowed to send text messages in this chat.
        const CAN_SEND_MESSAGES  = 1 << 0;
        /// User can edit any of their own sent messages.
        const CAN_EDIT           = 1 << 1;
        /// User can only edit their most recent message (XMPP XEP-0308 / IRCv3 draft/message-edit).
        const CAN_EDIT_ONLY_LAST = 1 << 2;
        /// User can retract/delete messages for all participants.
        const CAN_DELETE_FOR_ALL = 1 << 3;
        /// User can attach emoji reactions to messages (`message-tags` on IRCv3, reactions on TG/MX).
        const CAN_REACT          = 1 << 4;
        /// User can quote/reply to a specific message.
        const CAN_REPLY_QUOTE    = 1 << 5;
        /// User can pin messages to the chat header.
        const CAN_PIN            = 1 << 6;
        /// User can record and send voice messages.
        const CAN_SEND_VOICE     = 1 << 7;
        /// User can upload files/images via the Media Proxy.
        const CAN_UPLOAD_FILES   = 1 << 8;
        /// Chat supports spawning or viewing sub-threads/topics.
        const SUPPORTS_THREADS   = 1 << 9;
        /// Messages in this chat are end-to-end encrypted.
        const IS_E2EE_ACTIVE     = 1 << 10;
        /// Broadcast channel where the current user is read-only.
        const IS_READ_ONLY       = 1 << 11;
    }
}

impl ChatCapabilities {
    /// Rich modern chat preset (Telegram, Matrix E2EE, Stoat, Mattermost).
    pub fn full_featured() -> Self {
        Self::CAN_SEND_MESSAGES
            | Self::CAN_EDIT
            | Self::CAN_DELETE_FOR_ALL
            | Self::CAN_REACT
            | Self::CAN_REPLY_QUOTE
            | Self::CAN_PIN
            | Self::CAN_SEND_VOICE
            | Self::CAN_UPLOAD_FILES
    }

    /// Standard IRCv3 channel preset (no voice notes, no arbitrary history deletion, last-message edit only).
    pub fn irc_channel(has_message_tags: bool) -> Self {
        let mut caps = Self::CAN_SEND_MESSAGES | Self::CAN_REPLY_QUOTE;
        if has_message_tags {
            caps |= Self::CAN_REACT | Self::CAN_EDIT_ONLY_LAST;
        }
        caps
    }

    /// XMPP OMEMO 1-to-1 chat preset (supports XEP-0308 last message correction, voice, files, E2EE).
    pub fn xmpp_omemo_dm() -> Self {
        Self::CAN_SEND_MESSAGES
            | Self::CAN_EDIT_ONLY_LAST
            | Self::CAN_REACT
            | Self::CAN_REPLY_QUOTE
            | Self::CAN_SEND_VOICE
            | Self::CAN_UPLOAD_FILES
            | Self::IS_E2EE_ACTIVE
    }

    /// Nostr NIP-17 Gift-Wrapped DM preset (immutable signed events: no edit/delete-for-all, E2EE, reactions, replies).
    pub fn nostr_nip17_dm() -> Self {
        Self::CAN_SEND_MESSAGES
            | Self::CAN_REACT
            | Self::CAN_REPLY_QUOTE
            | Self::CAN_UPLOAD_FILES
            | Self::IS_E2EE_ACTIVE
    }

    /// SimpleX SMP pairwise queue preset (full E2EE, edits, deletion, voice, files).
    pub fn simplex_queue() -> Self {
        Self::CAN_SEND_MESSAGES
            | Self::CAN_EDIT
            | Self::CAN_DELETE_FOR_ALL
            | Self::CAN_REACT
            | Self::CAN_REPLY_QUOTE
            | Self::CAN_SEND_VOICE
            | Self::CAN_UPLOAD_FILES
            | Self::IS_E2EE_ACTIVE
    }
}

bitflags! {
    /// Per-message action capabilities driving the Slint message context menu.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct MessageCapabilities: u32 {
        const CAN_EDIT           = 1 << 0;
        const CAN_DELETE_FOR_ALL = 1 << 1;
        const CAN_DELETE_LOCALLY = 1 << 2;
        const CAN_REACT          = 1 << 3;
        const CAN_REPLY_QUOTE    = 1 << 4;
        const CAN_PIN            = 1 << 5;
        const CAN_FORWARD        = 1 << 6;
        const CAN_COPY_LINK      = 1 << 7;
    }
}

impl MessageCapabilities {
    /// Derives the capabilities for a specific message given its parent chat's
    /// capabilities, whether the message was sent by us, and whether it is the
    /// latest message in the chat.
    pub fn derive_from_chat(
        chat_caps: ChatCapabilities,
        is_outgoing: bool,
        is_last_outgoing_message: bool,
    ) -> Self {
        let mut caps = Self::CAN_DELETE_LOCALLY | Self::CAN_FORWARD;
        if chat_caps.contains(ChatCapabilities::CAN_REACT) {
            caps |= Self::CAN_REACT;
        }
        if chat_caps.contains(ChatCapabilities::CAN_REPLY_QUOTE) {
            caps |= Self::CAN_REPLY_QUOTE;
        }
        if chat_caps.contains(ChatCapabilities::CAN_PIN) {
            caps |= Self::CAN_PIN;
        }
        if is_outgoing {
            if chat_caps.contains(ChatCapabilities::CAN_EDIT)
                || (chat_caps.contains(ChatCapabilities::CAN_EDIT_ONLY_LAST)
                    && is_last_outgoing_message)
            {
                caps |= Self::CAN_EDIT;
            }
            if chat_caps.contains(ChatCapabilities::CAN_DELETE_FOR_ALL) {
                caps |= Self::CAN_DELETE_FOR_ALL;
            }
        }
        caps
    }
}

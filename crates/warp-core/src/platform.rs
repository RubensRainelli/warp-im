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

//! Cross-Platform Target, Form-Factor & Runtime Capability Abstraction (`PlatformTarget`, `FormFactorMode`, `TransportCapabilities`).
//!
//! Ensures **Warp IM** can compile and adapt seamlessly across:
//! 1. **Desktop Native**: Linux (Wayland/X11), macOS (Metal), Windows (Direct3D/Vulkan)
//! 2. **Mobile Native**: Android (`aarch64-linux-android` / `cargo-apk`) & iOS (`aarch64-apple-ios`)
//! 3. **WebAssembly (`wasm32-unknown-unknown`)**: Browser Canvas/WebGL via Rust + Slint (`wasm-bindgen`),
//!    automatically switching transports from raw TCP sockets to WebSockets (`wss://`) and storage to IndexedDB/in-memory VFS.

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// Execution platform where Warp IM is compiled and running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformTarget {
    DesktopLinux,
    DesktopMacOs,
    DesktopWindows,
    MobileAndroid,
    MobileIos,
    WebWasm32,
}

impl PlatformTarget {
    /// Detects the active compilation target at compile/runtime using Rust `cfg!` predicates.
    pub const fn detect_current() -> Self {
        if cfg!(target_arch = "wasm32") {
            Self::WebWasm32
        } else if cfg!(target_os = "android") {
            Self::MobileAndroid
        } else if cfg!(target_os = "ios") {
            Self::MobileIos
        } else if cfg!(target_os = "macos") {
            Self::DesktopMacOs
        } else if cfg!(target_os = "windows") {
            Self::DesktopWindows
        } else {
            Self::DesktopLinux
        }
    }

    pub const fn is_desktop(&self) -> bool {
        matches!(
            self,
            Self::DesktopLinux | Self::DesktopMacOs | Self::DesktopWindows
        )
    }

    pub const fn is_mobile(&self) -> bool {
        matches!(self, Self::MobileAndroid | Self::MobileIos)
    }

    pub const fn is_wasm32(&self) -> bool {
        matches!(self, Self::WebWasm32)
    }

    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::DesktopLinux => "Linux Desktop (Native)",
            Self::DesktopMacOs => "macOS Desktop (Native)",
            Self::DesktopWindows => "Windows Desktop (Native)",
            Self::MobileAndroid => "Android Mobile (Native)",
            Self::MobileIos => "iOS Mobile (Native)",
            Self::WebWasm32 => "WebAssembly (wasm32-unknown-unknown)",
        }
    }

    /// Default UI form-factor for this platform target.
    pub const fn default_form_factor(&self) -> FormFactorMode {
        if self.is_mobile() {
            FormFactorMode::MobileCompactSinglePane
        } else {
            FormFactorMode::DesktopWide
        }
    }
}

/// UI viewport ergonomics & responsive layout mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormFactorMode {
    /// Multi-column split view (Optional Server Rail + Chat List Sidebar + Active Chat Viewport).
    DesktopWide,
    /// Collapsible drawer + viewport for medium-width tablets or narrow desktop windows.
    TabletAdaptive,
    /// Single-pane stack navigation for smartphones (`< 720px`): switches between the Chat List
    /// and the Active Chat Viewport with a hardware/touch Back button and bottom/top touch bars.
    MobileCompactSinglePane,
}

impl FormFactorMode {
    /// Automatically selects the responsive form factor based on window width in logical pixels.
    pub const fn from_viewport_width(width_px: f32, force_mobile: bool) -> Self {
        if force_mobile || width_px < 680.0 {
            Self::MobileCompactSinglePane
        } else if width_px < 960.0 {
            Self::TabletAdaptive
        } else {
            Self::DesktopWide
        }
    }
}

bitflags! {
    /// Hardware & OS transport capabilities available on the current [`PlatformTarget`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct TransportCapabilities: u32 {
        /// Direct TCP/TLS sockets (`tokio::net::TcpStream` for MTProto TCP, IRCv3, XMPP, SimpleX SMP).
        const RAW_TCP_TLS            = 1 << 0;
        /// WebSocket (`wss://`) transport (required on `wasm32-unknown-unknown` for MTProto WS, IRCv3 WS RFC 8394, SimpleX WS, Nostr, Matrix, Stoat, Mattermost).
        const WEBSOCKET_WSS          = 1 << 1;
        /// HTTPS REST / Fetch API requests.
        const HTTPS_REST             = 1 << 2;
        /// Local POSIX/Win32 filesystem SQLite WAL & encrypted media disk cache.
        const LOCAL_FILESYSTEM_CACHE = 1 << 3;
        /// Browser IndexedDB / Origin-Private File System (OPFS) for `wasm32-unknown-unknown`.
        const INDEXED_DB_STORAGE     = 1 << 4;
        /// Mobile background push notifications (UnifiedPush / FCM / APNs) to wake up sockets on Android/iOS.
        const MOBILE_PUSH_WAKEUP     = 1 << 5;
    }
}

impl TransportCapabilities {
    /// Returns the transport & persistence capabilities supported by `target`.
    pub const fn for_target(target: PlatformTarget) -> Self {
        match target {
            PlatformTarget::DesktopLinux
            | PlatformTarget::DesktopMacOs
            | PlatformTarget::DesktopWindows => Self::RAW_TCP_TLS
                .union(Self::WEBSOCKET_WSS)
                .union(Self::HTTPS_REST)
                .union(Self::LOCAL_FILESYSTEM_CACHE),
            PlatformTarget::MobileAndroid | PlatformTarget::MobileIos => Self::RAW_TCP_TLS
                .union(Self::WEBSOCKET_WSS)
                .union(Self::HTTPS_REST)
                .union(Self::LOCAL_FILESYSTEM_CACHE)
                .union(Self::MOBILE_PUSH_WAKEUP),
            PlatformTarget::WebWasm32 => Self::WEBSOCKET_WSS
                .union(Self::HTTPS_REST)
                .union(Self::INDEXED_DB_STORAGE),
        }
    }
}

/// OS & Mobile lifecycle events dispatched to `WarpStorage` and `ProtocolRegistry`
/// to keep RAM usage strictly `< 50MB` and preserve SQLite WAL integrity on iOS/Android/Web.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppLifecycleEvent {
    /// Application entered the foreground; resume real-time sync streams.
    Foregrounded,
    /// Application moved to background (Mobile iOS/Android); checkpoint SQLite WAL and pause non-essential polling.
    BackgroundedFlushWal,
    /// OS signaled memory pressure; evict decrypted in-RAM media cache (`MediaProxy`) and run `PRAGMA shrink_memory`.
    LowMemoryTrimCache,
    /// Network connectivity state changed (Wi-Fi <-> Cellular <-> Offline); trigger Outbox flush when back online.
    NetworkReachabilityChanged { online: bool },
}

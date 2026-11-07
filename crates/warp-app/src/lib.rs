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

//! # `warp-app` — Cross-Platform Shared Library (`Desktop`, `Mobile Android/iOS`, `wasm32-unknown-unknown`)
//!
//! Provides the unified application bootstrap (`run_warp_app`) across:
//! - **Desktop Native**: Linux (Wayland/X11), macOS (Metal), Windows (DirectX/Vulkan) via `src/main.rs`.
//! - **Mobile Native**: Android (`cdylib` / `android-activity`) and iOS (`staticlib`) with automatic
//!   [`FormFactorMode::MobileCompactSinglePane`](warp_core::FormFactorMode::MobileCompactSinglePane) detection.
//! - **WebAssembly (`wasm32-unknown-unknown`)**: Browser WebGL2 / WebGPU canvas + WSS WebSocket transports.

slint::include_modules!();

pub mod android_platform;
pub mod theme_manager;
pub mod ui_bridge;

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::info;
use warp_core::{AuthFlowDescriptor, FormFactorMode, PlatformTarget, ProtocolKind};
use warp_protocols::{seed_simulated_environment, ProtocolRegistry};
use warp_storage::{OutboxEngine, WarpStorage};

use crate::theme_manager::ThemeManager;
use crate::ui_bridge::{
    apply_auth_flow_to_window, apply_snapshot_to_window, build_ui_snapshot, init_pefl_eula_modal,
    is_pefl_clause3_approved, spawn_16ms_coalescer, wire_window_callbacks, UiSelectionState,
};

/// Handles Android system Back gesture / hardware Back key & in-app Back navigation:
/// 1. Closes the Built-In Mobile Touch Keyboard / Android IME if open.
/// 2. Steps back from Auth Modal -> Protocol Picker Modal -> Main View.
/// 3. Closes Settings Modal or New Chat Modal if open.
/// 4. Returns from Mobile Single-Pane Active Chat Viewport -> Chat List.
pub fn handle_back_action(win: &MainWindow) -> bool {
    let st = win.global::<SuperTheme>();
    if st.get_mobile_keyboard_open() {
        st.set_mobile_keyboard_open(false);
        crate::android_platform::set_android_soft_keyboard_visible(false);
        return true;
    }
    if win.get_show_auth_modal() {
        win.set_show_auth_modal(false);
        win.set_show_protocol_picker_modal(true);
        return true;
    }
    if win.get_show_protocol_picker_modal() {
        win.set_show_protocol_picker_modal(false);
        return true;
    }
    if win.get_show_settings_modal() {
        win.set_show_settings_modal(false);
        return true;
    }
    if win.get_show_new_chat_modal() {
        win.set_show_new_chat_modal(false);
        return true;
    }
    if st.get_mobile_showing_chat() {
        st.set_mobile_showing_chat(false);
        return true;
    }
    false
}

/// Shared cross-platform bootstrap for Warp IM (Desktop, Mobile, and Headless CI).
pub async fn run_warp_app() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let platform = PlatformTarget::detect_current();
    let form_factor = platform.default_form_factor();

    info!(
        "Initializing Warp IM on platform={} (form_factor={:?}) under PEFL v1.0 (Copyright (c) 2026 Rubens Rainelli)...",
        platform.display_name(),
        form_factor
    );

    let is_headless_check = std::env::var("WARP_HEADLESS_CHECK").as_deref() == Ok("1");
    let force_demo_env = std::env::var("WARP_DEMO_MOCKUP").as_deref() == Ok("1");

    // 1. Initialize SQLite WAL Storage (persistent on disk by default; in-memory for headless check or explicit `:memory:`)
    let storage = match std::env::var("WARP_DB_PATH") {
        Ok(path) if path == ":memory:" => WarpStorage::open_in_memory()?,
        Ok(path) if !path.trim().is_empty() => WarpStorage::open(&path)?,
        _ if is_headless_check => WarpStorage::open_in_memory()?,
        _ => WarpStorage::open_default_persistent()?,
    };
    storage.ensure_default_folders()?;

    // 2. Initialize ProtocolRegistry with all 8 compiled protocol plugins
    let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());

    // Re-hydrate any persisted user accounts into the live ProtocolRegistry
    if let Ok(existing_accounts) = storage.list_accounts() {
        for acct in existing_accounts {
            let _ = registry.build_and_register_backend(
                &acct.protocol,
                acct.account_id.clone(),
                serde_json::json!({"is_active": acct.enabled}),
            );
            let _ = registry
                .set_account_enabled(acct.account_id.clone(), acct.enabled)
                .await;
        }
    }

    // 3. Seed simulated mockup ONLY if requested (`WARP_HEADLESS_CHECK=1`, `WARP_DEMO_MOCKUP=1`, or persisted `demo_mode_active == "true"`)
    let demo_mode_persisted = storage
        .get_app_setting("demo_mode_active")
        .ok()
        .flatten()
        .as_deref()
        == Some("true");
    if is_headless_check || force_demo_env || demo_mode_persisted {
        seed_simulated_environment(&storage, &registry).await?;
        let _ = storage.set_app_setting("demo_mode_active", "true");
        info!(
            "Demo / Mockup environment active: {} enabled protocols, {} accounts, {} containers, {} chats",
            registry.enabled_protocols().len(),
            storage.list_accounts()?.len(),
            storage.list_containers(true)?.len(),
            storage.list_chats(true)?.len()
        );
    } else {
        info!(
            "Loaded persistent user workspace: {} accounts, {} chats (First-Run Onboarding shown if 0 accounts)",
            storage.list_accounts()?.len(),
            storage.list_chats(true)?.len()
        );
    }

    // 4. Initialize Transactional Outbox Engine (< 1ms optimistic UI + background retry worker)
    let outbox = Arc::new(OutboxEngine::new(storage.clone(), registry.clone()));
    let _outbox_worker = outbox
        .clone()
        .spawn_worker(std::time::Duration::from_millis(250));

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    // 5. Check if running in headless smoke-check mode (`WARP_HEADLESS_CHECK=1`)
    if is_headless_check {
        let mut sel = UiSelectionState::default();
        let snap = build_ui_snapshot(&storage, &registry, &mut sel);
        let eula_cached = is_pefl_clause3_approved(&storage, now_ms);
        info!(
            "Headless verification succeeded (platform={}, PEFL Clause 3 cached={}): {} protocol toggles, {} accounts, isolation_mode='{}', {} folders, {} server rail items, {} chats, {} messages in active chat '{}'",
            platform.display_name(),
            eula_cached,
            snap.protocol_toggles.len(),
            snap.accounts.len(),
            snap.isolation_mode_slug,
            snap.folder_tabs.len(),
            snap.server_rail.len(),
            snap.visible_chats.len(),
            snap.messages.len(),
            snap.active_chat_title
        );
        return Ok(());
    }

    // 6. Initialize Slint MainWindow, Dual-Layer ThemeManager & PEFL v1.0 Clause 3 Foreground EULA Modal
    let window = MainWindow::new()?;
    let theme_manager = Arc::new(ThemeManager::new());
    let initial_supertheme = storage
        .get_app_setting("supertheme_slug")
        .ok()
        .flatten()
        .unwrap_or_else(|| "telegram".to_string());
    let initial_palette = storage
        .get_app_setting("palette_slug")
        .ok()
        .flatten()
        .unwrap_or_else(|| "night_telegram".to_string());
    theme_manager.apply_supertheme(&window, &initial_supertheme);
    theme_manager.apply_palette(&window, &initial_palette);

    // Apply platform-default form factor (`MobileCompactSinglePane` on Android/iOS or `WARP_MOBILE_PREVIEW=1`)
    crate::android_platform::ensure_android_local_storage_and_permissions();
    let start_mobile = matches!(form_factor, FormFactorMode::MobileCompactSinglePane)
        || std::env::var("WARP_MOBILE_PREVIEW").as_deref() == Ok("1");
    {
        let st = window.global::<SuperTheme>();
        st.set_is_mobile_compact(start_mobile);
        let (top_px, bottom_px) = crate::android_platform::current_android_safe_insets();
        if top_px > 0.0 || bottom_px > 0.0 {
            st.set_safe_area_top(top_px);
            st.set_safe_area_bottom(bottom_px);
        }
    }

    // Register dynamic Android status bar, navigation bar & soft keyboard insets listener
    {
        let win_weak = window.as_weak();
        crate::android_platform::register_android_insets_handler(std::sync::Arc::new(
            move |top_px, bottom_px| {
                let weak = win_weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(win) = weak.upgrade() {
                        let st = win.global::<SuperTheme>();
                        st.set_safe_area_top(top_px);
                        st.set_safe_area_bottom(bottom_px);
                    }
                });
            },
        ));
    }

    // Register Android system Back gesture / hardware Back key & left-edge swipe handler
    {
        let win_weak = window.as_weak();
        crate::android_platform::register_android_back_handler(std::sync::Arc::new(move || {
            let weak = win_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(win) = weak.upgrade() {
                    let _ = handle_back_action(&win);
                }
            });
        }));
    }

    init_pefl_eula_modal(&window, &storage, now_ms);

    // 7. Initial UI Snapshot + Declarative AuthFlow Inspector initialization
    let mut initial_sel = UiSelectionState::default();
    if let Ok(Some(saved_enter)) = storage.get_app_setting("send_on_enter") {
        initial_sel.send_on_enter = saved_enter != "false";
    }
    let selection = Arc::new(Mutex::new(initial_sel));
    {
        let mut sel = selection.lock().unwrap();
        let initial_snap = build_ui_snapshot(&storage, &registry, &mut sel);
        apply_snapshot_to_window(&window, initial_snap);
    }
    apply_auth_flow_to_window(&window, &AuthFlowDescriptor::initial_for(ProtocolKind::Telegram));

    // 8. Wire UI Callbacks & Spawn 16ms Tokio <-> Slint Coalescer
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    wire_window_callbacks(
        &window,
        storage.clone(),
        theme_manager,
        selection.clone(),
        cmd_tx,
    );
    let _coalescer = spawn_16ms_coalescer(
        window.as_weak(),
        storage,
        registry,
        outbox,
        selection,
        cmd_rx,
    );

    window.run()?;
    Ok(())
}

/// NativeActivity entry point (`android-activity` crate) exported inside `libwarp_app.so` for Android `.apk` packaging.
/// Initializes the `ANativeWindow` software surface renderer and runs the Slint event loop on the native activity thread.
#[cfg(target_os = "android")]
#[no_mangle]
pub fn android_main(app: android_activity::AndroidApp) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::android_platform::init_android_slint_platform(app);
        if let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            let _ = rt.block_on(run_warp_app());
        }
    }));
}


#[cfg(test)]
mod tests {
    use super::*;
    use warp_core::{ChatCapabilities, ChatListIsolationMode};

    #[tokio::test]
    async fn test_android_software_window_full_render_and_navigation_lifecycle() {
        use slint::platform::software_renderer::{
            MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType,
        };
        use slint::{LogicalPosition, Model};

        struct HeadlessAndroidSoftwarePlatform {
            window: std::rc::Rc<MinimalSoftwareWindow>,
            start: std::time::Instant,
        }

        impl slint::platform::Platform for HeadlessAndroidSoftwarePlatform {
            fn create_window_adapter(
                &self,
            ) -> Result<std::rc::Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError>
            {
                Ok(self.window.clone())
            }

            fn duration_since_start(&self) -> std::time::Duration {
                self.start.elapsed()
            }
        }

        let sw_window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        sw_window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
            scale_factor: 2.75,
        });
        sw_window.set_size(slint::PhysicalSize::new(1080, 2400));

        let _ = slint::platform::set_platform(Box::new(HeadlessAndroidSoftwarePlatform {
            window: sw_window.clone(),
            start: std::time::Instant::now(),
        }));

        // Construct MainWindow & wire full mobile state just like android_main -> run_warp_app
        let storage = WarpStorage::open_in_memory().expect("in-memory storage");
        storage.ensure_default_folders().expect("default folders");
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        let window = MainWindow::new().expect("create Slint MainWindow on software renderer");
        let theme_manager = Arc::new(ThemeManager::new());
        theme_manager.apply_supertheme(&window, "telegram");
        theme_manager.apply_palette(&window, "night_telegram");

        {
            let st = window.global::<SuperTheme>();
            st.set_is_mobile_compact(true);
            st.set_safe_area_top(38.0);
            st.set_safe_area_bottom(20.0);
        }

        let now_ms = 1_750_000_000_000_i64;
        let _ = std::fs::remove_file(crate::ui_bridge::PEFL_APPROVAL_CACHE_FILE);
        init_pefl_eula_modal(&window, &storage, now_ms);
        let selection = Arc::new(Mutex::new(UiSelectionState::default()));
        {
            let mut sel = selection.lock().unwrap();
            let snap = build_ui_snapshot(&storage, &registry, &mut sel);
            apply_snapshot_to_window(&window, snap);
        }
        apply_auth_flow_to_window(&window, &AuthFlowDescriptor::initial_for(ProtocolKind::Telegram));

        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        wire_window_callbacks(
            &window,
            storage.clone(),
            theme_manager.clone(),
            selection.clone(),
            cmd_tx,
        );

        let mut pixel_buffer = vec![PremultipliedRgbaColor::default(); 1080 * 2400];
        let mut frame_idx = 0usize;
        let mut render_frame = |label: &str| {
            slint::platform::update_timers_and_animations();
            sw_window.request_redraw();
            let drew = sw_window.draw_if_needed(|renderer| {
                renderer.render(&mut pixel_buffer, 1080);
            });
            assert!(drew, "Expected software renderer to draw frame for {label}");
            let non_zero = pixel_buffer
                .iter()
                .any(|px| px.red != 0 || px.green != 0 || px.blue != 0 || px.alpha != 0);
            assert!(non_zero, "Frame for {label} must contain non-black rendered pixels");
            if std::env::var("WARP_DUMP_FRAMES").as_deref() == Ok("1") {
                let raw_bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        pixel_buffer.as_ptr() as *const u8,
                        pixel_buffer.len() * 4,
                    )
                };
                let _ = std::fs::write(format!("/tmp/warp_frame_{frame_idx}.rgba"), raw_bytes);
            }
            frame_idx += 1;
        };

        // 1. Frame 0: PEFL v1.0 EULA foreground modal on 1080x2400 Android screen
        assert!(window.get_show_pefl_eula_modal());
        render_frame("PEFL EULA Modal");

        // Verify touch drag vertical scrolling inside the PEFL EULA ScrollView
        sw_window.dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position: LogicalPosition::new(196.0, 520.0),
            button: slint::platform::PointerEventButton::Left,
        });
        sw_window.dispatch_event(slint::platform::WindowEvent::PointerMoved {
            position: LogicalPosition::new(196.0, 260.0),
        });
        sw_window.dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position: LogicalPosition::new(196.0, 260.0),
            button: slint::platform::PointerEventButton::Left,
        });
        render_frame("PEFL EULA Modal Scrolled");

        // 2. Accept PEFL EULA -> triggers Android runtime permissions & shows First-Run Welcome Screen
        window.invoke_accept_pefl_eula(true);
        let _ = std::fs::remove_file(crate::ui_bridge::PEFL_APPROVAL_CACHE_FILE);
        assert!(!window.get_show_pefl_eula_modal());
        assert!(
            crate::android_platform::permissions_request_count() >= 1,
            "Accepting PEFL EULA must trigger Android runtime permissions request"
        );
        render_frame("First-Run Welcome Screen");

        // 3. Step 1 -> Step 2: Open Protocol Picker Modal
        window.set_show_protocol_picker_modal(true);
        render_frame("Step 2 Protocol Picker Modal");

        // 4. Step 2 -> Step 3: Select protocol -> Open Auth Modal
        window.set_show_protocol_picker_modal(false);
        window.set_show_auth_modal(true);
        render_frame("Step 3 Protocol Auth Modal");

        // 5. Open Built-In Mobile Touch Keyboard + Native JNI Soft Keyboard for Auth phone/token field
        window
            .global::<SuperTheme>()
            .invoke_request_soft_keyboard("auth:phone_or_token".into(), "Telefono".into());
        assert!(window.global::<SuperTheme>().get_mobile_keyboard_open());
        assert!(crate::android_platform::is_android_soft_keyboard_visible());

        // Type "+39" on the Built-In Mobile Touch Keyboard and verify first auth field updates to "+39"
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("+".into());
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("3".into());
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("9".into());
        let first_field_val = window
            .get_auth_modal_fields()
            .row_data(0)
            .expect("first auth field present")
            .value
            .to_string();
        assert_eq!(first_field_val, "+39");
        render_frame("Step 3 Auth Modal with Built-In Mobile Touch Keyboard (+39)");

        // 6. Android Back Gesture: closes Mobile Touch Keyboard FIRST, then Auth Modal -> Protocol Picker -> Welcome Screen
        {
            let win_weak = window.as_weak();
            crate::android_platform::register_android_back_handler(std::sync::Arc::new(move || {
                if let Some(win) = win_weak.upgrade() {
                    let _ = handle_back_action(&win);
                }
            }));
        }
        crate::android_platform::trigger_android_back();
        assert!(!window.global::<SuperTheme>().get_mobile_keyboard_open());
        assert!(!crate::android_platform::is_android_soft_keyboard_visible());
        assert!(window.get_show_auth_modal());
        render_frame("Back closes Mobile Touch Keyboard first");

        crate::android_platform::trigger_android_back();
        assert!(!window.get_show_auth_modal());
        assert!(window.get_show_protocol_picker_modal());
        render_frame("Back from Auth to Protocol Picker");

        crate::android_platform::trigger_android_back();
        assert!(!window.get_show_protocol_picker_modal());
        render_frame("Back from Protocol Picker to Welcome Screen");

        // 7. Seed all 8 protocols & render Mobile Chat List + test vertical touch drag scrolling on Chat List
        seed_simulated_environment(&storage, &registry)
            .await
            .expect("seed 8 protocols");
        {
            let mut sel = selection.lock().unwrap();
            let snap = build_ui_snapshot(&storage, &registry, &mut sel);
            apply_snapshot_to_window(&window, snap);
        }
        window.global::<SuperTheme>().set_mobile_showing_chat(false);
        render_frame("Mobile Single-Pane Chat List");

        sw_window.dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position: LogicalPosition::new(196.0, 640.0),
            button: slint::platform::PointerEventButton::Left,
        });
        sw_window.dispatch_event(slint::platform::WindowEvent::PointerMoved {
            position: LogicalPosition::new(196.0, 280.0),
        });
        sw_window.dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position: LogicalPosition::new(196.0, 280.0),
            button: slint::platform::PointerEventButton::Left,
        });
        render_frame("Mobile Single-Pane Chat List Scrolled");

        // 8. Tap chat -> Render Mobile Single-Pane Active Chat Viewport + Open Composer Mobile Touch Keyboard
        window.global::<SuperTheme>().set_mobile_showing_chat(true);
        render_frame("Mobile Single-Pane Active Chat Viewport");

        window
            .global::<SuperTheme>()
            .invoke_request_soft_keyboard("composer".into(), "Scrivi un messaggio".into());
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("C".into());
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("i".into());
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("a".into());
        window
            .global::<SuperTheme>()
            .invoke_mobile_key_tap("o".into());
        assert_eq!(window.get_composer_text().as_str(), "Ciao");
        render_frame("Mobile Active Chat with Built-In Mobile Touch Keyboard");

        // 9. Android Back Gesture -> closes Mobile Touch Keyboard first, then returns from Active Chat to Chat List
        crate::android_platform::trigger_android_back();
        assert!(!window.global::<SuperTheme>().get_mobile_keyboard_open());
        assert!(window.global::<SuperTheme>().get_mobile_showing_chat());

        crate::android_platform::trigger_android_back();
        assert!(!window.global::<SuperTheme>().get_mobile_showing_chat());
        render_frame("Back from Active Chat to Mobile Chat List");
    }

    #[tokio::test]
    async fn test_supertheme_and_capability_mapping_across_protocols() {
        let storage = WarpStorage::open_in_memory().expect("in-memory WAL storage");
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        seed_simulated_environment(&storage, &registry)
            .await
            .expect("seed 8 protocols");

        let mut selection = UiSelectionState::default();
        let snap = build_ui_snapshot(&storage, &registry, &mut selection);

        // Verify all 8 target protocols are represented in protocol_toggles
        assert_eq!(snap.protocol_toggles.len(), 8);
        // Verify 10 accounts are seeded across the 8 protocols (2 Telegram + 2 IRC + 6 others)
        assert_eq!(snap.accounts.len(), 10);
        assert!(
            snap.server_rail.len() >= 5,
            "Expected containers for Stoat, Mattermost, Matrix, IRC, Telegram"
        );
        assert!(
            snap.visible_chats.len() >= 8,
            "Expected chats from all 8 protocols"
        );

        // Verify IRC capability mapping hides voice notes and full edit
        let irc_caps = ui_bridge::map_chat_capabilities_to_ui(ChatCapabilities::irc_channel(true));
        assert!(!irc_caps.can_send_voice);
        assert!(!irc_caps.can_edit);
        assert!(irc_caps.can_edit_only_last);

        // Verify runtime protocol deactivation filters out disabled protocol chats
        registry
            .set_protocol_enabled(ProtocolKind::Irc, false)
            .await
            .expect("disable IRC");
        storage
            .set_protocol_enabled(&ProtocolKind::Irc, false)
            .expect("persist IRC disabled");

        let snap_after = build_ui_snapshot(&storage, &registry, &mut selection);
        assert!(
            !snap_after
                .visible_chats
                .iter()
                .any(|c| c.protocol_slug.as_str() == "irc"),
            "Disabled protocol chats must be filtered out dynamically"
        );
    }

    #[tokio::test]
    async fn test_ui_bridge_chat_list_isolation_modes_multi_account() {
        let storage = WarpStorage::open_in_memory().expect("in-memory WAL storage");
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        seed_simulated_environment(&storage, &registry)
            .await
            .expect("seed environment");

        let mut selection = UiSelectionState::default();

        // 1. UnifiedInbox: merges chats from all accounts marked `include_in_unified_inbox = true`
        // Note: `tg_dc2_lab` has `include_in_unified_inbox = false` by default so test chats don't pollute Unified Inbox!
        selection.isolation_mode = ChatListIsolationMode::UnifiedInbox;
        let snap_unified = build_ui_snapshot(&storage, &registry, &mut selection);
        assert!(snap_unified
            .visible_chats
            .iter()
            .any(|c| c.account_id.as_str() == "tg_main"));
        assert!(!snap_unified
            .visible_chats
            .iter()
            .any(|c| c.account_id.as_str() == "tg_dc2_lab"));

        // 2. PerProtocol (Telegram): shows BOTH Telegram accounts (`tg_main` + `tg_dc2_lab`)
        selection.isolation_mode = ChatListIsolationMode::PerProtocol;
        selection.active_protocol_filter = ProtocolKind::Telegram;
        let snap_tg_proto = build_ui_snapshot(&storage, &registry, &mut selection);
        assert!(snap_tg_proto
            .visible_chats
            .iter()
            .all(|c| c.protocol_slug.as_str() == "telegram"));
        assert!(snap_tg_proto
            .visible_chats
            .iter()
            .any(|c| c.account_id.as_str() == "tg_main"));
        assert!(snap_tg_proto
            .visible_chats
            .iter()
            .any(|c| c.account_id.as_str() == "tg_dc2_lab"));

        // 3. PerAccount (`tg_dc2_lab`): strictly isolates the chat list to ONLY `tg_dc2_lab`
        selection.isolation_mode = ChatListIsolationMode::PerAccount;
        selection.active_account_id = "tg_dc2_lab".to_string();
        let snap_dc2_only = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_dc2_only.visible_chats.len(), 1);
        assert_eq!(
            snap_dc2_only.visible_chats[0].account_id.as_str(),
            "tg_dc2_lab"
        );
        assert_eq!(
            snap_dc2_only.visible_chats[0].account_badge.as_str(),
            "TG•DC2"
        );

        // 4. PerAccount (`irc_oftc`): strictly isolates the chat list to ONLY `irc_oftc`
        selection.active_account_id = "irc_oftc".to_string();
        let snap_oftc_only = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_oftc_only.visible_chats.len(), 1);
        assert_eq!(
            snap_oftc_only.visible_chats[0].account_id.as_str(),
            "irc_oftc"
        );
        assert_eq!(
            snap_oftc_only.visible_chats[0].account_badge.as_str(),
            "IRC•OFTC"
        );
    }

    #[test]
    fn test_pefl_v1_clause3_eula_approval_and_7_day_expiration() {
        let storage = WarpStorage::open_in_memory().expect("in-memory storage");
        let day0_ms = 1_750_000_000_000_i64;

        // Before explicit user approval, PEFL Clause 3 must require foreground modal
        assert!(!storage.is_pefl_eula_valid(day0_ms).unwrap());

        // User explicitly approves PEFL v1.0
        storage.record_pefl_eula_acceptance(day0_ms).unwrap();
        assert!(storage.is_pefl_eula_valid(day0_ms + 1_000).unwrap());

        // Within 7 days (e.g. 6 days later), approval remains valid
        let six_days_later = day0_ms + 6 * 24 * 60 * 60 * 1000;
        assert!(storage.is_pefl_eula_valid(six_days_later).unwrap());

        // After 7 days + 1ms, Clause 3 requires re-displaying and re-approving the PEFL license
        let after_seven_days = day0_ms + WarpStorage::PEFL_SEVEN_DAYS_MS + 1;
        assert!(!storage.is_pefl_eula_valid(after_seven_days).unwrap());
    }

    #[tokio::test]
    async fn test_telegram_backend_mode_switcher_in_ui_bridge() {
        let storage = WarpStorage::open_in_memory().expect("in-memory WAL storage");
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        seed_simulated_environment(&storage, &registry)
            .await
            .expect("seed environment");

        let mut selection = UiSelectionState::default();
        let snap_default = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_default.telegram_backend_mode, "public");

        // Switch Telegram Backend to Test Server DC2 (149.154.167.40:443)
        let env_test = ui_bridge::apply_telegram_backend_mode_to_storage(
            &storage,
            &mut selection,
            "test_dc2",
        );
        assert!(env_test.is_test_server());
        let snap_test = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_test.telegram_backend_mode, "test_dc2");

        // Switch Telegram Backend back to Public Production (149.154.167.50:443)
        let env_pub =
            ui_bridge::apply_telegram_backend_mode_to_storage(&storage, &mut selection, "public");
        assert!(!env_pub.is_test_server());
        let snap_pub = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_pub.telegram_backend_mode, "public");
    }

    #[tokio::test]
    async fn test_first_run_onboarding_live_account_and_chat_actions() {
        let storage = WarpStorage::open_in_memory().expect("in-memory WAL storage");
        storage.ensure_default_folders().expect("default folders");
        let registry = Arc::new(ProtocolRegistry::with_compiled_plugins());
        let mut selection = UiSelectionState::default();

        // 1. First-run state with 0 accounts must NOT show mockup by default
        let snap_empty = build_ui_snapshot(&storage, &registry, &mut selection);
        assert!(snap_empty.accounts.is_empty());
        assert!(!snap_empty.is_demo_mockup_active);
        assert!(snap_empty.visible_chats.is_empty());

        // 2. Bootstrap a live authenticated account (e.g. Telegram Login)
        let acct_id = warp_core::AccountId::new("tg_rubens_live");
        let mut inputs = std::collections::BTreeMap::new();
        inputs.insert("phone_number".to_string(), "+393428115882".to_string());
        inputs.insert("backend_env".to_string(), "public".to_string());
        let _primary_chat = warp_protocols::bootstrap_live_authenticated_account(
            &storage,
            &registry,
            ProtocolKind::Telegram,
            &acct_id,
            "Rubens Rainelli",
            &inputs,
        )
        .await
        .expect("bootstrap live account");

        selection.active_account_id = acct_id.to_string();
        let snap_live = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_live.accounts.len(), 1);
        assert!(!snap_live.is_demo_mockup_active);
        assert!(snap_live.visible_chats.len() >= 2);

        // 3. Create a new chat / channel and filter via search_query
        let created_chat = storage
            .create_user_chat(
                &acct_id,
                ProtocolKind::Telegram,
                "Progetto Rust Slint",
                "@rust_slint",
                false,
            )
            .expect("create user chat");
        selection.search_query = "Rust Slint".to_string();
        let snap_filtered = build_ui_snapshot(&storage, &registry, &mut selection);
        assert_eq!(snap_filtered.visible_chats.len(), 1);
        assert_eq!(
            snap_filtered.visible_chats[0].uri.as_str(),
            created_chat.id.to_uri()
        );
    }
}

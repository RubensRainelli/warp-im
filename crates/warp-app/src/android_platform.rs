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

//! Pure-Rust Android Native Surface (`ANativeWindow`) & Input Engine for Slint.
//!
//! Attaches Slint's [`MinimalSoftwareWindow`] directly to Android's `ANativeWindow`
//! and `android-activity` event loop without requiring OpenGL/EGL setup, blitting
//! premultiplied `RGBA_8888` scanlines directly into the hardware gralloc surface buffer.

use std::ffi::c_void;

use slint::platform::software_renderer::PremultipliedRgbaColor;
use slint::{LogicalPosition, LogicalSize, PhysicalPosition, PhysicalSize};

/// Android NDK `AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM` / `WINDOW_FORMAT_RGBA_8888`.
pub const WINDOW_FORMAT_RGBA_8888: i32 = 1;

/// Default Android DPI baseline (`ACONFIGURATION_DENSITY_MEDIUM` = 160 dpi).
pub const ANDROID_BASELINE_DPI: f32 = 160.0;

/// Raw Android NDK `ANativeWindow_Buffer` C ABI layout (`<android/native_window.h>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ANativeWindow_Buffer {
    pub width: i32,
    pub height: i32,
    pub stride: i32,
    pub format: i32,
    pub bits: *mut c_void,
    pub reserved: [u32; 6],
}

#[cfg(target_os = "android")]
#[link(name = "android")]
extern "C" {
    pub fn ANativeWindow_getWidth(window: *mut c_void) -> i32;
    pub fn ANativeWindow_getHeight(window: *mut c_void) -> i32;
    pub fn ANativeWindow_setBuffersGeometry(
        window: *mut c_void,
        width: i32,
        height: i32,
        format: i32,
    ) -> i32;
    pub fn ANativeWindow_lock(
        window: *mut c_void,
        out_buffer: *mut ANativeWindow_Buffer,
        in_out_dirty_bounds: *mut c_void,
    ) -> i32;
    pub fn ANativeWindow_unlockAndPost(window: *mut c_void) -> i32;
}

/// Computes the Slint logical scale factor from Android's `AConfiguration_getDensity` DPI value,
/// clamped to `[1.5, 3.0]` with a `2.75` fallback so 1080p screens always have at least `360.0` logical width.
#[inline]
pub fn compute_android_scale_factor(density_dpi: Option<u32>) -> f32 {
    density_dpi
        .filter(|&d| d > 0)
        .map(|d| (d as f32 / ANDROID_BASELINE_DPI).clamp(1.5, 3.0))
        .unwrap_or(2.75)
}

/// Computes `(safe_area_top_px, safe_area_bottom_px)` in logical pixels for Android `NativeActivity`.
///
/// Even when `content_top_phys == 0` (Android 11–15 edge-to-edge `NativeActivity`), guarantees a
/// minimum top status bar inset of `36.0` logical px in portrait (`height_phys >= width_phys`) and
/// `24.0` logical px in landscape, plus a minimum bottom gesture navigation bar inset of `20.0` logical px.
/// When the Android soft keyboard (`adjustResize`) or system bar shrinks `content_bottom_phys` below
/// `height_phys`, the bottom inset expands automatically so the composer bar shifts above the keyboard.
#[inline]
pub fn compute_android_safe_insets_logical(
    width_phys: i32,
    height_phys: i32,
    scale_factor: f32,
    content_top_phys: i32,
    content_bottom_phys: i32,
) -> (f32, f32) {
    let scale = scale_factor.max(1.0);
    let min_top = if height_phys >= width_phys { 36.0 } else { 24.0 };
    let min_bottom = 20.0;

    let top_logical = if content_top_phys > 0 {
        (content_top_phys as f32 / scale).max(min_top)
    } else {
        min_top
    };

    let bottom_obscured_phys = if content_bottom_phys > 0 && height_phys > content_bottom_phys {
        height_phys - content_bottom_phys
    } else {
        0
    };

    let bottom_logical = if bottom_obscured_phys > 0 {
        (bottom_obscured_phys as f32 / scale).max(min_bottom)
    } else {
        min_bottom
    };

    (top_logical, bottom_logical)
}

/// Returns `true` if a touch gesture from `(start_x, start_y)` to `(end_x, end_y)` in logical pixels
/// is a horizontal left-edge back swipe (`start_x < 28.0`, `delta_x > 70.0`, `delta_y.abs() < 50.0`).
#[inline]
pub fn is_left_edge_back_swipe(start_x: f32, start_y: f32, end_x: f32, end_y: f32) -> bool {
    let delta_x = end_x - start_x;
    let delta_y = (end_y - start_y).abs();
    start_x >= 0.0 && start_x < 28.0 && delta_x > 70.0 && delta_y < 50.0
}

#[cfg(target_os = "android")]
const DEFAULT_SAFE_INSET_TOP_BITS: u32 = 38.0_f32.to_bits();
#[cfg(not(target_os = "android"))]
const DEFAULT_SAFE_INSET_TOP_BITS: u32 = 0.0_f32.to_bits();

#[cfg(target_os = "android")]
const DEFAULT_SAFE_INSET_BOTTOM_BITS: u32 = 20.0_f32.to_bits();
#[cfg(not(target_os = "android"))]
const DEFAULT_SAFE_INSET_BOTTOM_BITS: u32 = 0.0_f32.to_bits();

static SAFE_INSET_TOP_BITS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(DEFAULT_SAFE_INSET_TOP_BITS);
static SAFE_INSET_BOTTOM_BITS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(DEFAULT_SAFE_INSET_BOTTOM_BITS);

type BackHandler = std::sync::Arc<dyn Fn() + Send + Sync>;
type InsetsHandler = std::sync::Arc<dyn Fn(f32, f32) + Send + Sync>;

static ANDROID_BACK_HANDLER: std::sync::Mutex<Option<BackHandler>> = std::sync::Mutex::new(None);
static ANDROID_INSETS_HANDLER: std::sync::Mutex<Option<InsetsHandler>> =
    std::sync::Mutex::new(None);

static PERMISSIONS_REQUEST_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static SOFT_KEYBOARD_VISIBLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "android")]
static ANDROID_APP_HANDLE: std::sync::Mutex<Option<android_activity::AndroidApp>> =
    std::sync::Mutex::new(None);

/// Android runtime permissions requested on startup and when media/camera/mic features are invoked.
pub const ANDROID_RUNTIME_PERMISSIONS: [&str; 8] = [
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
];

/// Returns the current `(safe_area_top_px, safe_area_bottom_px)` in logical pixels.
/// Defaults to `(38.0, 20.0)` on Android and `(0.0, 0.0)` on Desktop.
#[inline]
pub fn current_android_safe_insets() -> (f32, f32) {
    let top = f32::from_bits(SAFE_INSET_TOP_BITS.load(std::sync::atomic::Ordering::Relaxed));
    let bottom = f32::from_bits(SAFE_INSET_BOTTOM_BITS.load(std::sync::atomic::Ordering::Relaxed));
    (top, bottom)
}

/// Updates the current Android safe area insets (in logical pixels) and notifies any registered listener
/// only when the insets actually changed by more than `0.5` logical px.
pub fn set_android_safe_insets(top_px: f32, bottom_px: f32) {
    let (prev_top, prev_bottom) = current_android_safe_insets();
    SAFE_INSET_TOP_BITS.store(top_px.to_bits(), std::sync::atomic::Ordering::Relaxed);
    SAFE_INSET_BOTTOM_BITS.store(bottom_px.to_bits(), std::sync::atomic::Ordering::Relaxed);
    if (top_px - prev_top).abs() > 0.5 || (bottom_px - prev_bottom).abs() > 0.5 {
        let handler = ANDROID_INSETS_HANDLER
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        if let Some(cb) = handler {
            cb(top_px, bottom_px);
        }
    }
}

/// Registers a callback invoked whenever Android safe area insets or soft-keyboard height change.
pub fn register_android_insets_handler(handler: std::sync::Arc<dyn Fn(f32, f32) + Send + Sync>) {
    if let Ok(mut guard) = ANDROID_INSETS_HANDLER.lock() {
        *guard = Some(handler);
    }
}

/// Registers a global callback invoked when the Android hardware Back button or system/edge swipe-back gesture fires.
pub fn register_android_back_handler(handler: std::sync::Arc<dyn Fn() + Send + Sync>) {
    if let Ok(mut guard) = ANDROID_BACK_HANDLER.lock() {
        *guard = Some(handler);
    }
}

/// Invokes the registered Android Back handler directly, returning `true` if a handler was registered.
pub fn trigger_android_back() -> bool {
    let handler = ANDROID_BACK_HANDLER
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    if let Some(cb) = handler {
        cb();
        true
    } else {
        false
    }
}

/// Returns the total number of times [`request_android_permissions_now`] has been invoked.
#[inline]
pub fn permissions_request_count() -> usize {
    PERMISSIONS_REQUEST_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

/// Requests Android runtime permissions (`POST_NOTIFICATIONS`, `READ/WRITE_EXTERNAL_STORAGE`,
/// `READ_MEDIA_IMAGES/VIDEO/AUDIO`, `RECORD_AUDIO`, `CAMERA`) on the Android Java UI thread
/// via `Activity.requestPermissions(String[], 1001)`.
pub fn request_android_permissions_now() -> bool {
    PERMISSIONS_REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    ensure_android_local_storage_and_permissions();

    #[cfg(target_os = "android")]
    {
        imp::dispatch_android_runtime_permissions();
    }

    true
}

/// Returns whether the Android soft keyboard (IME) is currently requested to be visible.
#[inline]
pub fn is_android_soft_keyboard_visible() -> bool {
    SOFT_KEYBOARD_VISIBLE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Shows or hides the Android soft keyboard (IME), focusing the `NativeActivity` decor `View`
/// on the Java UI thread so `InputMethodManager.showSoftInput` reliably opens the keyboard.
pub fn set_android_soft_keyboard_visible(visible: bool) {
    SOFT_KEYBOARD_VISIBLE.store(visible, std::sync::atomic::Ordering::SeqCst);

    #[cfg(target_os = "android")]
    {
        imp::dispatch_android_soft_keyboard(visible);
    }
}

/// Maps an Android `AKEYCODE_*` integer, shift modifier state, and optional `KeyCharacterMap`
/// Unicode character into a Slint [`slint::SharedString`] key payload.
///
/// Prioritizes printable Unicode characters from `KeyCharacterMap::get` (supporting international
/// soft keyboards and hardware layouts), with a comprehensive fallback table for letters, digits,
/// shifted symbols, numpad keys, punctuation, and navigation/editing keys.
pub fn map_android_key_to_text(
    keycode_raw: i32,
    shift_on: bool,
    unicode_char: Option<char>,
) -> Option<slint::SharedString> {
    use slint::platform::Key;

    // Navigation and editing keys take precedence when unicode_char is absent or control
    match keycode_raw {
        66 | 160 => return Some(Key::Return.into()),     // AKEYCODE_ENTER | AKEYCODE_NUMPAD_ENTER
        67 => return Some(Key::Backspace.into()),        // AKEYCODE_DEL
        112 => return Some(Key::Delete.into()),          // AKEYCODE_FORWARD_DEL
        61 => return Some(Key::Tab.into()),              // AKEYCODE_TAB
        19 => return Some(Key::UpArrow.into()),          // AKEYCODE_DPAD_UP
        20 => return Some(Key::DownArrow.into()),        // AKEYCODE_DPAD_DOWN
        21 => return Some(Key::LeftArrow.into()),        // AKEYCODE_DPAD_LEFT
        22 => return Some(Key::RightArrow.into()),       // AKEYCODE_DPAD_RIGHT
        4 | 111 => return Some(Key::Backspace.into()),   // AKEYCODE_BACK | AKEYCODE_ESCAPE
        _ => {}
    }

    if let Some(ch) = unicode_char {
        if ch == '\n' || ch == '\r' {
            return Some(Key::Return.into());
        } else if ch == '\t' {
            return Some(Key::Tab.into());
        } else if ch == '\u{0008}' {
            return Some(Key::Backspace.into());
        } else if ch == '\u{007f}' {
            return Some(Key::Delete.into());
        } else if !ch.is_control() {
            return Some(ch.to_string().into());
        }
    }

    match keycode_raw {
        // AKEYCODE_A (29) ..= AKEYCODE_Z (54)
        29..=54 => {
            let offset = (keycode_raw - 29) as u8;
            let ch = if shift_on {
                (b'A' + offset) as char
            } else {
                (b'a' + offset) as char
            };
            Some(ch.to_string().into())
        }
        // AKEYCODE_0 (7) ..= AKEYCODE_9 (16)
        7..=16 => {
            const SHIFTED_DIGITS: [&str; 10] = [")", "!", "@", "#", "$", "%", "^", "&", "*", "("];
            let idx = (keycode_raw - 7) as usize;
            if shift_on {
                Some(SHIFTED_DIGITS[idx].into())
            } else {
                let ch = (b'0' + idx as u8) as char;
                Some(ch.to_string().into())
            }
        }
        // AKEYCODE_NUMPAD_0 (144) ..= AKEYCODE_NUMPAD_9 (153)
        144..=153 => {
            let ch = (b'0' + (keycode_raw - 144) as u8) as char;
            Some(ch.to_string().into())
        }
        81 | 157 => Some("+".into()), // AKEYCODE_PLUS | AKEYCODE_NUMPAD_ADD
        69 | 156 => Some(if shift_on { "_" } else { "-" }.into()), // AKEYCODE_MINUS | AKEYCODE_NUMPAD_SUBTRACT
        70 | 161 => Some(if shift_on { "+" } else { "=" }.into()), // AKEYCODE_EQUALS | AKEYCODE_NUMPAD_EQUALS
        77 => Some("@".into()),                                    // AKEYCODE_AT
        56 | 158 => Some(if shift_on { ">" } else { "." }.into()), // AKEYCODE_PERIOD | AKEYCODE_NUMPAD_DOT
        55 | 159 => Some(if shift_on { "<" } else { "," }.into()), // AKEYCODE_COMMA | AKEYCODE_NUMPAD_COMMA
        74 => Some(if shift_on { ":" } else { ";" }.into()),       // AKEYCODE_SEMICOLON
        76 | 154 => Some(if shift_on { "?" } else { "/" }.into()), // AKEYCODE_SLASH | AKEYCODE_NUMPAD_DIVIDE
        73 => Some(if shift_on { "|" } else { "\\" }.into()),      // AKEYCODE_BACKSLASH
        75 => Some(if shift_on { "\"" } else { "'" }.into()),      // AKEYCODE_APOSTROPHE
        68 => Some(if shift_on { "~" } else { "`" }.into()),       // AKEYCODE_GRAVE
        71 => Some(if shift_on { "{" } else { "[" }.into()),       // AKEYCODE_LEFT_BRACKET
        72 => Some(if shift_on { "}" } else { "]" }.into()),       // AKEYCODE_RIGHT_BRACKET
        162 => Some("(".into()),                                   // AKEYCODE_NUMPAD_LEFT_PAREN
        163 => Some(")".into()),                                   // AKEYCODE_NUMPAD_RIGHT_PAREN
        18 => Some("#".into()),                                    // AKEYCODE_POUND
        17 | 155 => Some("*".into()), // AKEYCODE_STAR | AKEYCODE_NUMPAD_MULTIPLY
        62 => Some(" ".into()),       // AKEYCODE_SPACE
        _ => None,
    }
}

/// Ensures local storage directories, theme `.toml` files, and Android permission metadata
/// are initialized in the app's persistent data directory.
pub fn ensure_android_local_storage_and_permissions() {
    let mut mgr = crate::theme_manager::ThemeManager::new();
    let _ = mgr.ensure_local_themes_materialized();

    if let Some(data_dir) = crate::theme_manager::resolve_warp_data_dir() {
        let _ = std::fs::create_dir_all(&data_dir);
        let manifest_path = data_dir.join("permissions_status.json");
        let manifest_json = r#"{
  "package": "it.rainelli.rubens.warpim",
  "declared_permissions": [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.VIBRATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO"
  ]
}
"#;
        let _ = std::fs::write(manifest_path, manifest_json);
    }
}

/// Converts physical touch coordinates `(x, y)` into a Slint [`LogicalPosition`].
#[inline]
pub fn physical_to_logical_position(x: f32, y: f32, scale_factor: f32) -> LogicalPosition {
    LogicalPosition::from_physical(PhysicalPosition::new(x as i32, y as i32), scale_factor)
}

/// Converts physical `ANativeWindow` dimensions `(width, height)` into a Slint [`LogicalSize`].
#[inline]
pub fn physical_to_logical_size(width: i32, height: i32, scale_factor: f32) -> LogicalSize {
    PhysicalSize::new(width.max(1) as u32, height.max(1) as u32).to_logical(scale_factor)
}

/// Copies rendered `PremultipliedRgbaColor` rows into an `ANativeWindow_Buffer` surface,
/// respecting the hardware gralloc `dst_stride` (in `u32` pixels per row).
///
/// Returns the number of rows copied (`copy_h`).
///
/// # Safety
/// `dst_bits` must point to a valid writable buffer of at least `dst_stride * dst_height`
/// 32-bit RGBA pixels, and `dst_stride >= dst_width`.
pub unsafe fn copy_rgba8888_rows_with_stride(
    src: &[PremultipliedRgbaColor],
    src_width: usize,
    src_height: usize,
    dst_bits: *mut u32,
    dst_width: usize,
    dst_height: usize,
    dst_stride: usize,
) -> usize {
    if dst_bits.is_null()
        || src_width == 0
        || src_height == 0
        || dst_width == 0
        || dst_height == 0
        || dst_stride < dst_width
        || src.len() < src_width.saturating_mul(src_height)
    {
        return 0;
    }

    let copy_w = src_width.min(dst_width);
    let copy_h = src_height.min(dst_height);
    let src_u32 = src.as_ptr() as *const u32;

    for row in 0..copy_h {
        let src_row = unsafe { src_u32.add(row * src_width) };
        let dst_row = unsafe { dst_bits.add(row * dst_stride) };
        unsafe {
            std::ptr::copy_nonoverlapping(src_row, dst_row, copy_w);
        }
    }

    copy_h
}

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use android_activity::input::{InputEvent, KeyAction, KeyMapChar, Keycode, MotionAction};
    use android_activity::{AndroidApp, AndroidAppWaker, InputStatus, MainEvent, PollEvent};
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
    use slint::platform::{
        EventLoopProxy, Key, Platform, PlatformError, PointerEventButton, WindowAdapter,
        WindowEvent,
    };

    mod jni_sdk {
        jni::bind_java_type! { pub(super) IBinder => "android.os.IBinder" }
        jni::bind_java_type! {
            pub(super) View => "android.view.View",
            type_map {
                IBinder => "android.os.IBinder",
            },
            methods {
                fn get_window_token() -> IBinder,
                fn set_focusable(focusable: bool),
                fn set_focusable_in_touch_mode(focusable_in_touch_mode: bool),
                fn request_focus() -> bool,
            }
        }
        jni::bind_java_type! {
            pub(super) InputMethodManager => "android.view.inputmethod.InputMethodManager",
            type_map {
                View => "android.view.View",
                IBinder => "android.os.IBinder",
            },
            methods {
                fn show_soft_input(view: View, flags: i32) -> bool,
                fn toggle_soft_input(show_flags: i32, hide_flags: i32),
                fn hide_soft_input_from_window(window_token: IBinder, flags: i32) -> bool,
            }
        }
        jni::bind_java_type! {
            pub(super) Context => "android.content.Context",
            fields {
                #[allow(non_snake_case)]
                static INPUT_METHOD_SERVICE: JString
            },
            methods {
                fn get_system_service(service_name: JString) -> JObject,
            }
        }
        jni::bind_java_type! {
            pub(super) Window => "android.view.Window",
            type_map {
                View => "android.view.View",
            },
            methods {
                fn get_decor_view() -> View,
            }
        }
        jni::bind_java_type! {
            pub(super) Activity => "android.app.Activity",
            type_map {
                Context => "android.content.Context",
                Window => "android.view.Window",
            },
            is_instance_of {
                context: Context
            },
            methods {
                fn get_window() -> Window,
                fn request_permissions(permissions: JString[], request_code: i32),
            }
        }
    }

    pub(super) fn dispatch_android_runtime_permissions() {
        if AndroidApp::sdk_version() < 23 {
            return;
        }
        let Some(app) = ANDROID_APP_HANDLE.lock().ok().and_then(|g| g.clone()) else {
            return;
        };
        let app_for_ui = app.clone();
        app.run_on_java_main_thread(Box::new(move || {
            let vm_ptr = app_for_ui.vm_as_ptr();
            let act_ptr = app_for_ui.activity_as_ptr();
            if vm_ptr.is_null() || act_ptr.is_null() {
                return;
            }
            let jvm = unsafe { jni::vm::JavaVM::from_raw(vm_ptr.cast()) };
            let _ = jvm.attach_current_thread(|env| -> jni::errors::Result<()> {
                let raw_activity: jni::sys::jobject = act_ptr.cast();
                let activity =
                    unsafe { env.as_cast_raw::<jni::refs::Global<jni_sdk::Activity>>(&raw_activity)? };
                let first = jni::objects::JString::from_str(env, ANDROID_RUNTIME_PERMISSIONS[0])?;
                let perms_array = jni::objects::JObjectArray::<jni::objects::JString>::new(
                    env,
                    ANDROID_RUNTIME_PERMISSIONS.len(),
                    &first,
                )?;
                for (idx, perm) in ANDROID_RUNTIME_PERMISSIONS.iter().enumerate().skip(1) {
                    let jperm = jni::objects::JString::from_str(env, *perm)?;
                    perms_array.set_element(env, idx, &jperm)?;
                }
                activity.request_permissions(env, &perms_array, 1001)?;
                Ok(())
            });
        }));
    }

    pub(super) fn dispatch_android_soft_keyboard(visible: bool) {
        let Some(app) = ANDROID_APP_HANDLE.lock().ok().and_then(|g| g.clone()) else {
            return;
        };
        if visible {
            // Pass false so flags = 0 (explicit request, not SHOW_IMPLICIT)
            app.show_soft_input(false);
        } else {
            app.hide_soft_input(false);
        }

        let app_for_ui = app.clone();
        app.run_on_java_main_thread(Box::new(move || {
            let vm_ptr = app_for_ui.vm_as_ptr();
            let act_ptr = app_for_ui.activity_as_ptr();
            if vm_ptr.is_null() || act_ptr.is_null() {
                return;
            }
            let jvm = unsafe { jni::vm::JavaVM::from_raw(vm_ptr.cast()) };
            let _ = jvm.attach_current_thread(|env| -> jni::errors::Result<()> {
                let raw_activity: jni::sys::jobject = act_ptr.cast();
                let activity =
                    unsafe { env.as_cast_raw::<jni::refs::Global<jni_sdk::Activity>>(&raw_activity)? };
                let window = activity.get_window(env)?;
                let decor_view = window.get_decor_view(env)?;
                let ims = jni_sdk::Context::INPUT_METHOD_SERVICE(env)?;
                let imm_obj = activity.as_context().get_system_service(env, &ims)?;
                let imm = jni_sdk::InputMethodManager::cast_local(env, imm_obj)?;

                if visible {
                    decor_view.set_focusable(env, true)?;
                    decor_view.set_focusable_in_touch_mode(env, true)?;
                    let _ = decor_view.request_focus(env)?;
                    let shown = imm.show_soft_input(env, &decor_view, 0)?;
                    if !shown {
                        imm.toggle_soft_input(env, 2, 0)?;
                    }
                } else {
                    let token = decor_view.get_window_token(env)?;
                    let _ = imm.hide_soft_input_from_window(env, &token, 0)?;
                }
                Ok(())
            });
        }));
    }

    type QueuedClosure = Box<dyn FnOnce() + Send>;

    struct AndroidEventLoopProxy {
        queue: Arc<Mutex<VecDeque<QueuedClosure>>>,
        quit_requested: Arc<AtomicBool>,
        waker: AndroidAppWaker,
    }

    impl EventLoopProxy for AndroidEventLoopProxy {
        fn quit_event_loop(&self) -> Result<(), slint::EventLoopError> {
            self.quit_requested.store(true, Ordering::SeqCst);
            self.waker.wake();
            Ok(())
        }

        fn invoke_from_event_loop(
            &self,
            event: Box<dyn FnOnce() + Send>,
        ) -> Result<(), slint::EventLoopError> {
            if let Ok(mut guard) = self.queue.lock() {
                guard.push_back(event);
            }
            self.waker.wake();
            Ok(())
        }
    }

    /// Pure-Rust Slint [`Platform`] backed by `android-activity` and `ANativeWindow` software blitting.
    pub struct AndroidSoftwarePlatform {
        app: AndroidApp,
        window: Rc<MinimalSoftwareWindow>,
        scale_factor: Cell<f32>,
        last_pointer_pos: Cell<LogicalPosition>,
        touch_down_pos: Cell<Option<LogicalPosition>>,
        is_dragging: Cell<bool>,
        last_content_rect: Cell<(i32, i32, i32, i32)>,
        event_queue: Arc<Mutex<VecDeque<QueuedClosure>>>,
        quit_requested: Arc<AtomicBool>,
        start_time: Instant,
    }

    impl AndroidSoftwarePlatform {
        /// Creates a new `AndroidSoftwarePlatform` bound to the given [`AndroidApp`].
        pub fn new(app: AndroidApp) -> Self {
            if let Ok(mut guard) = ANDROID_APP_HANDLE.lock() {
                *guard = Some(app.clone());
            }

            let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
            let initial_scale = compute_android_scale_factor(app.config().density());
            window.dispatch_event(WindowEvent::ScaleFactorChanged {
                scale_factor: initial_scale,
            });
            // Provide sensible initial mobile dimensions before InitWindow arrives
            window.set_size(PhysicalSize::new(1080, 2400));
            let default_logical = physical_to_logical_size(1080, 2400, initial_scale);
            window.dispatch_event(WindowEvent::Resized {
                size: default_logical,
            });
            let (top_inset, bottom_inset) =
                compute_android_safe_insets_logical(1080, 2400, initial_scale, 0, 2400);
            set_android_safe_insets(top_inset, bottom_inset);

            Self {
                app,
                window,
                scale_factor: Cell::new(initial_scale),
                last_pointer_pos: Cell::new(LogicalPosition::new(0.0, 0.0)),
                touch_down_pos: Cell::new(None),
                is_dragging: Cell::new(false),
                last_content_rect: Cell::new((0, 0, 1080, 2400)),
                event_queue: Arc::new(Mutex::new(VecDeque::new())),
                quit_requested: Arc::new(AtomicBool::new(false)),
                start_time: Instant::now(),
            }
        }

        /// Synchronizes `ANativeWindow` buffer geometry (`WINDOW_FORMAT_RGBA_8888`), DPI scale factor,
        /// safe area insets (`content_rect`), and logical window size with the Slint [`MinimalSoftwareWindow`].
        fn sync_native_window_geometry(&self) {
            let scale_factor = compute_android_scale_factor(self.app.config().density());
            self.scale_factor.set(scale_factor);
            self.window
                .dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor });

            if let Some(native_win) = self.app.native_window() {
                let win_ptr = native_win.ptr().as_ptr() as *mut c_void;
                let w = unsafe { ANativeWindow_getWidth(win_ptr) }.max(1);
                let h = unsafe { ANativeWindow_getHeight(win_ptr) }.max(1);
                unsafe {
                    // Pass (0, 0) so SurfaceFlinger auto-tracks the window dimensions on rotation/IME resize
                    ANativeWindow_setBuffersGeometry(win_ptr, 0, 0, WINDOW_FORMAT_RGBA_8888);
                }

                let content_rect = self.app.content_rect();
                self.last_content_rect.set((
                    content_rect.left,
                    content_rect.top,
                    content_rect.right,
                    content_rect.bottom,
                ));
                let (top_inset, bottom_inset) = compute_android_safe_insets_logical(
                    w,
                    h,
                    scale_factor,
                    content_rect.top,
                    content_rect.bottom,
                );
                set_android_safe_insets(top_inset, bottom_inset);

                let phys_size = PhysicalSize::new(w as u32, h as u32);
                self.window.set_size(phys_size);
                self.window.dispatch_event(WindowEvent::Resized {
                    size: phys_size.to_logical(scale_factor),
                });
                self.window.request_redraw();
            }
        }
    }

    impl Platform for AndroidSoftwarePlatform {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
            self.sync_native_window_geometry();
            Ok(self.window.clone())
        }

        fn duration_since_start(&self) -> Duration {
            self.start_time.elapsed()
        }

        fn new_event_loop_proxy(&self) -> Option<Box<dyn EventLoopProxy>> {
            Some(Box::new(AndroidEventLoopProxy {
                queue: self.event_queue.clone(),
                quit_requested: self.quit_requested.clone(),
                waker: self.app.create_waker(),
            }))
        }

        fn run_event_loop(&self) -> Result<(), PlatformError> {
            self.quit_requested.store(false, Ordering::SeqCst);
            self.sync_native_window_geometry();

            let mut pixel_buffer: Vec<PremultipliedRgbaColor> = Vec::new();
            let mut should_exit = false;

            while !should_exit && !self.quit_requested.load(Ordering::SeqCst) {
                self.app
                    .poll_events(Some(Duration::from_millis(16)), |event| match event {
                        PollEvent::Main(main_event) => match main_event {
                            MainEvent::InitWindow { .. }
                            | MainEvent::WindowResized { .. }
                            | MainEvent::RedrawNeeded { .. }
                            | MainEvent::ConfigChanged { .. }
                            | MainEvent::ContentRectChanged { .. } => {
                                self.sync_native_window_geometry();
                            }
                            MainEvent::GainedFocus => {
                                self.window
                                    .dispatch_event(WindowEvent::WindowActiveChanged(true));
                                self.window.request_redraw();
                            }
                            MainEvent::LostFocus => {
                                self.window
                                    .dispatch_event(WindowEvent::WindowActiveChanged(false));
                            }
                            MainEvent::Destroy => {
                                should_exit = true;
                            }
                            _ => {}
                        },
                        PollEvent::Wake | PollEvent::Timeout => {}
                        _ => {}
                    });

                if should_exit || self.quit_requested.load(Ordering::SeqCst) {
                    break;
                }

                // Drain queued cross-thread UI callbacks from `slint::invoke_from_event_loop`
                loop {
                    let next_task = self
                        .event_queue
                        .lock()
                        .ok()
                        .and_then(|mut q| q.pop_front());
                    match next_task {
                        Some(task) => {
                            task();
                            self.window.request_redraw();
                        }
                        None => break,
                    }
                }

                // Advance Slint timers before processing input so Flickable timestamps are fresh
                slint::platform::update_timers_and_animations();

                // Process Android touch & key input events
                let scale_factor = self.scale_factor.get();
                if let Ok(mut input_iter) = self.app.input_events_iter() {
                    while input_iter.next(|event| match event {
                        InputEvent::MotionEvent(motion) => {
                            if motion.pointer_count() > 0 {
                                let pointer = motion.pointer_at_index(0);
                                let position = physical_to_logical_position(
                                    pointer.x(),
                                    pointer.y(),
                                    scale_factor,
                                );

                                match motion.action() {
                                    MotionAction::Down
                                    | MotionAction::PointerDown
                                    | MotionAction::ButtonPress => {
                                        self.touch_down_pos.set(Some(position));
                                        self.last_pointer_pos.set(position);
                                        self.is_dragging.set(false);
                                        self.window
                                            .dispatch_event(WindowEvent::PointerMoved { position });
                                        self.window.dispatch_event(WindowEvent::PointerPressed {
                                            position,
                                            button: PointerEventButton::Left,
                                        });
                                    }
                                    MotionAction::Move
                                    | MotionAction::HoverMove
                                    | MotionAction::HoverEnter => {
                                        let prev_pos = self.last_pointer_pos.get();
                                        let _dx = position.x - prev_pos.x;
                                        let _dy = position.y - prev_pos.y;
                                        self.last_pointer_pos.set(position);
                                        if let Some(start) = self.touch_down_pos.get() {
                                            if (position.x - start.x).hypot(position.y - start.y)
                                                > 8.0
                                            {
                                                self.is_dragging.set(true);
                                            }
                                        }
                                        self.window
                                            .dispatch_event(WindowEvent::PointerMoved { position });
                                        slint::platform::update_timers_and_animations();
                                    }
                                    MotionAction::Up
                                    | MotionAction::PointerUp
                                    | MotionAction::ButtonRelease => {
                                        self.last_pointer_pos.set(position);
                                        self.window.dispatch_event(WindowEvent::PointerReleased {
                                            position,
                                            button: PointerEventButton::Left,
                                        });
                                        if let Some(start) = self.touch_down_pos.take() {
                                            if is_left_edge_back_swipe(
                                                start.x,
                                                start.y,
                                                position.x,
                                                position.y,
                                            ) {
                                                let _ = trigger_android_back();
                                            }
                                        }
                                        self.is_dragging.set(false);
                                    }
                                    MotionAction::Cancel
                                    | MotionAction::Outside
                                    | MotionAction::HoverExit => {
                                        self.touch_down_pos.set(None);
                                        self.is_dragging.set(false);
                                        let last_pos = self.last_pointer_pos.get();
                                        self.window.dispatch_event(WindowEvent::PointerReleased {
                                            position: last_pos,
                                            button: PointerEventButton::Left,
                                        });
                                        self.window.dispatch_event(WindowEvent::PointerExited);
                                    }
                                    _ => {}
                                }
                                self.window.request_redraw();
                            }
                            InputStatus::Handled
                        }
                        InputEvent::KeyEvent(key_event) => {
                            let keycode = key_event.key_code();
                            if matches!(keycode, Keycode::Back | Keycode::Escape) {
                                match key_event.action() {
                                    KeyAction::Down => {
                                        if is_android_soft_keyboard_visible() {
                                            set_android_soft_keyboard_visible(false);
                                        }
                                        self.window.dispatch_event(WindowEvent::KeyPressed {
                                            text: Key::Backspace.into(),
                                        });
                                        let _ = trigger_android_back();
                                        self.window.request_redraw();
                                    }
                                    KeyAction::Up => {
                                        self.window.dispatch_event(WindowEvent::KeyReleased {
                                            text: Key::Backspace.into(),
                                        });
                                        self.window.request_redraw();
                                    }
                                    _ => {}
                                }
                                InputStatus::Handled
                            } else {
                                let meta_state = key_event.meta_state();
                                let shift_on = meta_state.shift_on() || meta_state.caps_lock_on();
                                let unicode_char = self
                                    .app
                                    .device_key_character_map(key_event.device_id())
                                    .ok()
                                    .and_then(|m| match m.get(keycode, meta_state) {
                                        Ok(KeyMapChar::Unicode(c)) => Some(c),
                                        _ => None,
                                    });
                                let keycode_raw = u32::from(keycode) as i32;
                                if let Some(text) =
                                    map_android_key_to_text(keycode_raw, shift_on, unicode_char)
                                {
                                    match key_event.action() {
                                        KeyAction::Down => {
                                            self.window
                                                .dispatch_event(WindowEvent::KeyPressed { text });
                                            self.window.request_redraw();
                                        }
                                        KeyAction::Up => {
                                            self.window
                                                .dispatch_event(WindowEvent::KeyReleased { text });
                                            self.window.request_redraw();
                                        }
                                        _ => {}
                                    }
                                    InputStatus::Handled
                                } else {
                                    InputStatus::Unhandled
                                }
                            }
                        }
                        _ => InputStatus::Unhandled,
                    }) {}
                }

                // Advance Slint timers & animations
                slint::platform::update_timers_and_animations();

                // Blit software-rendered RGBA_8888 frame to ANativeWindow if a surface is attached
                if let Some(native_win) = self.app.native_window() {
                    let win_ptr = native_win.ptr().as_ptr() as *mut c_void;
                    let width = unsafe { ANativeWindow_getWidth(win_ptr) };
                    let height = unsafe { ANativeWindow_getHeight(win_ptr) };

                    if width > 0 && height > 0 {
                        let target_phys = PhysicalSize::new(width as u32, height as u32);
                        let cr = self.app.content_rect();
                        let cr_tuple = (cr.left, cr.top, cr.right, cr.bottom);
                        if self.window.size() != target_phys
                            || self.last_content_rect.get() != cr_tuple
                        {
                            self.sync_native_window_geometry();
                        }

                        let w = width as usize;
                        let h = height as usize;

                        self.window.draw_if_needed(|renderer| {
                            let required_len = w.saturating_mul(h);
                            if pixel_buffer.len() != required_len {
                                pixel_buffer.resize(required_len, PremultipliedRgbaColor::default());
                            }

                            renderer.render(&mut pixel_buffer, w);

                            let mut raw_buffer = ANativeWindow_Buffer {
                                width: 0,
                                height: 0,
                                stride: 0,
                                format: 0,
                                bits: std::ptr::null_mut(),
                                reserved: [0; 6],
                            };

                            if unsafe {
                                ANativeWindow_lock(
                                    win_ptr,
                                    &mut raw_buffer,
                                    std::ptr::null_mut(),
                                )
                            } == 0
                            {
                                if !raw_buffer.bits.is_null()
                                    && raw_buffer.width > 0
                                    && raw_buffer.height > 0
                                    && raw_buffer.stride >= raw_buffer.width
                                {
                                    unsafe {
                                        copy_rgba8888_rows_with_stride(
                                            &pixel_buffer,
                                            w,
                                            h,
                                            raw_buffer.bits as *mut u32,
                                            raw_buffer.width as usize,
                                            raw_buffer.height as usize,
                                            raw_buffer.stride as usize,
                                        );
                                    }
                                }
                                unsafe {
                                    ANativeWindow_unlockAndPost(win_ptr);
                                }
                            }
                        });
                    }
                }
            }

            Ok(())
        }
    }

    /// Initializes the Android Slint software platform via [`slint::platform::set_platform`],
    /// configures `WARP_DATA_DIR` and `WARP_DB_PATH` inside the app's internal storage,
    /// materializes local theme TOMLs (`superthemes/*.toml` and `palettes/*.toml`), and
    /// triggers the Android runtime permissions dialog.
    pub fn init_android_slint_platform(app: android_activity::AndroidApp) {
        if let Ok(mut guard) = ANDROID_APP_HANDLE.lock() {
            *guard = Some(app.clone());
        }

        let internal_dir = app
            .internal_data_path()
            .unwrap_or_else(|| std::path::PathBuf::from("/data/data/it.rainelli.rubens.warpim/files"))
            .join("warp-im");
        let _ = std::fs::create_dir_all(&internal_dir);
        std::env::set_var("WARP_DATA_DIR", &internal_dir);
        if std::env::var_os("WARP_DB_PATH").is_none() {
            std::env::set_var("WARP_DB_PATH", internal_dir.join("warp_im.sqlite3"));
        }

        let _ = slint::platform::set_platform(Box::new(AndroidSoftwarePlatform::new(app)));
        ensure_android_local_storage_and_permissions();
        let _ = request_android_permissions_now();
    }
}

#[cfg(target_os = "android")]
pub use imp::{init_android_slint_platform, AndroidSoftwarePlatform};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_android_scale_factor_clamping_and_defaults() {
        assert!((compute_android_scale_factor(None) - 2.75).abs() < f32::EPSILON);
        assert!((compute_android_scale_factor(Some(160)) - 1.5).abs() < f32::EPSILON);
        assert!((compute_android_scale_factor(Some(320)) - 2.0).abs() < f32::EPSILON);
        assert!((compute_android_scale_factor(Some(440)) - 2.75).abs() < f32::EPSILON);
        assert!((compute_android_scale_factor(Some(640)) - 3.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_compute_android_safe_insets_logical_portrait_landscape_and_ime() {
        // Edge-to-edge portrait (content_top = 0, content_bottom = 2400) -> min (36.0, 20.0)
        let (top_p, bot_p) = compute_android_safe_insets_logical(1080, 2400, 3.0, 0, 2400);
        assert!((top_p - 36.0).abs() < 0.01);
        assert!((bot_p - 20.0).abs() < 0.01);

        // Edge-to-edge landscape (width > height) -> min (24.0, 20.0)
        let (top_l, bot_l) = compute_android_safe_insets_logical(2400, 1080, 3.0, 0, 1080);
        assert!((top_l - 24.0).abs() < 0.01);
        assert!((bot_l - 20.0).abs() < 0.01);

        // Reported status bar (132px / 3.0 = 44.0) and soft keyboard (900px / 3.0 = 300.0)
        let (top_k, bot_k) = compute_android_safe_insets_logical(1080, 2400, 3.0, 132, 1500);
        assert!((top_k - 44.0).abs() < 0.01);
        assert!((bot_k - 300.0).abs() < 0.01);
    }

    #[test]
    fn test_left_edge_back_swipe_detection_and_back_handler() {
        assert!(is_left_edge_back_swipe(12.0, 300.0, 110.0, 310.0));
        assert!(!is_left_edge_back_swipe(50.0, 300.0, 150.0, 310.0)); // Not started from left edge
        assert!(!is_left_edge_back_swipe(12.0, 300.0, 50.0, 310.0)); // Delta X too short
        assert!(!is_left_edge_back_swipe(12.0, 300.0, 110.0, 400.0)); // Vertical scroll, not horizontal swipe

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        register_android_back_handler(std::sync::Arc::new(move || {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        assert!(trigger_android_back());
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn test_physical_to_logical_conversions() {
        let pos = physical_to_logical_position(550.0, 1100.0, 2.75);
        assert!((pos.x - 200.0).abs() < 0.01);
        assert!((pos.y - 400.0).abs() < 0.01);

        let size = physical_to_logical_size(1080, 2400, 3.0);
        assert!((size.width - 360.0).abs() < 0.01);
        assert!((size.height - 800.0).abs() < 0.01);
    }

    #[test]
    fn test_copy_rgba8888_rows_with_padded_gralloc_stride() {
        let src_w = 4;
        let src_h = 3;
        let dst_w = 4;
        let dst_h = 3;
        let dst_stride = 6; // Simulates hardware gralloc row padding (stride > width)

        let mut src = Vec::with_capacity(src_w * src_h);
        for y in 0..src_h {
            for x in 0..src_w {
                src.push(PremultipliedRgbaColor {
                    red: (y * 10 + x) as u8,
                    green: 100,
                    blue: 200,
                    alpha: 255,
                });
            }
        }

        let mut dst = vec![0u32; dst_stride * dst_h];
        let copied_rows = unsafe {
            copy_rgba8888_rows_with_stride(
                &src,
                src_w,
                src_h,
                dst.as_mut_ptr(),
                dst_w,
                dst_h,
                dst_stride,
            )
        };
        assert_eq!(copied_rows, 3);

        // Verify active pixels and untouched stride padding bytes
        for y in 0..dst_h {
            for x in 0..dst_w {
                let pixel_bytes = dst[y * dst_stride + x].to_ne_bytes();
                assert_eq!(pixel_bytes[0], (y * 10 + x) as u8);
                assert_eq!(pixel_bytes[1], 100);
                assert_eq!(pixel_bytes[2], 200);
                assert_eq!(pixel_bytes[3], 255);
            }
            // Padding columns [dst_w..dst_stride] must remain untouched (0)
            for pad_x in dst_w..dst_stride {
                assert_eq!(dst[y * dst_stride + pad_x], 0);
            }
        }
    }

    #[test]
    fn test_android_permissions_and_soft_keyboard_state() {
        let before = permissions_request_count();
        assert!(request_android_permissions_now());
        assert_eq!(permissions_request_count(), before + 1);
        assert_eq!(ANDROID_RUNTIME_PERMISSIONS.len(), 8);
        assert!(ANDROID_RUNTIME_PERMISSIONS.contains(&"android.permission.POST_NOTIFICATIONS"));
        assert!(ANDROID_RUNTIME_PERMISSIONS.contains(&"android.permission.CAMERA"));
        assert!(ANDROID_RUNTIME_PERMISSIONS.contains(&"android.permission.RECORD_AUDIO"));

        set_android_soft_keyboard_visible(true);
        assert!(is_android_soft_keyboard_visible());
        set_android_soft_keyboard_visible(false);
        assert!(!is_android_soft_keyboard_visible());
    }

    #[test]
    fn test_map_android_key_to_text_unicode_and_fallback_keycodes() {
        // Unicode character from KeyCharacterMap (including international & symbols)
        assert_eq!(
            map_android_key_to_text(0, false, Some('é')).as_deref(),
            Some("é")
        );
        assert_eq!(
            map_android_key_to_text(29, false, Some('a')).as_deref(),
            Some("a")
        );
        assert_eq!(
            map_android_key_to_text(29, true, Some('A')).as_deref(),
            Some("A")
        );

        // Fallback letter mapping when KeyCharacterMap returns None
        assert_eq!(map_android_key_to_text(29, false, None).as_deref(), Some("a"));
        assert_eq!(map_android_key_to_text(29, true, None).as_deref(), Some("A"));
        assert_eq!(map_android_key_to_text(54, false, None).as_deref(), Some("z"));
        assert_eq!(map_android_key_to_text(54, true, None).as_deref(), Some("Z"));

        // Digits & shifted symbols
        assert_eq!(map_android_key_to_text(7, false, None).as_deref(), Some("0"));
        assert_eq!(map_android_key_to_text(7, true, None).as_deref(), Some(")"));
        assert_eq!(map_android_key_to_text(8, false, None).as_deref(), Some("1"));
        assert_eq!(map_android_key_to_text(8, true, None).as_deref(), Some("!"));
        assert_eq!(map_android_key_to_text(9, true, None).as_deref(), Some("@"));
        assert_eq!(map_android_key_to_text(144, false, None).as_deref(), Some("0"));
        assert_eq!(map_android_key_to_text(153, false, None).as_deref(), Some("9"));

        // Punctuation & phone/email symbols (+, -, _, @, ., /, :)
        assert_eq!(map_android_key_to_text(81, false, None).as_deref(), Some("+"));
        assert_eq!(map_android_key_to_text(69, false, None).as_deref(), Some("-"));
        assert_eq!(map_android_key_to_text(69, true, None).as_deref(), Some("_"));
        assert_eq!(map_android_key_to_text(77, false, None).as_deref(), Some("@"));
        assert_eq!(map_android_key_to_text(56, false, None).as_deref(), Some("."));
        assert_eq!(map_android_key_to_text(74, true, None).as_deref(), Some(":"));
        assert_eq!(map_android_key_to_text(62, false, None).as_deref(), Some(" "));

        // Editing & navigation keys
        let enter_expected: slint::SharedString = slint::platform::Key::Return.into();
        let backspace_expected: slint::SharedString = slint::platform::Key::Backspace.into();
        assert_eq!(map_android_key_to_text(66, false, None), Some(enter_expected));
        assert_eq!(
            map_android_key_to_text(67, false, None),
            Some(backspace_expected)
        );
    }
}

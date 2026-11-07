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

//! Hot-reloadable dual-layer theme loader (`SuperThemeConfig` & `ThemePaletteConfig`).
//!
//! Strictly decouples structural layout/ergonomics (`themes/superthemes/*.toml`)
//! from color/typography palettes (`themes/palettes/*.toml`), supporting
//! Daylight Light, Dark Slate, and True Black OLED display modes.

use crate::{
    MainWindow, MessageLayout, NavigationLayout, ReactionStyle, SuperTheme, ThemePalette,
};
use serde::{Deserialize, Serialize};
use slint::{Color, ComponentHandle, SharedString};
use std::collections::HashMap;
use std::path::Path;

/// Parsed representation of a `themes/superthemes/*.toml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperThemeConfig {
    pub id: String,
    pub name: String,
    pub description: String,
    pub navigation_layout: String,
    pub message_layout: String,
    pub reaction_style: String,
    pub enable_swipe_to_reply: bool,
    pub show_protocol_badge: bool,
    pub compact_timestamps: bool,
    pub sidebar_width_px: f32,
    pub server_rail_width_px: f32,
    pub bubble_corner_radius_px: f32,
    pub avatar_size_px: f32,
}

/// Parsed representation of a `themes/palettes/*.toml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemePaletteConfig {
    pub id: String,
    pub name: String,
    pub font_family: String,
    pub font_size_base: f32,
    pub font_size_small: f32,
    pub bg_primary: String,
    pub bg_secondary: String,
    pub bg_tertiary: String,
    pub bg_elevated: String,
    pub bubble_outgoing: String,
    pub bubble_incoming: String,
    pub text_primary: String,
    pub text_secondary: String,
    pub text_muted: String,
    pub accent_primary: String,
    pub accent_secondary: String,
    pub border_subtle: String,
    pub status_online: String,
    pub status_warning: String,
    pub status_danger: String,
    pub surface_opacity: f32,
    #[serde(default)]
    pub is_light_mode: bool,
    #[serde(default)]
    pub is_oled_mode: bool,
}

/// Manages embedded and on-disk `SuperThemeConfig` and `ThemePaletteConfig` definitions
/// and applies them onto the Slint `SuperTheme` and `ThemePalette` globals at 120fps.
pub struct ThemeManager {
    superthemes: HashMap<String, SuperThemeConfig>,
    palettes: HashMap<String, ThemePaletteConfig>,
}

impl Default for ThemeManager {
    fn default() -> Self {
        Self::new()
    }
}

const EMBEDDED_SUPERTHEME_FILES: &[(&str, &str)] = &[
    (
        "telegram.toml",
        include_str!("../themes/superthemes/telegram.toml"),
    ),
    (
        "discord.toml",
        include_str!("../themes/superthemes/discord.toml"),
    ),
    (
        "whatsapp.toml",
        include_str!("../themes/superthemes/whatsapp.toml"),
    ),
    (
        "irc_classic.toml",
        include_str!("../../../themes/superthemes/irc_classic.toml"),
    ),
];

const EMBEDDED_PALETTE_FILES: &[(&str, &str)] = &[
    (
        "light_daylight.toml",
        include_str!("../themes/palettes/light_daylight.toml"),
    ),
    (
        "dark_slate.toml",
        include_str!("../themes/palettes/dark_slate.toml"),
    ),
    (
        "oled_pitch_black.toml",
        include_str!("../themes/palettes/oled_pitch_black.toml"),
    ),
    (
        "night_telegram.toml",
        include_str!("../../../themes/palettes/night_telegram.toml"),
    ),
    (
        "discord_dark.toml",
        include_str!("../../../themes/palettes/discord_dark.toml"),
    ),
    (
        "catppuccin_mocha.toml",
        include_str!("../../../themes/palettes/catppuccin_mocha.toml"),
    ),
];

const LOCAL_THEMES_README: &str = "\
Warp IM — Local SuperThemes & Color Palettes
============================================

All .toml files in `superthemes/` and `palettes/` are materialized locally on first run
so Warp IM works 100% offline on Android, iOS, Linux, macOS, and Windows.

You can edit any existing .toml file or drop new .toml files into:
  - superthemes/*.toml  (layout ergonomics: navigation_layout, message_layout, reaction_style, radii)
  - palettes/*.toml     (colors, OLED Pitch Black / Daylight Light flags, typography)

Changes are hot-reloaded on the fly whenever you switch SuperTheme or Palette in Settings!
";

/// Resolves the persistent user data directory for Warp IM across Desktop and Mobile (Android/iOS).
pub fn resolve_warp_data_dir() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("WARP_DATA_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return Some(std::path::PathBuf::from(trimmed));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return Some(std::path::PathBuf::from(trimmed).join("warp-im"));
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        let trimmed = appdata.trim();
        if !trimmed.is_empty() {
            return Some(std::path::PathBuf::from(trimmed).join("WarpIM"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return Some(
                std::path::PathBuf::from(trimmed)
                    .join(".local")
                    .join("share")
                    .join("warp-im"),
            );
        }
    }
    #[cfg(target_os = "android")]
    {
        return Some(std::path::PathBuf::from(
            "/data/data/it.rainelli.rubens.warpim/files/warp-im",
        ));
    }
    #[cfg(not(target_os = "android"))]
    {
        None
    }
}

impl ThemeManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            superthemes: HashMap::new(),
            palettes: HashMap::new(),
        };
        mgr.load_embedded_defaults();
        let _ = mgr.ensure_local_themes_materialized();
        mgr.reload_from_candidate_dirs();
        mgr
    }

    /// Materializes all 4 embedded SuperTheme `.toml` files and all 6 embedded Palette `.toml` files
    /// into `<data_dir>/themes/{superthemes,palettes}` on local storage if they do not exist yet,
    /// along with `README_THEMES.txt`. Preserves any user modifications to existing files.
    pub fn ensure_local_themes_materialized(&mut self) -> Option<std::path::PathBuf> {
        let data_dir = resolve_warp_data_dir()?;
        let themes_root = data_dir.join("themes");
        let superthemes_dir = themes_root.join("superthemes");
        let palettes_dir = themes_root.join("palettes");

        if std::fs::create_dir_all(&superthemes_dir).is_err()
            || std::fs::create_dir_all(&palettes_dir).is_err()
        {
            return None;
        }

        for (filename, content) in EMBEDDED_SUPERTHEME_FILES {
            let path = superthemes_dir.join(filename);
            if !path.exists() {
                let _ = std::fs::write(&path, content);
            }
        }

        for (filename, content) in EMBEDDED_PALETTE_FILES {
            let path = palettes_dir.join(filename);
            if !path.exists() {
                let _ = std::fs::write(&path, content);
            }
        }

        let readme_path = themes_root.join("README_THEMES.txt");
        if !readme_path.exists() {
            let _ = std::fs::write(&readme_path, LOCAL_THEMES_README);
        }

        self.reload_from_dir(&themes_root);
        Some(themes_root)
    }

    /// Hot-reloads any customized `.toml` files from disk (`themes/`, `./crates/warp-app/themes/`,
    /// `<data_dir>/themes`, or `WARP_THEMES_DIR`) so UI ergonomics, dimensions, radii, and color
    /// palettes can be tweaked on the fly without recompiling.
    pub fn reload_from_candidate_dirs(&mut self) {
        if let Ok(custom_dir) = std::env::var("WARP_THEMES_DIR") {
            self.reload_from_dir(custom_dir);
        }
        if let Some(data_dir) = resolve_warp_data_dir() {
            self.reload_from_dir(data_dir.join("themes"));
        }
        self.reload_from_dir("themes");
        self.reload_from_dir("crates/warp-app/themes");
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                self.reload_from_dir(exe_dir.join("themes"));
                self.reload_from_dir(exe_dir.join("../share/warp-im/themes"));
                self.reload_from_dir(exe_dir.join("../Resources/themes"));
            }
        }
    }

    fn load_embedded_defaults(&mut self) {
        for (_, raw) in EMBEDDED_SUPERTHEME_FILES {
            if let Ok(cfg) = toml::from_str::<SuperThemeConfig>(raw) {
                self.superthemes.insert(cfg.id.clone(), cfg);
            }
        }

        for (_, raw) in EMBEDDED_PALETTE_FILES {
            if let Ok(cfg) = toml::from_str::<ThemePaletteConfig>(raw) {
                self.palettes.insert(cfg.id.clone(), cfg);
            }
        }
    }

    /// Optionally reloads `.toml` files from disk if a `themes/` directory exists.
    pub fn reload_from_dir(&mut self, themes_dir: impl AsRef<Path>) {
        let base = themes_dir.as_ref();
        if let Ok(entries) = std::fs::read_dir(base.join("superthemes")) {
            for entry in entries.flatten() {
                if let Ok(raw) = std::fs::read_to_string(entry.path()) {
                    if let Ok(cfg) = toml::from_str::<SuperThemeConfig>(&raw) {
                        self.superthemes.insert(cfg.id.clone(), cfg);
                    }
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(base.join("palettes")) {
            for entry in entries.flatten() {
                if let Ok(raw) = std::fs::read_to_string(entry.path()) {
                    if let Ok(cfg) = toml::from_str::<ThemePaletteConfig>(&raw) {
                        self.palettes.insert(cfg.id.clone(), cfg);
                    }
                }
            }
        }
    }

    pub fn get_supertheme(&self, id: &str) -> Option<&SuperThemeConfig> {
        self.superthemes.get(id)
    }

    pub fn get_palette(&self, id: &str) -> Option<&ThemePaletteConfig> {
        self.palettes.get(id)
    }

    /// Applies a `SuperThemeConfig` to the Slint `SuperTheme` singleton without touching colors.
    /// Automatically checks on-disk `themes/superthemes/*.toml` first for on-the-fly hot-reloading.
    pub fn apply_supertheme(&self, window: &MainWindow, id: &str) -> bool {
        let mut live_clone = self.superthemes.clone();
        let mut temp_mgr = Self {
            superthemes: std::mem::take(&mut live_clone),
            palettes: HashMap::new(),
        };
        temp_mgr.reload_from_candidate_dirs();
        let Some(cfg) = temp_mgr.superthemes.get(id).or_else(|| self.superthemes.get(id)) else {
            return false;
        };
        let st = window.global::<SuperTheme>();
        st.set_supertheme_id(SharedString::from(&cfg.id));
        st.set_supertheme_name(SharedString::from(&cfg.name));

        let nav = match cfg.navigation_layout.as_str() {
            "VerticalServerRail" | "DiscordServerRail" => NavigationLayout::VerticalServerRail,
            "MinimalistTabs" | "WhatsAppMinimalTabs" => NavigationLayout::MinimalistTabs,
            _ => NavigationLayout::HorizontalFolders,
        };
        st.set_navigation_layout(nav);
        st.set_nav_layout(nav);

        let msg = match cfg.message_layout.as_str() {
            "FlatFullWidthRows" | "CompactFlatRows" => MessageLayout::FlatFullWidthRows,
            "SplitBubbles" => MessageLayout::SplitBubbles,
            _ => MessageLayout::CurvedBubbles,
        };
        st.set_message_layout(msg);

        let react = match cfg.reaction_style.as_str() {
            "BelowMessagePills" => ReactionStyle::BelowMessagePills,
            "FloatingRight" => ReactionStyle::FloatingRight,
            _ => ReactionStyle::InsideBubbleCorner,
        };
        st.set_reaction_style(react);

        st.set_enable_swipe_to_reply(cfg.enable_swipe_to_reply);
        st.set_show_protocol_badge(cfg.show_protocol_badge);
        st.set_compact_timestamps(cfg.compact_timestamps);
        st.set_sidebar_width(cfg.sidebar_width_px);
        st.set_server_rail_width(cfg.server_rail_width_px);
        st.set_bubble_corner_radius(cfg.bubble_corner_radius_px);
        st.set_bubble_radius(cfg.bubble_corner_radius_px);
        st.set_avatar_size(cfg.avatar_size_px);
        true
    }

    /// Applies a `ThemePaletteConfig` to the Slint `ThemePalette` singleton without touching layout.
    /// Automatically checks on-disk `themes/palettes/*.toml` first for on-the-fly hot-reloading.
    pub fn apply_palette(&self, window: &MainWindow, id: &str) -> bool {
        let mut live_clone = self.palettes.clone();
        let mut temp_mgr = Self {
            superthemes: HashMap::new(),
            palettes: std::mem::take(&mut live_clone),
        };
        temp_mgr.reload_from_candidate_dirs();
        let Some(cfg) = temp_mgr.palettes.get(id).or_else(|| self.palettes.get(id)) else {
            return false;
        };
        let tp = window.global::<ThemePalette>();
        tp.set_palette_id(SharedString::from(&cfg.id));
        tp.set_palette_name(SharedString::from(&cfg.name));
        tp.set_font_family(SharedString::from(&cfg.font_family));
        tp.set_font_size_base(cfg.font_size_base);
        tp.set_font_size_small(cfg.font_size_small);

        tp.set_is_light_mode(cfg.is_light_mode || cfg.id == "light");
        tp.set_is_oled_mode(cfg.is_oled_mode || cfg.id == "oled");

        tp.set_bg_primary(parse_hex_color(&cfg.bg_primary));
        tp.set_bg_secondary(parse_hex_color(&cfg.bg_secondary));
        tp.set_bg_tertiary(parse_hex_color(&cfg.bg_tertiary));
        tp.set_bg_elevated(parse_hex_color(&cfg.bg_elevated));
        tp.set_bubble_outgoing(parse_hex_color(&cfg.bubble_outgoing));
        tp.set_bubble_incoming(parse_hex_color(&cfg.bubble_incoming));
        tp.set_bg_bubble_out(parse_hex_color(&cfg.bubble_outgoing));
        tp.set_bg_bubble_in(parse_hex_color(&cfg.bubble_incoming));
        tp.set_text_primary(parse_hex_color(&cfg.text_primary));
        tp.set_text_secondary(parse_hex_color(&cfg.text_secondary));
        tp.set_text_muted(parse_hex_color(&cfg.text_muted));
        tp.set_accent_primary(parse_hex_color(&cfg.accent_primary));
        tp.set_accent_secondary(parse_hex_color(&cfg.accent_secondary));
        tp.set_border_subtle(parse_hex_color(&cfg.border_subtle));
        tp.set_status_online(parse_hex_color(&cfg.status_online));
        tp.set_status_warning(parse_hex_color(&cfg.status_warning));
        tp.set_status_danger(parse_hex_color(&cfg.status_danger));
        tp.set_surface_opacity(cfg.surface_opacity);
        true
    }
}

pub fn parse_hex_color(hex: &str) -> Color {
    let clean = hex.trim().trim_start_matches('#');
    if clean.len() == 6 {
        let r = u8::from_str_radix(&clean[0..2], 16).unwrap_or(30);
        let g = u8::from_str_radix(&clean[2..4], 16).unwrap_or(30);
        let b = u8::from_str_radix(&clean[4..6], 16).unwrap_or(46);
        Color::from_rgb_u8(r, g, b)
    } else {
        Color::from_rgb_u8(24, 37, 51)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_palettes_and_superthemes_loaded_and_valid() {
        let mgr = ThemeManager::new();

        // 1. Verify all 6 required palettes are loaded
        for palette_id in [
            "light",
            "dark",
            "oled",
            "night_telegram",
            "discord_dark",
            "catppuccin_mocha",
        ] {
            assert!(
                mgr.get_palette(palette_id).is_some(),
                "Missing embedded palette: {palette_id}"
            );
        }

        // Verify Light Daylight palette colors & flags
        let light = mgr.get_palette("light").unwrap();
        assert_eq!(light.name, "☀️ Chiaro (Daylight)");
        assert_eq!(light.bg_primary, "#FFFFFF");
        assert_eq!(light.bg_secondary, "#F0F2F5");
        assert_eq!(light.bubble_outgoing, "#D9FDD3");
        assert_eq!(light.text_primary, "#111B21");
        assert!(light.is_light_mode);
        assert!(!light.is_oled_mode);
        assert_eq!(
            parse_hex_color(&light.bg_primary),
            Color::from_rgb_u8(255, 255, 255)
        );

        // Verify Dark Slate palette colors & flags
        let dark = mgr.get_palette("dark").unwrap();
        assert_eq!(dark.name, "🌙 Scuro (Dark Slate)");
        assert_eq!(dark.bg_primary, "#0E1621");
        assert_eq!(dark.bg_secondary, "#17212B");
        assert_eq!(dark.bubble_outgoing, "#2B5278");
        assert!(!dark.is_light_mode);
        assert!(!dark.is_oled_mode);

        // Verify OLED True Black palette colors & flags
        let oled = mgr.get_palette("oled").unwrap();
        assert_eq!(oled.name, "🖤 OLED (True Black)");
        assert_eq!(oled.bg_primary, "#000000");
        assert_eq!(oled.bg_secondary, "#050507");
        assert_eq!(oled.text_primary, "#FFFFFF");
        assert!(!oled.is_light_mode);
        assert!(oled.is_oled_mode);
        assert_eq!(
            parse_hex_color(&oled.bg_primary),
            Color::from_rgb_u8(0, 0, 0)
        );

        // 2. Verify all 4 SuperThemes are loaded and have distinct layout ergonomics
        let tg = mgr.get_supertheme("telegram").expect("telegram supertheme");
        assert_eq!(tg.navigation_layout, "HorizontalFolders");
        assert_eq!(tg.message_layout, "CurvedBubbles");
        assert_eq!(tg.reaction_style, "InsideBubbleCorner");

        let wa = mgr.get_supertheme("whatsapp").expect("whatsapp supertheme");
        assert_eq!(wa.navigation_layout, "MinimalistTabs");
        assert_eq!(wa.message_layout, "SplitBubbles");
        assert_eq!(wa.reaction_style, "FloatingRight");

        let dc = mgr.get_supertheme("discord").expect("discord supertheme");
        assert_eq!(dc.navigation_layout, "VerticalServerRail");
        assert_eq!(dc.message_layout, "FlatFullWidthRows");
        assert_eq!(dc.reaction_style, "BelowMessagePills");

        let irc = mgr
            .get_supertheme("irc_classic")
            .expect("irc_classic supertheme");
        assert_eq!(irc.reaction_style, "BelowMessagePills");
        assert!(irc.compact_timestamps);
    }

    #[test]
    fn test_ensure_local_themes_materialized_writes_all_files() {
        let temp_dir = std::env::temp_dir().join(format!(
            "warp_im_themes_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::env::set_var("WARP_DATA_DIR", &temp_dir);

        let mut mgr = ThemeManager::new();
        let materialized_dir = mgr
            .ensure_local_themes_materialized()
            .expect("should materialize local themes directory");

        assert_eq!(materialized_dir, temp_dir.join("themes"));
        assert!(materialized_dir.join("README_THEMES.txt").is_file());

        for (file, _) in EMBEDDED_SUPERTHEME_FILES {
            assert!(
                materialized_dir.join("superthemes").join(file).is_file(),
                "Expected supertheme file {file} to be materialized on disk"
            );
        }
        for (file, _) in EMBEDDED_PALETTE_FILES {
            assert!(
                materialized_dir.join("palettes").join(file).is_file(),
                "Expected palette file {file} to be materialized on disk"
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

//! Colour palettes for the TUI (selectable via `[tui] theme = "..."`).

use ratatui::style::Color;

/// A named set of colours used across the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// Window background.
    pub bg: Color,
    /// Raised panel background.
    pub surface: Color,
    /// Higher-contrast surface (selection, bars).
    pub surface_hi: Color,
    /// Primary text.
    pub text: Color,
    /// Muted text.
    pub dim: Color,
    /// Accent (titles, chips, user prompt).
    pub accent: Color,
    /// Diff additions / positive.
    pub green: Color,
    /// Diff removals / errors.
    pub red: Color,
    /// Warnings / proposals.
    pub yellow: Color,
}

/// The default soft-violet dark theme.
pub const DEFAULT: Palette = Palette {
    bg: Color::Rgb(17, 18, 22),
    surface: Color::Rgb(30, 31, 37),
    surface_hi: Color::Rgb(44, 46, 54),
    text: Color::Rgb(226, 226, 232),
    dim: Color::Rgb(132, 134, 148),
    accent: Color::Rgb(167, 139, 250),
    green: Color::Rgb(134, 239, 172),
    red: Color::Rgb(248, 150, 150),
    yellow: Color::Rgb(250, 220, 120),
};

/// Nord-inspired cool blue-grey theme.
pub const NORD: Palette = Palette {
    bg: Color::Rgb(46, 52, 64),
    surface: Color::Rgb(59, 66, 82),
    surface_hi: Color::Rgb(67, 76, 94),
    text: Color::Rgb(236, 239, 244),
    dim: Color::Rgb(129, 161, 193),
    accent: Color::Rgb(136, 192, 208),
    green: Color::Rgb(163, 190, 140),
    red: Color::Rgb(191, 97, 106),
    yellow: Color::Rgb(235, 203, 139),
};

/// Gruvbox-inspired warm theme.
pub const GRUVBOX: Palette = Palette {
    bg: Color::Rgb(40, 40, 40),
    surface: Color::Rgb(60, 56, 54),
    surface_hi: Color::Rgb(80, 73, 69),
    text: Color::Rgb(235, 219, 178),
    dim: Color::Rgb(146, 131, 116),
    accent: Color::Rgb(250, 189, 47),
    green: Color::Rgb(184, 187, 38),
    red: Color::Rgb(251, 73, 52),
    yellow: Color::Rgb(250, 189, 47),
};

/// Solarized-dark theme.
pub const SOLARIZED: Palette = Palette {
    bg: Color::Rgb(0, 43, 54),
    surface: Color::Rgb(7, 54, 66),
    surface_hi: Color::Rgb(88, 110, 117),
    text: Color::Rgb(238, 232, 213),
    dim: Color::Rgb(131, 148, 150),
    accent: Color::Rgb(38, 139, 210),
    green: Color::Rgb(133, 153, 0),
    red: Color::Rgb(220, 50, 47),
    yellow: Color::Rgb(181, 137, 0),
};

/// Monochrome (grayscale) theme.
pub const MONO: Palette = Palette {
    bg: Color::Rgb(12, 12, 12),
    surface: Color::Rgb(24, 24, 24),
    surface_hi: Color::Rgb(40, 40, 40),
    text: Color::Rgb(224, 224, 224),
    dim: Color::Rgb(128, 128, 128),
    accent: Color::Rgb(192, 192, 192),
    green: Color::Rgb(200, 200, 200),
    red: Color::Rgb(160, 160, 160),
    yellow: Color::Rgb(180, 180, 180),
};

/// Look up a palette by name (case-insensitive).
pub fn by_name(name: &str) -> Option<Palette> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "default" | "violet" => DEFAULT,
        "nord" => NORD,
        "gruvbox" => GRUVBOX,
        "solarized" | "solarized-dark" => SOLARIZED,
        "mono" | "monochrome" | "gray" | "grey" => MONO,
        _ => return None,
    })
}

/// All selectable theme names.
pub fn names() -> &'static [&'static str] {
    &["default", "nord", "gruvbox", "solarized", "mono"]
}

impl Default for Palette {
    fn default() -> Self {
        DEFAULT
    }
}

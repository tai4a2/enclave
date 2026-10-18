//! Configurable key bindings for the TUI (`[tui.keybinds]`).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::config::TuiSettings;

/// Actions that can be rebound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindAction {
    Quit,
    Clear,
    CopyMode,
    SessionPicker,
    ToggleSidebar,
    ToggleMode,
    Newline,
    HistoryPrev,
    HistoryNext,
    DeleteWord,
    ClearInput,
    Send,
    SessionSearch,
    EditInput,
}

fn action_by_name(name: &str) -> Option<BindAction> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "quit" => BindAction::Quit,
        "clear" => BindAction::Clear,
        "copy_mode" | "copy" => BindAction::CopyMode,
        "session_picker" | "picker" => BindAction::SessionPicker,
        "toggle_sidebar" | "sidebar" => BindAction::ToggleSidebar,
        "toggle_mode" | "mode" => BindAction::ToggleMode,
        "newline" => BindAction::Newline,
        "history_prev" => BindAction::HistoryPrev,
        "history_next" => BindAction::HistoryNext,
        "delete_word" => BindAction::DeleteWord,
        "clear_input" => BindAction::ClearInput,
        "send" => BindAction::Send,
        "session_search" | "search" => BindAction::SessionSearch,
        "edit_input" | "editor" => BindAction::EditInput,
        _ => return None,
    })
}

fn key_code(name: &str) -> Option<KeyCode> {
    let n = name.trim().to_ascii_lowercase();
    Some(match n.as_str() {
        "enter" | "return" => KeyCode::Enter,
        "esc" | "escape" => KeyCode::Esc,
        "tab" => KeyCode::Tab,
        "backtab" | "shift+tab" => KeyCode::BackTab,
        "space" => KeyCode::Char(' '),
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pgup" | "pageup" => KeyCode::PageUp,
        "pgdn" | "pagedown" => KeyCode::PageDown,
        "f1" => KeyCode::F(1),
        "f2" => KeyCode::F(2),
        "f3" => KeyCode::F(3),
        "f4" => KeyCode::F(4),
        "f5" => KeyCode::F(5),
        "f6" => KeyCode::F(6),
        "f7" => KeyCode::F(7),
        "f8" => KeyCode::F(8),
        "f9" => KeyCode::F(9),
        "f10" => KeyCode::F(10),
        "f11" => KeyCode::F(11),
        "f12" => KeyCode::F(12),
        other => {
            let mut chars = other.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            KeyCode::Char(c)
        }
    })
}

/// Parse a key spec such as `ctrl+y`, `alt+x`, `shift+tab`, `f5`, `esc`.
pub fn parse_spec(spec: &str) -> Option<(KeyCode, KeyModifiers)> {
    let mut modifiers = KeyModifiers::NONE;
    let parts: Vec<&str> = spec.split('+').collect();
    let (key_part, mods) = parts.split_last()?;
    // `shift+tab` is expressed as the BackTab code, not a modifier.
    if mods.len() == 1
        && mods[0].eq_ignore_ascii_case("shift")
        && key_part.eq_ignore_ascii_case("tab")
    {
        return Some((KeyCode::BackTab, KeyModifiers::NONE));
    }
    for m in mods {
        match m.trim().to_ascii_lowercase().as_str() {
            "ctrl" | "control" => modifiers |= KeyModifiers::CONTROL,
            "alt" | "option" => modifiers |= KeyModifiers::ALT,
            "shift" => modifiers |= KeyModifiers::SHIFT,
            "" => {}
            _ => return None,
        }
    }
    Some((key_code(key_part)?, modifiers))
}

/// Resolved key overrides.
#[derive(Debug, Default)]
pub struct Keybinds {
    map: Vec<((KeyCode, KeyModifiers), BindAction)>,
}

impl Keybinds {
    /// Build from the `[tui.keybinds]` table (invalid entries are ignored).
    pub fn from_settings(settings: &TuiSettings) -> Self {
        let mut map = Vec::new();
        for (name, spec) in &settings.keybinds {
            if let (Some(action), Some(binding)) = (action_by_name(name), parse_spec(spec)) {
                map.push((binding, action));
            }
        }
        Self { map }
    }

    /// The overridden action for a key event, if any.
    pub fn action_for(&self, key: &KeyEvent) -> Option<BindAction> {
        self.map
            .iter()
            .find(|((code, mods), _)| *code == key.code && key.modifiers.contains(*mods))
            .map(|(_, action)| *action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modifier_specs() {
        assert_eq!(
            parse_spec("ctrl+y"),
            Some((KeyCode::Char('y'), KeyModifiers::CONTROL))
        );
        assert_eq!(
            parse_spec("alt+x"),
            Some((KeyCode::Char('x'), KeyModifiers::ALT))
        );
        assert_eq!(
            parse_spec("shift+tab"),
            Some((KeyCode::BackTab, KeyModifiers::NONE))
        );
        assert_eq!(parse_spec("f5"), Some((KeyCode::F(5), KeyModifiers::NONE)));
        assert_eq!(parse_spec("esc"), Some((KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(parse_spec("bogus+thing"), None);
    }

    #[test]
    fn resolves_overrides_from_settings() {
        let mut settings = TuiSettings::default();
        settings.keybinds.insert("quit".into(), "ctrl+q".into());
        let kb = Keybinds::from_settings(&settings);
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(kb.action_for(&key), Some(BindAction::Quit));
        let other = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL);
        assert_eq!(kb.action_for(&other), None);
    }
}

//! System clipboard helper (cross-platform).
//!
//! Used by the TUI to copy assistant replies / selections. On macOS this
//! writes to the general pasteboard (same mechanism as `pbcopy`), so it needs
//! no special permission.

use arboard::Clipboard;

use crate::error::{EnclaveError, Result};

/// Copy `text` to the system clipboard.
pub fn copy(text: &str) -> Result<()> {
    let mut clipboard =
        Clipboard::new().map_err(|e| EnclaveError::other(format!("clipboard unavailable: {e}")))?;
    clipboard
        .set_text(text.to_string())
        .map_err(|e| EnclaveError::other(format!("clipboard write failed: {e}")))
}

/// Read the current clipboard text, if any.
pub fn paste() -> Result<String> {
    let mut clipboard =
        Clipboard::new().map_err(|e| EnclaveError::other(format!("clipboard unavailable: {e}")))?;
    clipboard
        .get_text()
        .map_err(|e| EnclaveError::other(format!("clipboard read failed: {e}")))
}

/// Copy `text`, then clear the clipboard after `ttl_secs` seconds **only if** it
/// still holds exactly that text (so we never clobber something the user copied
/// in the meantime). `ttl_secs == 0` disables the timer.
pub fn copy_with_ttl(text: &str, ttl_secs: u64) -> Result<()> {
    copy(text)?;
    if ttl_secs > 0 {
        let expected = text.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(ttl_secs));
            if let Ok(current) = paste() {
                if current == expected {
                    let _ = copy("");
                }
            }
        });
    }
    Ok(())
}

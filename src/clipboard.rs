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

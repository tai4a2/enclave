//! File attachments for chat messages: images (sent to multimodal models) and
//! text files (injected into the prompt, and scanned by the privacy guard).
//!
//! Attachments are stored inside the encrypted database: image bytes are
//! base64-encoded into the message metadata, so they remain encrypted at rest
//! like every other part of the history.

use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{EnclaveError, Result};

/// Largest image we accept (protects the encrypted DB from runaway growth).
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

/// What kind of attachment this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentKind {
    /// An image (stored as base64 in `data`).
    Image,
    /// A text file (stored as UTF-8 text in `data`).
    Text,
}

/// One file attached to a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// Image or text.
    pub kind: AttachmentKind,
    /// Original file name (for display and labelling in the prompt).
    pub name: String,
    /// MIME type (e.g. `image/png`, `text/plain`).
    pub mime: String,
    /// Image: base64 bytes. Text: the raw UTF-8 content.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String,
}

impl Attachment {
    /// Whether this is an image.
    pub fn is_image(&self) -> bool {
        self.kind == AttachmentKind::Image
    }

    /// The text body of a text attachment (images return `None`).
    pub fn text_body(&self) -> Option<&str> {
        (self.kind == AttachmentKind::Text).then_some(self.data.as_str())
    }

    /// A `data:` URL carrying the base64 image (OpenAI/OpenRouter format).
    pub fn data_url(&self) -> String {
        format!("data:{};base64,{}", self.mime, self.data)
    }

    /// Read a file from disk and classify it as an image or a text attachment.
    pub fn from_file(path: &Path) -> Result<Attachment> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());
        let mime = guess_mime(&name);
        let bytes = std::fs::read(path)
            .map_err(|e| EnclaveError::other(format!("cannot read {}: {e}", path.display())))?;

        if mime.starts_with("image/") {
            if bytes.len() > MAX_IMAGE_BYTES {
                return Err(EnclaveError::other(format!(
                    "image too large ({:.1} MB, max {} MB)",
                    bytes.len() as f64 / 1_048_576.0,
                    MAX_IMAGE_BYTES / 1_048_576
                )));
            }
            let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(Attachment {
                kind: AttachmentKind::Image,
                name,
                mime: mime.to_string(),
                data,
            })
        } else {
            let text = String::from_utf8(bytes).map_err(|_| {
                EnclaveError::other(format!("{name} is not UTF-8 text (not an image either)"))
            })?;
            Ok(Attachment {
                kind: AttachmentKind::Text,
                name,
                mime: mime.to_string(),
                data: text,
            })
        }
    }
}

/// Best-effort MIME type from the file extension.
pub fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "json" => "application/json",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "xml" => "text/xml",
        _ => "text/plain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guesses_image_and_text_mimes() {
        assert!(guess_mime("photo.PNG").starts_with("image/"));
        assert_eq!(guess_mime("notes.txt"), "text/plain");
        assert_eq!(guess_mime("data.json"), "application/json");
        assert_eq!(guess_mime("README.md"), "text/markdown");
    }

    #[test]
    fn reads_a_text_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, "ciao enclave").unwrap();
        let a = Attachment::from_file(&path).unwrap();
        assert_eq!(a.kind, AttachmentKind::Text);
        assert_eq!(a.text_body(), Some("ciao enclave"));
        assert!(!a.is_image());
    }

    #[test]
    fn reads_an_image_as_base64_data_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixel.png");
        // 1x1 transparent PNG.
        let png: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        std::fs::write(&path, png).unwrap();
        let a = Attachment::from_file(&path).unwrap();
        assert!(a.is_image());
        assert_eq!(a.mime, "image/png");
        assert!(a.data_url().starts_with("data:image/png;base64,"));
        assert!(a.text_body().is_none());
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(Attachment::from_file(Path::new("/no/such/file-xyz.txt")).is_err());
    }
}

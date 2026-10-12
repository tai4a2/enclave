//! Local DLP judge (C3).
//!
//! An optional second pair of eyes: when `[policy] judge = "<ollama-model>"` is
//! set, every outbound payload is reviewed by a **local** model (via Ollama)
//! before it is sent. Nothing leaves the machine to run the check; only the
//! verdict ("is this sensitive?") is used locally.
use crate::error::{EnclaveError, Result};

const INSTRUCTION: &str = "You are a data-loss-prevention classifier. Answer with a single word: \
YES if the text below contains sensitive personal or confidential data (real people's names, \
emails, phone numbers, addresses, credentials, secrets, financial or medical data), otherwise NO.";

/// Ask the local model whether `text` looks sensitive. Returns `true` for a
/// positive verdict. Errors are returned so the caller can decide (fail-open).
pub async fn judge(model: &str, base_url: &str, text: &str) -> Result<bool> {
    let url = format!("{}/api/generate", base_url.trim_end_matches('/'));
    let prompt = format!("{INSTRUCTION}\n\n----- TEXT -----\n{text}\n----- END -----");
    let body = serde_json::json!({ "model": model, "prompt": prompt, "stream": false });

    let client = crate::providers::http::client();
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| EnclaveError::provider(format!("dlp judge: {e}")))?;
    if !resp.status().is_success() {
        return Err(EnclaveError::provider(format!(
            "dlp judge HTTP {}",
            resp.status()
        )));
    }
    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| EnclaveError::provider(format!("dlp judge: {e}")))?;
    let answer = value["response"].as_str().unwrap_or("").to_ascii_uppercase();
    Ok(answer.trim_start().starts_with("YES"))
}

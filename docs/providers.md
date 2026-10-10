# Providers

Providers implement the `Provider` trait (`src/providers/mod.rs`):

```rust
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_model(&self) -> &'static str;
    async fn chat_stream(&self, messages: Vec<Message>, model: &str)
        -> Result<ChunkStream>; // async stream of text chunks
    // chat() is provided: collects the stream into a String
}
```

All remote providers use SSE streaming (`stream: true`) over `reqwest` with rustls.

## Supported providers

| Provider | Requires API key | Default model | Notes |
|----------|------------------|---------------|-------|
| `openrouter` | yes (`keys set openrouter`) | `mistralai/mistral-large` | Gateway to hundreds of models |
| `openai` | yes (`keys set openai`) | `gpt-4o-mini` | Direct OpenAI API |
| `anthropic` | yes (`keys set anthropic`) | `claude-3-5-sonnet-latest` | Anthropic Messages API |
| `ollama` | **no** | `llama3.1` | Local, 100% offline |

## Examples

```bash
# OpenRouter with a specific model
enclave chat --provider openrouter --model openai/gpt-4o

# OpenAI direct
enclave chat --provider openai --model gpt-4o-mini

# Anthropic
enclave chat --provider anthropic --model claude-3-5-sonnet-latest

# Ollama (start it first: `ollama serve`)
enclave chat --provider ollama --model llama3.1
```

## Adding a provider

1. Create `src/providers/myprovider.rs`
2. Implement `Provider` (name, default model, `chat_stream` returning an async stream of chunks)
3. Register it in `create_provider()` in `src/providers/mod.rs` and add it to `known_providers()`
4. If it needs an API key it is handled automatically: `enclave keys set myprovider`

The trait keeps streaming first-class, so TUI and line-based chat both render tokens as they arrive.

## Privacy per provider

- **ollama**: nothing leaves the machine. Recommended for sensitive content.
- **openrouter / openai / anthropic**: the prompt leaves the device (TLS-encrypted, but provider-readable). These providers apply their own content policies — e.g. OpenRouter may reject requests with detected PII (`403 PII detected`).
//! Minimal Model Context Protocol client over stdio (line-delimited JSON-RPC).
//!
//! Servers are launched locally as child processes and speak newline-delimited
//! JSON-RPC 2.0 on their stdin/stdout. Nothing leaves the machine except what
//! the server itself decides to do; each exposed tool is gated by the normal
//! permission model (default: ask).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::config::{McpServer, McpSettings};
use crate::error::{EnclaveError, Result};
use crate::providers::ToolDef;

/// One tool advertised by a connected server.
struct McpTool {
    server: String,
    remote_name: String,
    def: ToolDef,
}

struct Client {
    name: String,
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl Client {
    fn connect(name: &str, server: &McpServer) -> Result<Client> {
        let mut cmd = Command::new(&server.command);
        cmd.args(&server.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in &server.env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| EnclaveError::other(format!("mcp '{name}': spawn failed: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| EnclaveError::other("mcp: no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| EnclaveError::other("mcp: no stdout"))?;
        Ok(Client {
            name: name.to_string(),
            child,
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn write_msg(&mut self, value: &Value) -> Result<()> {
        let mut line = serde_json::to_string(value)
            .map_err(|e| EnclaveError::other(format!("mcp '{}': encode failed: {e}", self.name)))?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| EnclaveError::other(format!("mcp '{}': write failed: {e}", self.name)))?;
        let _ = self.stdin.flush();
        Ok(())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.write_msg(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let mut buf = String::new();
            let n = self.reader.read_line(&mut buf).map_err(|e| {
                EnclaveError::other(format!("mcp '{}': read failed: {e}", self.name))
            })?;
            if n == 0 {
                return Err(EnclaveError::other(format!(
                    "mcp '{}': server closed the connection",
                    self.name
                )));
            }
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = value.get("error") {
                    return Err(EnclaveError::other(format!("mcp '{}': {err}", self.name)));
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
            // Notifications or unrelated responses are ignored.
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        self.write_msg(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }

    fn initialize(&mut self) -> Result<()> {
        self.request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "enclave", "version": env!("CARGO_PKG_VERSION")}
            }),
        )?;
        self.notify("notifications/initialized", json!({}))?;
        Ok(())
    }

    fn list_tools(&mut self) -> Result<Vec<Value>> {
        let result = self.request("tools/list", json!({}))?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn call_tool(&mut self, name: &str, args: Value) -> Result<String> {
        let result = self.request("tools/call", json!({"name": name, "arguments": args}))?;
        if let Some(content) = result.get("content").and_then(Value::as_array) {
            let mut out = String::new();
            for part in content {
                if let Some(t) = part.get("text").and_then(Value::as_str) {
                    if !out.is_empty() {
                        out.push('\n');
                    }
                    out.push_str(t);
                }
            }
            if out.is_empty() {
                out = result.to_string();
            }
            Ok(out)
        } else if result.get("isError").and_then(Value::as_bool) == Some(true) {
            Ok(format!("tool reported an error: {result}"))
        } else {
            Ok(result.to_string())
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Live MCP server connections plus the tools they advertise.
pub struct McpRegistry {
    clients: Vec<Mutex<Client>>,
    tools: Vec<McpTool>,
}

impl McpRegistry {
    /// Connect to every configured server, initialise and discover tools.
    /// Returns `None` when no server is configured.
    pub fn connect_all(settings: &McpSettings) -> Option<McpRegistry> {
        if settings.servers.is_empty() {
            return None;
        }
        let mut clients = Vec::new();
        let mut tools = Vec::new();
        for (name, server) in &settings.servers {
            let mut client = match Client::connect(name, server) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("warning: {e}");
                    continue;
                }
            };
            if let Err(e) = client.initialize() {
                eprintln!("warning: mcp '{name}': {e}");
                continue;
            }
            match client.list_tools() {
                Ok(list) => {
                    for t in list {
                        let rname = t
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        if rname.is_empty() {
                            continue;
                        }
                        let desc = t
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or("(MCP tool)")
                            .to_string();
                        let schema = t
                            .get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| json!({"type": "object"}));
                        let full = format!("mcp__{name}__{rname}");
                        tools.push(McpTool {
                            server: name.clone(),
                            remote_name: rname,
                            def: ToolDef::new(&full, &desc, schema),
                        });
                    }
                    clients.push(Mutex::new(client));
                }
                Err(e) => eprintln!("warning: mcp '{name}': {e}"),
            }
        }
        Some(McpRegistry { clients, tools })
    }

    /// Tool definitions to expose to the model.
    pub fn defs(&self) -> Vec<ToolDef> {
        self.tools.iter().map(|t| t.def.clone()).collect()
    }

    /// Names of the discovered tools (diagnostics).
    pub fn tool_names(&self) -> Vec<String> {
        self.tools.iter().map(|t| t.def.name.clone()).collect()
    }

    /// Invoke a tool by its full name (`mcp__server__tool`).
    pub fn call(&self, full_name: &str, args: Value) -> Result<String> {
        let tool = self
            .tools
            .iter()
            .find(|t| t.def.name == full_name)
            .ok_or_else(|| EnclaveError::other(format!("unknown mcp tool '{full_name}'")))?;
        let entry = self
            .clients
            .iter()
            .find(|c| c.lock().map(|g| g.name == tool.server).unwrap_or(false))
            .ok_or_else(|| {
                EnclaveError::other(format!("mcp server '{}' not connected", tool.server))
            })?;
        let mut guard = entry
            .lock()
            .map_err(|_| EnclaveError::other("mcp client poisoned"))?;
        guard.call_tool(&tool.remote_name, args)
    }
}

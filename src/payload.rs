//! The PreToolUse payload, reduced to the fields the guards read.

use serde_json::Value;

pub struct Payload {
    pub tool_name: String,
    pub command: String,
    pub file_path: String,
    /// Text an edit would introduce: Write content, Edit new_string, every
    /// MultiEdit new_string.
    pub new_text: String,
    pub cwd: String,
}

impl Payload {
    pub fn parse(raw: &str) -> Option<Payload> {
        let value: Value = serde_json::from_str(raw).ok()?;
        let input = value.get("tool_input").cloned().unwrap_or(Value::Null);
        let text = |key: &str| {
            input
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };

        let mut pieces: Vec<String> = Vec::new();
        for key in ["content", "new_string"] {
            if let Some(s) = input.get(key).and_then(Value::as_str) {
                pieces.push(s.to_string());
            }
        }
        if let Some(edits) = input.get("edits").and_then(Value::as_array) {
            for edit in edits {
                if let Some(s) = edit.get("new_string").and_then(Value::as_str) {
                    pieces.push(s.to_string());
                }
            }
        }

        Some(Payload {
            tool_name: value
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            command: text("command"),
            file_path: text("file_path"),
            new_text: pieces.join("\n"),
            cwd: value
                .get("cwd")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }
}

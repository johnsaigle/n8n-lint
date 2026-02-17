// src/model.rs
use serde::Deserialize;
use serde_json::Value;

/// Top-level n8n workflow structure
#[derive(Debug, Deserialize)]
pub struct Workflow {
    pub name: Option<String>,
    pub nodes: Option<Vec<Node>>,
    pub connections: Option<Value>,
    pub settings: Option<Value>,
    pub tags: Option<Value>,
}

/// An n8n node
#[derive(Debug, Deserialize)]
pub struct Node {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub node_type: Option<String>,
    #[serde(rename = "typeVersion")]
    pub type_version: Option<Value>,
    pub parameters: Option<Value>,
    pub position: Option<Value>,
    pub credentials: Option<Value>,
    #[serde(rename = "onError")]
    pub on_error: Option<String>,
    pub notes: Option<String>,
}

impl Node {
    /// Get node type as str, defaulting to empty
    pub fn type_str(&self) -> &str {
        self.node_type.as_deref().unwrap_or("")
    }

    /// Get node id as str
    pub fn id_str(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Get node name as str
    pub fn name_str(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get a string parameter value by key
    pub fn param_str(&self, key: &str) -> Option<&str> {
        self.parameters.as_ref()?.get(key)?.as_str()
    }

    /// Get the full parameters value
    pub fn params(&self) -> Option<&Value> {
        self.parameters.as_ref()
    }

    /// Check if this is an SSH node
    pub fn is_ssh(&self) -> bool {
        self.type_str() == "n8n-nodes-base.ssh"
    }

    /// Check if this is a Code node
    pub fn is_code(&self) -> bool {
        self.type_str() == "n8n-nodes-base.code"
    }

    /// Check if this is an HTTP Request node
    pub fn is_http_request(&self) -> bool {
        self.type_str() == "n8n-nodes-base.httpRequest"
    }

    /// Check if this is a Schedule Trigger
    pub fn is_schedule_trigger(&self) -> bool {
        self.type_str() == "n8n-nodes-base.scheduleTrigger"
    }

    /// Check if this is a Manual Trigger
    pub fn is_manual_trigger(&self) -> bool {
        self.type_str() == "n8n-nodes-base.manualTrigger"
    }

    /// Check if this is an Error Trigger
    pub fn is_error_trigger(&self) -> bool {
        self.type_str() == "n8n-nodes-base.errorTrigger"
    }

    /// Recursively collect all string values from the parameters (for deep searching)
    pub fn all_param_strings(&self) -> Vec<String> {
        let mut strings = Vec::new();
        if let Some(params) = &self.parameters {
            collect_strings(params, &mut strings);
        }
        strings
    }
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => {
            for v in arr {
                collect_strings(v, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}

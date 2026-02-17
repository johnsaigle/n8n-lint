// src/rules/ntfy.rs
use crate::finding::Finding;
use crate::model::Node;

/// Heuristic: does this HTTP Request node talk to ntfy?
pub fn is_ntfy_node(node: &Node) -> bool {
    if !node.is_http_request() {
        return false;
    }

    // Check node name for ntfy or notification patterns
    if let Some(name) = node.name_str() {
        let lower = name.to_lowercase();
        if lower.contains("ntfy") {
            return true;
        }
        // Common naming patterns: "Notify: ...", "Notification: ..."
        if lower.starts_with("notify") || lower.starts_with("notification") {
            return true;
        }
    }

    // Check all parameter strings for ntfy indicators
    let strings = node.all_param_strings();

    // Direct ntfy URL references
    let has_url_indicator = strings.iter().any(|s| {
        let lower = s.to_lowercase();
        lower.contains("/ntfy") || lower.contains("ntfy.") || lower.contains(":ntfy")
    });
    if has_url_indicator {
        return true;
    }

    // ntfy JSON publish pattern: body contains "topic" + ("message" or "title")
    // This catches nodes that POST JSON to ntfy without "ntfy" in the URL
    let has_topic = strings
        .iter()
        .any(|s| s.contains("topic:") || s.contains("\"topic\"") || s.contains("topic\":"));
    let has_message_or_title = strings.iter().any(|s| {
        s.contains("message:")
            || s.contains("\"message\"")
            || s.contains("title:")
            || s.contains("\"title\"")
    });

    has_topic && has_message_or_title
}

/// Check ntfy nodes use JSON.stringify pattern for body
pub fn check_json_stringify(node: &Node) -> Vec<Finding> {
    if !is_ntfy_node(node) {
        return vec![];
    }

    let mut findings = vec![];
    let strings = node.all_param_strings();

    // Look for ntfy JSON body fields without JSON.stringify
    let has_ntfy_body_fields = strings.iter().any(|s| {
        (s.contains("\"topic\"") || s.contains("\"message\"") || s.contains("\"title\""))
            && !s.contains("JSON.stringify")
    });

    // Also check if any string has topic/message as JS object keys (unquoted)
    let has_js_body_fields = strings.iter().any(|s| {
        (s.contains("topic:") || s.contains("message:") || s.contains("title:"))
            && s.contains("JSON.stringify")
    });

    if has_ntfy_body_fields && !has_js_body_fields {
        findings.push(
            Finding::warning(
                "ntfy-json-stringify",
                "ntfy body should use ={{ JSON.stringify({...}) }} pattern. \
                 Without this, nested objects (actions array) break n8n's expression parser",
            )
            .with_node(node.id_str(), node.name_str())
            .with_suggestion(
                "Use ={{ JSON.stringify({ topic: \"...\", message: \"...\", ... }) }}",
            ),
        );
    }

    findings
}

/// Check ntfy nodes have Authorization header
pub fn check_auth_header(node: &Node) -> Vec<Finding> {
    if !is_ntfy_node(node) {
        return vec![];
    }

    let mut findings = vec![];
    let strings = node.all_param_strings();

    let has_auth = strings
        .iter()
        .any(|s| s.to_lowercase().contains("authorization"));

    if !has_auth {
        findings.push(
            Finding::error(
                "ntfy-auth-header",
                "ntfy node missing Authorization header. \
                 ntfy returns 403 Forbidden without Basic auth",
            )
            .with_node(node.id_str(), node.name_str())
            .with_suggestion("Add header: Authorization: Basic YWRtaW46MTIzNDU2Nzg="),
        );
    }

    findings
}

/// Check ntfy header values for non-ASCII characters
pub fn check_ascii_headers(node: &Node) -> Vec<Finding> {
    if !is_ntfy_node(node) {
        return vec![];
    }

    let mut findings = vec![];

    if let Some(params) = node.params() {
        // Check headerParameters and sendHeaders
        let header_keys = ["headerParameters", "sendHeaders"];
        for key in &header_keys {
            if let Some(headers) = params.get(key) {
                check_value_for_non_ascii(headers, node, &mut findings);
            }
        }
    }

    findings
}

fn check_value_for_non_ascii(value: &serde_json::Value, node: &Node, findings: &mut Vec<Finding>) {
    match value {
        serde_json::Value::String(s) => {
            // Skip n8n expressions - they're dynamic
            if s.starts_with('=') || s.contains("{{") {
                return;
            }
            // Check for non-ASCII
            if s.bytes()
                .any(|b| b > 0x7E || (b < 0x20 && b != b'\n' && b != b'\r'))
            {
                let non_ascii: String = s
                    .chars()
                    .filter(|c| !c.is_ascii() || (*c as u32) < 0x20)
                    .take(5)
                    .collect();
                findings.push(
                    Finding::warning(
                        "ntfy-ascii-headers",
                        &format!(
                            "ntfy header contains non-ASCII characters: {:?}. \
                             HTTP headers must be ASCII-only (RFC 7230)",
                            non_ascii
                        ),
                    )
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion(
                        "Replace: em dash -> -, smart quotes -> regular quotes, ellipsis -> ...",
                    ),
                );
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                check_value_for_non_ascii(v, node, findings);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                check_value_for_non_ascii(v, node, findings);
            }
        }
        _ => {}
    }
}

/// Check for hardcoded service ports in ntfy URLs
pub fn check_hardcoded_port(node: &Node) -> Vec<Finding> {
    if !is_ntfy_node(node) {
        return vec![];
    }

    let mut findings = vec![];
    let strings = node.all_param_strings();

    let port_pattern = regex::Regex::new(r"172\.17\.0\.1:\d{4,5}").unwrap();
    for s in &strings {
        if port_pattern.is_match(s) {
            findings.push(
                Finding::warning(
                    "ntfy-hardcoded-port",
                    "ntfy URL contains hardcoded Docker bridge port. \
                     Ports change when containers are recreated",
                )
                .with_node(node.id_str(), node.name_str())
                .with_suggestion(
                    "Use homelab status to discover live service ports before authoring",
                ),
            );
            break;
        }
    }

    findings
}

/// Run all ntfy rules
pub fn check_all(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_json_stringify(node));
    findings.extend(check_auth_header(node));
    findings.extend(check_ascii_headers(node));
    findings.extend(check_hardcoded_port(node));
    findings
}

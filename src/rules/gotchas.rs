// src/rules/gotchas.rs
use crate::finding::Finding;
use crate::model::{Node, Workflow};
use std::collections::HashMap;

/// Check `OpenCode` HTTP calls have sufficient timeout
#[must_use]
pub fn check_opencode_timeout(node: &Node) -> Vec<Finding> {
    if !node.is_http_request() {
        return vec![];
    }

    // Only check the URL parameter — not all strings (ntfy bodies may reference /session/ in PWA links)
    let url = node.param_str("url").unwrap_or("");
    let is_opencode = url.contains("/session");

    if !is_opencode {
        return vec![];
    }

    let mut findings = vec![];

    if let Some(params) = node.params() {
        let timeout = params
            .get("timeout")
            .or_else(|| params.get("options").and_then(|o| o.get("timeout")));

        match timeout {
            Some(t) => {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                if let Some(ms) = t.as_u64().or_else(|| t.as_f64().map(|f| f as u64))
                    && ms < 300_000
                {
                    findings.push(
                        Finding::error(
                            "opencode-timeout",
                            &format!(
                                "OpenCode HTTP call has timeout of {ms}ms (< 300000ms). \
                                 Tool-heavy prompts can take minutes"
                            ),
                        )
                        .with_node(node.id_str(), node.name_str())
                        .with_suggestion("Set timeout to 300000+ ms"),
                    );
                }
            }
            None => {
                findings.push(
                    Finding::error(
                        "opencode-timeout",
                        "OpenCode HTTP call has no explicit timeout set. \
                         Default timeout is likely too low for tool-heavy prompts",
                    )
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion("Set timeout to 300000+ ms"),
                );
            }
        }
    }

    findings
}

/// Check for unmatched expression delimiters
#[must_use]
pub fn check_expression_syntax(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    let strings = node.all_param_strings();

    for s in &strings {
        // Skip pure JS expressions (= prefix) — {{ }} inside them is valid n8n template syntax
        if s.starts_with('=') {
            continue;
        }

        let opens = s.matches("{{").count();
        let closes = s.matches("}}").count();

        if opens != closes {
            findings.push(
                Finding::error(
                    "expression-syntax",
                    &format!(
                        "Unmatched expression delimiters: {opens} opening '{{{{' vs {closes} closing '}}}}'"
                    ),
                )
                .with_node(node.id_str(), node.name_str())
                .with_suggestion("Fix unmatched {{ or }} delimiters"),
            );
            break; // One finding per node
        }
    }

    findings
}

/// Known placeholder patterns in credential IDs and values.
/// These indicate credentials that were never configured with real values.
const CREDENTIAL_PLACEHOLDER_PATTERNS: &[&str] = &[
    "CONFIGURE_ME",
    "REPLACE_WITH_",
    "PLACEHOLDER",
    "TODO",
    "CHANGEME",
    "INSERT_",
    "YOUR_",
    "XXX",
];

/// Check for placeholder credentials
#[must_use]
pub fn check_credential_placeholder(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];

    if let Some(creds) = node.credentials.as_ref()
        && let Some(obj) = creds.as_object()
    {
        for (cred_type, cred_value) in obj {
            let cred_str = cred_value.to_string();
            let cred_upper = cred_str.to_uppercase();

            // Check against all known placeholder patterns
            for pattern in CREDENTIAL_PLACEHOLDER_PATTERNS {
                if cred_upper.contains(pattern) {
                    findings.push(
                        Finding::error(
                            "credential-placeholder",
                            &format!(
                                "Credential '{cred_type}' contains placeholder pattern '{pattern}' \
                                 (value: {cred_str}). \
                                 Credential IDs are opaque strings like 'Fy5DPVPe3GcEl7ZI' \
                                 assigned by n8n — you cannot invent them"
                            ),
                        )
                        .with_node(node.id_str(), node.name_str())
                        .with_suggestion(
                            "Get the real credential ID from a working workflow: \
                             run n8n_get on a workflow that uses this credential type \
                             and copy the {\"id\": \"...\", \"name\": \"...\"} block. \
                             Do NOT rename the placeholder — the ID must match an \
                             existing credential configured in the n8n UI",
                        ),
                    );
                    break; // One finding per credential, not per pattern
                }
            }

            // Check for credential IDs that look human-authored rather than n8n-generated.
            // Real n8n credential IDs are 16-char alphanumeric strings (e.g. "Fy5DPVPe3GcEl7ZI").
            // Human-authored IDs contain underscores, hyphens, spaces, or are too long/short.
            if let Some(id) = cred_value.get("id")
                && let Some(id_str) = id.as_str()
                && !id_str.is_empty()
            {
                let looks_fabricated = id_str.contains('_')
                    || id_str.contains('-')
                    || id_str.contains(' ')
                    || id_str.len() > 20
                    || id_str.len() < 10
                    || id_str.chars().all(|c| c.is_ascii_lowercase());

                if looks_fabricated {
                    findings.push(
                        Finding::warning(
                            "credential-suspicious-id",
                            &format!(
                                "Credential '{cred_type}' has ID '{id_str}' which doesn't look \
                                 like an n8n-generated credential ID. Real IDs are ~16 char \
                                 mixed-case alphanumeric strings (e.g. 'Fy5DPVPe3GcEl7ZI')"
                            ),
                        )
                        .with_node(node.id_str(), node.name_str())
                        .with_suggestion(
                            "Verify this is a real credential ID from n8n, not a fabricated one. \
                             Run n8n_get on a working workflow to find valid credential IDs",
                        ),
                    );
                }
            }

            // Check for empty credential ID
            if let Some(id) = cred_value.get("id")
                && id.as_str() == Some("")
            {
                findings.push(
                    Finding::error(
                        "credential-placeholder",
                        &format!(
                            "Credential '{cred_type}' has empty ID. \
                             Credential IDs are opaque strings like 'Fy5DPVPe3GcEl7ZI' \
                             assigned by n8n — you cannot invent them"
                        ),
                    )
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion(
                        "Get the real credential ID from a working workflow: \
                         run n8n_get on a workflow that uses this credential type \
                         and copy the {\"id\": \"...\", \"name\": \"...\"} block",
                    ),
                );
            }
        }
    }

    findings
}

/// Check `OpenCode` PWA URLs have proper base64 padding
///
/// # Panics
///
/// Panics if the regex pattern is invalid (should never happen with a static pattern).
#[must_use]
pub fn check_base64_padding(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    let strings = node.all_param_strings();

    let re = regex::Regex::new(r"/([A-Za-z0-9+/_-]+)/session/").unwrap();

    for s in &strings {
        // Look for OpenCode PWA URL pattern
        if !s.contains("/session/") {
            continue;
        }

        // Pattern: http://host:port/<base64>/session/<session_id>
        // The base64 segment for /home/psychopomp should be L2hvbWUvcHN5Y2hvcG9tcA==
        if let Some(caps) = re.captures(s) {
            let b64 = &caps[1];
            // Check if it looks like base64 but missing padding
            if b64.len() % 4 != 0 && !b64.ends_with('=') {
                findings.push(
                    Finding::warning(
                        "base64-padding",
                        "OpenCode PWA URL appears to have unpadded base64 segment. \
                         Missing padding can cause client-side routing failures",
                    )
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion("Include base64 padding (==) in the directory segment"),
                );
                break;
            }
        }
    }

    findings
}

/// Check workflow tags are string array, not object array
#[must_use]
pub fn check_tags_format(workflow: &Workflow) -> Vec<Finding> {
    if let Some(tags) = &workflow.tags
        && let Some(arr) = tags.as_array()
        && arr.iter().any(serde_json::Value::is_object)
    {
        return vec![
            Finding::warning(
                "tags-format",
                "Workflow tags should be a string array, not an object array. \
                 The n8n API expects string arrays for import",
            )
            .with_suggestion("Flatten tags: [{\"name\": \"foo\"}] -> [\"foo\"]"),
        ];
    }

    vec![]
}

/// Check for `/no_think` in Ollama API calls (should use "think": false)
#[must_use]
pub fn check_ollama_no_think(node: &Node) -> Vec<Finding> {
    if !node.is_http_request() {
        return vec![];
    }

    let mut findings = vec![];
    let strings = node.all_param_strings();

    let is_ollama = strings
        .iter()
        .any(|s| s.contains("/api/generate") || s.contains("/api/chat"));

    if !is_ollama {
        return findings;
    }

    let has_no_think_prompt = strings.iter().any(|s| {
        let lower = s.to_lowercase();
        lower.contains("/no_think") || lower.contains("/nothink")
    });

    if has_no_think_prompt {
        findings.push(
            Finding::error(
                "ollama-no-think",
                "/no_think in the prompt does nothing at the API level. \
                 The model still thinks, puts output in the 'thinking' field, \
                 and returns an empty 'response' field",
            )
            .with_node(node.id_str(), node.name_str())
            .with_suggestion(
                "Remove /no_think from prompt and add \"think\": false to the request body",
            ),
        );
    }

    findings
}

/// Check for overly-frequent polling intervals
#[must_use]
pub fn check_polling_interval(node: &Node) -> Vec<Finding> {
    if !node.is_schedule_trigger() {
        return vec![];
    }

    let mut findings = vec![];

    if let Some(params) = node.params() {
        // Check cron expressions
        let param_str = serde_json::to_string(params).unwrap_or_default();

        // Look for cron patterns with very frequent intervals
        // Common patterns: "*/30 * * * * *" (every 30 seconds), "* * * * *" (every minute)
        // We check for second-level cron or sub-minute intervals
        if param_str.contains("\"seconds\"") {
            findings.push(
                Finding::warning(
                    "polling-interval",
                    "Schedule trigger uses second-level intervals. \
                     Polling more than once per minute wastes API quota",
                )
                .with_node(node.id_str(), node.name_str())
                .with_suggestion("Use 1-5 minute intervals for external API polling"),
            );
        }
    }

    findings
}

/// Check for duplicate node positions (workflow-level)
#[must_use]
pub fn check_duplicate_positions(nodes: &[Node]) -> Vec<Finding> {
    let mut positions: HashMap<String, Vec<String>> = HashMap::new();

    for node in nodes {
        if let Some(pos) = &node.position {
            let key = pos.to_string();
            let name = node.name_str().unwrap_or("unnamed").to_string();
            positions.entry(key).or_default().push(name);
        }
    }

    let mut findings = vec![];
    for (pos, names) in &positions {
        if names.len() > 1 {
            findings.push(
                Finding::warning(
                    "duplicate-node-position",
                    &format!(
                        "Nodes at same position {pos}: {}. This creates visual overlap in n8n UI",
                        names.join(", ")
                    ),
                )
                .with_suggestion("Space nodes apart for readability"),
            );
        }
    }

    findings
}

/// Run per-node gotcha checks
#[must_use]
pub fn check_node(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_opencode_timeout(node));
    findings.extend(check_expression_syntax(node));
    findings.extend(check_credential_placeholder(node));
    findings.extend(check_base64_padding(node));
    findings.extend(check_ollama_no_think(node));
    findings.extend(check_polling_interval(node));
    findings
}

/// Run workflow-level gotcha checks
#[must_use]
pub fn check_workflow(workflow: &Workflow, nodes: &[Node]) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_tags_format(workflow));
    findings.extend(check_duplicate_positions(nodes));
    findings
}

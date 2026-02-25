// src/rules/code_node.rs
use crate::finding::Finding;
use crate::model::Node;

/// Forbidden modules in Code node sandbox
const FORBIDDEN_MODULES: &[&str] = &[
    "fs",
    "child_process",
    "path",
    "http",
    "https",
    "os",
    "net",
    "crypto",
    "stream",
    "util",
    "events",
    "dns",
    "tls",
    "cluster",
    "readline",
];

/// Check Code nodes for forbidden `require()` calls
#[must_use]
pub fn check_forbidden_require(node: &Node) -> Vec<Finding> {
    if !node.is_code() {
        return vec![];
    }

    let mut findings = vec![];

    if let Some(code) = node.param_str("jsCode") {
        for module in FORBIDDEN_MODULES {
            let patterns = [
                format!("require('{module}')"),
                format!("require(\"{module}\")"),
                format!("require('{module}/"),
                format!("require(\"{module}/"),
            ];

            for pattern in &patterns {
                if code.contains(pattern.as_str()) {
                    findings.push(
                        Finding::error(
                            "code-forbidden-require",
                            &format!(
                                "Code node uses require('{module}') which is blocked in n8n's sandbox"
                            ),
                        )
                        .with_node(node.id_str(), node.name_str())
                        .with_suggestion(
                            "Code nodes cannot import Node.js built-ins. \
                             Use readWriteFile for file ops, HTTP Request for network, \
                             SSH node for shell commands",
                        ),
                    );
                    break; // One finding per module is enough
                }
            }
        }
    }

    findings
}

/// Check for node types that don't exist in Docker n8n
#[must_use]
pub fn check_invalid_node_type(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];

    let invalid_types = [(
        "n8n-nodes-base.executeCommand",
        "executeCommand node does not exist in Docker n8n. \
             Import will fail with 'Unrecognized node type'",
        "Use SSH node (resource: command, operation: execute) or readWriteFile instead",
    )];

    for (invalid_type, message, suggestion) in &invalid_types {
        if node.type_str() == *invalid_type {
            findings.push(
                Finding::error("invalid-node-type", message)
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion(suggestion),
            );
        }
    }

    findings
}

/// Detect truncated JavaScript in Code nodes.
///
/// Checks for unbalanced braces, missing `return` statements, and code that
/// ends mid-token (e.g. inside a comment or string). A truncated Code node
/// will throw a `SyntaxError` at runtime, silently killing the workflow path.
#[must_use]
pub fn check_truncated_code(node: &Node) -> Vec<Finding> {
    if !node.is_code() {
        return vec![];
    }

    let Some(code) = node.param_str("jsCode") else {
        return vec![];
    };

    // Skip trivially short code (one-liners, stubs)
    if code.len() < 80 {
        return vec![];
    }

    let mut findings = vec![];

    // --- Check 1: Unbalanced braces ---
    // Walk the code tracking brace depth, ignoring braces inside strings and
    // comments. A net-positive depth at EOF means the code was cut off inside
    // a block.
    let depth = brace_depth(code);
    if depth > 0 {
        findings.push(
            Finding::error(
                "code-truncated",
                &format!(
                    "Code node appears truncated: {depth} unclosed brace(s) at end of code \
                     ({} chars). This will throw a SyntaxError at runtime.",
                    code.len()
                ),
            )
            .with_node(node.id_str(), node.name_str())
            .with_suggestion(
                "The jsCode was likely cut off during a workflow update. \
                 Compare against the working version or the source-of-truth \
                 and re-paste the full code.",
            ),
        );
    }

    // --- Check 2: Missing return statement ---
    // n8n Code nodes must return data. If the code has function-level logic
    // (loops, conditionals, variables) but no `return` keyword, it's either
    // truncated or broken.
    // Only count `return` that appears as actual code, not inside comments.
    let has_return = code.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with("//") && trimmed.contains("return ")
    });
    let has_logic = code.contains("for ") || code.contains("if (") || code.contains("const ");
    if has_logic && !has_return {
        findings.push(
            Finding::error(
                "code-truncated",
                &format!(
                    "Code node has logic but no return statement ({} chars). \
                     Likely truncated or incomplete.",
                    code.len()
                ),
            )
            .with_node(node.id_str(), node.name_str())
            .with_suggestion(
                "n8n Code nodes must return an array of items. \
                 Ensure the code ends with `return [{ json: ... }]`.",
            ),
        );
    }

    // --- Check 3: Ends inside a line comment ---
    // If the last non-whitespace line starts with `//` and doesn't look like
    // a closing comment (e.g. a section divider), the code was probably cut
    // mid-comment.
    let last_line = code.lines().rev().find(|l| !l.trim().is_empty());
    if let Some(line) = last_line {
        let trimmed = line.trim();
        // Ends mid-comment (not a section divider like "// ═══")
        let is_divider = trimmed.len() > 10
            && trimmed
                .chars()
                .skip(2)
                .all(|c| c == '=' || c == '-' || c == ' ' || c == '─' || c == '═');
        if trimmed.starts_with("//") && !is_divider && !trimmed.ends_with("*/") {
            // Only flag if the comment looks like it was cut mid-sentence
            // (doesn't end with punctuation)
            let comment_text = trimmed.trim_start_matches('/').trim();
            if !comment_text.is_empty()
                && !comment_text.ends_with('.')
                && !comment_text.ends_with(')')
                && !comment_text.ends_with('}')
                && !comment_text.ends_with(';')
            {
                findings.push(
                    Finding::warning(
                        "code-truncated",
                        &format!(
                            "Code node ends inside a comment: \"{}\" — may be truncated",
                            if trimmed.len() > 60 {
                                format!("{}...", &trimmed[..57])
                            } else {
                                trimmed.to_string()
                            }
                        ),
                    )
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion(
                        "Code appears to end mid-comment. Verify the full \
                         jsCode was saved during the last workflow update.",
                    ),
                );
            }
        }
    }

    findings
}

/// Count net unclosed braces in JavaScript code, skipping strings and comments.
fn brace_depth(code: &str) -> i32 {
    let mut depth: i32 = 0;
    let bytes = code.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let ch = bytes[i];

        // Skip single-line comments
        if ch == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Skip block comments
        if ch == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2; // skip */
            continue;
        }

        // Skip string literals (single, double, backtick)
        if ch == b'\'' || ch == b'"' || ch == b'`' {
            let quote = ch;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2; // skip escaped char
                    continue;
                }
                if bytes[i] == quote {
                    break;
                }
                i += 1;
            }
            i += 1; // skip closing quote
            continue;
        }

        // Skip regex literals (heuristic: after = or ( or , or ;)
        // This is imperfect but good enough for brace counting
        if ch == b'/' && i > 0 {
            let prev = find_prev_non_whitespace(bytes, i);
            if prev == Some(b'=')
                || prev == Some(b'(')
                || prev == Some(b',')
                || prev == Some(b';')
                || prev == Some(b':')
                || prev == Some(b'!')
                || prev == Some(b'&')
                || prev == Some(b'|')
                || prev == Some(b'{')
                || prev == Some(b'}')
                || prev == Some(b'[')
            {
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'/' {
                        break;
                    }
                    i += 1;
                }
                i += 1; // skip closing /
                // skip flags
                while i < len && bytes[i].is_ascii_alphabetic() {
                    i += 1;
                }
                continue;
            }
        }

        if ch == b'{' {
            depth += 1;
        } else if ch == b'}' {
            depth -= 1;
        }

        i += 1;
    }

    depth
}

/// Find the previous non-whitespace byte before position `pos`.
fn find_prev_non_whitespace(bytes: &[u8], pos: usize) -> Option<u8> {
    let mut j = pos;
    while j > 0 {
        j -= 1;
        if !bytes[j].is_ascii_whitespace() {
            return Some(bytes[j]);
        }
    }
    None
}

/// Run all code node rules
#[must_use]
pub fn check_all(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_forbidden_require(node));
    findings.extend(check_invalid_node_type(node));
    findings.extend(check_truncated_code(node));
    findings
}

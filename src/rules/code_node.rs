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

/// Run all code node rules
#[must_use]
pub fn check_all(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_forbidden_require(node));
    findings.extend(check_invalid_node_type(node));
    findings
}

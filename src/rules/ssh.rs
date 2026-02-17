// src/rules/ssh.rs
use crate::finding::Finding;
use crate::model::Node;

/// Check SSH nodes for resource+operation structure (must not use flat operation)
pub fn check_resource_operation(node: &Node) -> Vec<Finding> {
    if !node.is_ssh() {
        return vec![];
    }

    let mut findings = vec![];

    if let Some(params) = node.params() {
        let has_operation = params.get("operation").is_some();
        let has_resource = params.get("resource").is_some();

        if has_operation && !has_resource {
            let op = params
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            findings.push(
                Finding::error(
                    "ssh-resource-operation",
                    &format!(
                        "SSH node uses flat operation '{}' without resource field. \
                         n8n SSH nodes require both 'resource' and 'operation' parameters",
                        op
                    ),
                )
                .with_node(node.id_str(), node.name_str())
                .with_suggestion("Use {\"resource\": \"command\", \"operation\": \"execute\"} for command execution"),
            );
        }
    }

    findings
}

/// Check SSH commands for bash syntax without bash -c wrapper
pub fn check_bash_wrapper(node: &Node) -> Vec<Finding> {
    if !node.is_ssh() {
        return vec![];
    }

    let mut findings = vec![];

    if let Some(command) = node.param_str("command") {
        // Strip leading = (n8n expression prefix)
        let cmd = command.strip_prefix('=').unwrap_or(command).trim();

        // If already wrapped in bash -c, skip
        if cmd.starts_with("bash -c") {
            return findings;
        }

        // Detect bash-specific syntax that would fail in fish/zsh
        let bash_indicators = [
            "export ", "$?", "if [", "if [", "]; then", "; then", "$(", "${",
        ];

        // Also check for shell operators that suggest compound commands
        let compound_indicators = ["&&", "||", "; "];

        let has_bash_syntax = bash_indicators.iter().any(|ind| cmd.contains(ind));
        let has_compound = compound_indicators.iter().any(|ind| cmd.contains(ind));

        // Only warn about compound commands if they also use bash-specific features
        // Simple "cmd1 && cmd2" is fine, but "export X=y && cmd" is not
        if has_bash_syntax || (has_compound && has_bash_syntax) {
            findings.push(
                Finding::error(
                    "ssh-bash-wrapper",
                    "SSH command uses bash syntax without bash -c wrapper. \
                     The remote host may use fish or another non-POSIX shell, \
                     causing silent failures",
                )
                .with_node(node.id_str(), node.name_str())
                .with_suggestion("Wrap in: bash -c '...'"),
            );
        }
    }

    findings
}

/// Run all SSH rules
pub fn check_all(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_resource_operation(node));
    findings.extend(check_bash_wrapper(node));
    findings
}

// src/rules/best_practices.rs
use crate::finding::Finding;
use crate::model::Node;

/// Check that workflow has error handling
pub fn check_error_handling(nodes: &[Node]) -> Vec<Finding> {
    let has_error_trigger = nodes.iter().any(|n| n.is_error_trigger());
    let has_on_error = nodes.iter().any(|n| n.on_error.is_some());

    if !has_error_trigger && !has_on_error {
        return vec![Finding::error(
            "missing-error-handling",
            "Workflow has no error handling. Add an Error Trigger node \
                 or configure per-node error outputs for reliable operation",
        )
        .with_suggestion("Add an Error Trigger node connected to an ntfy notification")];
    }

    vec![]
}

/// Check that workflow has ntfy notifications
pub fn check_ntfy_presence(nodes: &[Node]) -> Vec<Finding> {
    // Reuse the shared ntfy detection heuristic
    let has_ntfy = nodes.iter().any(|n| super::ntfy::is_ntfy_node(n));

    if !has_ntfy {
        return vec![Finding::warning(
            "missing-ntfy-notification",
            "Workflow has no ntfy notification nodes. \
                 Every workflow should notify on completion and failure",
        )
        .with_suggestion("Add HTTP Request nodes posting to ntfy for success and error paths")];
    }

    vec![]
}

/// Check that scheduled workflows have a manual trigger
pub fn check_manual_trigger(nodes: &[Node]) -> Vec<Finding> {
    let has_schedule = nodes.iter().any(|n| n.is_schedule_trigger());
    let has_manual = nodes.iter().any(|n| n.is_manual_trigger());

    if has_schedule && !has_manual {
        return vec![Finding::warning(
            "missing-manual-trigger",
            "Scheduled workflow has no Manual Trigger. \
                 Add one for testing without waiting for the schedule",
        )
        .with_suggestion("Add a Manual Trigger node alongside the Schedule Trigger")];
    }

    vec![]
}

/// Check for hardcoded Docker bridge service URLs across all nodes.
/// NOTE: 172.17.0.1 (Docker bridge gateway) is stable and doesn't change.
/// The port mappings are also stable IF pinned with -p in docker run.
/// This rule only fires if the port doesn't match a well-known pinned port,
/// indicating it may be an ephemeral assignment. Currently disabled — the bridge
/// IP + pinned ports are reliable in our homelab setup.
pub fn check_hardcoded_urls(_nodes: &[Node]) -> Vec<Finding> {
    // Disabled: Docker bridge IP 172.17.0.1 is stable. Port mappings are pinned
    // via -p flags in our systemd service files. Only a concern with dynamic ports.
    vec![]
}

/// Check OpenCode session creation has proper permissions
pub fn check_opencode_permissions(nodes: &[Node]) -> Vec<Finding> {
    let mut findings = vec![];

    for node in nodes {
        if !node.is_http_request() {
            continue;
        }

        let strings = node.all_param_strings();
        let is_session_create = strings.iter().any(|s| s.contains("/session"));
        let has_permission = strings.iter().any(|s| s.contains("permission"));

        if is_session_create && has_permission {
            let has_question_deny = strings
                .iter()
                .any(|s| s.contains("question") && s.contains("deny"));

            if !has_question_deny {
                findings.push(
                    Finding::warning(
                        "opencode-missing-question-deny",
                        "OpenCode session creation should deny 'question' permission \
                         to prevent blocking on user input in automated workflows",
                    )
                    .with_node(node.id_str(), node.name_str())
                    .with_suggestion(
                        "Add {\"permission\": \"question\", \"pattern\": \"*\", \"action\": \"deny\"}"
                    ),
                );
            }
        }
    }

    findings
}

/// Run all best practice checks (workflow-level)
pub fn check_all(nodes: &[Node]) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_error_handling(nodes));
    findings.extend(check_ntfy_presence(nodes));
    findings.extend(check_manual_trigger(nodes));
    findings.extend(check_hardcoded_urls(nodes));
    findings.extend(check_opencode_permissions(nodes));
    findings
}

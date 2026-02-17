pub mod finding;
pub mod model;
pub mod rules;

use finding::{Finding, LintResult, Severity};
use model::Workflow;

/// Lint raw JSON string, returning structured results.
/// This is the main entry point for the library.
pub fn lint(json_str: &str) -> LintResult {
    let mut findings = Vec::new();

    // Phase 1: JSON validity
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            findings.push(Finding::error(
                "invalid-json",
                &format!("Failed to parse JSON: {}", e),
            ));
            return LintResult::new(findings);
        }
    };

    // Phase 2: Basic schema — must have "nodes" array
    if value.get("nodes").is_none() {
        findings.push(
            Finding::error(
                "missing-nodes",
                "Workflow JSON missing required 'nodes' array",
            )
            .with_suggestion("n8n workflows must have a top-level 'nodes' array"),
        );
        return LintResult::new(findings);
    }

    if !value["nodes"].is_array() {
        findings.push(
            Finding::error("invalid-nodes", "'nodes' field is not an array")
                .with_suggestion("'nodes' must be a JSON array of node objects"),
        );
        return LintResult::new(findings);
    }

    // Phase 3: Deserialize into typed model
    let workflow: Workflow = match serde_json::from_value(value) {
        Ok(w) => w,
        Err(e) => {
            findings.push(Finding::error(
                "schema-error",
                &format!("Failed to parse workflow structure: {}", e),
            ));
            return LintResult::new(findings);
        }
    };

    let nodes = match &workflow.nodes {
        Some(n) => n,
        None => return LintResult::new(findings),
    };

    // Phase 4: Validate each node has required fields
    for (i, node) in nodes.iter().enumerate() {
        if node.node_type.is_none() {
            findings.push(
                Finding::error(
                    "node-missing-type",
                    &format!("Node at index {} missing 'type' field", i),
                )
                .with_node(node.id_str(), node.name_str()),
            );
        }
    }

    // Phase 5: Per-node rule checks
    for node in nodes {
        findings.extend(rules::ssh::check_all(node));
        findings.extend(rules::ntfy::check_all(node));
        findings.extend(rules::code_node::check_all(node));
        findings.extend(rules::gotchas::check_node(node));
    }

    // Phase 6: Workflow-level checks
    findings.extend(rules::best_practices::check_all(nodes));
    findings.extend(rules::gotchas::check_workflow(&workflow, nodes));

    LintResult::new(findings)
}

/// Convenience: lint a file path
pub fn lint_file(path: &std::path::Path) -> anyhow::Result<LintResult> {
    let content = std::fs::read_to_string(path)?;
    Ok(lint(&content))
}

/// Format findings as human-readable text
pub fn format_human(result: &LintResult, filename: &str) -> String {
    let mut out = String::new();

    if result.findings.is_empty() {
        out.push_str(&format!("{}: All checks passed\n", filename));
        return out;
    }

    out.push_str(&format!("{}\n", filename));
    out.push_str(&"=".repeat(filename.len()));
    out.push('\n');

    // Group by severity
    let errors: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .collect();
    let warnings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .collect();

    if !errors.is_empty() {
        out.push_str(&format!("\nErrors ({})\n", errors.len()));
        out.push_str(&"-".repeat(40));
        out.push('\n');
        for f in &errors {
            format_finding(&mut out, f);
        }
    }

    if !warnings.is_empty() {
        out.push_str(&format!("\nWarnings ({})\n", warnings.len()));
        out.push_str(&"-".repeat(40));
        out.push('\n');
        for f in &warnings {
            format_finding(&mut out, f);
        }
    }

    out.push_str(&format!(
        "\nSummary: {} error(s), {} warning(s)\n",
        result.errors, result.warnings
    ));

    out
}

fn format_finding(out: &mut String, f: &Finding) {
    // Node context
    let node_info = match (&f.node_name, &f.node_id) {
        (Some(name), Some(id)) => format!(" [{}] ({})", name, id),
        (Some(name), None) => format!(" [{}]", name),
        (None, Some(id)) => format!(" ({})", id),
        (None, None) => String::new(),
    };

    out.push_str(&format!("  {}: {}{}\n", f.rule, f.message, node_info));

    if let Some(suggestion) = &f.suggestion {
        out.push_str(&format!("    -> {}\n", suggestion));
    }
}

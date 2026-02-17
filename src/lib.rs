pub mod finding;
pub mod model;
pub mod rules;

use std::fmt::Write;

use finding::{Finding, LintResult, Severity};
use model::Workflow;

/// Lint raw JSON string, returning structured results.
/// This is the main entry point for the library.
#[must_use]
pub fn lint(json_str: &str) -> LintResult {
    let mut findings = Vec::new();

    // Phase 1: JSON validity
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            findings.push(Finding::error(
                "invalid-json",
                &format!("Failed to parse JSON: {e}"),
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
                &format!("Failed to parse workflow structure: {e}"),
            ));
            return LintResult::new(findings);
        }
    };

    let Some(nodes) = &workflow.nodes else {
        return LintResult::new(findings);
    };

    // Phase 4: Validate each node has required fields
    for (i, node) in nodes.iter().enumerate() {
        if node.node_type.is_none() {
            findings.push(
                Finding::error(
                    "node-missing-type",
                    &format!("Node at index {i} missing 'type' field"),
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
        findings.extend(rules::extract_from_file::check_all(node));
        findings.extend(rules::gotchas::check_node(node));
    }

    // Phase 6: Workflow-level checks
    findings.extend(rules::best_practices::check_all(nodes));
    findings.extend(rules::gotchas::check_workflow(&workflow, nodes));

    LintResult::new(findings)
}

/// Convenience: lint a file path
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn lint_file(path: &std::path::Path) -> anyhow::Result<LintResult> {
    let content = std::fs::read_to_string(path)?;
    Ok(lint(&content))
}

/// Format findings as human-readable text
#[must_use]
pub fn format_human(result: &LintResult, filename: &str) -> String {
    let mut out = String::new();

    if result.findings.is_empty() {
        let _ = writeln!(out, "{filename}: All checks passed");
        return out;
    }

    let _ = writeln!(out, "{filename}");
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
        let _ = writeln!(out, "\nErrors ({})", errors.len());
        out.push_str(&"-".repeat(40));
        out.push('\n');
        for f in &errors {
            format_finding(&mut out, f);
        }
    }

    if !warnings.is_empty() {
        let _ = writeln!(out, "\nWarnings ({})", warnings.len());
        out.push_str(&"-".repeat(40));
        out.push('\n');
        for f in &warnings {
            format_finding(&mut out, f);
        }
    }

    let _ = writeln!(
        out,
        "\nSummary: {} error(s), {} warning(s)",
        result.errors, result.warnings
    );

    out
}

fn format_finding(out: &mut String, f: &Finding) {
    // Node context
    let node_info = match (&f.node_name, &f.node_id) {
        (Some(name), Some(id)) => format!(" [{name}] ({id})"),
        (Some(name), None) => format!(" [{name}]"),
        (None, Some(id)) => format!(" ({id})"),
        (None, None) => String::new(),
    };

    let _ = writeln!(out, "  {}: {}{}", f.rule, f.message, node_info);

    if let Some(suggestion) = &f.suggestion {
        let _ = writeln!(out, "    -> {suggestion}");
    }
}

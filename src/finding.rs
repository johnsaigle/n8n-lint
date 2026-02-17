// src/finding.rs
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl Finding {
    #[must_use]
    pub fn error(rule: &str, message: &str) -> Self {
        Self {
            rule: rule.to_string(),
            severity: Severity::Error,
            message: message.to_string(),
            node_id: None,
            node_name: None,
            suggestion: None,
        }
    }

    #[must_use]
    pub fn warning(rule: &str, message: &str) -> Self {
        Self {
            rule: rule.to_string(),
            severity: Severity::Warning,
            message: message.to_string(),
            node_id: None,
            node_name: None,
            suggestion: None,
        }
    }

    #[must_use]
    pub fn with_node(mut self, id: Option<&str>, name: Option<&str>) -> Self {
        self.node_id = id.map(std::string::ToString::to_string);
        self.node_name = name.map(std::string::ToString::to_string);
        self
    }

    #[must_use]
    pub fn with_suggestion(mut self, suggestion: &str) -> Self {
        self.suggestion = Some(suggestion.to_string());
        self
    }
}

#[derive(Debug, Serialize)]
pub struct LintResult {
    pub valid: bool,
    pub findings: Vec<Finding>,
    pub errors: usize,
    pub warnings: usize,
}

impl LintResult {
    #[must_use]
    pub fn new(findings: Vec<Finding>) -> Self {
        let errors = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warnings = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        Self {
            valid: errors == 0 && warnings == 0,
            findings,
            errors,
            warnings,
        }
    }
}

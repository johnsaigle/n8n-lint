// src/rules/extract_from_file.rs
use crate::finding::Finding;
use crate::model::Node;

/// Valid operation values for the extractFromFile node.
/// Source: n8n-nodes-base.extractFromFile node definition.
const VALID_OPERATIONS: &[&str] = &[
    "binaryToPropery",
    "csv",
    "html",
    "fromIcs",
    "fromJson",
    "ods",
    "pdf",
    "rtf",
    "text",
    "xls",
    "xlsx",
    "xml",
];

/// Common misspellings/confusions mapped to the correct operation value.
/// Each entry is (`wrong_value`, `correct_value`).
const FUZZY_MATCHES: &[(&str, &str)] = &[
    ("json", "fromJson"),
    ("fromjson", "fromJson"),
    ("ics", "fromIcs"),
    ("fromics", "fromIcs"),
    ("ical", "fromIcs"),
    ("fromical", "fromIcs"),
    ("binarytoproperty", "binaryToPropery"),
    ("binaryToPropery", "binaryToPropery"),
    ("binaryToProperty", "binaryToPropery"),
    ("binary", "binaryToPropery"),
    ("spreadsheet", "xlsx"),
    ("excel", "xlsx"),
    ("tsv", "csv"),
    ("richtext", "rtf"),
    ("rich_text", "rtf"),
];

/// Check that extractFromFile nodes use a known operation value.
#[must_use]
pub fn check_operation(node: &Node) -> Vec<Finding> {
    if !node.is_extract_from_file() {
        return vec![];
    }

    let mut findings = vec![];

    let Some(operation) = node.param_str("operation") else {
        findings.push(
            Finding::error(
                "extract-from-file-operation",
                "extractFromFile node is missing the 'operation' parameter",
            )
            .with_node(node.id_str(), node.name_str())
            .with_suggestion(&format!(
                "Add an 'operation' parameter with one of: {}",
                VALID_OPERATIONS.join(", ")
            )),
        );
        return findings;
    };

    if VALID_OPERATIONS.contains(&operation) {
        return findings;
    }

    // Not a valid operation — try fuzzy matching
    let suggestion = find_suggestion(operation);

    let message = format!(
        "Unknown extractFromFile operation \"{operation}\". \
         Valid operations are: {}",
        VALID_OPERATIONS.join(", ")
    );

    let mut finding = Finding::error("extract-from-file-operation", &message)
        .with_node(node.id_str(), node.name_str());

    if let Some(suggested) = suggestion {
        finding = finding.with_suggestion(&format!("Did you mean \"{suggested}\"?"));
    } else {
        finding = finding.with_suggestion(&format!("Use one of: {}", VALID_OPERATIONS.join(", ")));
    }

    findings.push(finding);
    findings
}

/// Try to find a likely intended operation for a misspelled value.
fn find_suggestion(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();

    // 1. Exact match in fuzzy table (case-insensitive)
    for &(wrong, correct) in FUZZY_MATCHES {
        if wrong.to_lowercase() == lower {
            return Some(correct);
        }
    }

    // 2. Check if input is a case-insensitive match to a valid operation
    for &valid in VALID_OPERATIONS {
        if valid.to_lowercase() == lower {
            return Some(valid);
        }
    }

    // 3. Substring match — if input is contained in a valid operation or vice versa
    for &valid in VALID_OPERATIONS {
        let valid_lower = valid.to_lowercase();
        if valid_lower.contains(&lower) || lower.contains(&valid_lower) {
            return Some(valid);
        }
    }

    None
}

/// Run all extractFromFile rules.
#[must_use]
pub fn check_all(node: &Node) -> Vec<Finding> {
    let mut findings = vec![];
    findings.extend(check_operation(node));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_json_to_from_json() {
        assert_eq!(find_suggestion("json"), Some("fromJson"));
    }

    #[test]
    fn fuzzy_ics_to_from_ics() {
        assert_eq!(find_suggestion("ics"), Some("fromIcs"));
    }

    #[test]
    fn fuzzy_case_insensitive_fromjson() {
        assert_eq!(find_suggestion("FROMJSON"), Some("fromJson"));
    }

    #[test]
    fn fuzzy_binary_to_property_typo() {
        assert_eq!(find_suggestion("binaryToProperty"), Some("binaryToPropery"));
    }

    #[test]
    fn fuzzy_excel_to_xlsx() {
        assert_eq!(find_suggestion("excel"), Some("xlsx"));
    }

    #[test]
    fn fuzzy_no_match_for_garbage() {
        assert_eq!(find_suggestion("notarealformat"), None);
    }

    #[test]
    fn fuzzy_case_insensitive_csv() {
        assert_eq!(find_suggestion("CSV"), Some("csv"));
    }

    #[test]
    fn fuzzy_ical_to_from_ics() {
        assert_eq!(find_suggestion("ical"), Some("fromIcs"));
    }
}

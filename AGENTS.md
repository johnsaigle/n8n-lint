# AGENTS.md - n8n-lint

Opinionated linter for n8n workflow JSON files. Pure Rust project (2024 edition) with no async runtime, minimal dependencies, and strict clippy enforcement.

## Build / Lint / Test Commands

```bash
cargo build                          # Debug build
cargo build --release                # Optimized release build (LTO, opt-level 3)
cargo test                           # Run all tests (unit + integration)
cargo test --verbose                 # Verbose test output
cargo test <test_name>               # Run a single test by name
cargo test ssh                       # Run all tests matching "ssh"
cargo clippy                         # Lint (warn mode)
cargo clippy -- -D warnings          # Lint strict (CI mode - warnings are errors)
cargo run -- <file.json>             # Run linter on a workflow file
cargo run -- -f json <file.json>     # Run linter with JSON output
```

CI runs three jobs on every push/PR: `cargo test --verbose`, `cargo clippy -- -D warnings`, and `cargo build --release`. All three must pass.

## Project Structure

```
src/
  main.rs              # CLI entry point (clap derive, exit codes)
  lib.rs               # Public API: lint(), lint_file(), format_human()
  model.rs             # Data structures: Workflow, Node (serde deserialization)
  finding.rs           # Finding, Severity, LintResult types
  rules/
    mod.rs             # Re-exports all rule modules
    ssh.rs             # SSH node validation (bash wrapper, resource/operation)
    ntfy.rs            # ntfy notification checks (auth, encoding, ports)
    code_node.rs       # Code node checks (forbidden require, invalid types)
    extract_from_file.rs  # extractFromFile operation validation with fuzzy match
    gotchas.rs         # Common gotchas (expressions, credentials, base64, etc.)
    best_practices.rs  # Workflow-level checks (error handling, triggers)
tests/
  integration.rs       # Integration tests
  fixtures/            # n8n workflow JSON fixtures (one per rule scenario)
```

## Architecture

Linting is multi-phase (`lib.rs`):
1. JSON validity check
2. Schema check (`nodes` field exists and is an array)
3. Typed deserialization into `Workflow`/`Node` structs
4. Per-node rule checks (ssh, ntfy, code_node, extract_from_file, gotchas)
5. Workflow-level rule checks (best_practices, gotchas)

Each rule module exposes a `check_all(&Node) -> Vec<Finding>` (or similar) entry point. Findings carry a rule ID, severity, message, optional node context, and optional suggestion.

## Code Style

### Formatting & Linting

- **rustfmt**: Default Rust formatting (no custom config).
- **clippy**: Strict lints enabled in `Cargo.toml` across all major categories: `complexity`, `correctness`, `nursery`, `pedantic`, `perf`, `suspicious` -- all at warn level. CI promotes warnings to errors with `-D warnings`.

### Naming Conventions

- `snake_case` for functions, variables, modules, and file names.
- `PascalCase` for structs, enums, and traits (`Finding`, `Severity`, `LintResult`).
- `SCREAMING_SNAKE_CASE` for constants.
- Rule IDs are kebab-case strings: `"ssh-bash-wrapper"`, `"ntfy-auth-header"`.

### Imports

- Group imports: `std` first, then external crates, then crate-internal modules.
- Use specific imports, not glob (`use serde::Serialize;` not `use serde::*;`).
- Re-export modules from `mod.rs` with `pub mod`.

### Types & Data Modeling

- All `Node` and `Workflow` fields are `Option<T>` to handle partial/malformed JSON gracefully.
- Use `#[serde(rename = "camelCase")]` to map JSON field names to Rust conventions.
- Use `#[serde(skip_serializing_if = "Option::is_none")]` to omit empty fields in JSON output.
- Prefer `serde_json::Value` for deeply nested or variable-shape parameter structures.

### Error Handling

- **JSON parse errors**: Caught with `match`, returned as `Finding` objects -- never panic.
- **File I/O errors**: Propagated via `anyhow::Result` up to the CLI.
- **Static regex patterns**: Compiled inline with `.unwrap()` (guaranteed valid at compile time).
- Use `if let Some(x) = ...` and pattern matching for safe Option/Result navigation.
- No `.unwrap()` on runtime data. Use `match`, `if let`, or `unwrap_or`/`unwrap_or_default`.

### Attributes & Annotations

- `#[must_use]` on all public functions that return values (especially `check_*` and builder methods).
- `#[derive(Debug, Clone, Serialize)]` on all public structs.
- `#[derive(Debug, Clone, PartialEq, Eq, Serialize)]` on enums used in comparisons.
- Doc comments (`///`) on all public items. Explain intent, not mechanics.

### Builder Pattern

`Finding` uses a chainable builder pattern:
```rust
Finding::error("rule-id", "message")
    .with_node(node.id_str(), node.name_str())
    .with_suggestion("Fix by doing X")
```
All builder methods consume and return `Self`, are `#[must_use]`.

### Severity Levels

- **Error**: Critical issues that should block workflow deployment (invalid syntax, missing auth, forbidden operations, dangerous patterns).
- **Warning**: Best practices or minor issues (missing error handling, hardcoded ports, cosmetic problems).

## Adding a New Rule

1. Create a new file in `src/rules/` or add to an existing module.
2. Write a `pub fn check_something(node: &Node) -> Vec<Finding>` function.
3. Mark it `#[must_use]`. Early-return `vec![]` if the node type doesn't match.
4. Wire it into the rule's `check_all()` function.
5. If it's a new module, add `pub mod new_module;` to `src/rules/mod.rs` and call it from `lib.rs`.
6. Add a fixture JSON in `tests/fixtures/` and an integration test in `tests/integration.rs`.

## Testing Conventions

- **Framework**: Built-in Rust `#[test]` macro. No external test framework.
- **Fixtures**: JSON files in `tests/fixtures/`, one per scenario. Load via:
  ```rust
  fn fixture(name: &str) -> PathBuf {
      PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
  }
  ```
- **Inline JSON**: Use `r#"..."#` raw strings for small test cases.
- **Test names**: `<rule_category>_<scenario>` (e.g., `ssh_bad_operation`, `ntfy_missing_auth`).
- **Assertions**: Filter findings by rule ID, then assert on count, severity, node context, and message content.
- **Section headers**: Tests are grouped with `// -- Section Name --` comment dividers.
- **Pattern** for a typical rule test:
  ```rust
  #[test]
  fn rule_name_scenario() {
      let result = n8n_lint::lint_file(&fixture("fixture-name.json")).unwrap();
      let findings: Vec<_> = result.findings.iter()
          .filter(|f| f.rule == "rule-id")
          .collect();
      assert!(!findings.is_empty(), "Expected rule-id finding");
      assert_eq!(findings[0].severity, Severity::Error);
  }
  ```
- **Unit tests**: Inline in source files under `#[cfg(test)] mod tests { ... }` for pure logic (e.g., fuzzy matching in `extract_from_file.rs`).

## Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON deserialization into typed structs |
| `regex` | Pattern matching in rule checks |
| `clap` (derive) | CLI argument parsing |
| `anyhow` | Error propagation in file I/O paths |

## Exit Codes

- `0` -- All checks passed.
- `1` -- Linting findings (errors or warnings) detected.
- `2` -- File I/O or JSON parse failure.

use clap::Parser;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "n8n-lint")]
#[command(about = "Opinionated linter for n8n workflow JSON files")]
#[command(version)]
struct Cli {
    /// Workflow JSON files to lint
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output format: human (default) or json
    #[arg(short, long, default_value = "human")]
    format: String,
}

fn main() {
    let cli = Cli::parse();

    let mut any_findings = false;
    let mut results = Vec::new();

    for path in &cli.files {
        if !path.exists() {
            eprintln!("Error: file not found: {}", path.display());
            process::exit(2);
        }

        match n8n_lint::lint_file(path) {
            Ok(result) => {
                if !result.valid {
                    any_findings = true;
                }
                results.push((path.clone(), result));
            }
            Err(e) => {
                eprintln!("Error reading {}: {}", path.display(), e);
                process::exit(2);
            }
        }
    }

    match cli.format.as_str() {
        "json" => {
            let json_results: Vec<_> = results
                .iter()
                .map(|(path, result)| {
                    serde_json::json!({
                        "file": path.display().to_string(),
                        "valid": result.valid,
                        "errors": result.errors,
                        "warnings": result.warnings,
                        "findings": result.findings,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_results).unwrap());
        }
        _ => {
            for (path, result) in &results {
                let filename = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |f| f.to_string_lossy().to_string(),
                );
                print!("{}", n8n_lint::format_human(result, &filename));
            }
        }
    }

    if any_findings {
        process::exit(1);
    }
}

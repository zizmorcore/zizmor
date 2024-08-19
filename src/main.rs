use std::{io::stdout, path::PathBuf};

use anyhow::{anyhow, Result};
use clap::Parser;
use models::AuditOptions;

mod audit;
mod finding;
mod models;

/// A tool to detect "ArtiPACKED"-type credential disclosures in GitHub Actions.
#[derive(Parser)]
struct Args {
    /// Emit findings even when the context suggests an explicit security decision made by the user.
    #[arg(short, long)]
    pedantic: bool,

    /// The workflow filename or directory to audit.
    input: PathBuf,
}

impl From<&Args> for AuditOptions {
    fn from(value: &Args) -> Self {
        Self {
            pedantic: value.pedantic,
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let options = AuditOptions::from(&args);

    let mut workflow_paths = vec![];
    if args.input.is_file() {
        workflow_paths.push(args.input);
    } else if args.input.is_dir() {
        let mut absolute = std::fs::canonicalize(args.input)?;
        if !absolute.ends_with(".github/workflows") {
            absolute.push(".github/workflows")
        }

        log::debug!("collecting workflows from {absolute:?}");

        for entry in std::fs::read_dir(absolute)? {
            let workflow_path = entry?.path();
            match workflow_path.extension() {
                Some(ext) if ext == "yml" || ext == "yaml" => workflow_paths.push(workflow_path),
                _ => continue,
            }
        }

        if workflow_paths.is_empty() {
            return Err(anyhow!(
                "no workflow files collected; empty or wrong directory?"
            ));
        }
    } else {
        return Err(anyhow!("input must be a single workflow file or directory"));
    }

    let mut findings = vec![];
    for workflow_path in workflow_paths.iter() {
        let workflow = models::Workflow::from_file(workflow_path)?;
        // TODO: Proper abstraction for multiple audits here.
        findings.extend(audit::artipacked::audit(&options, &workflow));
        findings.extend(audit::pull_request_target::audit(&options, &workflow));
    }

    if !findings.is_empty() {
        serde_json::to_writer_pretty(stdout(), &findings)?;
    }

    Ok(())
}

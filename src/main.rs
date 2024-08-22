use std::{path::PathBuf};

use anyhow::{anyhow, Result};
use audit::WorkflowAudit;
use clap::Parser;
use models::AuditConfig;
use serde_jsonlines::{AsyncJsonLinesWriter};

mod audit;
mod finding;
mod models;

/// A tool to detect "ArtiPACKED"-type credential disclosures in GitHub Actions.
#[derive(Parser)]
struct Args {
    /// Emit findings even when the context suggests an explicit security decision made by the user.
    #[arg(short, long)]
    pedantic: bool,

    /// The GitHub API token to use.
    #[arg(long, env)]
    gh_token: String,

    /// The workflow filename or directory to audit.
    input: PathBuf,
}

impl<'a> From<&'a Args> for AuditConfig<'a> {
    fn from(value: &'a Args) -> Self {
        Self {
            pedantic: value.pedantic,
            gh_token: &value.gh_token,
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let config = AuditConfig::from(&args);

    let mut workflow_paths = vec![];
    if args.input.is_file() {
        workflow_paths.push(args.input.clone());
    } else if args.input.is_dir() {
        let mut absolute = std::fs::canonicalize(&args.input)?;
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

    let mut writer = AsyncJsonLinesWriter::new(tokio::io::stdout());
    for workflow_path in workflow_paths.iter() {
        let workflow = models::Workflow::from_file(workflow_path)?;
        // TODO: Proper abstraction for multiple audits here.

        for result in audit::artipacked::Artipacked::new(config)?
            .audit(&workflow)
            .await?
        {
            writer.write(&result).await?;
        }

        for result in audit::pull_request_target::PullRequestTarget::new(config)?
            .audit(&workflow)
            .await?
        {
            writer.write(&result).await?;
        }

        for result in audit::impostor_commit::ImpostorCommit::new(config)?
            .audit(&workflow)
            .await?
        {
            writer.write(&result).await?;
        }
    }

    Ok(())
}

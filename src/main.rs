use std::{
    io::{stdout, IsTerminal},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use audit::WorkflowAudit;
use clap::{Parser, ValueEnum};
use registry::{AuditRegistry, WorkflowRegistry};

mod audit;
mod finding;
mod github_api;
mod models;
mod registry;
mod render;
mod sarif;
mod utils;

/// A tool to detect "ArtiPACKED"-type credential disclosures in GitHub Actions.
#[derive(Parser)]
struct Args {
    /// Emit findings even when the context suggests an explicit security decision made by the user.
    #[arg(short, long)]
    pedantic: bool,

    /// Only perform audits that don't require network access.
    #[arg(short, long)]
    offline: bool,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// The GitHub API token to use.
    #[arg(long, env)]
    gh_token: Option<String>,

    /// The output format to emit. By default, plain text will be emitted
    /// on an interactive terminal and JSON otherwise.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// The workflow filename or directory to audit.
    input: PathBuf,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub(crate) enum OutputFormat {
    Plain,
    Json,
    Sarif,
}

#[derive(Copy, Clone)]
pub(crate) struct AuditConfig<'a> {
    pub(crate) pedantic: bool,
    pub(crate) offline: bool,
    pub(crate) gh_token: Option<&'a str>,
}

impl<'a> From<&'a Args> for AuditConfig<'a> {
    fn from(value: &'a Args) -> Self {
        Self {
            pedantic: value.pedantic,
            offline: value.offline,
            gh_token: value.gh_token.as_deref(),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

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

    let mut workflow_registry = WorkflowRegistry::new();
    for workflow_path in workflow_paths.iter() {
        workflow_registry.register_workflow(workflow_path)?;
    }

    let mut audit_registry = AuditRegistry::new();

    macro_rules! register_audit {
        ($rule:path) => {{
            // HACK: https://github.com/rust-lang/rust/issues/48067
            use $rule as base;
            match base::new(config) {
                Ok(audit) => audit_registry.register_workflow_audit(base::ident(), Box::new(audit)),
                Err(e) => log::warn!("{audit} is being skipped: {e}", audit = base::ident()),
            }
        }};
    }

    register_audit!(audit::artipacked::Artipacked);
    register_audit!(audit::excessive_permissions::ExcessivePermissions);
    register_audit!(audit::pull_request_target::PullRequestTarget);
    register_audit!(audit::impostor_commit::ImpostorCommit);
    register_audit!(audit::ref_confusion::RefConfusion);
    register_audit!(audit::use_trusted_publishing::UseTrustedPublishing);
    register_audit!(audit::template_injection::TemplateInjection);
    register_audit!(audit::hardcoded_container_credentials::HardcodedContainerCredentials);

    let mut results = vec![];
    for (name, audit) in audit_registry.iter_workflow_audits() {
        for (_, workflow) in workflow_registry.iter_workflows() {
            log::info!(
                "performing {name} on {workflow}",
                workflow = &workflow.filename
            );
            results.extend(audit.audit(workflow)?);
            log::info!(
                "completed {name} on {workflow}",
                workflow = &workflow.filename
            );
        }
    }

    let format = match args.format {
        None => {
            if stdout().is_terminal() {
                OutputFormat::Plain
            } else {
                OutputFormat::Json
            }
        }
        Some(f) => f,
    };

    match format {
        OutputFormat::Plain => render::render_findings(&workflow_registry, &results),
        OutputFormat::Json => serde_json::to_writer_pretty(stdout(), &results)?,
        OutputFormat::Sarif => serde_json::to_writer_pretty(stdout(), &sarif::build(results))?,
    };
    Ok(())
}

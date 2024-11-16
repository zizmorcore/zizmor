use std::{io::stdout, path::PathBuf, process::ExitCode, time::Duration};

use anstream::eprintln;
use anyhow::{anyhow, Context, Result};
use audit::WorkflowAudit;
use clap::{Parser, ValueEnum};
use config::Config;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use owo_colors::OwoColorize;
use registry::{AuditRegistry, FindingRegistry, WorkflowRegistry};
use state::AuditState;

mod audit;
mod config;
mod expr;
mod finding;
mod github_api;
mod models;
mod registry;
mod render;
mod sarif;
mod state;
mod utils;

/// Finds security issues in GitHub Actions setups.
#[derive(Parser)]
#[command(about, version)]
struct App {
    /// Emit findings even when the context suggests an explicit security decision made by the user.
    #[arg(short, long)]
    pedantic: bool,

    /// Only perform audits that don't require network access.
    #[arg(short, long)]
    offline: bool,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// Disable the progress bar. This is useful primarily when running
    /// with a high verbosity level, as the two will fight for stderr.
    #[arg(short, long)]
    no_progress: bool,

    /// The GitHub API token to use.
    #[arg(long, env)]
    gh_token: Option<String>,

    /// The output format to emit. By default, plain text will be emitted
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// The configuration file to load. By default, any config will be
    /// discovered relative to $CWD.
    #[arg(short, long, group = "conf")]
    config: Option<PathBuf>,

    /// Disable all configuration loading.
    #[arg(long, group = "conf")]
    no_config: bool,

    /// Disable all error codes besides success and tool failure.
    #[arg(long)]
    no_exit_codes: bool,

    /// The workflow filenames or directories to audit.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub(crate) enum OutputFormat {
    Plain,
    Json,
    Sarif,
}

fn run() -> Result<ExitCode> {
    human_panic::setup_panic!();

    let args = App::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let mut workflow_paths = vec![];
    for input in &args.inputs {
        if input.is_file() {
            workflow_paths.push(input.clone());
        } else if input.is_dir() {
            let mut absolute = std::fs::canonicalize(input)?;
            if !absolute.ends_with(".github/workflows") {
                absolute.push(".github/workflows")
            }

            log::debug!("collecting workflows from {absolute:?}");

            for entry in std::fs::read_dir(absolute)? {
                let workflow_path = entry?.path();
                match workflow_path.extension() {
                    Some(ext) if ext == "yml" || ext == "yaml" => {
                        workflow_paths.push(workflow_path)
                    }
                    _ => continue,
                }
            }
        } else {
            return Err(anyhow!("input malformed, expected file or directory"));
        }
    }

    if workflow_paths.is_empty() {
        return Err(anyhow!(
            "no workflow files collected; empty or wrong directory?"
        ));
    }

    log::debug!(
        "collected workflows: {workflows:?}",
        workflows = workflow_paths
    );

    let config = Config::new(&args)?;
    let audit_state = AuditState::new(&args);

    let mut workflow_registry = WorkflowRegistry::new();
    for workflow_path in workflow_paths.iter() {
        workflow_registry
            .register_workflow(workflow_path)
            .with_context(|| "failed to register workflow")?;
    }

    let mut audit_registry = AuditRegistry::new();
    macro_rules! register_audit {
        ($rule:path) => {{
            // HACK: https://github.com/rust-lang/rust/issues/48067
            use $rule as base;
            match base::new(audit_state.clone()) {
                Ok(audit) => audit_registry.register_workflow_audit(base::ident(), Box::new(audit)),
                Err(e) => log::warn!("{audit} is being skipped: {e}", audit = base::ident()),
            }
        }};
    }

    register_audit!(audit::artipacked::Artipacked);
    register_audit!(audit::excessive_permissions::ExcessivePermissions);
    register_audit!(audit::dangerous_triggers::DangerousTriggers);
    register_audit!(audit::impostor_commit::ImpostorCommit);
    register_audit!(audit::ref_confusion::RefConfusion);
    register_audit!(audit::use_trusted_publishing::UseTrustedPublishing);
    register_audit!(audit::template_injection::TemplateInjection);
    register_audit!(audit::hardcoded_container_credentials::HardcodedContainerCredentials);
    register_audit!(audit::self_hosted_runner::SelfHostedRunner);
    register_audit!(audit::known_vulnerable_actions::KnownVulnerableActions);
    register_audit!(audit::unpinned_uses::UnpinnedUses);

    let bar = ProgressBar::new((workflow_registry.len() * audit_registry.len()) as u64);

    // Hide the bar if the user has explicitly asked for quiet output
    // or to disable just the progress bar.
    if args.verbose.is_silent() || args.no_progress {
        bar.set_draw_target(ProgressDrawTarget::hidden());
    } else {
        bar.enable_steady_tick(Duration::from_millis(100));
        bar.set_style(
            ProgressStyle::with_template("[{elapsed_precise}] {msg} {bar:!30.cyan/blue}").unwrap(),
        );
    }

    let mut results = FindingRegistry::new(&config);
    for (_, workflow) in workflow_registry.iter_workflows() {
        bar.set_message(format!(
            "auditing {workflow}",
            workflow = workflow.filename().cyan()
        ));
        for (name, audit) in audit_registry.iter_workflow_audits() {
            results.extend(audit.audit(workflow).with_context(|| {
                format!(
                    "{name} failed on {workflow}",
                    workflow = workflow.filename()
                )
            })?);
            bar.inc(1);
        }
        bar.println(format!(
            "🌈 completed {workflow}",
            workflow = &workflow.filename().cyan()
        ));
    }

    bar.finish_and_clear();

    let format = match args.format {
        None => OutputFormat::Plain,
        Some(f) => f,
    };

    match format {
        OutputFormat::Plain => render::render_findings(&workflow_registry, &results),
        OutputFormat::Json => serde_json::to_writer_pretty(stdout(), &results.findings())?,
        OutputFormat::Sarif => serde_json::to_writer_pretty(
            stdout(),
            &sarif::build(&workflow_registry, results.findings()),
        )?,
    };

    if args.no_exit_codes || matches!(format, OutputFormat::Sarif) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(results.into())
    }
}

fn main() -> ExitCode {
    // This is a little silly, but returning an ExitCode like this ensures
    // we always exit cleanly, rather than performing a hard process exit.
    match run() {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("{err:?}");
            ExitCode::FAILURE
        }
    }
}

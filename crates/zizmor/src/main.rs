#![warn(clippy::all, clippy::dbg_macro)]

use std::{
    io::{Write, stdout},
    process::ExitCode,
};

use annotate_snippets::{Group, Level, Renderer};
use anstream::{eprintln, println, stderr};
use anyhow::anyhow;
use clap::{CommandFactory as _, Parser as _};
use finding::{Confidence, Persona, Severity};
use futures::stream::{FuturesOrdered, StreamExt as _};
use indicatif::ProgressStyle;
use owo_colors::OwoColorize as _;
use registry::input::{InputKey, InputRegistry};
use registry::{AuditRegistry, FindingRegistry};
use state::AuditState;
use terminal_link::Link;
use thiserror::Error;
use tracing::{Span, info_span, instrument, warn};
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt as _};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::{
    audit::AuditError,
    cli::{
        App, CliConfidence, CliSeverity, CollectionModeSet, CollectionOptions, ColorMode,
        OutputFormat, completions,
    },
    config::{Config, ConfigError, ConfigErrorInner},
    github::Client,
    models::AsDocument as _,
    registry::input::CollectionError,
    utils::once::warn_once,
};

mod audit;
mod cli;
mod config;
mod finding;
mod github;
#[cfg(feature = "lsp")]
mod lsp;
mod models;
mod output;
mod registry;
mod state;
mod utils;

#[cfg(all(
    not(target_family = "windows"),
    not(target_os = "openbsd"),
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        // NOTE(ww): Not a build we currently support.
        // target_arch = "powerpc64"
    )
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// TODO: Dedupe this with the top-level `sponsors.json` used by the
// README + docs site.
const THANKS: &[(&str, &str)] = &[
    ("Grafana Labs", "https://grafana.com"),
    ("Kusari", "https://kusari.dev"),
];

#[instrument(skip_all)]
async fn collect_inputs(
    inputs: &[String],
    options: &CollectionOptions,
    gh_client: Option<&Client>,
) -> Result<InputRegistry, CollectionError> {
    let mut registry = InputRegistry::new();

    // TODO: use tokio's JoinSet?
    for input in inputs.iter() {
        registry.register_group(input, options, gh_client).await?;
    }

    if registry.len() == 0 {
        return Err(CollectionError::NoInputs);
    }

    Ok(registry)
}

/// Top-level errors.
#[derive(Debug, Error)]
enum Error {
    /// An error in global configuration.
    #[error(transparent)]
    GlobalConfig(#[from] ConfigError),
    /// An error while collecting inputs.
    #[error(transparent)]
    Collection(#[from] CollectionError),
    /// An error while running the LSP server.
    #[error(transparent)]
    Lsp(#[from] lsp::Error),
    /// An error from the GitHub API client.
    #[error(transparent)]
    Client(#[from] github::ClientError),
    /// An error while loading audit rules.
    #[error("failed to load audit rules")]
    AuditLoad(#[source] anyhow::Error),
    /// An error while running an audit.
    #[error("'{ident}' audit failed on {input}")]
    Audit {
        ident: &'static str,
        source: AuditError,
        input: String,
    },
    /// An error while rendering output.
    #[error("failed to render output")]
    Output(#[source] anyhow::Error),
    /// An error while performing fixes.
    #[error("failed to apply fixes")]
    Fix(#[source] anyhow::Error),
}

async fn run(app: &mut App) -> Result<ExitCode, Error> {
    #[cfg(feature = "lsp")]
    if app.args.lsp.lsp {
        lsp::run(lsp::LspOptions {
            persona: app.audit.persona,
        })
        .await?;
        return Ok(ExitCode::SUCCESS);
    }

    if app.args.thanks {
        println!("zizmor's development is sustained by our generous sponsors:");
        for (name, url) in THANKS {
            let link = Link::new(name, url);
            println!("🌈 {link}")
        }
        return Ok(ExitCode::SUCCESS);
    }

    #[cfg(feature = "schema")]
    if app.args.generate_schema {
        println!("{}", config::schema::generate_schema());
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(shell) = app.args.completions {
        let mut cmd = App::command();
        completions(shell, &mut cmd);
        return Ok(ExitCode::SUCCESS);
    }

    let color_mode = match app.output.color {
        Some(color_mode) => color_mode,
        None => {
            // If `--color` wasn't specified, we first check a handful
            // of common environment variables, and then fall
            // back to `anstream`'s auto detection.
            if std::env::var("NO_COLOR").is_ok() {
                ColorMode::Never
            } else if std::env::var("FORCE_COLOR").is_ok()
                || std::env::var("CLICOLOR_FORCE").is_ok()
                || utils::is_ci()
            {
                ColorMode::Always
            } else {
                ColorMode::Auto
            }
        }
    };

    anstream::ColorChoice::write_global(color_mode.into());

    // Disable progress bars if colorized output is disabled.
    // We do this because `anstream` and `tracing_indicatif` don't
    // compose perfectly: `anstream` wants to strip all ANSI escapes,
    // while `tracing_indicatif` needs line control to render progress bars.
    // TODO: In the future, perhaps we could make these work together.
    //
    // Also, we disable progress bars if stderr is not a terminal.
    // Technically indicatif does this for us, but tracing_indicatif
    // surfaces a bug when multiple spans are active and the
    // output is not a terminal.
    // See: https://github.com/emersonford/tracing-indicatif/issues/24
    if matches!(color_mode, ColorMode::Never) || !stderr().is_terminal() {
        app.output.no_progress = true;
    }

    // `--pedantic` is a shortcut for `--persona=pedantic`.
    if app.audit.pedantic {
        app.audit.persona = Persona::Pedantic;
    }

    // Merge `--github-token` or `--zizmor-github-token` into `--gh-token`, if present.
    // TODO: Should probably be an `app.network.gh_token()` call or something.
    app.network.gh_token = app
        .network
        .gh_token
        .take()
        .or(app.network.github_token.take())
        .or(app.network.zizmor_github_token.take());

    // Unset the GitHub token if we're in offline mode.
    // We do this manually instead of with clap's `conflicts_with` because
    // we want to support explicitly enabling offline mode while still
    // having `GH_TOKEN` present in the environment.
    if app.network.offline {
        app.network.gh_token = None;
    }

    let indicatif_layer = IndicatifLayer::new();

    let writer = std::sync::Mutex::new(anstream::AutoStream::new(
        Box::new(indicatif_layer.get_stderr_writer()) as Box<dyn Write + Send>,
        color_mode.color_choice_for_terminal(std::io::stderr()),
    ));

    let filter = EnvFilter::builder()
        .with_default_directive(app.output.verbose.tracing_level_filter().into())
        .from_env()
        .expect("failed to parse RUST_LOG");

    // HACK: The current alpha release of http-cache (via http-cache-reqwest)
    // emits a lot of noisy WARN-level logs about invalid cache entries
    // due to their bincode -> postcard migration. These aren't actionable for us.
    #[allow(clippy::unwrap_used)]
    let filter = filter.add_directive("http_cache::managers::cacache=error".parse().unwrap());

    let reg = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                // NOTE: We don't need `with_ansi` here since our writer is
                // an `anstream::AutoStream` that handles color output for us.
                .with_writer(writer),
        )
        .with(filter);

    if app.output.no_progress {
        reg.init();
    } else {
        reg.with(indicatif_layer).init();
    }

    tracing::info!("🌈 zizmor v{version}", version = env!("CARGO_PKG_VERSION"));

    // Validate stdin input constraints: `-` must be the only input,
    // and cannot be combined with `--fix`.
    if app.input.inputs.iter().any(|i| i == "-") {
        if app.input.inputs.len() > 1 {
            let mut cmd = App::command();
            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "`-` (stdin) cannot be combined with other inputs",
            )
            .exit();
        }

        if app.audit.fix.is_some() {
            let mut cmd = App::command();
            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "`--fix` cannot be used with `-` (stdin)",
            )
            .exit();
        }
    }

    let collection_mode_set = CollectionModeSet::from(app.input.collect.as_slice());

    let min_severity = match app.audit.min_severity {
        Some(CliSeverity::Unknown) => {
            tracing::warn!("`unknown` is a deprecated minimum severity that has no effect");
            tracing::warn!("future versions of zizmor will reject this value");
            None
        }
        Some(CliSeverity::Informational) => Some(Severity::Informational),
        Some(CliSeverity::Low) => Some(Severity::Low),
        Some(CliSeverity::Medium) => Some(Severity::Medium),
        Some(CliSeverity::High) => Some(Severity::High),
        None => None,
    };

    let min_confidence = match app.audit.min_confidence {
        Some(CliConfidence::Unknown) => {
            tracing::warn!("`unknown` is a deprecated minimum confidence that has no effect");
            tracing::warn!("future versions of zizmor will reject this value");
            None
        }
        Some(CliConfidence::Low) => Some(Confidence::Low),
        Some(CliConfidence::Medium) => Some(Confidence::Medium),
        Some(CliConfidence::High) => Some(Confidence::High),
        None => None,
    };

    let global_config = Config::global(app)?;

    let gh_client = app
        .network
        .gh_token
        .as_ref()
        .map(|token| Client::new(&app.network.gh_hostname, token, &app.network.cache_dir))
        .transpose()?;

    let collection_options = CollectionOptions {
        mode_set: collection_mode_set,
        strict: app.input.strict_collection,
        no_config: app.args.no_config,
        global_config,
    };

    let registry = collect_inputs(
        app.input.inputs.as_slice(),
        &collection_options,
        gh_client.as_ref(),
    )
    .await?;

    let state = AuditState::new(app.network.no_online_audits, gh_client);

    let audit_registry = AuditRegistry::default_audits(&state).map_err(Error::AuditLoad)?;

    let mut results = FindingRegistry::new(
        &registry,
        min_severity,
        min_confidence,
        app.audit.persona,
        app.audit.no_ignores,
    );
    {
        // Note: block here so that we drop the span here at the right time.
        let span = info_span!("audit");
        span.pb_set_length((registry.len() * audit_registry.len()) as u64);
        span.pb_set_style(
            &ProgressStyle::with_template("[{elapsed_precise}] {bar:!30.cyan/blue} {msg}")
                .expect("couldn't set progress bar style"),
        );

        let _guard = span.enter();

        // zizmor's default behavior is to run in offline mode, unless the user explicitly
        // provides a GitHub API token. This snares some users, particularly if they're used
        // to the zizmor-action default (which is flipped, since GHA always has a token).
        //
        // See: <https://github.com/zizmorcore/zizmor/issues/2178>
        //
        // Note: This check only fires if the user explicitly passes `--offline`, since by
        // default `offline` is false (purely as a clap parsing artifact). This is confusing
        // and should be cleaned up by pushing all of this into `AuditState` for normalization.
        if app.network.offline {
            warn!(
                "zizmor is running in offline mode by default; some audits and auto-fixes will not be available. see https://docs.zizmor.sh/usage/#operating-modes for details"
            );
        }

        for (input_key, input) in registry.iter_inputs() {
            Span::current().pb_set_message(input.key().filename());

            if input.as_document().has_anchors() {
                warn_once!(
                    "one or more inputs contains YAML anchors; see https://docs.zizmor.sh/usage/#yaml-anchors for details"
                );
            }

            let mut completion_stream = FuturesOrdered::new();
            let config = registry.get_config(input_key.group());
            for (ident, audit) in audit_registry.iter_audits() {
                tracing::debug!("scheduling {ident} on {input}", input = input.key());

                completion_stream.push_back(audit.audit(ident, input, config));
            }

            while let Some(findings) = completion_stream.next().await {
                let findings = findings.map_err(|err| Error::Audit {
                    ident: err.ident(),
                    source: err,
                    input: input.key().to_string(),
                })?;

                results.extend(findings);

                Span::current().pb_inc(1);
            }

            tracing::info!(
                "🌈 completed {input}",
                input = input.key().presentation_path()
            );
        }
    }

    match app.output.format {
        OutputFormat::Plain => output::plain::render_findings(
            &registry,
            &results,
            &app.output.show_audit_urls.into(),
            &app.output.render_links.into(),
            app.output.naches,
        ),
        OutputFormat::Json | OutputFormat::JsonV1 => {
            output::json::v1::output(stdout(), results.findings()).map_err(Error::Output)?
        }
        OutputFormat::Sarif => {
            serde_json::to_writer_pretty(stdout(), &output::sarif::build(results.findings()))
                .map_err(|err| Error::Output(anyhow!(err)))?
        }
        OutputFormat::Github => {
            output::github::output(stdout(), results.findings()).map_err(Error::Output)?
        }
    };

    let all_fixed = if let Some(fix_mode) = app.audit.fix {
        let fix_result =
            output::fix::apply_fixes(fix_mode, &results, &registry).map_err(Error::Fix)?;

        // If all findings have applicable fixes and all were successfully applied,
        // we should exit with success.
        results.all_findings_have_applicable_fixes(fix_mode)
            && fix_result.failed_count == 0
            && fix_result.applied_count > 0
    } else {
        false
    };

    if app.output.no_exit_codes || matches!(app.output.format, OutputFormat::Sarif) {
        Ok(ExitCode::SUCCESS)
    } else if all_fixed {
        // All findings were auto-fixed, no manual intervention needed
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(results.exit_code())
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    human_panic::setup_panic!();

    let mut app = App::parse();

    // This is a little silly, but returning an ExitCode like this ensures
    // we always exit cleanly, rather than performing a hard process exit.
    match run(&mut app).await {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!(
                "{fatal}: no audit was performed",
                fatal = "fatal".red().bold()
            );

            let report = match &err {
                // NOTE(ww): Slightly annoying that we have two different config error
                // wrapper states, but oh well.
                Error::GlobalConfig(err) | Error::Collection(CollectionError::Config(err)) => {
                    let mut group = Group::with_title(Level::ERROR.primary_title(err.to_string()));

                    match err.source {
                        ConfigErrorInner::Syntax(_) => {
                            group = group.elements([
                                Level::HELP
                                    .message("check your configuration file for syntax errors"),
                                Level::HELP.message("see: https://docs.zizmor.sh/configuration/"),
                            ]);
                        }
                        ConfigErrorInner::AuditSyntax(_, ident) => {
                            group = group.elements([
                                Level::HELP.message(format!(
                                    "check the configuration for the '{ident}' rule"
                                )),
                                Level::HELP.message(format!(
                                    "see: https://docs.zizmor.sh/audits/#{ident}-configuration"
                                )),
                            ]);
                        }
                        _ => {}
                    }

                    let renderer = Renderer::styled();
                    let report = renderer.render(&[group]);

                    Some(report)
                }
                Error::Collection(err) => match err.inner() {
                    CollectionError::NoInputs => {
                        let group = Group::with_title(Level::ERROR.primary_title(err.to_string()))
                            .element(Level::HELP.message("collection yielded no auditable inputs"))
                            .element(Level::HELP.message("inputs must contain at least one valid workflow, action, or Dependabot config"));

                        let renderer = Renderer::styled();
                        let report = renderer.render(&[group]);

                        Some(report)
                    }
                    CollectionError::DuplicateInput(..) => {
                        let group = Group::with_title(Level::ERROR.primary_title(err.to_string()))
                            .element(Level::HELP.message(format!(
                                "valid inputs are files, directories, GitHub {slug} slugs, or {stdin} for stdin",
                                slug = "user/repo[@ref]".green(),
                                stdin = "-".green()
                            )))
                            .element(Level::HELP.message(format!(
                                "examples: {ex1}, {ex2}, {ex3}, {ex4}, or {ex5}",
                                ex1 = "path/to/workflow.yml".green(),
                                ex2 = ".github/".green(),
                                ex3 = "example/example".green(),
                                ex4 = "example/example@v1.2.3".green(),
                                ex5 = "-".green()
                            )));

                        let renderer = Renderer::styled();
                        let report = renderer.render(&[group]);

                        Some(report)
                    }
                    CollectionError::NoGitHubClient(..) => {
                        let mut group =
                            Group::with_title(Level::ERROR.primary_title(err.to_string()));

                        if app.network.offline {
                            group = group.elements([Level::HELP
                                .message("remove --offline to audit remote repositories")]);
                        } else if app.network.gh_token.is_none() {
                            group = group.elements([Level::HELP
                                .message("set a GitHub token with --gh-token or GH_TOKEN")]);
                        }

                        let renderer = Renderer::styled();
                        let report = renderer.render(&[group]);

                        Some(report)
                    }
                    // These errors only happen if something is wrong with zizmor itself.
                    CollectionError::Yamlpath(..) | CollectionError::Model(..) => {
                        let group = Group::with_title(Level::ERROR.primary_title(err.to_string())).elements([
                            Level::HELP.message("this typically indicates a bug in zizmor; please report it"),
                            Level::HELP.message(
                                "https://github.com/zizmorcore/zizmor/issues/new?template=bug-report.yml",
                            ),
                        ]);
                        let renderer = Renderer::styled();
                        let report = renderer.render(&[group]);

                        Some(report)
                    }
                    CollectionError::RemoteWithoutWorkflows(_, slug) => {
                        let group = Group::with_title(Level::ERROR.primary_title(err.to_string()))
                            .elements([
                                Level::HELP.message(
                                    format!(
                                        "ensure that {slug} contains one or more workflows under `.github/workflows/`"
                                    )
                                ),
                                Level::HELP.message(
                                    format!("ensure that {slug} exists and you have access to it")
                                )
                            ]);

                        let renderer = Renderer::styled();
                        let report = renderer.render(&[group]);

                        Some(report)
                    }
                    _ => None,
                },
                _ => None,
            };

            let exit = if matches!(err, Error::Collection(CollectionError::NoInputs)) {
                ExitCode::from(3)
            } else {
                ExitCode::FAILURE
            };

            let mut err = anyhow!(err);
            if let Some(report) = report {
                err = err.context(report);
            }

            eprintln!("{err:?}");

            exit
        }
    }
}

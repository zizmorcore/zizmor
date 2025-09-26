#![warn(clippy::all, clippy::dbg_macro)]

use std::{
    io::{Write, stdout},
    process::ExitCode,
};

use annotate_snippets::{Group, Level, Renderer};
use anstream::{eprintln, println, stream::IsTerminal};
use anyhow::anyhow;
use camino::Utf8PathBuf;
use clap::{Args, CommandFactory, Parser, ValueEnum, builder::NonEmptyStringValueParser};
use clap_complete::Generator;
use clap_verbosity_flag::InfoLevel;
use etcetera::AppStrategy as _;
use finding::{Confidence, Persona, Severity};
use github_api::{GitHubHost, GitHubToken};
use indicatif::ProgressStyle;
use owo_colors::OwoColorize;
use registry::input::{InputKey, InputRegistry};
use registry::{AuditRegistry, FindingRegistry};
use state::AuditState;
use terminal_link::Link;
use thiserror::Error;
use tracing::{Span, info_span, instrument};
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::{
    config::{Config, ConfigError, ConfigErrorInner},
    github_api::Client,
    registry::input::CollectionError,
};

mod audit;
mod config;
mod finding;
mod github_api;
#[cfg(feature = "lsp")]
mod lsp;
mod models;
mod output;
mod registry;
mod state;
mod utils;

// TODO: Dedupe this with the top-level `sponsors.json` used by the
// README + docs site.
const THANKS: &[(&str, &str)] = &[("Grafana Labs", "https://grafana.com")];

/// Finds security issues in GitHub Actions setups.
#[derive(Parser)]
#[command(about, version)]
struct App {
    #[cfg(feature = "lsp")]
    #[command(flatten)]
    lsp: LspArgs,

    /// Emit 'pedantic' findings.
    ///
    /// This is an alias for --persona=pedantic.
    #[arg(short, long, group = "_persona")]
    pedantic: bool,

    /// The persona to use while auditing.
    #[arg(long, group = "_persona", value_enum, default_value_t)]
    persona: Persona,

    /// Perform only offline operations.
    ///
    /// This disables all online audit rules, and prevents zizmor from
    /// auditing remote repositories.
    #[arg(short, long, env = "ZIZMOR_OFFLINE")]
    offline: bool,

    /// The GitHub API token to use.
    #[arg(long, env, value_parser = GitHubToken::new)]
    gh_token: Option<GitHubToken>,

    /// The GitHub Server Hostname. Defaults to github.com
    #[arg(long, env = "GH_HOST", default_value_t)]
    gh_hostname: GitHubHost,

    /// Perform only offline audits.
    ///
    /// This is a weaker version of `--offline`: instead of completely
    /// forbidding all online operations, it only disables audits that
    /// require connectivity.
    #[arg(long, env = "ZIZMOR_NO_ONLINE_AUDITS")]
    no_online_audits: bool,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity<InfoLevel>,

    /// Don't show progress bars, even if the terminal supports them.
    #[arg(long)]
    no_progress: bool,

    /// The output format to emit. By default, cargo-style diagnostics will be emitted.
    #[arg(long, value_enum, default_value_t)]
    format: OutputFormat,

    /// Control the use of color in output.
    #[arg(long, value_enum, value_name = "MODE")]
    color: Option<ColorMode>,

    /// The configuration file to load.
    /// This loads a single configuration file across all input groups,
    /// which may not be what you intend.
    #[arg(
        short,
        long,
        env = "ZIZMOR_CONFIG",
        group = "conf",
        value_parser = NonEmptyStringValueParser::new()
    )]
    config: Option<String>,

    /// Disable all configuration loading.
    #[arg(long, group = "conf")]
    no_config: bool,

    /// Disable all error codes besides success and tool failure.
    #[arg(long)]
    no_exit_codes: bool,

    /// Filter all results below this severity.
    #[arg(long)]
    min_severity: Option<CliSeverity>,

    /// Filter all results below this confidence.
    #[arg(long)]
    min_confidence: Option<CliConfidence>,

    /// The directory to use for HTTP caching. By default, a
    /// host-appropriate user-caching directory will be used.
    #[arg(long, default_value_t = App::default_cache_dir(), hide_default_value = true)]
    cache_dir: Utf8PathBuf,

    /// Control which kinds of inputs are collected for auditing.
    ///
    /// By default, all workflows and composite actions are collected,
    /// while honoring `.gitignore` files.
    #[arg(long, value_enum, default_value_t)]
    collect: CollectionMode,

    /// Fail instead of warning on syntax and schema errors
    /// in collected inputs.
    #[arg(long)]
    strict_collection: bool,

    /// Generate tab completion scripts for the specified shell.
    #[arg(long, value_enum, value_name = "SHELL", exclusive = true)]
    completions: Option<Shell>,

    /// Enable naches mode.
    #[arg(long, hide = true, env = "ZIZMOR_NACHES")]
    naches: bool,

    /// Fix findings automatically, when available (EXPERIMENTAL).
    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        // NOTE: These attributes are needed to make `--fix` behave as the
        // default for `--fix=safe`. Unlike other flags we don't support
        // `--fix safe`, since `clap` can't disambiguate that.
        num_args=0..=1,
        require_equals = true,
        default_missing_value = "safe",
    )]
    fix: Option<FixMode>,

    /// Emit thank-you messages for zizmor's sponsors.
    #[arg(long, exclusive = true)]
    thanks: bool,

    /// The inputs to audit.
    ///
    /// These can be individual workflow filenames, action definitions
    /// (typically `action.yml`), entire directories, or a `user/repo` slug
    /// for a GitHub repository. In the latter case, a `@ref` can be appended
    /// to audit the repository at a particular git reference state.
    #[arg(required = true)]
    inputs: Vec<String>,
}

impl App {
    fn default_cache_dir() -> Utf8PathBuf {
        etcetera::choose_app_strategy(etcetera::AppStrategyArgs {
            top_level_domain: "io.github".into(),
            author: "woodruffw".into(),
            app_name: "zizmor".into(),
        })
        .expect("failed to determine default cache directory")
        .cache_dir()
        .try_into()
        .expect("failed to turn cache directory into a sane path")
    }
}

// NOTE(ww): This can be removed once `--min-severity=unknown`
// is fully removed.
#[derive(Debug, Copy, Clone, ValueEnum)]
enum CliSeverity {
    Unknown,
    Informational,
    Low,
    Medium,
    High,
}

// NOTE(ww): This can be removed once `--min-confidence=unknown`
// is fully removed.
#[derive(Debug, Copy, Clone, ValueEnum)]
enum CliConfidence {
    Unknown,
    Low,
    Medium,
    High,
}

#[cfg(feature = "lsp")]
#[derive(Args)]
#[group(multiple = true, conflicts_with = "inputs")]
struct LspArgs {
    /// Run in language server mode (EXPERIMENTAL).
    ///
    /// This flag cannot be used with any other flags.
    #[arg(long)]
    lsp: bool,

    // This flag exists solely because VS Code's LSP client implementation
    // insists on appending `--stdio` to the LSP server's arguments when
    // using the 'stdio' transport. It has no actual meaning or use.
    // See: <https://github.com/microsoft/vscode-languageserver-node/issues/1222
    #[arg(long, hide = true)]
    stdio: bool,
}

/// Shell with auto-generated completion script available.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ValueEnum)]
#[allow(clippy::enum_variant_names)]
enum Shell {
    /// Bourne Again `SHell` (bash)
    Bash,
    /// Elvish shell
    Elvish,
    /// Friendly Interactive `SHell` (fish)
    Fish,
    /// Nushell
    Nushell,
    /// `PowerShell`
    Powershell,
    /// Z `SHell` (zsh)
    Zsh,
}

impl Generator for Shell {
    fn file_name(&self, name: &str) -> String {
        match self {
            Shell::Bash => clap_complete::shells::Bash.file_name(name),
            Shell::Elvish => clap_complete::shells::Elvish.file_name(name),
            Shell::Fish => clap_complete::shells::Fish.file_name(name),
            Shell::Nushell => clap_complete_nushell::Nushell.file_name(name),
            Shell::Powershell => clap_complete::shells::PowerShell.file_name(name),
            Shell::Zsh => clap_complete::shells::Zsh.file_name(name),
        }
    }

    fn generate(&self, cmd: &clap::Command, buf: &mut dyn std::io::Write) {
        match self {
            Shell::Bash => clap_complete::shells::Bash.generate(cmd, buf),
            Shell::Elvish => clap_complete::shells::Elvish.generate(cmd, buf),
            Shell::Fish => clap_complete::shells::Fish.generate(cmd, buf),
            Shell::Nushell => clap_complete_nushell::Nushell.generate(cmd, buf),
            Shell::Powershell => clap_complete::shells::PowerShell.generate(cmd, buf),
            Shell::Zsh => clap_complete::shells::Zsh.generate(cmd, buf),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, ValueEnum)]
pub(crate) enum OutputFormat {
    /// cargo-style output.
    #[default]
    Plain,
    // NOTE: clap doesn't support visible aliases for enum variants yet,
    // so we need an explicit Json variant here.
    // See: https://github.com/clap-rs/clap/pull/5480
    /// JSON-formatted output (currently v1).
    Json,
    /// "v1" JSON format.
    JsonV1,
    /// SARIF-formatted output.
    Sarif,
    /// GitHub Actions workflow command-formatted output.
    Github,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub(crate) enum ColorMode {
    /// Use color output if the output supports it.
    Auto,
    /// Force color output, even if the output isn't a terminal.
    Always,
    /// Disable color output, even if the output is a compatible terminal.
    Never,
}

impl ColorMode {
    /// Returns a concrete (i.e. non-auto) `anstream::ColorChoice` for the given terminal.
    ///
    /// This is useful for passing to `anstream::AutoStream` when the underlying
    /// stream is something that is a terminal or should be treated as such,
    /// but can't be inferred due to type erasure (e.g. `Box<dyn Write>`).
    fn color_choice_for_terminal(&self, io: impl IsTerminal) -> anstream::ColorChoice {
        match self {
            ColorMode::Auto => {
                if io.is_terminal() {
                    anstream::ColorChoice::Always
                } else {
                    anstream::ColorChoice::Never
                }
            }
            ColorMode::Always => anstream::ColorChoice::Always,
            ColorMode::Never => anstream::ColorChoice::Never,
        }
    }
}

impl From<ColorMode> for anstream::ColorChoice {
    /// Maps `ColorMode` to `anstream::ColorChoice`.
    fn from(value: ColorMode) -> Self {
        match value {
            ColorMode::Auto => Self::Auto,
            ColorMode::Always => Self::Always,
            ColorMode::Never => Self::Never,
        }
    }
}

/// How `zizmor` collects inputs from local and remote repository sources.
#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub(crate) enum CollectionMode {
    /// Collect all possible inputs, ignoring `.gitignore` files.
    All,
    /// Collect all possible inputs, respecting `.gitignore` files.
    #[default]
    Default,
    /// Collect only workflow definitions.
    WorkflowsOnly,
    /// Collect only action definitions (i.e. `action.yml`).
    ActionsOnly,
}

impl CollectionMode {
    pub(crate) fn respects_gitignore(&self) -> bool {
        matches!(
            self,
            CollectionMode::Default | CollectionMode::WorkflowsOnly | CollectionMode::ActionsOnly
        )
    }

    pub(crate) fn workflows(&self) -> bool {
        matches!(
            self,
            CollectionMode::All | CollectionMode::Default | CollectionMode::WorkflowsOnly
        )
    }

    pub(crate) fn actions(&self) -> bool {
        matches!(
            self,
            CollectionMode::All | CollectionMode::Default | CollectionMode::ActionsOnly
        )
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum FixMode {
    /// Apply only safe fixes (the default).
    Safe,
    /// Apply only unsafe fixes.
    UnsafeOnly,
    /// Apply all fixes, both safe and unsafe.
    All,
}

pub(crate) fn tips(err: impl AsRef<str>, tips: &[impl AsRef<str>]) -> String {
    // NOTE: We use secondary_title here because primary_title doesn't
    // allow ANSI colors, and some of our errors contain colorized text.
    let report = vec![
        Group::with_title(Level::ERROR.secondary_title(err.as_ref()))
            .elements(tips.iter().map(|tip| Level::HELP.message(tip.as_ref()))),
    ];

    let renderer = Renderer::styled();
    renderer.render(&report).to_string()
}

/// State used when collecting input groups.
pub(crate) struct CollectionOptions {
    pub(crate) mode: CollectionMode,
    pub(crate) strict: bool,
    pub(crate) no_config: bool,
    /// Global configuration, if any.
    pub(crate) global_config: Option<Config>,
}

#[instrument(skip_all)]
fn collect_inputs(
    inputs: &[String],
    options: &CollectionOptions,
    gh_client: Option<&Client>,
) -> Result<InputRegistry, CollectionError> {
    let mut registry = InputRegistry::new();

    for input in inputs.iter() {
        registry.register_group(input, options, gh_client)?;
    }

    if registry.len() == 0 {
        return Err(CollectionError::NoInputs);
    }

    Ok(registry)
}

fn completions<G: clap_complete::Generator>(generator: G, cmd: &mut clap::Command) {
    clap_complete::generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut std::io::stdout(),
    );
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
    Client(#[from] github_api::ClientError),
    /// An error while loading audit rules.
    #[error("failed to load audit rules")]
    AuditLoad(#[source] anyhow::Error),
    /// An error while running an audit.
    #[error("{ident} failed on {input}")]
    Audit {
        source: anyhow::Error,
        ident: &'static str,
        input: String,
    },
    /// An error while rendering output.
    #[error("failed to render output")]
    Output(#[source] anyhow::Error),
    /// An error while performing fixes.
    #[error("failed to apply fixes")]
    Fix(#[source] anyhow::Error),
}

fn run(app: &mut App) -> Result<ExitCode, Error> {
    #[cfg(feature = "lsp")]
    if app.lsp.lsp {
        lsp::run()?;
        return Ok(ExitCode::SUCCESS);
    }

    if app.thanks {
        println!("zizmor's development is sustained by our generous sponsors:");
        for (name, url) in THANKS {
            let link = Link::new(name, url);
            println!("🌈 {link}")
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(shell) = app.completions {
        let mut cmd = App::command();
        completions(shell, &mut cmd);
        return Ok(ExitCode::SUCCESS);
    }

    let color_mode = match app.color {
        Some(color_mode) => color_mode,
        None => {
            // If `--color` wasn't specified, we first check a handful
            // of common environment variables, and then fall
            // back to `anstream`'s auto detection.
            if std::env::var("NO_COLOR").is_ok() {
                ColorMode::Never
            } else if std::env::var("FORCE_COLOR").is_ok()
                || std::env::var("CLICOLOR_FORCE").is_ok()
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
    if matches!(color_mode, ColorMode::Never) {
        app.no_progress = true;
    }

    // `--pedantic` is a shortcut for `--persona=pedantic`.
    if app.pedantic {
        app.persona = Persona::Pedantic;
    }

    // Unset the GitHub token if we're in offline mode.
    // We do this manually instead of with clap's `conflicts_with` because
    // we want to support explicitly enabling offline mode while still
    // having `GH_TOKEN` present in the environment.
    if app.offline {
        app.gh_token = None;
    }

    let indicatif_layer = IndicatifLayer::new();

    let writer = std::sync::Mutex::new(anstream::AutoStream::new(
        Box::new(indicatif_layer.get_stderr_writer()) as Box<dyn Write + Send>,
        color_mode.color_choice_for_terminal(std::io::stderr()),
    ));

    let filter = EnvFilter::builder()
        .with_default_directive(app.verbose.tracing_level_filter().into())
        .from_env()
        .expect("failed to parse RUST_LOG");

    let reg = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                // NOTE: We don't need `with_ansi` here since our writer is
                // an `anstream::AutoStream` that handles color output for us.
                .with_writer(writer),
        )
        .with(filter);

    if app.no_progress {
        reg.init();
    } else {
        reg.with(indicatif_layer).init();
    }

    let min_severity = match app.min_severity {
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

    let min_confidence = match app.min_confidence {
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
        .gh_token
        .as_ref()
        .map(|token| Client::new(&app.gh_hostname, token, &app.cache_dir))
        .transpose()?;

    let collection_options = CollectionOptions {
        mode: app.collect,
        strict: app.strict_collection,
        no_config: app.no_config,
        global_config,
    };

    let registry = collect_inputs(
        app.inputs.as_slice(),
        &collection_options,
        gh_client.as_ref(),
    )?;

    let state = AuditState::new(app.no_online_audits, gh_client);

    let audit_registry = AuditRegistry::default_audits(&state).map_err(Error::AuditLoad)?;

    let mut results = FindingRegistry::new(&registry, min_severity, min_confidence, app.persona);
    {
        // Note: block here so that we drop the span here at the right time.
        let span = info_span!("audit");
        span.pb_set_length((registry.len() * audit_registry.len()) as u64);
        span.pb_set_style(
            &ProgressStyle::with_template("[{elapsed_precise}] {bar:!30.cyan/blue} {msg}").unwrap(),
        );

        let _guard = span.enter();

        for (input_key, input) in registry.iter_inputs() {
            Span::current().pb_set_message(input.key().filename());
            let config = registry.get_config(input_key.group());
            for (ident, audit) in audit_registry.iter_audits() {
                tracing::debug!("running {ident} on {input}", input = input.key());

                results.extend(
                    audit
                        .audit(ident, input, config)
                        .map_err(|err| Error::Audit {
                            source: err,
                            ident,
                            input: input.key().to_string(),
                        })?,
                );

                Span::current().pb_inc(1);
            }
            tracing::info!(
                "🌈 completed {input}",
                input = input.key().presentation_path()
            );
        }
    }

    match app.format {
        OutputFormat::Plain => output::plain::render_findings(&registry, &results, app.naches),
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

    if let Some(fix_mode) = app.fix {
        output::fix::apply_fixes(fix_mode, &results, &registry).map_err(Error::Fix)?;
    }

    if app.no_exit_codes || matches!(app.format, OutputFormat::Sarif) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(results.exit_code())
    }
}

fn main() -> ExitCode {
    human_panic::setup_panic!();

    let mut app = App::parse();

    // This is a little silly, but returning an ExitCode like this ensures
    // we always exit cleanly, rather than performing a hard process exit.
    match run(&mut app) {
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
                                    "check the configuration for the '{ident}' rule",
                                    ident = ident
                                )),
                                Level::HELP.message(format!(
                                    "see: https://docs.zizmor.sh/audits/#{ident}-configuration",
                                    ident = ident
                                )),
                            ]);
                        }
                        _ => {}
                    }

                    let renderer = Renderer::styled();
                    let report = renderer.render(&[group]);

                    Some(report)
                }
                Error::Collection(err @ CollectionError::InvalidInput(..)) => {
                    let group = Group::with_title(Level::ERROR.primary_title(err.to_string()))
                        .element(Level::HELP.message(format!(
                            "valid inputs are files, directories, or GitHub {slug} slugs",
                            slug = "user/repo[@ref]".green()
                        )))
                        .element(Level::HELP.message(format!(
                            "examples: {ex1}, {ex2}, {ex3}, or {ex4}",
                            ex1 = "path/to/workflow.yml".green(),
                            ex2 = ".github/".green(),
                            ex3 = "example/example".green(),
                            ex4 = "example/example@v1.2.3".green()
                        )));

                    let renderer = Renderer::styled();
                    let report = renderer.render(&[group]);

                    Some(report)
                }
                Error::Collection(err @ CollectionError::NoGitHubClient(_)) => {
                    let mut group = Group::with_title(Level::ERROR.primary_title(err.to_string()));

                    if app.offline {
                        group = group
                            .elements([Level::HELP
                                .message("remove --offline to audit remote repositories")]);
                    } else if app.gh_token.is_none() {
                        group = group
                            .elements([Level::HELP
                                .message("set a GitHub token with --gh-token or GH_TOKEN")]);
                    }

                    let renderer = Renderer::styled();
                    let report = renderer.render(&[group]);

                    Some(report)
                }
                Error::Collection(err @ CollectionError::Yamlpath(_)) => {
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
                _ => None,
            };

            let mut err = anyhow!(err);
            if let Some(report) = report {
                err = err.context(report);
            }

            eprintln!("{err:?}");
            ExitCode::FAILURE
        }
    }
}

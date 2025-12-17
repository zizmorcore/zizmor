#![warn(clippy::all, clippy::dbg_macro)]

use std::{
    collections::HashSet,
    env,
    io::{Write, stdout},
    process::ExitCode,
};

use annotate_snippets::{Group, Level, Renderer};
use anstream::{eprintln, println, stderr, stream::IsTerminal};
use anyhow::anyhow;
use camino::Utf8PathBuf;
use clap::{Args, CommandFactory, Parser, ValueEnum, builder::NonEmptyStringValueParser};
use clap_complete::Generator;
use clap_verbosity_flag::InfoLevel;
use etcetera::AppStrategy as _;
use finding::{Confidence, Persona, Severity};
use futures::stream::{FuturesOrdered, StreamExt};
use github::{GitHubHost, GitHubToken};
use indicatif::ProgressStyle;
use owo_colors::OwoColorize;
use registry::input::{InputKey, InputRegistry};
use registry::{AuditRegistry, FindingRegistry};
use state::AuditState;
use terminal_link::Link;
use thiserror::Error;
use tracing::{Span, info_span, instrument, warn};
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::{
    audit::AuditError,
    config::{Config, ConfigError, ConfigErrorInner},
    github::Client,
    models::AsDocument,
    registry::input::CollectionError,
    utils::once::warn_once,
};

mod audit;
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

    /// Whether to render OSC 8 links in the output.
    ///
    /// This affects links under audit IDs, as well as any links
    /// produced by audit rules.
    ///
    /// Only affects `--format=plain` (the default).
    #[arg(long, value_enum, default_value_t, env = "ZIZMOR_RENDER_LINKS")]
    render_links: CliRenderLinks,

    /// Whether to render audit URLs in the output, separately from any URLs
    /// embedded in OSC 8 links.
    ///
    /// Only affects `--format=plain` (the default).
    #[arg(long, value_enum, default_value_t, env = "ZIZMOR_SHOW_AUDIT_URLS")]
    show_audit_urls: CliShowAuditUrls,

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
    #[arg(long, default_values = ["default"], num_args=1.., value_delimiter=',')]
    collect: Vec<CliCollectionMode>,

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
    #[value(hide = true)]
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
    #[value(hide = true)]
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

#[derive(Debug, Default, Copy, Clone, ValueEnum)]
pub(crate) enum CliRenderLinks {
    /// Render OSC 8 links in output if support is detected.
    #[default]
    Auto,
    /// Always render OSC 8 links in output.
    Always,
    /// Never render OSC 8 links in output.
    Never,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum RenderLinks {
    Always,
    Never,
}

impl From<CliRenderLinks> for RenderLinks {
    fn from(value: CliRenderLinks) -> Self {
        match value {
            CliRenderLinks::Auto => {
                // We render links if stdout is a terminal. This is assumed
                // to preclude CI environments and log files.
                //
                // TODO: Switch this to the support-hyperlinks crate?
                // See: https://github.com/zkat/supports-hyperlinks/pull/8
                if stdout().is_terminal() {
                    RenderLinks::Always
                } else {
                    RenderLinks::Never
                }
            }
            CliRenderLinks::Always => RenderLinks::Always,
            CliRenderLinks::Never => RenderLinks::Never,
        }
    }
}

#[derive(Debug, Default, Copy, Clone, ValueEnum)]
pub(crate) enum CliShowAuditUrls {
    /// Render audit URLs in output automatically based on output format and runtime context.
    ///
    /// For example, URLs will be shown if a CI runtime is detected.
    #[default]
    Auto,
    /// Always render audit URLs in output.
    Always,
    /// Never render audit URLs in output.
    Never,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum ShowAuditUrls {
    Always,
    Never,
}

impl From<CliShowAuditUrls> for ShowAuditUrls {
    fn from(value: CliShowAuditUrls) -> Self {
        match value {
            CliShowAuditUrls::Auto => {
                if utils::is_ci() || !stdout().is_terminal() {
                    ShowAuditUrls::Always
                } else {
                    ShowAuditUrls::Never
                }
            }
            CliShowAuditUrls::Always => ShowAuditUrls::Always,
            CliShowAuditUrls::Never => ShowAuditUrls::Never,
        }
    }
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
#[derive(Copy, Clone, Debug, Default, ValueEnum, Eq, PartialEq, Hash)]
pub(crate) enum CliCollectionMode {
    /// Collect all possible inputs, ignoring `.gitignore` files.
    All,
    /// Collect all possible inputs, respecting `.gitignore` files.
    #[default]
    Default,
    /// Collect only workflow definitions.
    ///
    /// Deprecated; use `--collect=workflows`
    #[value(hide = true)]
    WorkflowsOnly,
    /// Collect only action definitions (i.e. `action.yml`).
    ///
    /// Deprecated; use `--collect=actions`
    #[value(hide = true)]
    ActionsOnly,
    /// Collect workflows.
    Workflows,
    /// Collect action definitions (i.e. `action.yml`).
    Actions,
    /// Collect Dependabot configuration files (i.e. `dependabot.yml`).
    Dependabot,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum CollectionMode {
    All,
    Default,
    Workflows,
    Actions,
    Dependabot,
}

pub(crate) struct CollectionModeSet(HashSet<CollectionMode>);

impl From<&[CliCollectionMode]> for CollectionModeSet {
    fn from(modes: &[CliCollectionMode]) -> Self {
        if modes.len() > 1
            && modes.iter().any(|mode| {
                matches!(
                    mode,
                    CliCollectionMode::WorkflowsOnly | CliCollectionMode::ActionsOnly
                )
            })
        {
            let mut cmd = App::command();

            cmd.error(
                clap::error::ErrorKind::ArgumentConflict,
                "`workflows-only` and `actions-only` cannot be combined with other collection modes",
            )
            .exit();
        }

        Self(
            modes
                .iter()
                .map(|mode| match mode {
                    CliCollectionMode::All => CollectionMode::All,
                    CliCollectionMode::Default => CollectionMode::Default,
                    CliCollectionMode::WorkflowsOnly => {
                        warn!("--collect=workflows-only is deprecated; use --collect=workflows instead");
                        warn!("future versions of zizmor will reject this mode");

                        CollectionMode::Workflows
                    }
                    CliCollectionMode::ActionsOnly => {
                        warn!("--collect=actions-only is deprecated; use --collect=actions instead");
                        warn!("future versions of zizmor will reject this mode");

                        CollectionMode::Actions
                    }
                    CliCollectionMode::Workflows => CollectionMode::Workflows,
                    CliCollectionMode::Actions => CollectionMode::Actions,
                    CliCollectionMode::Dependabot => CollectionMode::Dependabot,
                })
                .collect(),
        )
    }
}

impl CollectionModeSet {
    /// Does our collection mode respect `.gitignore` files?
    pub(crate) fn respects_gitignore(&self) -> bool {
        // All modes except 'all' respect .gitignore files.
        !self.0.contains(&CollectionMode::All)
    }

    /// Should we collect workflows?
    pub(crate) fn workflows(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::Workflows
            )
        })
    }

    /// Should we collect *only* workflows?
    pub(crate) fn workflows_only(&self) -> bool {
        self.0.len() == 1 && self.0.contains(&CollectionMode::Workflows)
    }

    /// Should we collect actions?
    pub(crate) fn actions(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::Actions
            )
        })
    }

    /// Should we collect Dependabot configuration files?
    pub(crate) fn dependabot(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::Dependabot
            )
        })
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

/// State used when collecting input groups.
pub(crate) struct CollectionOptions {
    pub(crate) mode_set: CollectionModeSet,
    pub(crate) strict: bool,
    pub(crate) no_config: bool,
    /// Global configuration, if any.
    pub(crate) global_config: Option<Config>,
}

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
    if app.lsp.lsp {
        lsp::run().await?;
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

    eprintln!("🌈 zizmor v{version}", version = env!("CARGO_PKG_VERSION"));

    let collection_mode_set = CollectionModeSet::from(app.collect.as_slice());

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
        mode_set: collection_mode_set,
        strict: app.strict_collection,
        no_config: app.no_config,
        global_config,
    };

    let registry = collect_inputs(
        app.inputs.as_slice(),
        &collection_options,
        gh_client.as_ref(),
    )
    .await?;

    let state = AuditState::new(app.no_online_audits, gh_client);

    let audit_registry = AuditRegistry::default_audits(&state).map_err(Error::AuditLoad)?;

    let mut results = FindingRegistry::new(&registry, min_severity, min_confidence, app.persona);
    {
        // Note: block here so that we drop the span here at the right time.
        let span = info_span!("audit");
        span.pb_set_length((registry.len() * audit_registry.len()) as u64);
        span.pb_set_style(
            &ProgressStyle::with_template("[{elapsed_precise}] {bar:!30.cyan/blue} {msg}")
                .expect("couldn't set progress bar style"),
        );

        let _guard = span.enter();

        for (input_key, input) in registry.iter_inputs() {
            Span::current().pb_set_message(input.key().filename());

            if input.as_document().has_anchors() {
                warn_once!(
                    "one or more inputs contains YAML anchors; you may encounter crashes or unpredictable behavior"
                );
                warn_once!("for more information, see: https://docs.zizmor.sh/usage/#yaml-anchors");
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

    match app.format {
        OutputFormat::Plain => output::plain::render_findings(
            &registry,
            &results,
            &app.show_audit_urls.into(),
            &app.render_links.into(),
            app.naches,
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

    let all_fixed = if let Some(fix_mode) = app.fix {
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

    if app.no_exit_codes || matches!(app.format, OutputFormat::Sarif) {
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
    // NOTE: We only use human-panic on non-CI environments.
    // This is because human-panic's output gets sent to a temporary file,
    // which is then typically inaccessible from an already failed
    // CI job. In those cases, it's better to dump directly to stderr,
    // since that'll typically be captured by console logging.
    if utils::is_ci() {
        std::panic::set_hook(Box::new(|info| {
            let trace = std::backtrace::Backtrace::force_capture();
            eprintln!("FATAL: zizmor crashed. This is a bug that should be reported.");
            eprintln!(
                "Please report to: {repo}",
                repo = env!("CARGO_PKG_REPOSITORY")
            );
            eprintln!("Panic information:\n{}", info);
            eprintln!("Backtrace:\n{}", trace);
        }));
    } else {
        human_panic::setup_panic!();
    }

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
                    CollectionError::NoGitHubClient(..) => {
                        let mut group =
                            Group::with_title(Level::ERROR.primary_title(err.to_string()));

                        if app.offline {
                            group = group.elements([Level::HELP
                                .message("remove --offline to audit remote repositories")]);
                        } else if app.gh_token.is_none() {
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

            let mut err = anyhow!(err);
            if let Some(report) = report {
                err = err.context(report);
            }

            eprintln!("{err:?}");
            ExitCode::FAILURE
        }
    }
}

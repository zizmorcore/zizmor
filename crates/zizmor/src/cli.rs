use std::collections::HashSet;
use std::fmt;
use std::io::stdout;

use annotate_snippets::renderer::{AnsiColor, Effects};
use anstream::stream::IsTerminal;
use camino::Utf8PathBuf;
use clap::builder::{NonEmptyStringValueParser, Styles};
use clap::{ArgAction, Args, CommandFactory as _, Parser, ValueEnum, ValueHint};
use clap_complete::Generator;
use clap_verbosity_flag::InfoLevel;
use etcetera::AppStrategy as _;
use tracing::warn;

use crate::config::Config;
use crate::finding::Persona;
use crate::github::{GitHubHost, GitHubToken};
use crate::utils;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

/// Finds security issues in GitHub Actions setups.
#[derive(Debug, Parser)]
#[command(about, version, styles = STYLES)]
#[command(disable_help_flag = true, disable_version_flag = true)]
#[command(next_display_order = 1)]
pub(crate) struct App {
    #[command(flatten)]
    pub(crate) input: InputArgs,

    #[command(flatten)]
    pub(crate) audit: AuditArgs,

    #[command(flatten)]
    pub(crate) output: OutputArgs,

    #[command(flatten)]
    pub(crate) network: NetworkArgs,

    #[command(flatten)]
    pub(crate) args: GlobalArgs,
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

#[derive(Debug, Args)]
#[command(next_help_heading = "Input Options")]
pub(crate) struct InputArgs {
    /// The inputs to audit.
    ///
    /// These can be individual workflow filenames, action definitions
    /// (typically `action.yml`), entire directories, or a `user/repo` slug
    /// for a GitHub repository. In the latter case, a `@ref` can be appended
    /// to audit the repository at a particular git reference state.
    ///
    /// Use `-` to read a single input from stdin.
    #[arg(required = true, value_name = "INPUT", display_order = 0)]
    pub(crate) inputs: Vec<String>,

    /// Control which kinds of inputs are collected for auditing.
    ///
    /// By default, all workflows and composite actions are collected,
    /// while honoring `.gitignore` files.
    #[arg(long, default_values = ["default"], num_args=1.., value_delimiter=',', value_name = "KIND")]
    pub(crate) collect: Vec<CliCollectionMode>,

    /// Fail instead of warning on syntax and schema errors
    /// in collected inputs.
    #[arg(long)]
    pub(crate) strict_collection: bool,
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Audit Options")]
pub(crate) struct AuditArgs {
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
    pub(crate) fix: Option<FixMode>,

    /// Emit 'pedantic' findings.
    ///
    /// This is an alias for --persona=pedantic.
    #[arg(short, long, group = "_persona")]
    pub(crate) pedantic: bool,

    /// The persona to use while auditing.
    #[arg(long, group = "_persona", value_enum, default_value_t)]
    pub(crate) persona: Persona,

    /// Filter all results below this severity.
    #[arg(long, value_name = "LEVEL")]
    pub(crate) min_severity: Option<CliSeverity>,

    /// Filter all results below this confidence.
    #[arg(long, value_name = "LEVEL")]
    pub(crate) min_confidence: Option<CliConfidence>,

    /// Don't honor ignore comments or ignore rules in configuration.
    #[arg(long)]
    pub(crate) no_ignores: bool,
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Output Options")]
pub(crate) struct OutputArgs {
    #[command(flatten)]
    pub(crate) verbose: clap_verbosity_flag::Verbosity<InfoLevel>,

    /// The output format to emit. By default, cargo-style diagnostics will be emitted.
    #[arg(long, value_enum, default_value_t, value_name = "KIND")]
    pub(crate) format: OutputFormat,

    /// Don't show progress bars, even if the terminal supports them.
    #[arg(long)]
    pub(crate) no_progress: bool,

    /// Control the use of color in output.
    #[arg(long, value_enum, value_name = "WHEN")]
    pub(crate) color: Option<ColorMode>,

    /// Whether to render OSC 8 links in the output.
    ///
    /// This affects links under audit IDs, as well as any links
    /// produced by audit rules.
    ///
    /// Only affects `--format=plain` (the default).
    #[arg(
        long,
        value_enum,
        default_value_t,
        env = "ZIZMOR_RENDER_LINKS",
        value_name = "WHEN"
    )]
    pub(crate) render_links: CliRenderLinks,

    /// Whether to render audit URLs in the output, separately from any URLs
    /// embedded in OSC 8 links.
    ///
    /// Only affects `--format=plain` (the default).
    #[arg(
        long,
        value_enum,
        default_value_t,
        env = "ZIZMOR_SHOW_AUDIT_URLS",
        value_name = "WHEN"
    )]
    pub(crate) show_audit_urls: CliShowAuditUrls,

    /// Disable all error codes besides success and tool failure.
    #[arg(long)]
    pub(crate) no_exit_codes: bool,

    /// Enable naches mode.
    #[arg(long, hide = true, env = "ZIZMOR_NACHES")]
    pub(crate) naches: bool,
}

#[derive(Args, Debug)]
#[command(next_help_heading = "Network Options")]
pub(crate) struct NetworkArgs {
    /// Perform only offline operations.
    ///
    /// This disables all online audit rules, and prevents zizmor from
    /// auditing remote repositories.
    #[arg(short, long, env = "ZIZMOR_OFFLINE")]
    pub(crate) offline: bool,

    /// The GitHub API token to use [env: GH_TOKEN or GITHUB_TOKEN or ZIZMOR_GITHUB_TOKEN]
    #[arg(long, env, hide_env = true, value_parser = GitHubToken::new)]
    pub(crate) gh_token: Option<GitHubToken>,

    /// This is an alias for `--gh-token` / `GH_TOKEN`.
    #[arg(long, env, hide = true, value_parser = GitHubToken::new)]
    pub(crate) github_token: Option<GitHubToken>,

    /// This is an alias for `--gh-token` / `GH_TOKEN` / `--github-token` / `GITHUB_TOKEN`
    #[arg(long, env, hide = true, value_parser = GitHubToken::new)]
    pub(crate) zizmor_github_token: Option<GitHubToken>,

    /// The GitHub Server Hostname. Defaults to github.com
    #[arg(long, env = "GH_HOST", default_value_t)]
    pub(crate) gh_hostname: GitHubHost,

    /// Perform only offline audits.
    ///
    /// This is a weaker version of `--offline`: instead of completely
    /// forbidding all online operations, it only disables audits that
    /// require connectivity.
    #[arg(long, env = "ZIZMOR_NO_ONLINE_AUDITS")]
    pub(crate) no_online_audits: bool,

    /// The directory to use for HTTP caching. By default, a
    /// host-appropriate user-caching directory will be used.
    #[arg(
        long,
        value_name = "DIR",
        default_value_t = App::default_cache_dir(),
        hide_default_value = true,
        value_hint = ValueHint::DirPath
    )]
    pub(crate) cache_dir: Utf8PathBuf,
}

#[derive(Args, Debug)]
#[command(next_help_heading = "Options")]
pub(crate) struct GlobalArgs {
    #[cfg(feature = "lsp")]
    #[command(flatten)]
    pub(crate) lsp: LspArgs,

    /// The configuration file to load.
    /// This loads a single configuration file across all input groups,
    /// which may not be what you intend.
    #[arg(
        short,
        long,
        value_name = "FILE",
        env = "ZIZMOR_CONFIG",
        group = "conf",
        value_parser = NonEmptyStringValueParser::new(),
        value_hint = ValueHint::FilePath
    )]
    pub(crate) config: Option<String>,

    /// Disable all configuration loading.
    #[arg(long, group = "conf")]
    pub(crate) no_config: bool,

    /// Generate tab completion scripts for the specified shell.
    #[arg(long, value_enum, value_name = "SHELL", exclusive = true)]
    pub(crate) completions: Option<Shell>,

    /// Generate JSON Schema for zizmor.yml configuration files.
    #[cfg(feature = "schema")]
    #[arg(long, exclusive = true)]
    pub(crate) generate_schema: bool,

    /// Emit thank-you messages for zizmor's sponsors.
    #[arg(long, exclusive = true)]
    pub(crate) thanks: bool,

    /// Print help.
    #[arg(
        short,
        long,
        help = "Print help (see more with '--help')",
        long_help = "Print help (see a summary with '-h')",
        action = ArgAction::Help
    )]
    pub(crate) help: (),

    /// Print version.
    #[arg(short = 'V', long, action = ArgAction::Version)]
    pub(crate) version: (),
}

// NOTE(ww): This can be removed once `--min-severity=unknown`
// is fully removed.
#[derive(Debug, Copy, Clone, ValueEnum)]
pub(crate) enum CliSeverity {
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
pub(crate) enum CliConfidence {
    #[value(hide = true)]
    Unknown,
    Low,
    Medium,
    High,
}

#[cfg(feature = "lsp")]
#[derive(Args, Debug)]
#[group(multiple = true, conflicts_with = "inputs")]
pub(crate) struct LspArgs {
    /// Run in language server mode (EXPERIMENTAL).
    ///
    /// This flag cannot be used with any other flags.
    #[arg(long)]
    pub(crate) lsp: bool,

    // This flag exists solely because VS Code's LSP client implementation
    // insists on appending `--stdio` to the LSP server's arguments when
    // using the 'stdio' transport. It has no actual meaning or use.
    // See: <https://github.com/microsoft/vscode-languageserver-node/issues/1222
    #[arg(long, hide = true)]
    pub(crate) stdio: bool,
}

/// Shell with auto-generated completion script available.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ValueEnum)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Shell {
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
    pub(crate) fn color_choice_for_terminal(&self, io: impl IsTerminal) -> anstream::ColorChoice {
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
    /// Collect pre-commit configuration and hooks files,
    /// i.e. `.pre-commit-config.yml` and `.pre-commit-hooks.yml`.
    PreCommit,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum CollectionMode {
    All,
    Default,
    Workflows,
    Actions,
    Dependabot,
    PreCommit,
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
                    CliCollectionMode::PreCommit => CollectionMode::PreCommit,
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

    /// Shouldn we collect pre-commit files?
    pub(crate) fn pre_commit(&self) -> bool {
        self.0.iter().any(|mode| {
            matches!(
                mode,
                CollectionMode::All | CollectionMode::Default | CollectionMode::PreCommit
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

impl fmt::Display for FixMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FixMode::Safe => write!(f, "safe"),
            FixMode::UnsafeOnly => write!(f, "unsafe-only"),
            FixMode::All => write!(f, "all"),
        }
    }
}

/// State used when collecting input groups.
pub(crate) struct CollectionOptions {
    pub(crate) mode_set: CollectionModeSet,
    pub(crate) strict: bool,
    pub(crate) no_config: bool,
    /// Global configuration, if any.
    pub(crate) global_config: Option<Config>,
}

pub(crate) fn completions<G: clap_complete::Generator>(generator: G, cmd: &mut clap::Command) {
    clap_complete::generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut std::io::stdout(),
    );
}

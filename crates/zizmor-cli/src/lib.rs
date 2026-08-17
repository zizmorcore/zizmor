use std::fmt;
use std::marker::PhantomData;

use annotate_snippets::renderer::{AnsiColor, Effects};
use anstream::stream::IsTerminal;
use camino::Utf8PathBuf;
use clap::builder::{
    EnumValueParser, NonEmptyStringValueParser, PossibleValue, Styles, TypedValueParser,
};
use clap::{ArgAction, Args, Parser, ValueEnum, ValueHint};
use clap_complete::Generator;
use clap_verbosity_flag::InfoLevel;
use etcetera::AppStrategy as _;

use zizmor_collect::CollectionMode;
use zizmor_core::{
    finding::{Confidence, Persona, Severity},
    github::{GitHubHost, GitHubToken},
};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

/// Finds security issues in CI/CD systems.
#[derive(Debug, Parser)]
#[command(
    name = "zizmor",
    about = "Static analysis for CI/CD systems",
    version,
    styles = STYLES
)]
#[command(disable_help_flag = true, disable_version_flag = true)]
#[command(next_display_order = 1)]
pub struct App {
    #[command(flatten)]
    pub input: InputArgs,

    #[command(flatten)]
    pub audit: AuditArgs,

    #[command(flatten)]
    pub output: OutputArgs,

    #[command(flatten)]
    pub network: NetworkArgs,

    #[command(flatten)]
    pub args: GlobalArgs,
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
pub struct InputArgs {
    /// The inputs to audit.
    ///
    /// These can be individual workflow filenames, action definitions
    /// (typically `action.yml`), entire directories, or a `user/repo` slug
    /// for a GitHub repository. In the latter case, a `@ref` can be appended
    /// to audit the repository at a particular git reference state.
    ///
    /// Use `-` to read a single input from stdin.
    #[arg(required = true, value_name = "INPUT", display_order = 0)]
    pub inputs: Vec<String>,

    /// Control which kinds of inputs are collected for auditing.
    ///
    /// By default, all workflows and composite actions are collected,
    /// while honoring `.gitignore` files.
    #[arg(
        long,
        default_values = ["default"],
        num_args=1..,
        value_delimiter=',',
        value_name = "KIND",
        value_enum,
    )]
    pub collect: Vec<CollectionMode>,

    /// Fail instead of warning on syntax and schema errors
    /// in collected inputs.
    #[arg(long)]
    pub strict_collection: bool,
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Audit Options")]
pub struct AuditArgs {
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
    pub fix: Option<FixMode>,

    /// Emit 'pedantic' findings.
    ///
    /// This is an alias for --persona=pedantic.
    #[arg(short, long, group = "_persona")]
    pub pedantic: bool,

    /// The persona to use while auditing.
    #[arg(long, group = "_persona", default_value = "regular", value_enum)]
    pub persona: Persona,

    /// Filter all results below this severity.
    #[arg(long, value_name = "LEVEL", value_parser = ThresholdParser::<Severity>::new())]
    pub min_severity: Option<Threshold<Severity>>,

    /// Filter all results below this confidence.
    #[arg(long, value_name = "LEVEL", value_parser = ThresholdParser::<Confidence>::new())]
    pub min_confidence: Option<Threshold<Confidence>>,

    /// Don't honor ignore comments or ignore rules in configuration.
    #[arg(long)]
    pub no_ignores: bool,
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Output Options")]
pub struct OutputArgs {
    #[command(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity<InfoLevel>,

    /// The output format to emit. By default, cargo-style diagnostics will be emitted.
    #[arg(long, value_enum, default_value_t, value_name = "KIND")]
    pub format: OutputFormat,

    /// Don't show progress bars, even if the terminal supports them.
    #[arg(long)]
    pub no_progress: bool,

    /// Control the use of color in output.
    #[arg(long, value_enum, value_name = "WHEN")]
    pub color: Option<ColorMode>,

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
    pub render_links: CliRenderLinks,

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
    pub show_audit_urls: CliShowAuditUrls,

    /// Disable all error codes besides success and tool failure.
    #[arg(long)]
    pub no_exit_codes: bool,

    /// Enable naches mode.
    #[arg(long, hide = true, env = "ZIZMOR_NACHES")]
    pub naches: bool,
}

#[derive(Args, Debug)]
#[command(next_help_heading = "Network Options")]
pub struct NetworkArgs {
    /// Perform only offline operations.
    ///
    /// This disables all online audit rules, and prevents zizmor from
    /// auditing remote repositories.
    #[arg(short, long, env = "ZIZMOR_OFFLINE")]
    pub offline: bool,

    /// The GitHub API token to use [env: GH_TOKEN or GITHUB_TOKEN or ZIZMOR_GITHUB_TOKEN]
    #[arg(long, env, hide_env = true, value_parser = GitHubToken::new)]
    pub gh_token: Option<GitHubToken>,

    /// This is an alias for `--gh-token` / `GH_TOKEN`.
    #[arg(long, env, hide = true, value_parser = GitHubToken::new)]
    pub github_token: Option<GitHubToken>,

    /// This is an alias for `--gh-token` / `GH_TOKEN` / `--github-token` / `GITHUB_TOKEN`
    #[arg(long, env, hide = true, value_parser = GitHubToken::new)]
    pub zizmor_github_token: Option<GitHubToken>,

    /// The GitHub Server Hostname. Defaults to github.com
    #[arg(long, env = "GH_HOST", default_value_t)]
    pub gh_hostname: GitHubHost,

    /// Perform only offline audits.
    ///
    /// This is a weaker version of `--offline`: instead of completely
    /// forbidding all online operations, it only disables audits that
    /// require connectivity.
    #[arg(long, env = "ZIZMOR_NO_ONLINE_AUDITS")]
    pub no_online_audits: bool,

    /// The directory to use for HTTP caching. By default, a
    /// host-appropriate user-caching directory will be used.
    #[arg(
        long,
        value_name = "DIR",
        default_value_t = App::default_cache_dir(),
        hide_default_value = true,
        value_hint = ValueHint::DirPath
    )]
    pub cache_dir: Utf8PathBuf,
}

#[derive(Args, Debug)]
#[command(next_help_heading = "Options")]
pub struct GlobalArgs {
    #[cfg(feature = "lsp")]
    #[command(flatten)]
    pub lsp: LspArgs,

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
    pub config: Option<String>,

    /// Disable all configuration loading.
    #[arg(long, group = "conf")]
    pub no_config: bool,

    /// Generate tab completion scripts for the specified shell.
    #[arg(long, value_enum, value_name = "SHELL", exclusive = true)]
    pub completions: Option<Shell>,

    /// Generate JSON Schema for zizmor.yml configuration files.
    #[cfg(feature = "schema")]
    #[arg(long, exclusive = true)]
    pub generate_schema: bool,

    /// Emit thank-you messages for zizmor's sponsors.
    #[arg(long, exclusive = true)]
    pub thanks: bool,

    /// Print help.
    #[arg(
        short,
        long,
        help = "Print help (see more with '--help')",
        long_help = "Print help (see a summary with '-h')",
        action = ArgAction::Help
    )]
    pub help: (),

    /// Print version.
    #[arg(short = 'V', long, action = ArgAction::Version)]
    pub version: (),
}

/// A threshold supplied on the command line.
///
/// The inner value is absent only for the deprecated, hidden `unknown` value.
#[derive(Debug, Copy, Clone)]
pub struct Threshold<T>(pub Option<T>);

#[derive(Clone)]
struct ThresholdParser<T>(PhantomData<T>);

impl<T> ThresholdParser<T> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> TypedValueParser for ThresholdParser<T>
where
    T: clap::ValueEnum + Clone + Send + Sync + 'static,
{
    type Value = Threshold<T>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        if value == "unknown" {
            Ok(Threshold(None))
        } else {
            EnumValueParser::<T>::new()
                .parse_ref(cmd, arg, value)
                .map(|value| Threshold(Some(value)))
        }
    }

    fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
        Some(Box::new(
            std::iter::once(PossibleValue::new("unknown").hide(true)).chain(
                T::value_variants()
                    .iter()
                    .filter_map(clap::ValueEnum::to_possible_value),
            ),
        ))
    }
}

#[cfg(feature = "lsp")]
#[derive(Args, Debug)]
#[group(multiple = true, conflicts_with = "inputs")]
pub struct LspArgs {
    /// Run in language server mode (EXPERIMENTAL).
    ///
    /// This flag cannot be used with any other flags.
    #[arg(long)]
    pub lsp: bool,

    // This flag exists solely because VS Code's LSP client implementation
    // insists on appending `--stdio` to the LSP server's arguments when
    // using the 'stdio' transport. It has no actual meaning or use.
    // See: <https://github.com/microsoft/vscode-languageserver-node/issues/1222
    #[arg(long, hide = true)]
    pub stdio: bool,
}

/// Shell with auto-generated completion script available.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ValueEnum)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
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
            Self::Bash => clap_complete::shells::Bash.file_name(name),
            Self::Elvish => clap_complete::shells::Elvish.file_name(name),
            Self::Fish => clap_complete::shells::Fish.file_name(name),
            Self::Nushell => clap_complete_nushell::Nushell.file_name(name),
            Self::Powershell => clap_complete::shells::PowerShell.file_name(name),
            Self::Zsh => clap_complete::shells::Zsh.file_name(name),
        }
    }

    fn generate(&self, cmd: &clap::Command, buf: &mut dyn std::io::Write) {
        match self {
            Self::Bash => clap_complete::shells::Bash.generate(cmd, buf),
            Self::Elvish => clap_complete::shells::Elvish.generate(cmd, buf),
            Self::Fish => clap_complete::shells::Fish.generate(cmd, buf),
            Self::Nushell => clap_complete_nushell::Nushell.generate(cmd, buf),
            Self::Powershell => clap_complete::shells::PowerShell.generate(cmd, buf),
            Self::Zsh => clap_complete::shells::Zsh.generate(cmd, buf),
        }
    }
}

#[derive(Debug, Default, Copy, Clone, ValueEnum)]
pub enum OutputFormat {
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
pub enum CliRenderLinks {
    /// Render OSC 8 links in output if support is detected.
    #[default]
    Auto,
    /// Always render OSC 8 links in output.
    Always,
    /// Never render OSC 8 links in output.
    Never,
}

#[derive(Debug, Default, Copy, Clone, ValueEnum)]
pub enum CliShowAuditUrls {
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

#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum ColorMode {
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
    pub fn color_choice_for_terminal(&self, io: impl IsTerminal) -> anstream::ColorChoice {
        match self {
            Self::Auto => {
                if io.is_terminal() {
                    anstream::ColorChoice::Always
                } else {
                    anstream::ColorChoice::Never
                }
            }
            Self::Always => anstream::ColorChoice::Always,
            Self::Never => anstream::ColorChoice::Never,
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

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum FixMode {
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
            Self::Safe => write!(f, "safe"),
            Self::UnsafeOnly => write!(f, "unsafe-only"),
            Self::All => write!(f, "all"),
        }
    }
}

pub fn completions<G: clap_complete::Generator>(generator: G, cmd: &mut clap::Command) {
    clap_complete::generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut std::io::stdout(),
    );
}

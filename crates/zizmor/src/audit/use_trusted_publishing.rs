use std::collections::HashSet;
use std::{sync::LazyLock, vec};

use anyhow::Context as _;
use subfeature::Subfeature;
use tree_sitter::StreamingIterator as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::finding::location::Locatable;
use crate::{
    finding::{Confidence, Finding, Severity},
    models::{
        StepBodyCommon, StepCommon,
        coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle},
        workflow::JobExt as _,
    },
    state::AuditState,
    utils,
};

const USES_MANUAL_CREDENTIAL: &str =
    "uses a manually-configured credential instead of Trusted Publishing";

const KNOWN_RUBY_TP_INDICES: &[&str] = &["https://rubygems.org"];

const KNOWN_PYTHON_TP_INDICES: &[&str] = &[
    "https://upload.pypi.org/legacy/",
    "https://test.pypi.org/legacy/",
];

const KNOWN_NPMJS_TP_INDICES: &[&str] =
    &["https://registry.npmjs.org", "https://registry.npmjs.org/"];

#[allow(clippy::unwrap_used)]
static KNOWN_TRUSTED_PUBLISHING_ACTIONS: LazyLock<Vec<(ActionCoordinate, &[&str])>> =
    LazyLock::new(|| {
        vec![
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "pypa/gh-action-pypi-publish".parse().unwrap(),
                    control: ControlExpr::all([
                        ControlExpr::single(
                            Toggle::OptIn,
                            "password",
                            ControlFieldType::FreeString,
                            false,
                        ),
                        // TIP: On first glance you might think this should be
                        // `any` instead, but observe that each of these control
                        // expressions is marked with `enabled_by_default: true`.
                        // If we used `any` we'd end up accidentally satisfying
                        // when the user only sets one of the control fields.
                        ControlExpr::all([
                            ControlExpr::single(
                                Toggle::OptIn,
                                "repository-url",
                                ControlFieldType::Exact(KNOWN_PYTHON_TP_INDICES),
                                true,
                            ),
                            ControlExpr::single(
                                Toggle::OptIn,
                                "repository_url",
                                ControlFieldType::Exact(KNOWN_PYTHON_TP_INDICES),
                                true,
                            ),
                        ]),
                    ]),
                },
                &["with", "password"],
            ),
            // TODO: Not sufficiently sensitive; we need to detect whether
            // a TP-compatible registry is being published to.
            // (
            //     ActionCoordinate::Configurable {
            //         uses_pattern: "PyO3/maturin-action".parse().unwrap(),
            //         control: ControlExpr::single(
            //             Toggle::OptIn,
            //             "command",
            //             ControlFieldType::Exact(&["upload", "publish"]),
            //             true,
            //         ),
            //     },
            //     &["with", "command"],
            // ),
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "rubygems/release-gem".parse().unwrap(),
                    control: ControlExpr::not(ControlExpr::single(
                        Toggle::OptIn,
                        "setup-trusted-publisher",
                        ControlFieldType::Boolean,
                        true,
                    )),
                },
                &["with", "setup-trusted-publisher"],
            ),
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "rubygems/configure-rubygems-credentials".parse().unwrap(),
                    control: ControlExpr::all([
                        ControlExpr::single(
                            Toggle::OptIn,
                            "api-token",
                            ControlFieldType::FreeString,
                            false,
                        ),
                        ControlExpr::single(
                            Toggle::OptIn,
                            "gem-server",
                            ControlFieldType::Exact(KNOWN_RUBY_TP_INDICES),
                            true,
                        ),
                    ]),
                },
                &["with", "api-token"],
            ),
            // NPM publishing actions that should use trusted publishing
            // Detects when actions/setup-node is configured for npmjs with always-auth
            (
                ActionCoordinate::Configurable {
                    uses_pattern: "actions/setup-node".parse().unwrap(),
                    control: ControlExpr::all([
                        ControlExpr::single(
                            Toggle::OptIn,
                            "registry-url",
                            ControlFieldType::Exact(KNOWN_NPMJS_TP_INDICES),
                            true,
                        ),
                        // Detect when always-auth is enabled (indicating manual token usage)
                        ControlExpr::single(
                            Toggle::OptIn,
                            "always-auth",
                            ControlFieldType::Boolean,
                            false,
                        ),
                    ]),
                },
                &["with", "always-auth"],
            ),
        ]
    });

const BASH_COMMAND_QUERY: &str = "(command name: (_) @cmd argument: (_)+ @args) @span";
const PWSH_COMMAND_QUERY: &str =
    "(command command_name: (_) @cmd command_elements: (_ (generic_token) @args)+) @span";

pub(crate) struct UseTrustedPublishing {
    bash_command_query: utils::SpannedQuery,
    pwsh_command_query: utils::SpannedQuery,
}

audit_meta!(
    UseTrustedPublishing,
    "use-trusted-publishing",
    "prefer trusted publishing for authentication"
);

impl UseTrustedPublishing {
    fn query<'a>(
        &self,
        query: &'a utils::SpannedQuery,
        cursor: &'a mut tree_sitter::QueryCursor,
        tree: &'a tree_sitter::Tree,
        source: &'a str,
    ) -> tree_sitter::QueryMatches<'a, 'a, &'a [u8], &'a [u8]> {
        cursor.matches(query, tree.root_node(), source.as_bytes())
    }

    /// Determine whether the given command and arguments correspond to a publishing
    /// command, e.g., `cargo publish`, `twine upload`, etc.
    fn is_publish_command<'a>(&self, cmd: &'a str, args: impl Iterator<Item = &'a str>) -> bool {
        // NOTE(ww): The implementation below is frustratingly manual.
        // Ideally we'd use clap or similar to define an (imprecise) model of what we're
        // looking for, but as of 2025-11 none of the popular Rust command-line parsing
        // libraries do a great job of handling unknown commands and arguments (which we want,
        // because we don't want to have to define a perfectly accurate model for all
        // of the commands we're trying to match).
        let mut args = args;

        match cmd {
            "cargo" => {
                let args = args.collect::<HashSet<_>>();

                // Looking for `cargo ... publish` without `--dry-run` or `-n`.
                args.contains("publish") && !args.contains("--dry-run") && !args.contains("-n")
            }
            "uv" => {
                let args = args.collect::<HashSet<_>>();

                // Looking for `uv ... publish` without `--dry-run`.
                args.contains("publish") && !args.contains("--dry-run")
            }
            "hatch" | "pdm" => {
                // Looking for `hatch ... publish` or `pdm ... publish`.
                args.any(|arg| arg == "publish")
            }
            "twine" => {
                // Looking for `twine ... upload`.
                args.any(|arg| arg == "upload")
            }
            "gem" => {
                // Looking for `gem ... push`.
                args.any(|arg| arg == "push")
            }
            "npm" => {
                let args = args.collect::<HashSet<_>>();

                // TODO: Figure out `npm run ... publish` patterns.

                // Looking for `npm ... publish` without `--dry-run`.
                args.contains("publish") && !args.contains("--dry-run")
            }
            "yarn" => {
                let args = args.collect::<HashSet<_>>();

                // TODO: Figure out `yarn run ... publish` patterns.
                // TODO: Figure out `yarn ... publish` patterns for lerna/npm workspaces.

                // Looking for `yarn ... npm publish` without `--dry-run` or `-n`.
                args.contains("npm")
                    && args.contains("publish")
                    && !args.contains("--dry-run")
                    && !args.contains("-n")
            }
            "pnpm" => {
                let args = args.collect::<HashSet<_>>();

                // TODO: Figure out `pnpm run ... publish` patterns.

                // Looking for `pnpm ... publish` without `--dry-run`.
                args.contains("publish") && !args.contains("--dry-run")
            }
            _ => false,
        }
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for (coordinate, keys) in KNOWN_TRUSTED_PUBLISHING_ACTIONS.iter() {
            // TODO: Capture the Some(Usage) here and specialize the
            // finding with it.
            if coordinate.usage(step).is_some() {
                findings.push(
                    Self::finding()
                        .severity(Severity::Informational)
                        .confidence(Confidence::High)
                        .add_location(step.location().hidden())
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["uses".into()])
                                .annotated("this step"),
                        )
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(keys.iter().map(|k| (*k).into()))
                                .annotated(USES_MANUAL_CREDENTIAL),
                        )
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }

    fn trusted_publishing_command_candidates<'doc>(
        &self,
        run: &'doc str,
        shell: &str,
    ) -> Result<Vec<Subfeature<'doc>>, AuditError> {
        let normalized = utils::normalize_shell(shell);

        let mut cursor = tree_sitter::QueryCursor::new();
        let (query, tree) = match normalized {
            "bash" | "sh" | "zsh" => {
                let mut parser = utils::bash_parser();
                let tree = parser
                    .parse(run, None)
                    .context("failed to parse `run:` body as bash")
                    .map_err(Self::err)?;

                (&self.bash_command_query, tree)
            }
            "pwsh" | "powershell" => {
                let mut parser = utils::pwsh_parser();
                let tree = parser
                    .parse(run, None)
                    .context("failed to parse `run:` body as pwsh")
                    .map_err(Self::err)?;

                (&self.pwsh_command_query, tree)
            }
            _ => {
                tracing::debug!("unable to analyze 'run:' block: unknown shell '{normalized}'");
                return Ok(vec![]);
            }
        };

        let matches = self.query(query, &mut cursor, &tree, run);
        let cmd = query
            .capture_index_for_name("cmd")
            .expect("internal error: missing capture index for 'cmd'");
        let args = query
            .capture_index_for_name("args")
            .expect("internal error: missing capture index for 'args'");

        let mut subfeatures = vec![];
        matches.for_each(|mat| {
            let cmd = {
                let cap = mat
                    .captures
                    .iter()
                    .find(|cap| cap.index == cmd)
                    .expect("internal error: expected capture for cmd");
                cap.node
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction")
            };

            let args = mat
                .captures
                .iter()
                .filter(|cap| cap.index == args)
                .map(|cap| {
                    cap.node
                        .utf8_text(run.as_bytes())
                        .expect("impossible: capture should be UTF-8 by construction")
                });

            if self.is_publish_command(cmd, args) {
                let span = mat
                    .captures
                    .iter()
                    .find(|cap| cap.index == query.span_idx)
                    .expect("internal error: expected capture for span");

                let span_contents = span
                    .node
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction");

                subfeatures.push(Subfeature::new(span.node.start_byte(), span_contents));
            }
        });

        Ok(subfeatures)
    }
}

#[async_trait::async_trait]
impl Audit for UseTrustedPublishing {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self {
            bash_command_query: utils::SpannedQuery::new(BASH_COMMAND_QUERY, &utils::BASH),
            pwsh_command_query: utils::SpannedQuery::new(PWSH_COMMAND_QUERY, &utils::PWSH),
        })
    }

    async fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<super::Finding<'doc>>, AuditError> {
        let mut findings = self.process_step(step)?;

        // In addition to the shared action matching above, we can
        // also check for some `run:` patterns that indicate publishing
        // without Trusted Publishing.

        // We can only check these reliably on workflows and not actions,
        // since we need to be able to see the `id-token` permission's
        // state to filter out any false positives.
        //
        // NOTE(ww): With #1161 we loosened this check and turned the
        // "has ID token" check into a confidence modifier rather than
        // a strict filter. This ended up being overly imprecise, since a lot
        // of publishing commands use trusted publishing implicitly if
        // the environment supports it. We reverted this with #1191.
        if let StepBodyCommon::Run { run, .. } = step.body()
            && !step.parent.has_id_token()
        {
            let shell = step.shell().unwrap_or_else(|| {
                tracing::debug!(
                    "use-trusted-publishing: couldn't determine shell type for {workflow}:{job} step {stepno}",
                    workflow = step.workflow().key.filename(),
                    job = step.parent.id(),
                    stepno = step.index
                );

                "bash"
            });

            for subfeature in self.trusted_publishing_command_candidates(run, shell)? {
                findings.push(
                    Self::finding()
                        .severity(Severity::Informational)
                        .confidence(Confidence::High)
                        .add_location(step.location().hidden())
                        .add_location(
                            step.location()
                                .with_keys(["run".into()])
                                .key_only()
                                .annotated("this step"),
                        )
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["run".into()])
                                .subfeature(subfeature)
                                .annotated("this command"),
                        )
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }
}

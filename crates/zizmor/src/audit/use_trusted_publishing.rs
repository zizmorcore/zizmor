use std::{sync::LazyLock, vec};

use anyhow::Context as _;
use regex::RegexSet;
use subfeature::Subfeature;
use tree_sitter::Language;
use tree_sitter::StreamingIterator as _;

use super::{Audit, AuditLoadError, audit_meta};
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
        ]
    });

// Queries that match a command with at least one argument.
//
// NOTE: These queries are intentionally very simple. The operating theory here
// is that it's faster to match a simple query and then filter the results
// with a compiled regular expression than it is to write a complex
// query that uses tree-sitter's baked-in regex support.
const BASH_COMMAND_QUERY: &str = "(command name: (_) argument: (_)+) @cmd";
const PWSH_COMMAND_QUERY: &str = "(command command_name: (_) command_elements: (_)+) @cmd";

const NON_TP_COMMAND_PATTERNS: &[&str] = &[
    // cargo ... publish ...
    r"(?s)cargo\s+(.+\s+)?publish",
    // uv ... publish ...
    r"(?s)uv\s+(.+\s+)?publish",
    // hatch ... publish ...
    r"(?s)hatch\s+(.+\s+)?publish",
    // pdm ... publish ...
    r"(?s)pdm\s+(.+\s+)?publish",
    // twine ... upload ...
    r"(?s)twine\s+(.+\s+)?upload",
    // gem ... push ...
    r"(?s)gem\s+(.+\s+)?push",
];

static NON_TP_COMMAND_PATTERN_SET: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(NON_TP_COMMAND_PATTERNS).unwrap());

static NON_TP_COMMAND_PATTERN_REGEXES: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    NON_TP_COMMAND_PATTERNS
        .iter()
        .map(|p| regex::Regex::new(p).unwrap())
        .collect()
});

pub(crate) struct UseTrustedPublishing {
    bash: Language,
    pwsh: Language,

    bash_command_query: tree_sitter::Query,
    pwsh_command_query: tree_sitter::Query,
}

audit_meta!(
    UseTrustedPublishing,
    "use-trusted-publishing",
    "prefer trusted publishing for authentication"
);

impl UseTrustedPublishing {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
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

    fn bash_trusted_publishing_command_candidates<'doc>(
        &self,
        run: &'doc str,
    ) -> anyhow::Result<Vec<Subfeature<'doc>>> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&self.bash)?;

        let mut cursor = tree_sitter::QueryCursor::new();
        let tree = parser
            .parse(run, None)
            .context("failed to parse `run:` body as bash")?;

        Ok(cursor
            .captures(&self.bash_command_query, tree.root_node(), run.as_bytes())
            .filter_map(|(mat, cap_idx)| {
                let cap_node = mat.captures[*cap_idx].node;
                let cap_cmd = cap_node.utf8_text(run.as_bytes()).unwrap();

                NON_TP_COMMAND_PATTERN_SET
                    .is_match(cap_cmd)
                    .then(|| Subfeature::new(cap_node.start_byte(), cap_cmd))
            })
            .cloned()
            .collect())
    }

    fn pwsh_trusted_publishing_command_candidates<'doc>(
        &self,
        run: &'doc str,
    ) -> anyhow::Result<Vec<Subfeature<'doc>>> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&self.pwsh)?;

        let mut cursor = tree_sitter::QueryCursor::new();
        let tree = parser
            .parse(run, None)
            .context("failed to parse `run:` body as pwsh")?;

        Ok(cursor
            .captures(&self.pwsh_command_query, tree.root_node(), run.as_bytes())
            .filter_map(|(mat, cap_idx)| {
                let cap_node = mat.captures[*cap_idx].node;
                let cap_cmd = cap_node.utf8_text(run.as_bytes()).unwrap();

                NON_TP_COMMAND_PATTERN_SET
                    .is_match(cap_cmd)
                    .then(|| Subfeature::new(cap_node.start_byte(), cap_cmd))
            })
            .cloned()
            .collect())
    }

    fn raw_trusted_publishing_command_candidates<'doc>(
        &self,
        run: &'doc str,
    ) -> anyhow::Result<Vec<Subfeature<'doc>>> {
        Ok(NON_TP_COMMAND_PATTERN_SET
            .matches(run)
            .into_iter()
            .map(|idx| NON_TP_COMMAND_PATTERN_REGEXES[idx].find(run).unwrap())
            .map(|mat| Subfeature::new(mat.start(), mat.as_str()))
            .collect())
    }

    fn trusted_publishing_command_candidates<'doc>(
        &self,
        run: &'doc str,
        shell: &str,
    ) -> anyhow::Result<Vec<Subfeature<'doc>>> {
        let normalized = utils::normalize_shell(shell);

        match normalized {
            "bash" | "sh" | "zsh" => self.bash_trusted_publishing_command_candidates(run),
            "pwsh" | "powershell" => self.pwsh_trusted_publishing_command_candidates(run),
            _ => self.raw_trusted_publishing_command_candidates(run),
        }
    }
}

impl Audit for UseTrustedPublishing {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        let bash: Language = tree_sitter_bash::LANGUAGE.into();
        let pwsh: Language = tree_sitter_powershell::LANGUAGE.into();

        Ok(Self {
            bash_command_query: tree_sitter::Query::new(&bash, BASH_COMMAND_QUERY)
                .map_err(|e| AuditLoadError::Fail(e.into()))?,
            pwsh_command_query: tree_sitter::Query::new(&pwsh, PWSH_COMMAND_QUERY)
                .map_err(|e| AuditLoadError::Fail(e.into()))?,
            bash,
            pwsh,
        })
    }

    fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        let mut findings = self.process_step(step)?;

        // In addition to the shared action matching above, we can
        // also check for some `run:` patterns that indicate publishing
        // without Trusted Publishing.
        // We can only check these reliably on workflows and not actions,
        // since we need to be able to see the `id-token` permission's
        // state to filter out any false positives.
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
                        // Our confidence is lower here, since we have less
                        // insight into the publishing command's context
                        // (e.g. whether it's influenced by something in
                        // the environment to publish to a different index
                        // that doesn't support Trusted Publishing).
                        .confidence(Confidence::Medium)
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

    fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }
}

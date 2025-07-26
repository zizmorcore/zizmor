use std::{sync::LazyLock, vec};

use tree_sitter::Language;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{Confidence, Finding, Severity},
    models::{
        StepCommon,
        coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle},
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

const BASH_COMMAND_QUERY: &str =
    "(command name: (command_name) @cmd argument: (_)* @args) @span @destination";

pub(crate) struct UseTrustedPublishing {
    bash: Language,
    pwsh: Language,

    bash_command_query: utils::SpannedQuery,
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
}

impl Audit for UseTrustedPublishing {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        let bash: Language = tree_sitter_bash::LANGUAGE.into();
        let pwsh: Language = tree_sitter_powershell::LANGUAGE.into();

        Ok(Self {
            bash_command_query: utils::SpannedQuery::new(BASH_COMMAND_QUERY, &bash),
            bash,
            pwsh,
        })
    }

    fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }
}

//! Actions Runners modeling and APIs.

use crate::finding::location::{Locatable as _, SymbolicLocation};
use crate::models::workflow::NormalJob;
use github_actions_expressions::{Expr, SpannedExpr};
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::job::RunsOn;
use std::collections::HashSet;
use std::ops::Deref as _;
use std::sync::LazyLock;

/// The list of well-known Github runners
/// See https://docs.github.com/en/actions/reference/runners/github-hosted-runners
static KNOWN_GITHUB_HOSTED_RUNNERS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    include_str!("../../../data/github-hosted-runners.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|runner| runner.trim().to_string())
        .collect::<HashSet<_>>()
});

/// The evidence that backs a self-hosted-runner finding
pub(crate) enum RunnerEvidence {
    /// For classic registration methods like Runner binary self-registration
    /// and legacy ARC : both forces the "self-hosted" label
    ClassicSentinel,
    /// RunnerGroups imply self-hosting, with a notable exception for
    /// Github Large Runners
    RunnerGroup,
    /// Either Github Large Runners Groups or Third Party Runner Labels
    /// explicitly flagged by the user via zizmor config
    ExplicitlyFlagged,
}

/// The representation of an Actions Runner
pub(crate) enum Runner<'doc> {
    /// Loaded from static data
    GithubOwned,
    /// Runners provided as a service
    ThirdParty,
    /// Self-explained
    SelfHosted {
        location: SymbolicLocation<'doc>,
        evidence: RunnerEvidence,
        from_matrix: bool,
    },
    Indeterminate {
        location: SymbolicLocation<'doc>,
        /// Usually when runner groups or runner labels depend on expressions
        /// that can't be statically resolved but there are evidence of
        /// self-hosting, like the classic labels, runner-groups or
        /// runner labels not flagged as third party through zizmor configuration
        /// rules.
        self_hosted_evidence: bool,
        from_matrix: bool,
    },
}

/// Helper wrapping all runners evaluated for a Job
pub(crate) struct JobRunners<'doc> {
    runners: Vec<Runner<'doc>>,
}

impl<'doc> JobRunners<'doc> {
    pub(crate) fn new(
        job: &NormalJob<'doc>,
        included_runners: &HashSet<String>,
        excluded_groups: &HashSet<String>,
    ) -> Self {
        let mut runners = vec![];

        match &job.runs_on {
            LoE::Literal(RunsOn::Target(labels)) => {
                // check for self-hosting sentinel first
                // we won't process all labels as runners if we find an exact match
                if labels
                    .iter()
                    .any(|label| label.eq_ignore_ascii_case("self-hosted"))
                {
                    runners.push(Runner::SelfHosted {
                        location: job.location(),
                        evidence: RunnerEvidence::ClassicSentinel,
                        from_matrix: false,
                    });
                } else {
                    for label in labels.iter() {
                        // Evaluate all other scenarios
                        runners.push(Self::evaluate_runner(label, job, included_runners, false))
                    }
                }
            }
            LoE::Literal(RunsOn::Group { group, .. }) => {
                // NOTE: GHA docs are not precise whether runner groups always
                // imply self-hosted runners or not. All examples suggest that they
                // do, with larger runner groups being the notable exception.
                //
                // See: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups
                // See: https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/choosing-the-runner-for-a-job
                // See: https://docs.github.com/en/actions/how-tos/manage-runners/larger-runners/control-access
                //
                if let Some(runner_group) = group {
                    if excluded_groups
                        .iter()
                        .find(|gh_group| runner_group.eq_ignore_ascii_case(gh_group))
                        .is_some()
                    {
                        runners.push(Runner::GithubOwned)
                    } else {
                        runners.push(Runner::SelfHosted {
                            location: job.location(),
                            evidence: RunnerEvidence::RunnerGroup,
                            from_matrix: false,
                        })
                    };
                }
            }
            // Non-trivial scenario, where runs-on: is an expression
            LoE::Expr(exp) => {
                if let Ok(parsed) = Expr::parse(exp.as_bare()) {
                    // We walk the spanned expression and expand leafs.
                    // Each leaf eventually resolves to a `GithubActionsRunner`
                    parsed
                        .leaf_expressions()
                        .into_iter()
                        .flat_map(|leaf| {
                            Self::expand_runner_expression(leaf, job, included_runners)
                        })
                        .for_each(|runner| {
                            runners.push(runner);
                        })
                } else {
                    let maybe_self_hosted =
                        Self::evaluate_self_hosted_evidence(exp.as_bare(), included_runners);

                    runners.push(Runner::Indeterminate {
                        location: job.location(),
                        self_hosted_evidence: maybe_self_hosted,
                        from_matrix: false,
                    })
                }
            }
        }

        Self { runners }
    }

    /// Return an iterator over the inner collection
    pub(crate) fn iter(self) -> impl Iterator<Item = Runner<'doc>> {
        self.runners.into_iter()
    }

    /// Evaluates a single `runs-on` label as `GithubActionsRunner`
    fn evaluate_runner(
        label: &str,
        job: &NormalJob<'doc>,
        included_runners: &HashSet<String>,
        from_matrix: bool,
    ) -> Runner<'doc> {
        // Allows users to flag new ARC-based self-hosted runners
        if included_runners
            .iter()
            .find(|runner| label.eq_ignore_ascii_case(runner))
            .is_some()
        {
            return Runner::SelfHosted {
                location: job.location(),
                evidence: RunnerEvidence::ExplicitlyFlagged,
                from_matrix,
            };
        }

        // Trivial scenario
        if KNOWN_GITHUB_HOSTED_RUNNERS
            .deref()
            .iter()
            .find(|runner| label.eq_ignore_ascii_case(runner))
            .is_some()
        {
            return Runner::GithubOwned;
        }

        // Fallback is handled as a third party
        Runner::ThirdParty
    }

    /// Expands expressions for a runs-on: ${{ expression }}
    fn expand_runner_expression(
        parsed: &SpannedExpr,
        job: &NormalJob<'doc>,
        included_runners: &HashSet<String>,
    ) -> Vec<Runner<'doc>> {
        match &parsed.inner {
            // as literal, we evaluate almost as we do with LoE<RunsOn::Literal>
            Expr::Literal(lit) => {
                vec![Self::evaluate_runner(
                    lit.as_str().deref(),
                    job,
                    included_runners,
                    false,
                )]
            }
            // we evaluate only matrix expansion
            Expr::Context(context) if context.child_of("matrix") => {
                let Some(matrix) = job.matrix() else {
                    return vec![Runner::Indeterminate {
                        location: job.location(),
                        self_hosted_evidence: false,
                        from_matrix: false,
                    }];
                };

                // First, we collect expansion values and whether they are statically driven
                let expanded = matrix
                    .expansions()
                    .iter()
                    .filter(|expansion| context.matches(expansion.path.as_str()))
                    .map(|expansion| (expansion.is_static(), expansion.value.clone()))
                    .collect::<Vec<_>>();

                // As we did with RunsOn::Target, we check the self-hosted sentinel
                // for an exact match within the static expansion, and we won't process any
                // other expansions if we match
                // That avoids FPs in scenarios like matrix inclusions
                if expanded
                    .iter()
                    .filter(|(is_static, _)| *is_static)
                    .any(|(_, value)| value.eq_ignore_ascii_case("self-hosted"))
                {
                    return vec![Runner::SelfHosted {
                        location: job.location(),
                        evidence: RunnerEvidence::ClassicSentinel,
                        from_matrix: true,
                    }];
                }

                // Because we did not fully recurse, we evaluate also an inexact match for
                // the self-hosted sentinel evidence within the context
                if expanded
                    .iter()
                    .filter(|(is_static, _)| *is_static)
                    .any(|(_, value)| Self::evaluate_self_hosted_evidence(value, included_runners))
                {
                    return vec![Runner::Indeterminate {
                        location: job.location(),
                        self_hosted_evidence: true,
                        from_matrix: true,
                    }];
                }

                // Otherwise, we process all expansions, assigning indetermination if
                // they are not static
                expanded
                    .iter()
                    .map(|(is_static, value)| {
                        if *is_static {
                            Self::evaluate_runner(value, job, included_runners, true)
                        } else {
                            Runner::Indeterminate {
                                location: job.location(),
                                self_hosted_evidence: false,
                                from_matrix: true,
                            }
                        }
                    })
                    .collect()
            }
            _ => {
                // Fallback scenario, we can't do much other than
                // naively checking for self-hosting evidence
                let raw_expression = parsed.origin.raw;

                let maybe_self_hosted =
                    Self::evaluate_self_hosted_evidence(raw_expression, included_runners);

                let indeterminate_runner = Runner::Indeterminate {
                    location: job.location(),
                    self_hosted_evidence: maybe_self_hosted,
                    from_matrix: false,
                };
                vec![indeterminate_runner]
            }
        }
    }

    /// Simple helper to dedup functionality
    fn evaluate_self_hosted_evidence(input: &str, included_runners: &HashSet<String>) -> bool {
        let self_hosting_sentinel = input.to_lowercase().contains("self-hosted");
        let included_by_config = included_runners.iter().any(|runner| input.contains(runner));
        self_hosting_sentinel || included_by_config
    }
}

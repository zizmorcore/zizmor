use github_actions_expressions::{BinOp, Expr, UnOp, context::Context};
use github_actions_models::common::{If, expr::ExplicitExpr};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    finding::{Confidence, Fix, Severity},
    models::{JobExt, StepCommon},
};

pub(crate) struct BotConditions;

audit_meta!(BotConditions, "bot-conditions", "spoofable bot actor check");

const SPOOFABLE_ACTOR_CONTEXTS: &[&str] = &["github.actor", "github.triggering_actor"];

impl Audit for BotConditions {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        let mut findings = vec![];

        // TODO: Consider other triggers as well?
        // In practice we expect to mostly see this problem with `pull_request_target`
        // triggers inside of "automerge this Dependabot PR"-style workflows.
        if !job.parent().has_pull_request_target() {
            return Ok(vec![]);
        }

        let job_id = job.id();

        // Check job-level condition
        if let Some(If::Expr(expr)) = &job.r#if {
            if let Some(confidence) = Self::bot_condition(expr) {
                let condition_path = format!("/jobs/{}/if", job_id);

                let mut finding_builder = Self::finding()
                    .severity(Severity::High)
                    .confidence(confidence)
                    .add_location(
                        job.location()
                            .with_keys(&["if".into()])
                            .primary()
                            .annotated("actor context may be spoofable"),
                    );

                // Add a practical fix that replaces github.actor with github.event.pull_request.user.login
                finding_builder =
                    finding_builder.fix(Self::create_replace_actor_fix(condition_path, true));

                findings.push(finding_builder.build(job.parent())?);
            }
        }

        // Check step-level conditions
        for (step_index, step) in job.steps().enumerate() {
            if let Some(If::Expr(expr)) = &step.r#if {
                if let Some(confidence) = Self::bot_condition(expr) {
                    let condition_path = format!("/jobs/{}/steps/{}/if", job_id, step_index);

                    let mut finding_builder = Self::finding()
                        .severity(Severity::High)
                        .confidence(confidence)
                        .add_location(
                            step.location()
                                .with_keys(&["if".into()])
                                .primary()
                                .annotated("actor context may be spoofable"),
                        );

                    // Add a practical fix that replaces github.actor with github.event.pull_request.user.login
                    finding_builder =
                        finding_builder.fix(Self::create_replace_actor_fix(condition_path, false));

                    findings.push(finding_builder.build(job.parent())?);
                }
            }
        }

        Ok(findings)
    }
}

impl BotConditions {
    /// Create a fix that replaces github.actor with github.event.pull_request.user.login
    fn create_replace_actor_fix(path: String, is_job_level: bool) -> Fix {
        let target_type = if is_job_level { "job" } else { "step" };

        Fix {
            title: format!(
                "Replace github.actor with github.event.pull_request.user.login in {}",
                target_type
            ),
            description: format!(
                "Replace 'github.actor' with 'github.event.pull_request.user.login' in the condition. \
                The github.actor context refers to the last actor to perform an action on the triggering context \
                and can be spoofed by attackers. The github.event.pull_request.user.login context refers to \
                the actor who created the Pull Request and is more reliable for bot detection."
            ),
            apply: Box::new(move |content: &str| -> anyhow::Result<Option<String>> {
                // Parse the YAML to get the current condition
                let mut yaml: serde_yaml::Value = serde_yaml::from_str(content)?;

                // Navigate to the condition using the path
                let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                let mut current = &mut yaml;

                for part in &path_parts[..path_parts.len() - 1] {
                    if let Some(obj) = current.as_mapping_mut() {
                        current = obj
                            .get_mut(part)
                            .ok_or_else(|| anyhow::anyhow!("Path not found: {}", part))?;
                    } else {
                        return Err(anyhow::anyhow!("Expected mapping at path part: {}", part));
                    }
                }

                // Get the condition value and replace github.actor references
                if let Some(obj) = current.as_mapping_mut() {
                    if let Some(condition_value) = obj.get_mut("if") {
                        if let Some(condition_str) = condition_value.as_str() {
                            let updated_condition = condition_str
                                .replace("github.actor", "github.event.pull_request.user.login")
                                .replace("GitHub.actor", "github.event.pull_request.user.login")
                                .replace("GitHub.ACTOR", "github.event.pull_request.user.login")
                                .replace(
                                    "github.triggering_actor",
                                    "github.event.pull_request.user.login",
                                )
                                .replace(
                                    "GitHub.triggering_actor",
                                    "github.event.pull_request.user.login",
                                )
                                .replace(
                                    "GitHub.TRIGGERING_ACTOR",
                                    "github.event.pull_request.user.login",
                                );

                            *condition_value = serde_yaml::Value::String(updated_condition);
                        }
                    }
                }

                Ok(Some(serde_yaml::to_string(&yaml)?))
            }),
        }
    }

    fn walk_tree_for_bot_condition(expr: &Expr, dominating: bool) -> (bool, bool) {
        match expr {
            // We can't easily analyze the call's semantics, but we can
            // check to see if any of the call's arguments are
            // bot conditions. We treat a call as non-dominating always.
            Expr::Call {
                func: _,
                args: exprs,
            }
            | Expr::Context(Context { parts: exprs, .. }) => exprs
                .iter()
                .map(|arg| Self::walk_tree_for_bot_condition(arg, false))
                .reduce(|(bc, _), (bc_next, _)| (bc || bc_next, false))
                .unwrap_or((false, dominating)),
            Expr::Index(expr) => Self::walk_tree_for_bot_condition(expr, dominating),
            Expr::BinOp { lhs, op, rhs } => match op {
                // || is dominating.
                BinOp::Or => {
                    let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                    let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                    (bc_lhs || bc_rhs, true)
                }
                // == is trivially dominating.
                BinOp::Eq => match (lhs.as_ref(), rhs.as_ref()) {
                    (Expr::Context(ctx), Expr::String(s))
                    | (Expr::String(s), Expr::Context(ctx)) => {
                        // NOTE: Can't use `contains` here because we need
                        // Context's `PartialEq` for case insensitive matching.
                        if SPOOFABLE_ACTOR_CONTEXTS.iter().any(|x| ctx == *x)
                            && s.ends_with("[bot]")
                        {
                            (true, true)
                        } else {
                            (false, true)
                        }
                    }
                    (lhs, rhs) => {
                        let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                        let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                        (bc_lhs || bc_rhs, true)
                    }
                },
                // Every other binop is non-dominating.
                _ => {
                    let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, false);
                    let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, false);

                    (bc_lhs || bc_rhs, false)
                }
            },
            Expr::UnOp { op, expr } => match op {
                // We don't really know what we're negating, so naively
                // assume we're non-dominating.
                //
                // TODO: This is slightly incorrect, since we should
                // treat `!(github.actor == 'dependabot[bot]')` as a
                // negative case even though it has an interior bot condition.
                // However, to model this correctly we need to go from a
                // boolean condition to a three-state: `Some(bool)` for
                // an explicitly toggled condition, and `None` for no condition.
                UnOp::Not => Self::walk_tree_for_bot_condition(expr, false),
            },
            _ => (false, dominating),
        }
    }

    fn bot_condition(expr: &str) -> Option<Confidence> {
        // TODO: Remove clones here.
        let bare = match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => raw_expr.as_bare().to_string(),
            None => expr.to_string(),
        };

        let Ok(expr) = Expr::parse(&bare) else {
            tracing::warn!("couldn't parse expression: {expr}");
            return None;
        };

        // We're looking for `github.actor == *[bot]` anywhere in the expression tree.
        // The bot condition is said to "dominate" if controls the entire
        // expression truth value. For example, `github.actor == 'dependabot[bot]' || foo`
        // has the bot condition as dominating, since regardless of `foo` the check
        // always passes if the actor is dependabot[bot].
        match Self::walk_tree_for_bot_condition(&expr, true) {
            // We have a bot condition and it dominates the expression.
            (true, true) => Some(Confidence::High),
            // We have a bot condition but it doesn't dominate the expression.
            (true, false) => Some(Confidence::Medium),
            // No bot condition.
            (..) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{audit::bot_conditions::BotConditions, finding::Confidence};

    #[test]
    fn test_bot_condition() {
        for (cond, confidence) in &[
            // Trivial dominating cases.
            ("github.actor == 'dependabot[bot]'", Confidence::High),
            ("'dependabot[bot]' == github.actor", Confidence::High),
            ("'dependabot[bot]' == GitHub.actor", Confidence::High),
            ("'dependabot[bot]' == GitHub.ACTOR", Confidence::High),
            (
                "'dependabot[bot]' == GitHub.triggering_actor",
                Confidence::High,
            ),
            // Dominating cases with OR.
            (
                "'dependabot[bot]' == github.actor || true",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor || false",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor || github.actor == 'foobar'",
                Confidence::High,
            ),
            (
                "github.actor == 'foobar' || 'dependabot[bot]' == github.actor",
                Confidence::High,
            ),
            // Non-dominating cases with AND.
            (
                "'dependabot[bot]' == github.actor && something.else",
                Confidence::Medium,
            ),
            (
                "something.else && 'dependabot[bot]' == github.actor",
                Confidence::Medium,
            ),
        ] {
            assert_eq!(BotConditions::bot_condition(cond).unwrap(), *confidence);
        }
    }

    #[test]
    fn test_replace_actor_fix() {
        let yaml_content = r#"on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - run: echo "hello"
"#;

        let fix = BotConditions::create_replace_actor_fix("/jobs/test/if".to_string(), true);
        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();

        // Verify that github.actor was replaced with github.event.pull_request.user.login
        assert!(result.contains("github.event.pull_request.user.login == 'dependabot[bot]'"));
        assert!(!result.contains("github.actor == 'dependabot[bot]'"));
    }
}

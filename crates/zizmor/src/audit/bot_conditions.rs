use std::sync::LazyLock;

use github_actions_expressions::{
    BinOp, Expr, UnOp,
    context::{Context, ContextPattern},
};
use github_actions_models::common::{If, expr::ExplicitExpr};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    finding::{
        Confidence, Fix, Severity,
        location::{Locatable as _, Routable as _},
    },
    models::workflow::{JobExt, Step},
    yaml_patch::{Op, Patch},
};

pub(crate) struct BotConditions;

audit_meta!(BotConditions, "bot-conditions", "spoofable bot actor check");

static SPOOFABLE_ACTOR_NAME_CONTEXTS: LazyLock<Vec<ContextPattern>> = LazyLock::new(|| {
    vec![
        ContextPattern::try_new("github.actor").unwrap(),
        ContextPattern::try_new("github.triggering_actor").unwrap(),
        ContextPattern::try_new("github.event.pull_request.sender.login").unwrap(),
    ]
});

static SPOOFABLE_ACTOR_ID_CONTEXTS: LazyLock<Vec<ContextPattern>> = LazyLock::new(|| {
    vec![
        ContextPattern::try_new("github.actor_id").unwrap(),
        ContextPattern::try_new("github.event.pull_request.sender.id").unwrap(),
    ]
});

// A list of known bot actor IDs; we need to hardcode these because they
// have no equivalent `[bot]' suffix check.
//
// Stored as strings because every equality is stringly-typed
// in GHA expressions anyways.
//
// NOTE: This list also contains non-user IDs like integration IDs.
// The thinking there is that users will sometimes confuse the two,
// so we should flag them as well.
const BOT_ACTOR_IDS: &[&str] = &[
    "29110",    //dependabot[bot]'s integration ID
    "49699333", // dependabot[bot]
    "27856297", // dependabot-preview[bot]
    "29139614", // renovate[bot]
];

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

        let mut conds = vec![];
        if let Some(If::Expr(expr)) = &job.r#if {
            conds.push((
                expr,
                job.location_with_name(),
                job.location().with_keys(&["if".into()]),
            ));
        }

        for step in job.steps() {
            if let Some(If::Expr(expr)) = &step.r#if {
                conds.push((
                    expr,
                    step.location_with_name(),
                    step.location().with_keys(&["if".into()]),
                ));
            }
        }

        for (expr, parent, if_loc) in conds {
            if let Some(confidence) = Self::bot_condition(expr) {
                let mut finding_builder = Self::finding()
                    .severity(Severity::High)
                    .confidence(confidence)
                    .add_location(parent.clone())
                    .add_location(if_loc.primary().annotated("actor context may be spoofable"));

                // Add fixes
                if let Some(step) = job.steps().find(|s| s.location().key == parent.key) {
                    let step_ref = &step;
                    if let Some(fix) = Self::create_replace_actor_fix(step_ref) {
                        finding_builder = finding_builder.fix(fix);
                    }
                    finding_builder = finding_builder.fix(Self::create_trigger_change_fix(job));
                    if let Some(fix) = Self::create_remove_condition_fix(step_ref) {
                        finding_builder = finding_builder.fix(fix);
                    }
                }

                findings.push(finding_builder.build(job.parent())?);
            }
        }

        Ok(findings)
    }
}

impl BotConditions {
    fn walk_tree_for_bot_condition(expr: &Expr, dominating: bool) -> (bool, bool) {
        match expr {
            // We can't easily analyze the call's semantics, but we can
            // check to see if any of the call's arguments are
            // bot conditions. We treat a call as non-dominating always.
            // TODO: Should probably check some variant of `contains` here.
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
                    (Expr::Context(ctx), Expr::Literal(lit))
                    | (Expr::Literal(lit), Expr::Context(ctx)) => {
                        if (SPOOFABLE_ACTOR_NAME_CONTEXTS.iter().any(|x| x.matches(ctx))
                            && lit.as_str().ends_with("[bot]"))
                            || (SPOOFABLE_ACTOR_ID_CONTEXTS.iter().any(|x| x.matches(ctx))
                                && BOT_ACTOR_IDS.contains(&lit.as_str().as_ref()))
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

    /// Create a fix that replaces github.actor with github.event.pull_request.user.login
    fn create_replace_actor_fix<'doc>(step: &Step<'doc>) -> Option<Fix<'doc>> {
        // Only emit a patch if the step/job has an `if` key
        if let Some(If::Expr(expr)) = &step.r#if {
            Some(Fix {
                title: "Replace github.actor with github.event.pull_request.user.login".into(),
                description: "Replace github.actor with github.event.pull_request.user.login to ensure the job runs as the PR author".into(),
                _key: step.location().key,
                patches: vec![Patch {
                    route: step.route().with_keys(&["if".into()]),
                    operation: Op::Replace(serde_yaml::Value::String(
                        expr.replace("github.actor", "github.event.pull_request.user.login")
                            .replace("GitHub.actor", "github.event.pull_request.user.login")
                            .replace("GitHub.ACTOR", "github.event.pull_request.user.login")
                            .replace("github.triggering_actor", "github.event.pull_request.user.login")
                            .replace("GitHub.triggering_actor", "github.event.pull_request.user.login")
                            .replace("GitHub.TRIGGERING_ACTOR", "github.event.pull_request.user.login")
                            .into()
                    )),
                }],
            })
        } else {
            None
        }
    }

    /// Create a fix that suggests changing from pull_request_target to pull_request
    fn create_trigger_change_fix<'doc>(job: &impl JobExt<'doc>) -> Fix<'doc> {
        Fix {
            title: "Change trigger from pull_request_target to pull_request".into(),
            description: "Change the workflow trigger from pull_request_target to pull_request to prevent running with elevated permissions".into(),
            _key: job.location().key,
            patches: vec![Patch {
                route: job.parent().location().route.with_keys(&["on".into()]),
                operation: Op::Replace({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("pull_request".into()),
                        serde_yaml::Value::Mapping(Default::default()),
                    );
                    serde_yaml::Value::Mapping(map)
                }),
            }],
        }
    }

    /// Create a fix that removes the bot condition entirely
    fn create_remove_condition_fix<'doc>(step: &Step<'doc>) -> Option<Fix<'doc>> {
        if step.r#if.is_some() {
            Some(Fix {
                title: "Remove bot condition".into(),
                description: "Remove the bot condition to allow the job to run for all PRs".into(),
                _key: step.location().key,
                patches: vec![Patch {
                    route: step.route().with_keys(&["if".into()]),
                    operation: Op::Remove,
                }],
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        finding::Finding, github_api::GitHubHost, models::workflow::Workflow, registry::InputKey,
        state::AuditState,
    };

    /// Macro for testing workflow audits with common boilerplate
    macro_rules! test_workflow_audit {
        ($audit_type:ty, $filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local($filename, None::<&str>).unwrap();
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState {
                config: &Default::default(),
                no_online_audits: false,
                cache_dir: "/tmp/zizmor".into(),
                gh_token: None,
                gh_hostname: GitHubHost::Standard("github.com".into()),
            };
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit.audit_workflow(&workflow).unwrap();

            $test_fn(findings)
        }};
    }

    /// Helper function to apply a fix by title and return the result for snapshot testing
    fn apply_fix_by_title_for_snapshot(
        workflow_content: &str,
        finding: &Finding,
        expected_title: &str,
    ) -> String {
        let fix = finding
            .fixes
            .iter()
            .find(|f| f.title == expected_title)
            .unwrap_or_else(|| panic!("No fix found with title: {}", expected_title));

        fix.apply_to_content(workflow_content)
            .unwrap()
            .unwrap_or_else(|| panic!("Fix application returned None"))
    }

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
        let workflow_content = r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_replace_actor_fix.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                // Apply all fixes in sequence
                let mut content = workflow_content.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                            content = new_content;
                        }
                    }
                }
                insta::assert_snapshot!(content, @r#"
                name: Test Workflow
                on:
                  pull_request: {}

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        run: echo "hello"
                "#);
            }
        );
    }

    #[test]
    fn test_trigger_change_fix() {
        let workflow_content = r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_trigger_change_fix.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let fixed_content = apply_fix_by_title_for_snapshot(
                    workflow_content,
                    &findings[0],
                    "Change trigger from pull_request_target to pull_request",
                );
                insta::assert_snapshot!(fixed_content, @r#"
                name: Test Workflow
                on:
                  pull_request: {}

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.actor == 'dependabot[bot]'
                        run: echo "hello"
                "#);
            }
        );
    }

    #[test]
    fn test_remove_condition_fix() {
        let workflow_content = r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_remove_condition_fix.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let fixed_content = apply_fix_by_title_for_snapshot(
                    workflow_content,
                    &findings[0],
                    "Remove bot condition",
                );
                insta::assert_snapshot!(fixed_content, @r#"
                name: Test Workflow
                on:
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        run: echo "hello"
                "#);
            }
        );
    }

    #[test]
    fn test_all_fixes_together() {
        let workflow_content = r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_all_fixes_together.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                // Apply all fixes in sequence, handling errors gracefully
                let mut content = workflow_content.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                            content = new_content;
                        }
                    }
                }
                insta::assert_snapshot!(content, @r#"
                name: Test Workflow
                on:
                  pull_request: {}

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        run: echo "hello"
                "#);
            }
        );
    }

    #[test]
    fn test_fix_with_complex_conditions() {
        let workflow_content = r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]' && github.event.pull_request.title contains 'chore'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_fix_with_complex_conditions.yml",
            workflow_content,
            |findings: Vec<Finding>| {
                let fixed_content = apply_fix_by_title_for_snapshot(
                    workflow_content,
                    &findings[0],
                    "Replace github.actor with github.event.pull_request.user.login",
                );
                insta::assert_snapshot!(fixed_content, @r#"
                name: Test Workflow
                on:
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.pull_request.user.login == 'dependabot[bot]' && github.event.pull_request.title contains 'chore'
                        run: echo "hello"
                "#);
            }
        );
    }
}

use std::{ops::Deref, sync::LazyLock};

use github_actions_expressions::{
    BinOp, Expr, SpannedExpr, UnOp,
    context::{Context, ContextPattern},
};
use github_actions_models::{
    common::If,
    workflow::event::{BareEvent, OptionalBody},
};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    finding::{
        Confidence, Fix, FixDisposition, Severity,
        location::{Locatable as _, Route, Subfeature},
    },
    models::workflow::{JobExt, Workflow},
    utils::ExtractedExpr,
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

        // Track conditions with explicit categorization
        let mut conds = vec![];

        // Job-level condition
        if let Some(If::Expr(expr)) = &job.r#if {
            conds.push((
                expr,
                job.location_with_name(),
                job.location().with_keys(&["if".into()]),
            ));
        }

        // Step-level conditions
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
            let unparsed = ExtractedExpr::new(expr);

            let Ok(expr) = Expr::parse(unparsed.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}");
                continue;
            };

            if let Some((subfeature, actor_context, confidence)) = Self::bot_condition(&expr) {
                let if_route = if_loc.route.clone();

                let mut finding_builder = Self::finding()
                    .severity(Severity::High)
                    .confidence(confidence)
                    .add_location(parent.clone())
                    .add_location(
                        if_loc
                            .primary()
                            .subfeature(subfeature)
                            .annotated("actor context may be spoofable"),
                    );

                if let Some(fix) = Self::attempt_fix(job.parent(), actor_context, if_route) {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(job.parent())?);
            }
        }

        Ok(findings)
    }
}

impl BotConditions {
    /// Get appropriate user context paths based on workflow trigger events.
    /// Returns (actor_name_context, actor_id_context) for the given workflow.
    fn get_user_contexts_for_triggers(workflow: &Workflow) -> Option<(&str, &str)> {
        use github_actions_models::workflow::Trigger;

        // Check for single specific event types first
        match &workflow.on {
            Trigger::BareEvent(event) => Self::get_contexts_for_event(event),
            Trigger::BareEvents(event_list) if event_list.len() == 1 => {
                Self::get_contexts_for_event(&event_list[0])
            }
            Trigger::Events(event_map) if event_map.count() == 1 => {
                // Check each possible event type
                if !matches!(event_map.issue_comment, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::IssueComment);
                }
                if !matches!(event_map.pull_request, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::PullRequest);
                }
                if !matches!(event_map.pull_request_target, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::PullRequestTarget);
                }
                if !matches!(event_map.discussion_comment, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::DiscussionComment);
                }
                if !matches!(event_map.pull_request_review, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::PullRequestReview);
                }
                if !matches!(event_map.pull_request_review_comment, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::PullRequestReviewComment);
                }
                if !matches!(event_map.issues, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Issues);
                }
                if !matches!(event_map.discussion, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Discussion);
                }
                if !matches!(event_map.release, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Release);
                }
                if !matches!(event_map.push, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Push);
                }
                if !matches!(event_map.milestone, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Milestone);
                }
                if !matches!(event_map.label, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Label);
                }
                if !matches!(event_map.project, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Project);
                }
                if !matches!(event_map.watch, OptionalBody::Missing) {
                    return Self::get_contexts_for_event(&BareEvent::Watch);
                }

                None
            }
            _ => None,
        }
    }

    /// Get context paths for a specific event type.
    fn get_contexts_for_event(event: &BareEvent) -> Option<(&str, &str)> {
        match event {
            BareEvent::IssueComment => Some((
                "github.event.comment.user.login",
                "github.event.comment.user.id",
            )),
            BareEvent::DiscussionComment => Some((
                "github.event.comment.user.login",
                "github.event.comment.user.id",
            )),
            BareEvent::PullRequestReview => Some((
                "github.event.review.user.login",
                "github.event.review.user.id",
            )),
            BareEvent::PullRequestReviewComment => Some((
                "github.event.comment.user.login",
                "github.event.comment.user.id",
            )),
            BareEvent::Issues => Some((
                "github.event.issue.user.login",
                "github.event.issue.user.id",
            )),
            BareEvent::Discussion => Some((
                "github.event.discussion.user.login",
                "github.event.discussion.user.id",
            )),
            BareEvent::PullRequest | BareEvent::PullRequestTarget => Some((
                "github.event.pull_request.user.login",
                "github.event.pull_request.user.id",
            )),
            BareEvent::Release => Some((
                "github.event.release.author.login",
                "github.event.release.author.id",
            )),
            BareEvent::Create | BareEvent::Delete => {
                Some(("github.event.sender.login", "github.event.sender.id"))
            }
            BareEvent::Milestone => Some((
                "github.event.milestone.creator.login",
                "github.event.milestone.creator.id",
            )),
            BareEvent::Label
            | BareEvent::Project
            | BareEvent::Fork
            | BareEvent::Watch
            | BareEvent::Public => Some(("github.event.sender.login", "github.event.sender.id")),
            _ => None,
        }
    }

    /// Walks the expression tree to find a potentially dominating bot condition.
    ///
    /// Returns a two-tuple of `((expr, actor-expr), dominating)`, where
    /// `expr` is the expression that matches a bot condition,
    /// `actor-expr` is the sub-expression for the offending actor context, and
    /// `dominating` is a boolean indicating whether the condition dominates
    /// the overall expression.
    fn walk_tree_for_bot_condition<'a, 'src>(
        expr: &'a SpannedExpr<'src>,
        dominating: bool,
    ) -> (Option<(&'a SpannedExpr<'src>, &'a SpannedExpr<'src>)>, bool) {
        match expr.deref() {
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
                .reduce(|(bc, _), (bc_next, _)| (bc.or(bc_next), false))
                .unwrap_or((None, dominating)),
            Expr::Index(expr) => Self::walk_tree_for_bot_condition(expr, dominating),
            Expr::BinOp { lhs, op, rhs } => match op {
                // || is dominating.
                BinOp::Or => {
                    let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                    let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                    (bc_lhs.or(bc_rhs), true)
                }
                // == is trivially dominating.
                BinOp::Eq => {
                    let context_expr = match (lhs.as_ref().deref(), rhs.as_ref().deref()) {
                        (Expr::Context(_), _) => lhs.as_ref(),
                        (_, Expr::Context(_)) => rhs.as_ref(),
                        _ => return (None, true),
                    };

                    match (lhs.as_ref().deref(), rhs.as_ref().deref()) {
                        (Expr::Context(ctx), Expr::Literal(lit))
                        | (Expr::Literal(lit), Expr::Context(ctx)) => {
                            if (SPOOFABLE_ACTOR_NAME_CONTEXTS.iter().any(|x| x.matches(ctx))
                                && lit.as_str().ends_with("[bot]"))
                                || (SPOOFABLE_ACTOR_ID_CONTEXTS.iter().any(|x| x.matches(ctx))
                                    && BOT_ACTOR_IDS.contains(&lit.as_str().as_ref()))
                            {
                                ((Some((expr, context_expr))), true)
                            } else {
                                (None, true)
                            }
                        }
                        (_, _) => {
                            let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                            let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                            (bc_lhs.or(bc_rhs), true)
                        }
                    }
                }
                // Every other binop is non-dominating.
                _ => {
                    let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, false);
                    let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, false);

                    (bc_lhs.or(bc_rhs), false)
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
            _ => (None, dominating),
        }
    }

    fn bot_condition<'a, 'doc>(
        expr: &'a SpannedExpr<'doc>,
    ) -> Option<(Subfeature<'doc>, &'a SpannedExpr<'doc>, Confidence)> {
        // We're looking for `github.actor == *[bot]` anywhere in the expression tree.
        // The bot condition is said to "dominate" if controls the entire
        // expression truth value. For example, `github.actor == 'dependabot[bot]' || foo`
        // has the bot condition as dominating, since regardless of `foo` the check
        // always passes if the actor is dependabot[bot].
        match Self::walk_tree_for_bot_condition(expr, true) {
            // We have a bot condition and it dominates the expression.
            (Some((expr, context_expr)), true) => {
                Some((Subfeature::new(0, expr), context_expr, Confidence::High))
            }
            // We have a bot condition but it doesn't dominate the expression.
            (Some((expr, context_expr)), false) => {
                Some((Subfeature::new(0, expr), context_expr, Confidence::Medium))
            }
            // No bot condition.
            (..) => None,
        }
    }

    fn attempt_fix<'doc>(
        workflow: &'doc Workflow,
        spoofable_context: &SpannedExpr<'doc>,
        if_route: Route<'doc>,
    ) -> Option<Fix<'doc>> {
        // Get appropriate contexts based on workflow triggers
        let (safe_name_context, safe_id_context) = Self::get_user_contexts_for_triggers(workflow)?;

        // Get the exact spoofable context as it appears in the source;
        // we need this exactly as it appears to perform a reliable patch.
        let spoofable_context_raw = spoofable_context.origin.raw;

        let SpannedExpr {
            origin: _,
            inner: Expr::Context(spoofable_context),
        } = spoofable_context
        else {
            return None;
        };

        // Determine whether we need to replace our offending context
        // with a safe name or ID variant.
        let safe_context = if SPOOFABLE_ACTOR_NAME_CONTEXTS
            .iter()
            .any(|pat| pat.matches(spoofable_context))
        {
            safe_name_context
        } else {
            safe_id_context
        };

        Some(Fix {
            title: "replace spoofable actor context".into(),
            key: &workflow.key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: if_route,
                operation: Op::RewriteFragment {
                    from: spoofable_context_raw.into(),
                    to: safe_context.into(),
                    after: None,
                },
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        finding::Finding,
        github_api::GitHubHost,
        models::{AsDocument, workflow::Workflow},
        registry::InputKey,
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

            $test_fn(&workflow, findings)
        }};
    }

    #[test]
    fn test_bot_condition() {
        for (cond, context, confidence) in &[
            // Trivial dominating cases.
            (
                "github.actor == 'dependabot[bot]'",
                "github.actor",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor",
                "github.actor",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == GitHub.actor",
                "GitHub.actor",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == GitHub.ACTOR",
                "GitHub.ACTOR",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == GitHub.triggering_actor",
                "GitHub.triggering_actor",
                Confidence::High,
            ),
            // Dominating cases with OR.
            (
                "'dependabot[bot]' == github.actor || true",
                "github.actor",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor || false",
                "github.actor",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor || github.actor == 'foobar'",
                "github.actor",
                Confidence::High,
            ),
            (
                "github.actor == 'foobar' || 'dependabot[bot]' == github.actor",
                "github.actor",
                Confidence::High,
            ),
            // Non-dominating cases with AND.
            (
                "'dependabot[bot]' == github.actor && something.else",
                "github.actor",
                Confidence::Medium,
            ),
            (
                "something.else && 'dependabot[bot]' == github.actor",
                "github.actor",
                Confidence::Medium,
            ),
        ] {
            let cond = Expr::parse(cond).unwrap();
            let (_, found_context, found_confidence) = BotConditions::bot_condition(&cond).unwrap();
            assert_eq!(found_context.origin.raw, *context);
            assert_eq!(found_confidence, *confidence);
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
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Apply only the actor replacement fixes to avoid YAML conflicts
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("replace spoofable actor context") {
                            if let Ok(new_content) = fix.apply(&document) {
                                document = new_content;
                            }
                        }
                    }
                }

                insta::assert_snapshot!(document.source(), @r#"
                name: Test Workflow
                on:
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.pull_request.user.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.pull_request.user.login == 'dependabot[bot]'
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
        if: GITHUB['actor'] == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_all_fixes_together.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Apply all fixes in sequence, handling errors gracefully
                let mut document = workflow.as_document().clone();

                for finding in &findings {
                    for fix in &finding.fixes {
                        if let Ok(new_document) = fix.apply(&document) {
                            document = new_document;
                        }
                    }
                }
                insta::assert_snapshot!(document.source(), @r#"
                name: Test Workflow
                on:
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.pull_request.user.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.pull_request.user.login == 'dependabot[bot]'
                        run: echo "hello"
                "#);
            }
        );
    }

    #[test]
    fn test_event_specific_contexts() {
        // Test issue_comment event
        let issue_comment_workflow = r#"
name: Test Issue Comment
on: issue_comment

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.ACTOR == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_issue_comment.yml",
            issue_comment_workflow,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Should suggest github.event.comment.user.login for issue_comment
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("replace spoofable actor context") {
                            if let Ok(new_document) = fix.apply(&document) {
                                document = new_document;
                            }
                        }
                    }
                }

                // Verify it suggests comment.user.login for issue_comment events
                insta::assert_snapshot!(document.source(), @r#"
                name: Test Issue Comment
                on: issue_comment

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.comment.user.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.comment.user.login == 'dependabot[bot]'
                        run: echo "hello"
                "#);
            }
        );

        // Test pull_request_review event
        let pr_review_workflow = r#"
name: Test PR Review
on: pull_request_review

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
            "test_pr_review.yml",
            pr_review_workflow,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Should suggest github.event.review.user.login for pull_request_review
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("replace spoofable actor context") {
                            if let Ok(new_document) = fix.apply(&document) {
                                document = new_document;
                            }
                        }
                    }
                }

                // Verify it suggests review.user.login for pull_request_review events
                insta::assert_snapshot!(document.source(), @r#"
                name: Test PR Review
                on: pull_request_review

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.review.user.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.review.user.login == 'dependabot[bot]'
                        run: echo "hello"
                "#);
            }
        );

        // Test issues event
        let issues_workflow = r#"
name: Test Issues
on: issues

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
            "test_issues.yml",
            issues_workflow,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Should suggest github.event.issue.user.login for issues
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("replace spoofable actor context") {
                            if let Ok(new_document) = fix.apply(&document) {
                                document = new_document;
                            }
                        }
                    }
                }

                // Verify it suggests issue.user.login for issues events
                insta::assert_snapshot!(document.source(), @r#"
                name: Test Issues
                on: issues

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.issue.user.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.issue.user.login == 'dependabot[bot]'
                        run: echo "hello"
                "#);
            }
        );

        // Test release event
        let release_workflow = r#"
name: Test Release
on: release

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
            "test_release.yml",
            release_workflow,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Should suggest github.event.release.author.login for release
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("replace spoofable actor context") {
                            if let Ok(new_document) = fix.apply(&document) {
                                document = new_document;
                            }
                        }
                    }
                }

                // Verify it suggests release.author.login for release events
                insta::assert_snapshot!(document.source(), @r#"
                name: Test Release
                on: release

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.release.author.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.release.author.login == 'dependabot[bot]'
                        run: echo "hello"
                "#);
            }
        );

        // Test create event
        let create_workflow = r#"
name: Test Create
on: create

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
            "test_create.yml",
            create_workflow,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Should suggest github.event.sender.login for create
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("replace spoofable actor context") {
                            if let Ok(new_document) = fix.apply(&document) {
                                document = new_document;
                            }
                        }
                    }
                }

                insta::assert_snapshot!(document.source(), @r#"
                name: Test Create
                on: create

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.sender.login == 'dependabot[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.sender.login == 'dependabot[bot]'
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
        if: github.actor == 'dependabot[bot]' && contains(github.event.pull_request.title, 'chore')
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_fix_with_complex_conditions.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<Finding>| {
                // Apply all fixes
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if let Ok(new_document) = fix.apply(&document) {
                            document = new_document;
                        }
                    }
                }

                insta::assert_snapshot!(document.source(), @r#"
                name: Test Workflow
                on:
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.event.pull_request.user.login == 'dependabot[bot]' || github.actor == 'renovate[bot]'
                    steps:
                      - name: Test Step
                        if: github.event.pull_request.user.login == 'dependabot[bot]' && contains(github.event.pull_request.title, 'chore')
                        run: echo "hello"
                "#);
            }
        );
    }
}

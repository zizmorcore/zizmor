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
        Confidence, Fix, Severity,
        location::{Locatable as _, Routable as _, Subfeature},
    },
    models::workflow::{JobExt, Step, Workflow},
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

        // Check if this workflow has events where bot conditions are relevant
        if !Self::has_relevant_events(job.parent()) {
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
            if let Some((subfeature, confidence)) = Self::bot_condition(expr) {
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

                // Add fixes
                if let Some(step) = job.steps().find(|s| s.location().key == parent.key) {
                    // Step-level condition
                    let step_ref = &step;
                    if let Some(fix) = Self::create_replace_actor_fix(step_ref) {
                        finding_builder = finding_builder.fix(fix);
                    }
                } else if parent.key == job.location().key {
                    // Job-level condition - parse the expression first
                    let bare_expr = ExtractedExpr::new(expr).as_bare().to_string();

                    if let Ok(parsed_expr) = Expr::parse(&bare_expr) {
                        if let Some(fix) = Self::create_replace_actor_fix_for_job(job, &parsed_expr)
                        {
                            finding_builder = finding_builder.fix(fix);
                        }
                    }
                }

                findings.push(finding_builder.build(job.parent())?);
            }
        }

        Ok(findings)
    }
}

impl BotConditions {
    /// Check if the workflow has events where bot conditions are relevant.
    fn has_relevant_events(workflow: &Workflow) -> bool {
        use github_actions_models::workflow::Trigger;

        match &workflow.on {
            Trigger::BareEvent(event) => Self::is_relevant_event(event),
            Trigger::BareEvents(event_list) => {
                event_list.iter().any(|event| Self::is_relevant_event(event))
            }
            Trigger::Events(event_map) => {
                !matches!(event_map.issue_comment, OptionalBody::Missing) ||
                !matches!(event_map.pull_request, OptionalBody::Missing) ||
                !matches!(event_map.pull_request_target, OptionalBody::Missing) ||
                !matches!(event_map.discussion_comment, OptionalBody::Missing) ||
                !matches!(event_map.pull_request_review, OptionalBody::Missing) ||
                !matches!(event_map.pull_request_review_comment, OptionalBody::Missing) ||
                !matches!(event_map.issues, OptionalBody::Missing) ||
                !matches!(event_map.discussion, OptionalBody::Missing) ||
                !matches!(event_map.release, OptionalBody::Missing) ||
                !matches!(event_map.push, OptionalBody::Missing) ||
                !matches!(event_map.milestone, OptionalBody::Missing) ||
                !matches!(event_map.label, OptionalBody::Missing) ||
                !matches!(event_map.project, OptionalBody::Missing) ||
                !matches!(event_map.watch, OptionalBody::Missing)
            }
        }
    }

    /// Check if a specific event type is relevant for bot condition checks.
    fn is_relevant_event(event: &BareEvent) -> bool {
        matches!(event,
            BareEvent::IssueComment |
            BareEvent::DiscussionComment |
            BareEvent::PullRequestReview |
            BareEvent::PullRequestReviewComment |
            BareEvent::Issues |
            BareEvent::Discussion |
            BareEvent::PullRequest |
            BareEvent::PullRequestTarget |
            BareEvent::Release |
            BareEvent::Create |
            BareEvent::Delete |
            BareEvent::Push |
            BareEvent::Milestone |
            BareEvent::Label |
            BareEvent::Project |
            BareEvent::Fork |
            BareEvent::Watch |
            BareEvent::Public
        )
    }

    /// Get appropriate user context paths based on workflow trigger events.
    /// Returns (actor_name_context, actor_id_context) for the given workflow.
    fn get_user_contexts_for_triggers(workflow: &Workflow) -> (String, String) {
        use github_actions_models::workflow::Trigger;

        // Check for single specific event types first
        match &workflow.on {
            Trigger::BareEvent(event) => {
                return Self::get_contexts_for_event(event);
            }
            Trigger::BareEvents(event_list) => {
                if event_list.len() == 1 {
                    return Self::get_contexts_for_event(&event_list[0]);
                }
            }
            Trigger::Events(event_map) => {
                if event_map.count() == 1 {
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
                }
            }
        }

        // For multiple events or unknown events, default to pull request context
        ("github.event.pull_request.user.login".to_string(),
         "github.event.pull_request.user.id".to_string())
    }

    /// Get context paths for a specific event type.
    fn get_contexts_for_event(event: &BareEvent) -> (String, String) {
        match event {
            BareEvent::IssueComment => {
                ("github.event.comment.user.login".to_string(),
                 "github.event.comment.user.id".to_string())
            }
            BareEvent::DiscussionComment => {
                ("github.event.comment.user.login".to_string(),
                 "github.event.comment.user.id".to_string())
            }
            BareEvent::PullRequestReview => {
                ("github.event.review.user.login".to_string(),
                 "github.event.review.user.id".to_string())
            }
            BareEvent::PullRequestReviewComment => {
                ("github.event.comment.user.login".to_string(),
                 "github.event.comment.user.id".to_string())
            }
            BareEvent::Issues => {
                ("github.event.issue.user.login".to_string(),
                 "github.event.issue.user.id".to_string())
            }
            BareEvent::Discussion => {
                ("github.event.discussion.user.login".to_string(),
                 "github.event.discussion.user.id".to_string())
            }
            BareEvent::PullRequest | BareEvent::PullRequestTarget => {
                ("github.event.pull_request.user.login".to_string(),
                 "github.event.pull_request.user.id".to_string())
            }
            BareEvent::Release => {
                ("github.event.release.author.login".to_string(),
                 "github.event.release.author.id".to_string())
            }
            BareEvent::Create | BareEvent::Delete => {
                ("github.event.sender.login".to_string(),
                 "github.event.sender.id".to_string())
            }
            BareEvent::Push => {
                ("github.event.pusher.name".to_string(),
                 "github.event.pusher.email".to_string())
            }
            BareEvent::Milestone => {
                ("github.event.milestone.creator.login".to_string(),
                 "github.event.milestone.creator.id".to_string())
            }
            BareEvent::Label | BareEvent::Project | BareEvent::Fork | BareEvent::Watch | BareEvent::Public => {
                ("github.event.sender.login".to_string(),
                 "github.event.sender.id".to_string())
            }
            _ => {
                // For unknown events, default to pull request context
                ("github.event.pull_request.user.login".to_string(),
                 "github.event.pull_request.user.id".to_string())
            }
        }
    }

    fn walk_tree_for_bot_condition<'a, 'src>(
        expr: &'a SpannedExpr<'src>,
        dominating: bool,
    ) -> (Option<&'a SpannedExpr<'src>>, bool) {
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
                BinOp::Eq => match (lhs.as_ref().deref(), rhs.as_ref().deref()) {
                    (Expr::Context(ctx), Expr::Literal(lit))
                    | (Expr::Literal(lit), Expr::Context(ctx)) => {
                        if (SPOOFABLE_ACTOR_NAME_CONTEXTS.iter().any(|x| x.matches(ctx))
                            && lit.as_str().ends_with("[bot]"))
                            || (SPOOFABLE_ACTOR_ID_CONTEXTS.iter().any(|x| x.matches(ctx))
                                && BOT_ACTOR_IDS.contains(&lit.as_str().as_ref()))
                        {
                            ((Some(expr)), true)
                        } else {
                            (None, true)
                        }
                    }
                    (_, _) => {
                        let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                        let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                        (bc_lhs.or(bc_rhs), true)
                    }
                },
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

    fn bot_condition<'doc>(expr: &'doc str) -> Option<(Subfeature<'doc>, Confidence)> {
        let unparsed = ExtractedExpr::new(expr);

        let Ok(expr) = Expr::parse(unparsed.as_bare()) else {
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
            (Some(expr), true) => Some((Subfeature::new(0, expr), Confidence::High)),
            // We have a bot condition but it doesn't dominate the expression.
            (Some(expr), false) => Some((Subfeature::new(0, expr), Confidence::Medium)),
            // No bot condition.
            (..) => None,
        }
    }

    /// Find spoofable actor contexts in an expression and return their string representations
    fn find_spoofable_actor_fragments(expr: &Expr) -> Vec<String> {
        let mut fragments = vec![];

        match expr {
            Expr::Call {
                func: _,
                args: exprs,
            }
            | Expr::Context(Context { parts: exprs, .. }) => {
                for arg in exprs {
                    fragments.extend(Self::find_spoofable_actor_fragments(arg));
                }
            }
            Expr::Index(expr) => {
                fragments.extend(Self::find_spoofable_actor_fragments(expr));
            }
            Expr::BinOp { lhs, op, rhs } => {
                if let BinOp::Eq = op {
                    match (lhs.as_ref().deref(), rhs.as_ref().deref()) {
                        (Expr::Context(ctx), Expr::Literal(lit))
                        | (Expr::Literal(lit), Expr::Context(ctx)) => {
                            if (SPOOFABLE_ACTOR_NAME_CONTEXTS.iter().any(|x| x.matches(ctx))
                                && lit.as_str().ends_with("[bot]"))
                                || (SPOOFABLE_ACTOR_ID_CONTEXTS.iter().any(|x| x.matches(ctx))
                                    && BOT_ACTOR_IDS.contains(&lit.as_str().as_ref()))
                            {
                                // Convert context to string representation
                                let ctx_str = ctx.parts.iter()
                                    .map(|part| part.raw)
                                    .collect::<Vec<_>>()
                                    .join(".");
                                fragments.push(ctx_str);
                            }
                        }
                        _ => {}
                    }
                }

                fragments.extend(Self::find_spoofable_actor_fragments(lhs));
                fragments.extend(Self::find_spoofable_actor_fragments(rhs));
            }
            Expr::UnOp { expr, .. } => {
                fragments.extend(Self::find_spoofable_actor_fragments(expr));
            }
            _ => {}
        }

        fragments
    }

    /// Create a fix that replaces spoofable actor contexts with github.event.pull_request.user.login
    fn create_replace_actor_fix<'doc>(step: &Step<'doc>) -> Option<Fix<'doc>> {
        // Only emit a patch if the step/job has an `if` key
        if let Some(If::Expr(expr)) = &step.r#if {
            // Try to parse as curly expression first, otherwise use the raw string
            let bare_expr = ExtractedExpr::new(expr).as_bare().to_string();

            let Ok(parsed_expr) = Expr::parse(&bare_expr) else {
                return None;
            };

            // Find all spoofable actor fragments in the expression
            let fragments = Self::find_spoofable_actor_fragments(&parsed_expr);

            if fragments.is_empty() {
                return None;
            }

            // Get appropriate contexts based on workflow triggers
            let (actor_name_context, actor_id_context) =
                Self::get_user_contexts_for_triggers(step.workflow());

            // Create patches for each unique fragment
            let mut patches = vec![];
            let mut seen_fragments = std::collections::HashSet::new();

            for fragment in fragments {
                if seen_fragments.insert(fragment.clone()) {
                    // Replace the fragment with the secure alternative
                    let replacement = if SPOOFABLE_ACTOR_NAME_CONTEXTS.iter().any(|pattern| {
                        // Parse the fragment to check if it matches our patterns
                        if let Ok(test_expr) = Expr::parse(&fragment) {
                            if let Expr::Context(ctx) = test_expr.deref() {
                                pattern.matches(ctx)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }) {
                        actor_name_context.clone()
                    } else {
                        // This is an actor_id context, replace with user.id
                        actor_id_context.clone()
                    };

                    patches.push(Patch {
                        route: step.route().with_keys(&["if".into()]),
                        operation: Op::RewriteFragment {
                            from: fragment.clone().into(),
                            to: replacement.into(),
                            after: None,
                        },
                    });
                }
            }

            if !patches.is_empty() {
                Some(Fix {
                    title: format!("Replace spoofable actor context with {}", actor_name_context),
                    description: format!("Replace spoofable actor context with {} to ensure the job runs as the event author", actor_name_context),
                    key: step.location().key,
                    patches,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Create a fix for job-level conditions
    fn create_replace_actor_fix_for_job<'doc>(
        job: &super::NormalJob<'doc>,
        expr: &Expr,
    ) -> Option<Fix<'doc>> {
        let mut patches = vec![];

        let fragments = Self::find_spoofable_actor_fragments(expr);

        if fragments.is_empty() {
            return None;
        }

        // Get appropriate contexts based on workflow triggers
        let (actor_name_context, actor_id_context) =
            Self::get_user_contexts_for_triggers(job.parent());

        let mut seen_fragments = std::collections::HashSet::new();

        for fragment in fragments {
            if seen_fragments.insert(fragment.clone()) {
                let replacement = if SPOOFABLE_ACTOR_NAME_CONTEXTS.iter().any(|pattern| {
                    if let Ok(test_expr) = Expr::parse(&fragment) {
                        if let Expr::Context(ctx) = test_expr.deref() {
                            pattern.matches(ctx)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }) {
                    actor_name_context.clone()
                } else {
                    actor_id_context.clone()
                };

                patches.push(Patch {
                    route: job.location().route.with_keys(&["if".into()]),
                    operation: Op::RewriteFragment {
                        from: fragment.clone().into(),
                        to: replacement.into(),
                        after: None,
                    },
                });
            }
        }

        if !patches.is_empty() {
            Some(Fix {
                title: format!("Replace spoofable actor context with {} for job-level condition", actor_name_context),
                description: format!("Replace spoofable actor context with {} for job-level condition to ensure the job runs as the event author", actor_name_context),
                key: job.location().key,
                patches,
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
            assert_eq!(BotConditions::bot_condition(cond).unwrap().1, *confidence);
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
                // Apply only the actor replacement fixes to avoid YAML conflicts
                let mut content = workflow_content.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("Replace spoofable actor context") {
                            if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                                content = new_content;
                            }
                        }
                    }
                }

                insta::assert_snapshot!(content, @r#"
                name: Test Workflow
                on:
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]'
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
                  pull_request_target:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    if: github.actor == 'dependabot[bot]'
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
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

        test_workflow_audit!(
            BotConditions,
            "test_issue_comment.yml",
            issue_comment_workflow,
            |findings: Vec<Finding>| {
                // Should suggest github.event.comment.user.login for issue_comment
                let mut content = issue_comment_workflow.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("Replace spoofable actor context") {
                            if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                                content = new_content;
                            }
                        }
                    }
                }

                // Verify it suggests comment.user.login for issue_comment events
                assert!(content.contains("github.event.comment.user.login"));
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
            |findings: Vec<Finding>| {
                // Should suggest github.event.review.user.login for pull_request_review
                let mut content = pr_review_workflow.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("Replace spoofable actor context") {
                            if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                                content = new_content;
                            }
                        }
                    }
                }

                // Verify it suggests review.user.login for pull_request_review events
                assert!(content.contains("github.event.review.user.login"));
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
            |findings: Vec<Finding>| {
                // Should suggest github.event.issue.user.login for issues
                let mut content = issues_workflow.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("Replace spoofable actor context") {
                            if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                                content = new_content;
                            }
                        }
                    }
                }

                // Verify it suggests issue.user.login for issues events
                assert!(content.contains("github.event.issue.user.login"));
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
            |findings: Vec<Finding>| {
                // Should suggest github.event.release.author.login for release
                let mut content = release_workflow.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("Replace spoofable actor context") {
                            if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                                content = new_content;
                            }
                        }
                    }
                }

                // Verify it suggests release.author.login for release events
                assert!(content.contains("github.event.release.author.login"));
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
            |findings: Vec<Finding>| {
                // Should suggest github.event.sender.login for create
                let mut content = create_workflow.to_string();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if fix.title.contains("Replace spoofable actor context") {
                            if let Ok(Some(new_content)) = fix.apply_to_content(&content) {
                                content = new_content;
                            }
                        }
                    }
                }

                // Verify it suggests sender.login for create events
                assert!(content.contains("github.event.sender.login"));
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
            |findings: Vec<Finding>| {
                let fixed_content = apply_fix_by_title_for_snapshot(
                    workflow_content,
                    &findings[0],
                    "Replace spoofable actor context with github.event.pull_request.user.login",
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
                        if: github.event.pull_request.user.login == 'dependabot[bot]' && contains(github.event.pull_request.title, 'chore')
                        run: echo "hello"
                "#);
            }
        );
    }
}

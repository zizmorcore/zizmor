//! Audits GitHub Actions workflows for risky AI agent action configurations.
//!
//! AI-powered "agentic" actions (Claude Code Action, Codex, Gemini CLI, etc.)
//! execute LLM-driven agents that can read code, run commands, and create
//! pull requests. Misconfigured workflows can expose these agents to prompt
//! injection via attacker-controlled data (issue bodies, PR titles, comments).
//!
//! This audit detects:
//! - Attacker-controllable triggers that let untrusted users invoke an agent
//! - Attacker-controlled expressions flowing directly into agent prompt fields
//! - Missing tool restrictions on Gemini actions
//! - Dangerous sandbox, safety-strategy, or claude_args overrides
//! - Archived actions that should be migrated to their replacements

use std::sync::LazyLock;

use github_actions_models::common::{EnvValue, If, Uses};
use github_actions_models::workflow::Trigger;
use github_actions_models::workflow::event::{BareEvent, BranchFilters, OptionalBody, PathFilters};
use github_actions_models::workflow::job::StepBody;

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::audit::AuditError;
use crate::finding::location::Locatable as _;
use crate::models::uses::RepositoryUsesPattern;
use crate::models::workflow::{NormalJob, Step, Workflow};
use crate::{
    AuditState,
    finding::{Confidence, Severity},
};

/// Per-action configuration for risk signal checks.
struct ActionConfig {
    /// `with:` keys that control which users can trigger the
    /// agent. A wildcard value (`*`) in these fields is
    /// permissive.
    user_permission_keys: &'static [&'static str],
    /// Whether this action needs a tool-restriction check
    /// (Gemini `coreTools`/`excludeTools` in `settings`).
    check_tool_restriction: bool,
    /// If set, this action is archived and should be replaced.
    replacement: Option<&'static str>,
    /// `sandbox` values that grant unrestricted shell access.
    dangerous_sandbox_values: &'static [&'static str],
}

static AGENTIC_ACTIONS: LazyLock<Vec<(RepositoryUsesPattern, ActionConfig)>> =
    LazyLock::new(|| {
        vec![
            (
                "anthropics/claude-code-action"
                    .parse()
                    .expect("valid pattern"),
                ActionConfig {
                    user_permission_keys: &["allowed_non_write_users", "allowed_bots"],
                    check_tool_restriction: false,
                    replacement: None,
                    dangerous_sandbox_values: &[],
                },
            ),
            (
                "google-gemini/gemini-cli-action"
                    .parse()
                    .expect("valid pattern"),
                ActionConfig {
                    user_permission_keys: &[],
                    check_tool_restriction: true,
                    replacement: Some("google-github-actions/run-gemini-cli"),
                    dangerous_sandbox_values: &[],
                },
            ),
            (
                "google-github-actions/run-gemini-cli"
                    .parse()
                    .expect("valid pattern"),
                ActionConfig {
                    user_permission_keys: &[],
                    check_tool_restriction: true,
                    replacement: None,
                    dangerous_sandbox_values: &[],
                },
            ),
            (
                "openai/codex-action".parse().expect("valid pattern"),
                ActionConfig {
                    user_permission_keys: &["allow-users", "allow-bots"],
                    check_tool_restriction: false,
                    replacement: None,
                    dangerous_sandbox_values: &["danger-full-access"],
                },
            ),
            (
                "actions/ai-inference".parse().expect("valid pattern"),
                ActionConfig {
                    user_permission_keys: &[],
                    check_tool_restriction: false,
                    replacement: None,
                    dangerous_sandbox_values: &[],
                },
            ),
        ]
    });

const ATTACKER_CONTROLLABLE_TRIGGERS: &[BareEvent] = &[
    BareEvent::IssueComment,
    BareEvent::Issues,
    BareEvent::PullRequestTarget,
    BareEvent::PullRequest,
    BareEvent::PullRequestReview,
    BareEvent::PullRequestReviewComment,
    BareEvent::DiscussionComment,
    BareEvent::Discussion,
];

const ATTACKER_CONTROLLED_PATTERNS: &[&str] = &[
    "${{ github.event.issue.title }}",
    "${{ github.event.issue.body }}",
    "${{ github.event.comment.body }}",
    "${{ github.event.pull_request.title }}",
    "${{ github.event.pull_request.body }}",
    "${{ github.event.pull_request.head.ref }}",
    "${{ github.event.pull_request.head.sha }}",
    "${{ github.event.review.body }}",
    "${{ github.event.discussion.title }}",
    "${{ github.event.discussion.body }}",
    "${{ github.event.head_commit.message }}",
    "${{ github.event.head_commit.author.email }}",
    "${{ github.event.head_commit.author.name }}",
    "${{ github.head_ref }}",
];

const EXPANDABLE_COMMANDS: &[&str] =
    &["echo", "cat", "printf", "tee", "head", "tail", "wc", "sort"];

struct TriggerWithGates {
    name: &'static str,
    gates: Vec<String>,
}

pub(crate) struct AgenticActions;

audit_meta!(
    AgenticActions,
    "agentic-actions",
    "risky AI agent action configuration"
);

#[async_trait::async_trait]
impl Audit for AgenticActions {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        let dangerous_triggers = self.dangerous_triggers(workflow);

        for job in workflow.jobs() {
            let Job::NormalJob(job) = job else {
                continue;
            };

            for step in job.steps() {
                let StepBody::Uses { uses, with } = &step.body else {
                    continue;
                };
                let Uses::Repository(repo_uses) = uses else {
                    continue;
                };
                let Some(config) = AGENTIC_ACTIONS
                    .iter()
                    .find(|(pat, _)| pat.matches(repo_uses))
                    .map(|(_, cfg)| cfg)
                else {
                    continue;
                };

                findings.extend(self.check_archived_action(workflow, &step, config)?);
                findings.extend(self.check_permissive_users(workflow, &step, with, config)?);
                findings.extend(self.check_attacker_triggers(
                    workflow,
                    &step,
                    &job,
                    &dangerous_triggers,
                )?);
                findings.extend(self.check_attacker_expressions(workflow, &step, with)?);
                findings.extend(self.check_gemini_config(workflow, &step, with, config)?);
                findings.extend(self.check_sandbox_config(workflow, &step, with, config)?);
                findings.extend(self.check_safety_overrides(workflow, &step, with)?);
            }
        }

        Ok(findings)
    }
}

impl AgenticActions {
    fn dangerous_triggers(&self, workflow: &Workflow) -> Vec<TriggerWithGates> {
        let mut triggers = vec![];

        for event in ATTACKER_CONTROLLABLE_TRIGGERS {
            if !self.has_trigger(workflow, event) {
                continue;
            }

            let name = match event {
                BareEvent::IssueComment => "issue_comment",
                BareEvent::Issues => "issues",
                BareEvent::PullRequestTarget => "pull_request_target",
                BareEvent::PullRequest => "pull_request",
                BareEvent::PullRequestReview => "pull_request_review",
                BareEvent::PullRequestReviewComment => "pull_request_review_comment",
                BareEvent::DiscussionComment => "discussion_comment",
                BareEvent::Discussion => "discussion",
                _ => "unknown",
            };

            let gates = if let Trigger::Events(events) = &workflow.on {
                match event {
                    BareEvent::PullRequest => Self::collect_pr_gates(&events.pull_request, name),
                    BareEvent::PullRequestTarget => {
                        Self::collect_pr_gates(&events.pull_request_target, name)
                    }
                    _ => {
                        let body = match event {
                            BareEvent::IssueComment => &events.issue_comment,
                            BareEvent::Issues => &events.issues,
                            BareEvent::PullRequestReview => &events.pull_request_review,
                            BareEvent::PullRequestReviewComment => {
                                &events.pull_request_review_comment
                            }
                            BareEvent::Discussion => &events.discussion,
                            BareEvent::DiscussionComment => &events.discussion_comment,
                            _ => continue,
                        };
                        match body {
                            OptionalBody::Body(ge) if !ge.types.is_empty() => {
                                vec![format!(
                                    "{name} types [{}]",
                                    Self::summarize_list(&ge.types, 3)
                                )]
                            }
                            _ => vec![],
                        }
                    }
                }
            } else {
                vec![]
            };

            triggers.push(TriggerWithGates { name, gates });
        }

        triggers
    }

    fn has_trigger(&self, workflow: &Workflow, event: &BareEvent) -> bool {
        match &workflow.on {
            Trigger::BareEvent(e) => e == event,
            Trigger::BareEvents(events) => events.contains(event),
            Trigger::Events(events) => match event {
                BareEvent::IssueComment => !matches!(events.issue_comment, OptionalBody::Missing),
                BareEvent::Issues => !matches!(events.issues, OptionalBody::Missing),
                BareEvent::PullRequestTarget => {
                    !matches!(events.pull_request_target, OptionalBody::Missing)
                }
                BareEvent::PullRequest => !matches!(events.pull_request, OptionalBody::Missing),
                BareEvent::PullRequestReview => {
                    !matches!(events.pull_request_review, OptionalBody::Missing)
                }
                BareEvent::PullRequestReviewComment => {
                    !matches!(events.pull_request_review_comment, OptionalBody::Missing)
                }
                BareEvent::DiscussionComment => {
                    !matches!(events.discussion_comment, OptionalBody::Missing)
                }
                BareEvent::Discussion => !matches!(events.discussion, OptionalBody::Missing),
                _ => false,
            },
        }
    }

    fn collect_pr_gates(
        body: &OptionalBody<github_actions_models::workflow::event::PullRequest>,
        name: &str,
    ) -> Vec<String> {
        let OptionalBody::Body(pr) = body else {
            return vec![];
        };

        let mut gates = vec![];

        if !pr.types.is_empty() {
            gates.push(format!(
                "{name} types [{}]",
                Self::summarize_list(&pr.types, 3)
            ));
        }

        if let Some(bf) = &pr.branch_filters {
            match bf {
                BranchFilters::Branches(b) => {
                    gates.push(format!("{name} branches [{}]", Self::summarize_list(b, 3)));
                }
                BranchFilters::BranchesIgnore(b) => {
                    gates.push(format!(
                        "{name} branches-ignore [{}]",
                        Self::summarize_list(b, 3)
                    ));
                }
            }
        }

        if let Some(pf) = &pr.path_filters {
            match pf {
                PathFilters::Paths(p) => {
                    gates.push(format!("{name} paths [{}]", Self::summarize_list(p, 3)));
                }
                PathFilters::PathsIgnore(p) => {
                    gates.push(format!(
                        "{name} paths-ignore [{}]",
                        Self::summarize_list(p, 3)
                    ));
                }
            }
        }

        gates
    }

    fn summarize_list(items: &[String], max: usize) -> String {
        if items.len() <= max {
            items.join(", ")
        } else {
            format!("{}, ... ({} total)", items[..max].join(", "), items.len())
        }
    }

    fn check_archived_action<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        config: &ActionConfig,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let Some(replacement) = config.replacement else {
            return Ok(vec![]);
        };
        Ok(vec![
            Self::finding()
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(["uses".into()])
                        .annotated(format!("archived; migrate to {replacement}")),
                )
                .build(workflow)?,
        ])
    }

    fn check_permissive_users<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        with: &indexmap::IndexMap<String, EnvValue>,
        config: &ActionConfig,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        for key in config.user_permission_keys {
            if matches!(with.get(*key), Some(EnvValue::String(s)) if s == "*") {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into(), (*key).into()])
                                .annotated(format!(
                                    "{key}: '*' allows untrusted users to invoke this agent"
                                )),
                        )
                        .build(workflow)?,
                );
            }
        }
        Ok(findings)
    }

    fn check_attacker_triggers<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        job: &NormalJob<'doc>,
        triggers: &[TriggerWithGates],
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        for trigger in triggers {
            let mut all_gates = trigger.gates.clone();
            if let Some(If::Expr(expr)) = &job.r#if {
                all_gates.push(format!("job if [{expr}]"));
            }
            if let Some(If::Expr(expr)) = &step.r#if {
                all_gates.push(format!("step if [{expr}]"));
            }

            let mut builder = Self::finding()
                .severity(Severity::Medium)
                .confidence(Confidence::Medium)
                .add_location(step.location().with_keys(["uses".into()]))
                .add_location(
                    workflow
                        .location()
                        .primary()
                        .with_keys(["on".into()])
                        .annotated(format!(
                            "{} lets untrusted users trigger this agent",
                            trigger.name
                        )),
                );

            builder = if all_gates.is_empty() {
                builder.tip("no gates detected — any user can trigger this agent")
            } else {
                builder.tip(format!(
                    "detected gates that may limit exposure:\n{}",
                    all_gates
                        .iter()
                        .map(|g| format!("  • {g}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            };

            findings.push(builder.build(workflow)?);
        }
        Ok(findings)
    }

    fn check_attacker_expressions<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        with: &'doc indexmap::IndexMap<String, EnvValue>,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        for (key, value) in with {
            let EnvValue::String(s) = value else { continue };
            let Some(pattern) = ATTACKER_CONTROLLED_PATTERNS
                .iter()
                .find(|pat| s.contains(**pat))
                .copied()
            else {
                continue;
            };
            findings.push(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["with".into(), key.as_str().into()])
                            .annotated(format!(
                                "attacker-controlled {pattern} flows into agent prompt"
                            )),
                    )
                    .build(workflow)?,
            );
        }
        Ok(findings)
    }

    fn check_gemini_config<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        with: &indexmap::IndexMap<String, EnvValue>,
        config: &ActionConfig,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        if !config.check_tool_restriction {
            return Ok(vec![]);
        }

        let mut findings = vec![];
        let has_settings_key = with.contains_key("settings");
        let settings = with.get("settings").and_then(|v| match v {
            EnvValue::String(s) => serde_json::from_str(s)
                .inspect_err(|e| {
                    tracing::warn!("agentic-actions: malformed JSON in settings field: {e}");
                })
                .ok(),
            _ => None,
        });

        let has_restriction = settings.as_ref().is_some_and(|s: &serde_json::Value| {
            s.get("tools")
                .is_some_and(|t| t.get("core").is_some() || t.get("exclude").is_some())
        });
        if !has_restriction {
            let loc = if has_settings_key {
                step.location()
                    .primary()
                    .with_keys(["with".into(), "settings".into()])
                    .annotated("settings missing tools.core or tools.exclude restriction")
            } else {
                step.location()
                    .primary()
                    .with_keys(["with".into()])
                    .annotated("missing settings with tools.core or tools.exclude restriction")
            };
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::High)
                    .add_location(step.location().with_keys(["uses".into()]))
                    .add_location(loc)
                    .build(workflow)?,
            );
        }

        if let Some(settings) = &settings {
            if let Some(tools) = settings
                .get("tools")
                .and_then(|t| t.get("core"))
                .and_then(|v| v.as_array())
                && tools
                    .iter()
                    .any(|t| t.as_str().is_some_and(Self::is_dangerous_tool_specifier))
            {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into(), "settings".into()])
                                .annotated("tools.core includes unrestricted run_shell_command"),
                        )
                        .build(workflow)?,
                );
            }

            if settings.get("sandbox").and_then(|v| v.as_bool()) == Some(false) {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into(), "settings".into()])
                                .annotated("sandbox disabled — agent has unrestricted access"),
                        )
                        .build(workflow)?,
                );
            }

            let is_truthy = |key: &str| -> bool {
                settings
                    .get(key)
                    .is_some_and(|v| !v.is_null() && v != &serde_json::Value::Bool(false))
            };
            if is_truthy("--yolo") || is_truthy("--approval-mode=yolo") {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into(), "settings".into()])
                                .annotated("yolo mode disables approval for all tool calls"),
                        )
                        .build(workflow)?,
                );
            }
        }

        Ok(findings)
    }

    fn check_sandbox_config<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        with: &indexmap::IndexMap<String, EnvValue>,
        config: &ActionConfig,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let Some(EnvValue::String(val)) = with.get("sandbox") else {
            return Ok(vec![]);
        };
        let mut findings = vec![];
        for dangerous in config.dangerous_sandbox_values {
            if val == *dangerous {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into(), "sandbox".into()])
                                .annotated(format!(
                                    "sandbox: {dangerous} grants unrestricted shell access"
                                )),
                        )
                        .build(workflow)?,
                );
            }
        }
        Ok(findings)
    }

    fn check_safety_overrides<'doc>(
        &self,
        workflow: &'doc Workflow,
        step: &Step<'doc>,
        with: &indexmap::IndexMap<String, EnvValue>,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Some(EnvValue::String(val)) = with.get("safety-strategy")
            && val == "unsafe"
        {
            findings.push(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["with".into(), "safety-strategy".into()])
                            .annotated("safety-strategy: unsafe disables all safety enforcement"),
                    )
                    .build(workflow)?,
            );
        }

        if let Some(EnvValue::String(val)) = with.get("claude_args")
            && val.contains("Bash(*)")
        {
            findings.push(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["with".into(), "claude_args".into()])
                            .annotated("Bash(*) grants unrestricted shell access"),
                    )
                    .build(workflow)?,
            );
        }

        Ok(findings)
    }

    fn is_dangerous_tool_specifier(s: &str) -> bool {
        let needle = "run_shell_command";
        let Some(pos) = s.find(needle) else {
            return false;
        };
        let after = &s[pos + needle.len()..];
        let next_non_ws = after.chars().find(|c| !c.is_whitespace());
        match next_non_ws {
            Some(c) if c != '(' => true,
            None => true,
            Some(_) => {
                let trimmed = after.trim_start();
                if let Some(inner) = trimmed.strip_prefix('(') {
                    let cmd = inner.split([' ', ')', ',', '"', '\'']).next().unwrap_or("");
                    EXPANDABLE_COMMANDS.contains(&cmd)
                } else {
                    false
                }
            }
        }
    }
}

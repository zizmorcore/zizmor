use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_claude_permissive_users() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/claude-permissive-users.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:13:11
       |
    13 |           allowed_non_write_users: "*"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ allowed_non_write_users: '*' allows untrusted users to invoke this agent
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_codex_permissive_users() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/codex-permissive-users.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:13:11
       |
    13 |           allow-users: "*"
       |           ^^^^^^^^^^^^^^^^ allow-users: '*' allows untrusted users to invoke this agent
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_attacker_controlled_prompt() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/attacker-controlled-prompt.yml"
            ))
            .run()?,
        @r#"
    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:3:1
       |
     3 | on: issue_comment
       | ^^^^^^^^^^^^^^^^^ issue_comment lets untrusted users trigger this agent
    ...
    11 |       - uses: anthropics/claude-code-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |         ---------------------------------------------------------------------------- this step
       |
       = note: audit confidence → Medium
       = tip: no gates detected — any user can trigger this agent

    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:13:11
       |
    13 |           prompt: "Review: ${{ github.event.issue.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ attacker-controlled ${{ github.event.issue.body }} flows into agent prompt
       |
       = note: audit confidence → High

    5 findings (3 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_comment_trigger() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/issue-comment-trigger.yml"
            ))
            .run()?,
        @r"
    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:3:1
       |
     3 | on: issue_comment
       | ^^^^^^^^^^^^^^^^^ issue_comment lets untrusted users trigger this agent
    ...
    11 |       - uses: anthropics/claude-code-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |         ---------------------------------------------------------------------------- this step
       |
       = note: audit confidence → Medium
       = tip: no gates detected — any user can trigger this agent

    4 findings (3 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_gemini_unrestricted_tools() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gemini-unrestricted-tools.yml"
            ))
            .run()?,
        @r#"
    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-gemini/gemini-cli-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ archived; migrate to google-github-actions/run-gemini-cli
       |
       = note: audit confidence → High

    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:12:9
       |
    11 |         - uses: google-gemini/gemini-cli-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |           ------------------------------------------------------------------------------ this step
    12 | /         with:
    13 | |           prompt: "Review the code"
       | |____________________________________^ missing settings with tools.core or tools.exclude restriction
       |
       = note: audit confidence → High

    5 findings (3 suppressed): 0 informational, 0 low, 2 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_gemini_archived_action() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gemini-archived-action.yml"
            ))
            .run()?,
        @r"
    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-gemini/gemini-cli-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ archived; migrate to google-github-actions/run-gemini-cli
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_safe_no_findings() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/safe-no-findings.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    Ok(())
}

#[test]
fn test_multiple_findings() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/multiple-findings.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:13:11
       |
    13 |           allowed_non_write_users: "*"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ allowed_non_write_users: '*' allows untrusted users to invoke this agent
       |
       = note: audit confidence → High

    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:3:1
       |
     3 | on: issue_comment
       | ^^^^^^^^^^^^^^^^^ issue_comment lets untrusted users trigger this agent
    ...
    11 |       - uses: anthropics/claude-code-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |         ---------------------------------------------------------------------------- this step
       |
       = note: audit confidence → Medium
       = tip: no gates detected — any user can trigger this agent

    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           prompt: "Review: ${{ github.event.comment.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ attacker-controlled ${{ github.event.comment.body }} flows into agent prompt
       |
       = note: audit confidence → High

    6 findings (3 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "#
    );

    Ok(())
}

#[test]
fn test_gemini_dangerous_coretools() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gemini-dangerous-coretools.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           settings: '{"tools": {"core": ["run_shell_command"]}}'
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ tools.core includes unrestricted run_shell_command
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_codex_danger_sandbox() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/codex-danger-sandbox.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           sandbox: "danger-full-access"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ sandbox: danger-full-access grants unrestricted shell access
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_gated_trigger() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gated-trigger.yml"
            ))
            .run()?,
        @r"
    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:3:1
       |
     3 | / on:
     4 | |   issue_comment:
     5 | |     types: [created]
       | |____________________^ issue_comment lets untrusted users trigger this agent
    ...
    14 |         - uses: anthropics/claude-code-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |           ---------------------------------------------------------------------------- this step
       |
       = note: audit confidence → Medium
       = tip: detected gates that may limit exposure:
                • issue_comment types [created]
                • job if [github.event.comment.author_association != 'NONE']

    4 findings (3 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_codex_unsafe_safety() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/codex-unsafe-safety.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           safety-strategy: "unsafe"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^ safety-strategy: unsafe disables all safety enforcement
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_claude_unrestricted_bash() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/claude-unrestricted-bash.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:13:11
       |
    13 |           claude_args: '--allowedTools "Bash(*)"'
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Bash(*) grants unrestricted shell access
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_gemini_sandbox_disabled() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gemini-sandbox-disabled.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           settings: '{"sandbox": false, "tools": {"core": ["read_file"]}}'
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ sandbox disabled — agent has unrestricted access
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_gemini_yolo_mode() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gemini-yolo-mode.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           settings: '{"tools": {"core": ["read_file"]}, "--approval-mode=yolo": true}'
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ yolo mode disables approval for all tool calls
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_gemini_expandable_coretools() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gemini-expandable-coretools.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:14:11
       |
    14 |           settings: '{"tools": {"core": ["run_shell_command(echo)"]}}'
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ tools.core includes unrestricted run_shell_command
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_claude_permissive_bots() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/claude-permissive-bots.yml"
            ))
            .run()?,
        @r#"
    error[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:13:11
       |
    13 |           allowed_bots: "*"
       |           ^^^^^^^^^^^^^^^^^ allowed_bots: '*' allows untrusted users to invoke this agent
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_gated_pr_trigger() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "agentic-actions/gated-pr-trigger.yml"
            ))
            .run()?,
        @r#"
    warning[agentic-actions]: risky AI agent action configuration
      --> @@INPUT@@:3:1
       |
     3 | / on:
     4 | |   pull_request:
     5 | |     types: [opened]
     6 | |     paths:
     7 | |       - "docs/**"
       | |_________________^ pull_request lets untrusted users trigger this agent
    ...
    15 |         - uses: anthropics/claude-code-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
       |           ---------------------------------------------------------------------------- this step
       |
       = note: audit confidence → Medium
       = tip: detected gates that may limit exposure:
                • pull_request types [opened]
                • pull_request paths [docs/**]

    4 findings (3 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

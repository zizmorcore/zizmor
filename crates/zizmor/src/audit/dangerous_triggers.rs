use anyhow::Result;

use super::{Audit, AuditLoadError, audit_meta};
use crate::finding::{Confidence, Finding, Fix, Severity};
use crate::models::Workflow;
use crate::state::AuditState;
use crate::{apply_yaml_patch, yaml_patch::YamlPatchOperation};

pub(crate) struct DangerousTriggers;

audit_meta!(
    DangerousTriggers,
    "dangerous-triggers",
    "use of fundamentally insecure workflow trigger"
);

impl DangerousTriggers {
    /// Create a fix for replacing pull_request_target with pull_request
    fn create_pull_request_target_fix() -> Fix {
        Fix {
            title: "Replace pull_request_target with pull_request".to_string(),
            description: "Replace 'pull_request_target' with 'pull_request' to run workflows in the context of the fork repository instead of the base repository. This is safer as it prevents access to secrets and write permissions for external contributors. Only use 'pull_request_target' if you absolutely need repository write permissions.".to_string(),
            apply: apply_yaml_patch!(vec![
                YamlPatchOperation::Replace {
                    path: "/on/pull_request_target".to_string(),
                    value: serde_yaml::Value::Null,
                },
                YamlPatchOperation::Add {
                    path: "/on".to_string(),
                    key: "pull_request".to_string(),
                    value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                },
            ]),
        }
    }

    /// Create a fix for replacing workflow_run with workflow_call
    fn create_workflow_run_fix() -> Fix {
        Fix {
            title: "Replace workflow_run with workflow_call".to_string(),
            description: "Replace 'workflow_run' trigger with 'workflow_call' and convert this to a reusable workflow. This requires refactoring the workflow to accept inputs and be called by other workflows instead of being triggered automatically. This is much safer as it eliminates the risk of unexpected triggering and provides better control over when the workflow runs.".to_string(),
            apply: apply_yaml_patch!(vec![
                YamlPatchOperation::Replace {
                    path: "/on/workflow_run".to_string(),
                    value: serde_yaml::Value::Null,
                },
                YamlPatchOperation::Add {
                    path: "/on".to_string(),
                    key: "workflow_call".to_string(),
                    value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                },
            ]),
        }
    }

    /// Create a fix for bare pull_request_target trigger
    fn create_bare_pull_request_target_fix() -> Fix {
        Fix {
            title: "Replace pull_request_target with pull_request".to_string(),
            description: "Replace 'pull_request_target' with 'pull_request' to run workflows in the context of the fork repository instead of the base repository. This is safer as it prevents access to secrets and write permissions for external contributors.".to_string(),
            apply: apply_yaml_patch!(vec![
                YamlPatchOperation::Replace {
                    path: "/on".to_string(),
                    value: serde_yaml::Value::String("pull_request".to_string()),
                },
            ]),
        }
    }

    /// Create a fix for bare workflow_run trigger
    fn create_bare_workflow_run_fix() -> Fix {
        Fix {
            title: "Replace workflow_run with workflow_call".to_string(),
            description: "Replace 'workflow_run' with 'workflow_call' and convert this to a reusable workflow. This requires refactoring the workflow to accept inputs and be called by other workflows.".to_string(),
            apply: apply_yaml_patch!(vec![
                YamlPatchOperation::Replace {
                    path: "/on".to_string(),
                    value: serde_yaml::Value::String("workflow_call".to_string()),
                },
            ]),
        }
    }

    /// Create a fix for pull_request_target in array format
    fn create_array_pull_request_target_fix() -> Fix {
        Fix {
            title: "Replace pull_request_target with pull_request in trigger list".to_string(),
            description: "Replace 'pull_request_target' with 'pull_request' in the trigger list to run workflows more securely.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Parse the YAML to find and replace pull_request_target in arrays
                let mut yaml: serde_yaml::Value = serde_yaml::from_str(content)?;

                if let Some(on_value) = yaml.get_mut("on") {
                    if let serde_yaml::Value::Sequence(events) = on_value {
                        for event in events.iter_mut() {
                            if let serde_yaml::Value::String(event_str) = event {
                                if event_str == "pull_request_target" {
                                    *event_str = "pull_request".to_string();
                                }
                            }
                        }
                    }
                }

                Ok(Some(serde_yaml::to_string(&yaml)?))
            }),
        }
    }

    /// Create a fix for workflow_run in array format
    fn create_array_workflow_run_fix() -> Fix {
        Fix {
            title: "Replace workflow_run with workflow_call in trigger list".to_string(),
            description: "Replace 'workflow_run' with 'workflow_call' in the trigger list and convert this to a reusable workflow.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Parse the YAML to find and replace workflow_run in arrays
                let mut yaml: serde_yaml::Value = serde_yaml::from_str(content)?;

                if let Some(on_value) = yaml.get_mut("on") {
                    if let serde_yaml::Value::Sequence(events) = on_value {
                        for event in events.iter_mut() {
                            if let serde_yaml::Value::String(event_str) = event {
                                if event_str == "workflow_run" {
                                    *event_str = "workflow_call".to_string();
                                }
                            }
                        }
                    }
                }

                Ok(Some(serde_yaml::to_string(&yaml)?))
            }),
        }
    }

    /// Determine the appropriate fix based on the trigger structure
    fn get_trigger_fix(workflow: &Workflow, is_pull_request_target: bool) -> Option<Fix> {
        use github_actions_models::workflow::Trigger;

        match &workflow.on {
            // Single bare event: on: pull_request_target
            Trigger::BareEvent(_) => {
                if is_pull_request_target {
                    Some(Self::create_bare_pull_request_target_fix())
                } else {
                    Some(Self::create_bare_workflow_run_fix())
                }
            }
            // Array of events: on: [push, pull_request_target]
            Trigger::BareEvents(_) => {
                if is_pull_request_target {
                    Some(Self::create_array_pull_request_target_fix())
                } else {
                    Some(Self::create_array_workflow_run_fix())
                }
            }
            // Object with event configurations: on: { pull_request_target: { ... } }
            Trigger::Events(_) => {
                if is_pull_request_target {
                    Some(Self::create_pull_request_target_fix())
                } else {
                    Some(Self::create_workflow_run_fix())
                }
            }
        }
    }
}

impl Audit for DangerousTriggers {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_workflow<'doc>(&self, workflow: &'doc Workflow) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        if workflow.has_pull_request_target() {
            let mut finding_builder = Self::finding()
                .confidence(Confidence::Medium)
                .severity(Severity::High)
                .add_location(
                    workflow
                        .location()
                        .primary()
                        .with_keys(&["on".into()])
                        .annotated("pull_request_target is almost always used insecurely"),
                );

            if let Some(fix) = Self::get_trigger_fix(workflow, true) {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(workflow)?);
        }

        if workflow.has_workflow_run() {
            let mut finding_builder = Self::finding()
                .confidence(Confidence::Medium)
                .severity(Severity::High)
                .add_location(
                    workflow
                        .location()
                        .primary()
                        .with_keys(&["on".into()])
                        .annotated("workflow_run is almost always used insecurely"),
                );

            if let Some(fix) = Self::get_trigger_fix(workflow, false) {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(workflow)?);
        }

        Ok(findings)
    }
}

//! `tree-sitter` helpers for extracting and locating `Finding` features
//! in the original YAML.

use anyhow::Result;
use tree_sitter::{Language, Query, QueryCursor};

use crate::models::Workflow;

use super::{Finding, WorkflowLocation};

/// Captures just the `on:` block of a workflow.
const WORKFLOW_TRIGGER_BLOCK: &str = r#"
(
  (block_mapping_pair
    key: (flow_node (plain_scalar (string_scalar) @on_key))
    value: (
      [
        (block_node (block_mapping))
        (flow_node)
      ] @on_value
    )
  ) @on_block
  (#eq? @on_key "on")
)
"#;

/// Captures an entire workflow job, including non-step keys.
const ENTIRE_JOB: &str = r#"
(
  (block_mapping_pair
    key: (flow_node (plain_scalar (string_scalar) @jobs_key))
    value: (block_node
      (block_mapping
        (block_mapping_pair
          key: (flow_node (plain_scalar (string_scalar) @job_name))
          value: (block_node (block_mapping) @job_value)
        ) @full_job
      )
    )
  )
  (#eq? @jobs_key "jobs")
  (#eq? @job_name "__JOB_NAME__")
)
"#;

/// Captures the sub-list of steps in a particular workflow job.
/// `tree-sitter` doesn't seem to have a way to match a particular index
/// for e.g. a particular step without capturing chains of `(.)`, so we
/// use this to collect all steps in a job and then manually walk
/// the step list to find the step we're interested in.
const ALL_STEPS_FROM_JOB: &str = r#"
(
  (block_mapping_pair
    key: (flow_node (plain_scalar (string_scalar) @jobs_key))
    value: (block_node (block_mapping
      (block_mapping_pair
        key: (flow_node (plain_scalar (string_scalar) @job_name))
        value: (block_node (block_mapping
          (block_mapping_pair
            key: (flow_node (plain_scalar (string_scalar) @steps_key))
            value: (block_node (block_sequence
              . (block_sequence_item
                (block_node (block_mapping))
              )
            ) @steps)
          )
        ))
      )
    ))
  )
  (#eq? @jobs_key "jobs")
  (#eq? @job_name "__JOB_NAME__")
  (#eq? @steps_key "steps")
)
"#;

pub(crate) struct Locator {
    language: Language,
}

impl Locator {
    pub(crate) fn new() -> Self {
        Self {
            language: tree_sitter_yaml::language(),
        }
    }

    pub(crate) fn locate(&self, workflow: &Workflow, finding: &Finding) -> Result<()> {
        for location in &finding.locations {
            self.extract_location(workflow, location)?;
        }

        Ok(())
    }

    fn extract_location(&self, workflow: &Workflow, location: &WorkflowLocation) -> Result<()> {
        let mut cursor = QueryCursor::new();

        match &location.job {
            Some(job) => match &job.step {
                Some(step) => {
                    let steps_query = Query::new(
                        &self.language,
                        &ALL_STEPS_FROM_JOB.replace("__JOB_NAME__", job.id),
                    )?;

                    for (capture, idx) in cursor.captures(
                        &steps_query,
                        workflow.tree.root_node(),
                        workflow.raw.as_bytes(),
                    ) {
                        // The last capture is our `@steps` capture.
                        let cap = capture.captures.last().unwrap();

                        let children = cap.node.children(&mut cap.node.walk()).collect::<Vec<_>>();
                        let step_node = children[step.index];
                        println!("{}", step_node.utf8_text(workflow.raw.as_bytes())?);
                        // dbg!(children);
                    }
                }
                None => {
                    // Job with no interior step: capture the entire job
                    // and emit it.
                    let job_query =
                        Query::new(&self.language, &ENTIRE_JOB.replace("__JOB_NAME__", job.id))?;

                    for capture in cursor.captures(
                        &job_query,
                        workflow.tree.root_node(),
                        workflow.raw.as_bytes(),
                    ) {
                        // println!("{capture:?}");
                    }
                }
            },
            None => {
                // No job means the entire workflow is flagged.
                // TODO specialize top-level keys.
                println!(
                    "{}",
                    workflow
                        .tree
                        .root_node()
                        .utf8_text(workflow.raw.as_bytes())?
                )
            }
        }

        Ok(())
    }
}

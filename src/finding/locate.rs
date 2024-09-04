//! `tree-sitter` helpers for extracting and locating `Finding` features
//! in the original YAML.

use anyhow::{Ok, Result};
use tree_sitter::{Language, Query, QueryCursor};

use crate::models::Workflow;

use super::{Feature, WorkflowLocation};

/// Captures an arbitrary top-level key within a YAML stream.
const TOP_LEVEL_KEY: &str = r#"
(
  (block_mapping_pair
    key: (flow_node (plain_scalar (string_scalar) @key))
    value: (
      [
        (block_node (block_mapping))
        (flow_node)
      ]
    )
  ) @mapping
  (#eq? @key "__KEY_NAME__")
)
"#;

/// Captures an arbitrary job-level key.
const JOB_LEVEL_KEY: &str = r#"
(
  (block_mapping_pair
    key: (flow_node (plain_scalar (string_scalar) @jobs_key))
    value: (block_node
      (block_mapping
        (block_mapping_pair
          key: (flow_node (plain_scalar (string_scalar) @job_name))
          value: (block_node
            (block_mapping
              (block_mapping_pair
                key: (flow_node (plain_scalar (string_scalar) @job_key_name))
                value: (block_node)
              ) @job_key_value
            )
          )
        )
      )
    )
  )
  (#eq? @jobs_key "jobs")
  (#eq? @job_name "__JOB_NAME__")
  (#eq? @job_key_name "__JOB_KEY__")
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

    pub(crate) fn concretize<'w>(
        &self,
        workflow: &'w Workflow,
        location: &WorkflowLocation,
    ) -> Result<Feature<'w>> {
        let mut cursor = QueryCursor::new();

        match &location.job {
            Some(job) => match &job.step {
                Some(step) => {
                    let steps_query = Query::new(
                        &self.language,
                        &ALL_STEPS_FROM_JOB.replace("__JOB_NAME__", job.id),
                    )?;
                    let capture_index = steps_query.capture_index_for_name("steps").unwrap();

                    // We expect only one capture group, so we don't bother iterating.
                    let (group, _) = cursor
                        .captures(
                            &steps_query,
                            workflow.tree.root_node(),
                            workflow.raw.as_bytes(),
                        )
                        .next()
                        .expect("horrific, embarassing tree-sitter query failure");

                    let cap = group.captures[capture_index as usize];

                    let children = cap.node.children(&mut cap.node.walk()).collect::<Vec<_>>();
                    let step_node = children[step.index];

                    Ok(Feature {
                        location: step_node.into(),
                        feature: step_node.utf8_text(workflow.raw.as_bytes())?,
                    })
                }
                None => match job.key {
                    Some(key) => {
                        // Job with a non-step key; capture the matching key's
                        // span and emit it.
                        let job_key_query = Query::new(
                            &self.language,
                            &JOB_LEVEL_KEY
                                .replace("__JOB_NAME__", job.id)
                                .replace("__JOB_KEY__", key),
                        )?;

                        let (group, _) = cursor
                            .captures(
                                &job_key_query,
                                workflow.tree.root_node(),
                                workflow.raw.as_bytes(),
                            )
                            .next()
                            .expect("horrific, embarassing tree-sitter query failure");

                        let cap = group.captures[0];

                        Ok(Feature {
                            location: cap.node.into(),
                            feature: cap.node.utf8_text(workflow.raw.as_bytes())?,
                        })
                    }
                    None => {
                        // Job with no interior step and no explicit key:
                        // capture the entire job and emit it.
                        let job_query = Query::new(
                            &self.language,
                            &ENTIRE_JOB.replace("__JOB_NAME__", job.id),
                        )?;

                        let (group, _) = cursor
                            .captures(
                                &job_query,
                                workflow.tree.root_node(),
                                workflow.raw.as_bytes(),
                            )
                            .next()
                            .expect("horrific, embarassing tree-sitter query failure");

                        let cap = group.captures[0];

                        Ok(Feature {
                            location: cap.node.into(),
                            feature: cap.node.utf8_text(workflow.raw.as_bytes())?,
                        })
                    }
                },
            },
            None => match &location.key {
                // If we're given a top-level key to isolate, query for it.
                // Otherwise, return the entire workflow.
                Some(key) => {
                    let key_query =
                        Query::new(&self.language, &TOP_LEVEL_KEY.replace("__KEY_NAME__", key))?;

                    let (group, _) = cursor
                        .captures(
                            &key_query,
                            workflow.tree.root_node(),
                            workflow.raw.as_bytes(),
                        )
                        .next()
                        .expect("horrific, embarassing tree-sitter query failure");

                    let cap = dbg!(group).captures[0];

                    Ok(Feature {
                        location: cap.node.into(),
                        feature: cap.node.utf8_text(workflow.raw.as_bytes())?,
                    })
                }
                None => Ok(Feature {
                    location: workflow.tree.root_node().into(),
                    feature: &workflow.raw,
                }),
            },
        }
    }
}

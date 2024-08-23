//! `tree-sitter` helpers for extracting `Finding` features
//! from YAML.

/// Captures just the `on:` block of a workflow.
const WORKFLOW_TRIGGER_BLOCK: &'static str = r#"
(
  (block_mapping_pair
    key: (flow_node (plain_scalar (string_scalar) @on_key))
    value: (
      [
        (block_node (block_mapping) @on_value)
        (flow_node)
      ] @on_value
    )
  ) @on_block
  (#eq? @on_key "on")
)
"#;

/// Captures an entire workflow job, including non-step keys.
const ENTIRE_JOB: &'static str = r#"
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
const ALL_STEPS_FROM_JOB: &'static str = r#"
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

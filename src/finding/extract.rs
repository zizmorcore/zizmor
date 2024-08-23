//! `tree-sitter` helpers for extracting `Finding` features
//! from YAML.

const EXTRACT_ALL_STEPS_FROM_JOB: &'static str = r#"
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

const EXTRACT_ENTIRE_JOB: &'static str = r#"
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

//! Workflow jobs.

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};
use yaml_serde::Value;

use crate::common::expr::{BoE, LoE};
use crate::common::{DockerUses, Env, If, Permissions, Uses, custom_error};

use super::{Concurrency, Defaults};

/// A "normal" GitHub Actions workflow job, i.e. a job composed of one
/// or more steps on a runner.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct NormalJob {
    pub name: Option<String>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default, deserialize_with = "crate::common::scalar_or_vector")]
    pub needs: Vec<String>,
    pub r#if: Option<If>,
    pub runs_on: LoE<RunsOn>,
    pub environment: Option<DeploymentEnvironment>,
    pub concurrency: Option<Concurrency>,
    #[serde(default)]
    pub outputs: IndexMap<String, String>,
    #[serde(default)]
    pub env: LoE<Env>,
    pub defaults: Option<Defaults>,
    pub steps: Vec<Step>,
    /// An optional timeout for this job, in minutes.
    /// GitHub takes the floor of any non-whole numeric value provided.
    pub timeout_minutes: Option<LoE<f64>>,
    pub strategy: Option<Strategy>,
    #[serde(default)]
    pub continue_on_error: BoE,
    pub container: Option<Container>,
    #[serde(default)]
    pub services: IndexMap<String, Container>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case", untagged, remote = "Self")]
pub enum RunsOn {
    #[serde(deserialize_with = "crate::common::scalar_or_vector")]
    Target(Vec<String>),
    Group {
        group: Option<String>,
        // NOTE(ww): serde struggles with the null/empty case for custom
        // deserializers, so we help it out by telling it that it can default
        // to Vec::default.
        #[serde(deserialize_with = "crate::common::scalar_or_vector", default)]
        labels: Vec<String>,
    },
}

impl<'de> Deserialize<'de> for RunsOn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let runs_on = Self::deserialize(deserializer)?;

        // serde lacks the ability to do inter-field invariants at the derive
        // layer, so we enforce the invariant that a `RunsOn::Group`
        // has either a `group` or at least one label here.
        if let RunsOn::Group { group, labels } = &runs_on
            && group.is_none()
            && labels.is_empty()
        {
            return Err(custom_error::<D>(
                "runs-on must provide either `group` or one or more `labels`",
            ));
        }

        Ok(runs_on)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum DeploymentEnvironment {
    Name(String),
    NameURL { name: String, url: Option<String> },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Step {
    /// An optional ID for this step.
    pub id: Option<String>,

    /// An optional expression that prevents this step from running unless it evaluates to `true`.
    pub r#if: Option<If>,

    /// An optional name for this step.
    pub name: Option<String>,

    /// An optional timeout for this step, in minutes.
    /// GitHub takes the floor of any non-whole numeric value provided.
    pub timeout_minutes: Option<LoE<f64>>,

    /// An optional boolean or expression that, if `true`, prevents the job from failing when
    /// this step fails.
    #[serde(default)]
    pub continue_on_error: BoE,

    /// An optional environment mapping for this step.
    #[serde(default)]
    pub env: LoE<Env>,

    /// An optional boolean or expression that, if `true`, runs this step
    /// asynchronously so the job immediately continues to the next step.
    ///
    /// See <https://github.blog/changelog/2026-06-25-actions-steps-can-now-be-run-in-parallel/>.
    #[serde(default)]
    pub background: BoE,

    /// The `run:` or `uses:` body for this step.
    #[serde(flatten)]
    pub body: StepBody,
}

/// The body of a [`Step`], i.e. the action it performs.
#[derive(Debug)]
pub enum StepBody {
    /// A step that runs an action.
    Uses {
        /// The GitHub Action being used.
        uses: Uses,
        /// Any inputs to the action being used.
        with: LoE<Env>,
    },
    /// A step that runs a shell command.
    Run {
        /// The command to run.
        run: String,
        /// An optional working directory to run [`StepBody::Run::run`] from.
        working_directory: Option<String>,
        /// An optional shell to run in. Defaults to the job or workflow's
        /// default shell.
        shell: Option<LoE<String>>,
    },
    /// Runs a group of steps in parallel, then waits for all of them to finish.
    ///
    /// See <https://github.blog/changelog/2026-06-25-actions-steps-can-now-be-run-in-parallel/>.
    Parallel {
        /// The group of steps to run in parallel.
        parallel: Vec<Step>,
    },
    /// Pauses the job until one or more named background steps complete.
    Wait {
        /// One or more background step IDs to wait for.
        wait: Vec<String>,
    },
    /// Pauses the job until all active background steps complete.
    ///
    /// The `wait-all` keyword takes no arguments.
    WaitAll,
    /// Gracefully terminates a single running background step by its ID.
    Cancel {
        /// The ID of the background step to cancel.
        cancel: String,
    },
}

impl<'de> Deserialize<'de> for StepBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;

        // A step body is identified by which of its mutually-exclusive keys is
        // present. We dispatch on key presence rather than deriving an
        // `untagged` enum, because the `wait-all:` step's value is the YAML
        // null, which serde's untagged buffering cannot match against.
        //
        // These helper structs reuse the field-level custom deserializers.
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct UsesBody {
            #[serde(deserialize_with = "crate::common::step_uses")]
            uses: Uses,
            #[serde(default)]
            with: LoE<Env>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct RunBody {
            #[serde(deserialize_with = "crate::common::bool_is_string")]
            run: String,
            working_directory: Option<String>,
            shell: Option<LoE<String>>,
        }
        #[derive(Deserialize)]
        struct ParallelBody {
            parallel: Vec<Step>,
        }
        #[derive(Deserialize)]
        struct WaitBody {
            #[serde(deserialize_with = "crate::common::scalar_or_vector")]
            wait: Vec<String>,
        }
        #[derive(Deserialize)]
        struct CancelBody {
            cancel: String,
        }

        let map: IndexMap<String, Value> = IndexMap::deserialize(deserializer)?;

        enum Which {
            Uses,
            Run,
            Parallel,
            Wait,
            WaitAll,
            Cancel,
        }
        // Value-bearing keys are checked first to preserve their priority.
        let which = if map.contains_key("uses") {
            Which::Uses
        } else if map.contains_key("run") {
            Which::Run
        } else if map.contains_key("parallel") {
            Which::Parallel
        } else if map.contains_key("wait") {
            Which::Wait
        } else if map.contains_key("wait-all") {
            Which::WaitAll
        } else if map.contains_key("cancel") {
            Which::Cancel
        } else {
            return Err(D::Error::custom(
                "step must define one of `uses`, `run`, `parallel`, `wait`, `wait-all`, or `cancel`",
            ));
        };

        // `wait-all` carries no value, so it is determined purely by presence.
        if let Which::WaitAll = which {
            return Ok(StepBody::WaitAll);
        }

        let value = Value::Mapping(
            map.into_iter()
                .map(|(k, v)| (Value::String(k), v))
                .collect(),
        );
        match which {
            Which::Uses => {
                let b: UsesBody = yaml_serde::from_value(value).map_err(D::Error::custom)?;
                Ok(StepBody::Uses {
                    uses: b.uses,
                    with: b.with,
                })
            }
            Which::Run => {
                let b: RunBody = yaml_serde::from_value(value).map_err(D::Error::custom)?;
                Ok(StepBody::Run {
                    run: b.run,
                    working_directory: b.working_directory,
                    shell: b.shell,
                })
            }
            Which::Parallel => {
                let b: ParallelBody = yaml_serde::from_value(value).map_err(D::Error::custom)?;
                Ok(StepBody::Parallel {
                    parallel: b.parallel,
                })
            }
            Which::Wait => {
                let b: WaitBody = yaml_serde::from_value(value).map_err(D::Error::custom)?;
                Ok(StepBody::Wait { wait: b.wait })
            }
            Which::Cancel => {
                let b: CancelBody = yaml_serde::from_value(value).map_err(D::Error::custom)?;
                Ok(StepBody::Cancel { cancel: b.cancel })
            }
            // Handled above by early return.
            Which::WaitAll => unreachable!(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Strategy {
    pub matrix: Option<LoE<Matrix>>,
    pub fail_fast: Option<BoE>,
    pub max_parallel: Option<LoE<u64>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Matrix {
    #[serde(default)]
    pub include: LoE<Vec<IndexMap<String, Value>>>,
    #[serde(default)]
    pub exclude: LoE<Vec<IndexMap<String, Value>>>,
    #[serde(flatten)]
    pub dimensions: LoE<IndexMap<String, LoE<Vec<Value>>>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum Container {
    Name(LoE<DockerUses>),
    Container {
        image: LoE<DockerUses>,
        credentials: Option<DockerCredentials>,
        #[serde(default)]
        env: LoE<Env>,
        // TODO: model `ports`?
        #[serde(default)]
        volumes: Vec<String>,
        options: Option<String>,
    },
}

#[derive(Deserialize, Debug)]
pub struct DockerCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ReusableWorkflowCallJob {
    pub name: Option<String>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default, deserialize_with = "crate::common::scalar_or_vector")]
    pub needs: Vec<String>,
    pub r#if: Option<If>,
    #[serde(deserialize_with = "crate::common::reusable_step_uses")]
    pub uses: Uses,
    #[serde(default)]
    pub with: LoE<Env>,
    pub secrets: Option<Secrets>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Secrets {
    Inherit,
    #[serde(untagged)]
    Env(#[serde(default)] Env),
}

#[cfg(test)]
mod tests {
    use crate::{
        common::{EnvValue, expr::LoE},
        workflow::job::{Matrix, Secrets},
    };

    use super::{RunsOn, Strategy};

    #[test]
    fn test_secrets() {
        assert_eq!(
            yaml_serde::from_str::<Secrets>("inherit").unwrap(),
            Secrets::Inherit
        );

        let secrets = "foo-secret: bar";
        let Secrets::Env(secrets) = yaml_serde::from_str::<Secrets>(secrets).unwrap() else {
            panic!("unexpected secrets variant");
        };
        assert_eq!(secrets["foo-secret"], EnvValue::String("bar".into()));
    }

    #[test]
    fn test_strategy_matrix_expressions() {
        let strategy = "matrix: ${{ 'foo' }}";
        let Strategy {
            matrix: Some(LoE::Expr(expr)),
            ..
        } = yaml_serde::from_str::<Strategy>(strategy).unwrap()
        else {
            panic!("unexpected matrix variant");
        };

        assert_eq!(expr.as_curly(), "${{ 'foo' }}");

        let strategy = r#"
matrix:
  foo: ${{ 'foo' }}
"#;

        let Strategy {
            matrix:
                Some(LoE::Literal(Matrix {
                    include: _,
                    exclude: _,
                    dimensions: LoE::Literal(dims),
                })),
            ..
        } = yaml_serde::from_str::<Strategy>(strategy).unwrap()
        else {
            panic!("unexpected matrix variant");
        };

        assert!(matches!(dims.get("foo"), Some(LoE::Expr(_))));
    }

    #[test]
    fn test_runson_invalid_state() {
        let runson = "group: \nlabels: []";

        assert_eq!(
            yaml_serde::from_str::<RunsOn>(runson)
                .unwrap_err()
                .to_string(),
            "runs-on must provide either `group` or one or more `labels`"
        );
    }

    #[test]
    fn test_parallel_steps() {
        use super::{Step, StepBody};

        // `background` is accepted on a run step.
        let step: Step = yaml_serde::from_str("run: echo hi\nbackground: true").unwrap();
        assert!(matches!(step.background, LoE::Literal(true)));
        assert!(matches!(step.body, StepBody::Run { .. }));

        // `wait` accepts a single ID or a list of IDs.
        let step: Step = yaml_serde::from_str("wait: build").unwrap();
        let StepBody::Wait { wait } = step.body else {
            panic!("expected a wait step");
        };
        assert_eq!(wait.len(), 1);
        assert_eq!(wait[0], "build");
        let step: Step = yaml_serde::from_str("wait: [a, b]").unwrap();
        assert!(matches!(step.body, StepBody::Wait { .. }));

        // `wait-all` takes no arguments.
        let step: Step = yaml_serde::from_str("wait-all:").unwrap();
        assert!(matches!(step.body, StepBody::WaitAll));

        // `cancel` targets a single background step.
        let step: Step = yaml_serde::from_str("cancel: build").unwrap();
        assert!(matches!(step.body, StepBody::Cancel { .. }));

        // `parallel` groups nested steps, which are themselves parsed as steps.
        let step: Step =
            yaml_serde::from_str("parallel:\n  - run: echo a\n  - run: echo b").unwrap();
        let StepBody::Parallel { parallel } = step.body else {
            panic!("expected a parallel step");
        };
        assert_eq!(parallel.len(), 2);
        assert!(matches!(parallel[0].body, StepBody::Run { .. }));
    }
}

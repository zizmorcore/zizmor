//! Workflow jobs.

use indexmap::IndexMap;
use serde::{Deserialize, de};
use serde_yaml::Value;

use crate::common::expr::{BoE, LoE};
use crate::common::{Env, If, Permissions, Uses};

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
    pub timeout_minutes: Option<LoE<u64>>,
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
        if let RunsOn::Group { group, labels } = &runs_on {
            if group.is_none() && labels.is_empty() {
                return Err(de::Error::custom(
                    "runs-on must provide either `group` or one or more `labels`",
                ));
            }
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
    pub timeout_minutes: Option<LoE<u64>>,

    /// An optional boolean or expression that, if `true`, prevents the job from failing when
    /// this step fails.
    #[serde(default)]
    pub continue_on_error: BoE,

    /// The `run:` or `uses:` body for this step.
    #[serde(flatten)]
    pub body: StepBody,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum StepBody {
    Uses {
        /// The GitHub Action being used.
        #[serde(deserialize_with = "crate::common::step_uses")]
        uses: Uses,

        /// Any inputs to the action being used.
        #[serde(default)]
        with: Env,
    },
    Run {
        /// The command to run.
        #[serde(deserialize_with = "crate::common::bool_is_string")]
        run: String,

        /// An optional working directory to run [`StepBody::Run::run`] from.
        working_directory: Option<String>,

        /// An optional shell to run in. Defaults to the job or workflow's
        /// default shell.
        shell: Option<String>,

        /// An optional environment mapping for this step.
        #[serde(default)]
        env: LoE<Env>,
    },
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
    Name(String),
    Container {
        image: String,
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
    pub with: Env,
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
            serde_yaml::from_str::<Secrets>("inherit").unwrap(),
            Secrets::Inherit
        );

        let secrets = "foo-secret: bar";
        let Secrets::Env(secrets) = serde_yaml::from_str::<Secrets>(secrets).unwrap() else {
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
        } = serde_yaml::from_str::<Strategy>(strategy).unwrap()
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
        } = serde_yaml::from_str::<Strategy>(strategy).unwrap()
        else {
            panic!("unexpected matrix variant");
        };

        assert!(matches!(dims.get("foo"), Some(LoE::Expr(_))));
    }

    #[test]
    fn test_runson_invalid_state() {
        let runson = "group: \nlabels: []";

        assert_eq!(
            serde_yaml::from_str::<RunsOn>(runson)
                .unwrap_err()
                .to_string(),
            "runs-on must provide either `group` or one or more `labels`"
        );
    }
}

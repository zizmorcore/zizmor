//! Strategy matrix modeling and APIs.

use github_actions_expressions::context::Context;
use github_actions_models::{common::expr::LoE, workflow::job};
use indexmap::IndexMap;

use crate::{
    finding::location::{Locatable, SymbolicLocation},
    models::workflow::NormalJob,
    utils::extract_fenced_expressions,
};

/// Represents an execution Matrix within a Job.
///
/// This type implements [`std::ops::Deref`] for [`job::NormalJob::strategy`], providing
/// access to the underlying data model.
#[derive(Clone)]
pub(crate) struct Matrix<'doc> {
    inner: &'doc LoE<job::Matrix>,
    parent: NormalJob<'doc>,
    pub(crate) expanded_values: Vec<(String, String)>,
}

impl<'doc> Matrix<'doc> {
    /// Constructs a new [`Matrix`] from the given parent job, if the job has a matrix.
    pub(super) fn new(parent: &NormalJob<'doc>) -> Option<Self> {
        let matrix = parent.strategy.as_ref()?.matrix.as_ref()?;

        Some(Self {
            inner: matrix,
            parent: parent.clone(),
            expanded_values: Matrix::expand_values(matrix),
        })
    }

    /// Checks whether some expanded path leads to an expression
    pub(crate) fn expands_to_static_values(&self, context: &Context) -> bool {
        // If we have an indirect matrix, we can't determine whether it expands to
        // static values or not.
        if matches!(self.inner, LoE::Expr(_)) {
            return false;
        }

        let expands_to_expression = self.expanded_values.iter().any(|(path, expansion)| {
            // Each expanded value in the matrix might be an expression, or contain
            // one or more expressions (e.g. `foo-${{ bar }}-${{ baz }}`). So we
            // need to check for *any* expression in the expanded value,
            // not just that it starts and ends with the expression delimiters.
            let expansion_contains_expression = !extract_fenced_expressions(expansion).is_empty();
            context.matches(path.as_str()) && expansion_contains_expression
        });

        !expands_to_expression
    }

    /// Expands the current Matrix into all possible values
    /// By default, the return is a pair (String, String), in which
    /// the first component is the expanded path (e.g. 'matrix.os') and
    /// the second component is the string representation for the expanded value
    /// (e.g. ubuntu-latest)
    ///
    fn expand_values(inner: &LoE<job::Matrix>) -> Vec<(String, String)> {
        match inner {
            LoE::Expr(_) => vec![],
            LoE::Literal(matrix) => {
                let LoE::Literal(dimensions) = &matrix.dimensions else {
                    return vec![];
                };

                let mut expansions = Matrix::expand_dimensions(dimensions);

                if let LoE::Literal(includes) = &matrix.include {
                    let additional_expansions = includes
                        .iter()
                        .flat_map(Matrix::expand_explicit_rows)
                        .collect::<Vec<_>>();

                    expansions.extend(additional_expansions);
                };

                let LoE::Literal(excludes) = &matrix.exclude else {
                    return expansions;
                };

                let to_exclude = excludes
                    .iter()
                    .flat_map(Matrix::expand_explicit_rows)
                    .collect::<Vec<_>>();

                expansions
                    .into_iter()
                    .filter(|expanded| !to_exclude.contains(expanded))
                    .collect()
            }
        }
    }

    fn expand_explicit_rows(
        include: &IndexMap<String, serde_yaml::Value>,
    ) -> Vec<(String, String)> {
        let normalized = include
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v)))
            .collect::<IndexMap<_, _>>();

        Matrix::expand(normalized)
    }

    fn expand_dimensions(
        dimensions: &IndexMap<String, LoE<Vec<serde_yaml::Value>>>,
    ) -> Vec<(String, String)> {
        let normalized = dimensions
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v)))
            .collect::<IndexMap<_, _>>();

        Matrix::expand(normalized)
    }

    fn expand(values: IndexMap<String, serde_json::Value>) -> Vec<(String, String)> {
        values
            .iter()
            .flat_map(|(key, value)| Matrix::walk_path(value, format!("matrix.{key}")))
            .collect()
    }

    // Walks recursively a serde_json::Value tree, expanding it into a Vec<(String, String)>
    // according to the inner value of each node
    fn walk_path(tree: &serde_json::Value, current_path: String) -> Vec<(String, String)> {
        match tree {
            serde_json::Value::Null => vec![],

            // In the case of scalars, we just convert the value to a string
            serde_json::Value::Bool(inner) => vec![(current_path, inner.to_string())],
            serde_json::Value::Number(inner) => vec![(current_path, inner.to_string())],
            serde_json::Value::String(inner) => vec![(current_path, inner.to_string())],

            // In the case of an array, we recursively create on expansion pair for each item
            serde_json::Value::Array(inner) => inner
                .iter()
                .flat_map(|value| Matrix::walk_path(value, current_path.clone()))
                .collect(),

            // In the case of an object, we recursively create on expansion pair for each
            // value in the key/value set, using the key to form the expanded path using
            // the dot notation
            serde_json::Value::Object(inner) => inner
                .iter()
                .flat_map(|(key, value)| {
                    let mut new_path = current_path.clone();
                    new_path.push('.');
                    new_path.push_str(key);
                    Matrix::walk_path(value, new_path)
                })
                .collect(),
        }
    }
}

impl<'doc> std::ops::Deref for Matrix<'doc> {
    type Target = &'doc LoE<job::Matrix>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'doc> Locatable<'doc> for Matrix<'doc> {
    /// This matrix's [`SymbolicLocation`].
    fn location(&self) -> SymbolicLocation<'doc> {
        self.parent
            .location()
            .with_keys(["strategy".into(), "matrix".into()])
            .annotated("this matrix")
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::context::Context;

    use crate::{
        models::workflow::{NormalJob, Workflow, matrix::Matrix},
        registry::input::InputKey,
    };

    #[test]
    fn test_matrix_expanded_values() -> anyhow::Result<()> {
        let workflow_yaml = r#"
name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [12, 14, 16]
        nested:
          - { a: 1, b: 2 }
          - { a: 3, b: 4 }
    steps:
      - run: true
        "#;

        let workflow = Workflow::from_string(
            workflow_yaml.into(),
            InputKey::local("fakegroup".into(), "test.yml", None),
        )
        .unwrap();

        let job = {
            let github_actions_models::workflow::Job::NormalJob(job) =
                workflow.jobs.get("test").unwrap()
            else {
                panic!("Expected a normal job");
            };

            NormalJob::new("test", job, &workflow)
        };

        let matrix = Matrix::new(&job).unwrap();

        insta::assert_debug_snapshot!(matrix.expanded_values, @r#"
        [
            (
                "matrix.os",
                "ubuntu-latest",
            ),
            (
                "matrix.os",
                "windows-latest",
            ),
            (
                "matrix.os",
                "macos-latest",
            ),
            (
                "matrix.node",
                "12",
            ),
            (
                "matrix.node",
                "14",
            ),
            (
                "matrix.node",
                "16",
            ),
            (
                "matrix.nested.a",
                "1",
            ),
            (
                "matrix.nested.b",
                "2",
            ),
            (
                "matrix.nested.a",
                "3",
            ),
            (
                "matrix.nested.b",
                "4",
            ),
        ]
        "#);

        Ok(())
    }

    #[test]
    fn test_direct_matrix_expands_to_static_values() -> anyhow::Result<()> {
        let workflow_yaml = r#"
name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        trivially-static: [a, b, c, d]
        trivially-dynamic: [a, '${{ github.ref }}', c, d]
        nested-static:
          - { a: 1, b: 2 }
          - { a: 3, b: 4 }
        nested-dynamic:
          - { a: 1, b: '${{ github.ref }}' }
          - { a: 3, b: 4 }
    steps:
      - run: true
        "#;

        let workflow = Workflow::from_string(
            workflow_yaml.into(),
            InputKey::local("fakegroup".into(), "test.yml", None),
        )?;

        let job = {
            let github_actions_models::workflow::Job::NormalJob(job) =
                workflow.jobs.get("test").unwrap()
            else {
                panic!("Expected a normal job");
            };

            NormalJob::new("test", job, &workflow)
        };

        let matrix = Matrix::new(&job).unwrap();

        assert!(matrix.expands_to_static_values(&Context::parse("matrix.trivially-static")?));
        assert!(!matrix.expands_to_static_values(&Context::parse("matrix.trivially-dynamic")?));
        assert!(matrix.expands_to_static_values(&Context::parse("matrix.nested-static.a")?));
        assert!(!matrix.expands_to_static_values(&Context::parse("matrix.nested-dynamic.b")?));

        // We can assert that a nonexistent path expands to static values because
        // we have a 'direct' matrix here, not a dynamic expression.
        assert!(matrix.expands_to_static_values(&Context::parse("matrix.nonexistent")?));

        Ok(())
    }

    #[test]
    fn test_indirect_matrix_expands_to_static_values() -> anyhow::Result<()> {
        let workflow_yaml = r#"
name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ dynamic }}
    steps:
      - run: true
        "#;

        let workflow = Workflow::from_string(
            workflow_yaml.into(),
            InputKey::local("fakegroup".into(), "test.yml", None),
        )?;

        let job = {
            let github_actions_models::workflow::Job::NormalJob(job) =
                workflow.jobs.get("test").unwrap()
            else {
                panic!("Expected a normal job");
            };

            NormalJob::new("test", job, &workflow)
        };

        let matrix = Matrix::new(&job).unwrap();
        assert!(matrix.expanded_values.is_empty());

        assert!(!matrix.expands_to_static_values(&Context::parse("matrix.nonexistent")?));

        Ok(())
    }
}

//! Strategy matrix modeling and APIs.

mod rows;

use crate::{
    finding::location::{Locatable, SymbolicLocation},
    models::workflow::NormalJob,
    utils::extract_fenced_expressions,
};
use github_actions_models::{common::expr::LoE, workflow::job};
use indexmap::IndexMap;

/// Represents a concrete expansion of a matrix.
///
/// For example, given a matrix like:
///
/// ```yaml
/// strategy:
///   matrix:
///     os: [ubuntu-latest, windows-latest]
///     node: [12, 14]
/// ```
///
/// an expansion could represent the path `matrix.os` with the value `ubuntu-latest`.
#[derive(Clone, Debug)]
pub(crate) struct Expansion<'doc> {
    /// The expanded path within the matrix.
    // TODO: This should be a Context.
    pub(crate) path: String,
    /// The expanded value at the given path.
    // TODO: This should be a 'doc ExpansionValue.
    pub(crate) value: String,
    /// The expansion's origin location in the document.
    location: SymbolicLocation<'doc>,
}

impl PartialEq for Expansion<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.value == other.value
    }
}

impl<'doc> Locatable<'doc> for Expansion<'doc> {
    fn location(&self) -> SymbolicLocation<'doc> {
        self.location.clone()
    }
}

impl<'doc> Expansion<'doc> {
    fn new(path: String, value: String, location: SymbolicLocation<'doc>) -> Self {
        Self {
            path,
            value,
            location,
        }
    }

    /// Checks whether this expansion's value is static (i.e., contains no expressions).
    pub(crate) fn is_static(&self) -> bool {
        extract_fenced_expressions(&self.value).is_empty()
    }
}

/// The values that can be expanded statically from a matrix.
#[derive(Clone, Debug, Default)]
pub(crate) struct Expansions<'doc> {
    /// Consolidated expansions of dimensions and explicit rows,
    /// evaluating inclusions and exclusions, if any
    all_expansions: Vec<Expansion<'doc>>,
}

impl<'doc> Expansions<'doc> {
    pub(crate) fn new(matrix: &LoE<job::Matrix>, parent: &NormalJob<'doc>) -> Self {
        let matrix_location = parent
            .location()
            .with_keys(["strategy".into(), "matrix".into()])
            .annotated("this matrix");
        Self::expand_values(matrix, matrix_location)
    }

    /// Exposes an iterator over the evaluated expansions
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Expansion<'doc>> {
        self.all_expansions.iter()
    }

    fn expand_values(matrix: &LoE<job::Matrix>, location: SymbolicLocation<'doc>) -> Self {
        let LoE::Literal(matrix) = matrix else {
            return Self::default();
        };
        let LoE::Literal(dimensions) = &matrix.dimensions else {
            return Self::default();
        };

        let mut expanded = Self::expand_dimensions(dimensions, location.clone());

        // GitHub applies exclusions before inclusions.
        if let LoE::Literal(excludes) = &matrix.exclude {
            let to_exclude = excludes
                .iter()
                .flat_map(|exclude| {
                    Self::expand_explicit_rows(exclude, location.with_keys(["exclude".into()]))
                })
                .collect::<Vec<_>>();

            expanded.retain(|expanded| !to_exclude.contains(expanded));
        }

        if let LoE::Literal(includes) = &matrix.include {
            let additional_expansions = includes
                .iter()
                .enumerate()
                .flat_map(|(idx, include)| {
                    Self::expand_explicit_rows(
                        include,
                        location.with_keys(["include".into(), idx.into()]),
                    )
                })
                .collect::<Vec<_>>();

            expanded.extend(additional_expansions);
        }

        Self {
            all_expansions: expanded,
        }
    }

    fn expand_explicit_rows(
        include: &IndexMap<String, yaml_serde::Value>,
        base: SymbolicLocation<'doc>,
    ) -> Vec<Expansion<'doc>> {
        let normalized = include
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v)))
            .collect::<IndexMap<_, _>>();

        Self::expand(normalized, base)
    }

    fn expand_dimensions(
        dimensions: &IndexMap<String, LoE<Vec<yaml_serde::Value>>>,
        base: SymbolicLocation<'doc>,
    ) -> Vec<Expansion<'doc>> {
        let normalized = dimensions
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v)))
            .collect::<IndexMap<_, _>>();

        Self::expand(normalized, base)
    }

    fn expand(
        values: IndexMap<String, serde_json::Value>,
        base: SymbolicLocation<'doc>,
    ) -> Vec<Expansion<'doc>> {
        values
            .into_iter()
            .flat_map(|(key, value)| {
                Self::walk_path(
                    value,
                    format!("matrix.{key}"),
                    base.with_keys([key.into()]).annotated("this expansion"),
                )
            })
            .collect()
    }

    // Walks recursively a serde_json::Value tree, expanding it into a Vec<(String, String)>
    // according to the inner value of each node
    fn walk_path(
        tree: serde_json::Value,
        current_path: String,
        base: SymbolicLocation<'doc>,
    ) -> Vec<Expansion<'doc>> {
        match tree {
            serde_json::Value::Null => vec![],

            // In the case of scalars, we just convert the value to a string
            serde_json::Value::Bool(inner) => {
                vec![Expansion::new(current_path, inner.to_string(), base)]
            }
            serde_json::Value::Number(inner) => {
                vec![Expansion::new(current_path, inner.to_string(), base)]
            }
            serde_json::Value::String(inner) => {
                vec![Expansion::new(current_path, inner.to_string(), base)]
            }

            // In the case of an array, we recursively create on expansion pair for each item
            serde_json::Value::Array(inner) => inner
                .into_iter()
                .enumerate()
                .flat_map(|(idx, value)| {
                    Self::walk_path(value, current_path.clone(), base.with_keys([idx.into()]))
                })
                .collect(),

            // In the case of an object, we recursively create on expansion pair for each
            // value in the key/value set, using the key to form the expanded path using
            // the dot notation
            serde_json::Value::Object(inner) => inner
                .into_iter()
                .flat_map(|(key, value)| {
                    let mut new_path = current_path.clone();
                    new_path.push('.');
                    new_path.push_str(&key);
                    Self::walk_path(value, new_path, base.with_keys([key.into()]))
                })
                .collect(),
        }
    }
}

/// Represents an execution Matrix within a Job.
///
/// This type implements [`std::ops::Deref`] for [`job::NormalJob::strategy`], providing
/// access to the underlying data model.
#[derive(Clone)]
pub(crate) struct Matrix<'doc> {
    inner: &'doc LoE<job::Matrix>,
    parent: NormalJob<'doc>,
    expansions: std::sync::OnceLock<Expansions<'doc>>,
}

impl<'doc> Matrix<'doc> {
    /// Constructs a new [`Matrix`] from the given parent job, if the job has a matrix.
    pub(super) fn new(parent: &NormalJob<'doc>) -> Option<Self> {
        let matrix = parent.strategy.as_ref()?.matrix.as_ref()?;

        Some(Self {
            inner: matrix,
            parent: parent.clone(),
            expansions: Default::default(),
        })
    }

    /// The expansions for this matrix
    pub(crate) fn expansions(&self) -> &Expansions<'doc> {
        self.expansions
            .get_or_init(|| Expansions::new(self.inner, &self.parent))
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

    use crate::{
        models::{
            AsDocument as _,
            workflow::{NormalJob, Workflow, matrix::Matrix},
        },
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
        include:
          - os: ubuntu-latest
            node: 18
            nested:
              a: 5
              b: 6
    steps:
      - run: true
        "#;

        let workflow = Workflow::from_string(
            workflow_yaml.into(),
            InputKey::local("fakegroup".into(), "test.yml", None, None),
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

        insta::assert_debug_snapshot!(matrix.expansions().iter().collect::<Vec<_>>(), @r#"
        [
            Expansion {
                path: "matrix.os",
                value: "ubuntu-latest",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "os",
                            ),
                            Index(
                                0,
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.os",
                value: "windows-latest",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "os",
                            ),
                            Index(
                                1,
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.os",
                value: "macos-latest",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "os",
                            ),
                            Index(
                                2,
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.node",
                value: "12",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "node",
                            ),
                            Index(
                                0,
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.node",
                value: "14",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "node",
                            ),
                            Index(
                                1,
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.node",
                value: "16",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "node",
                            ),
                            Index(
                                2,
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.nested.a",
                value: "1",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "nested",
                            ),
                            Index(
                                0,
                            ),
                            Key(
                                "a",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.nested.b",
                value: "2",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "nested",
                            ),
                            Index(
                                0,
                            ),
                            Key(
                                "b",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.nested.a",
                value: "3",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "nested",
                            ),
                            Index(
                                1,
                            ),
                            Key(
                                "a",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.nested.b",
                value: "4",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "nested",
                            ),
                            Index(
                                1,
                            ),
                            Key(
                                "b",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.os",
                value: "ubuntu-latest",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "include",
                            ),
                            Index(
                                0,
                            ),
                            Key(
                                "os",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.node",
                value: "18",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "include",
                            ),
                            Index(
                                0,
                            ),
                            Key(
                                "node",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.nested.a",
                value: "5",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "include",
                            ),
                            Index(
                                0,
                            ),
                            Key(
                                "nested",
                            ),
                            Key(
                                "a",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
            Expansion {
                path: "matrix.nested.b",
                value: "6",
                location: SymbolicLocation {
                    key: Local(
                        LocalKey {
                            group: GroupID(
                                "fakegroup",
                            ),
                            prefix: None,
                            verbatim_path: "test.yml",
                            native_path: "test.yml",
                            root_relative_path: None,
                        },
                    ),
                    annotation: "this expansion",
                    link: None,
                    route: Route {
                        route: [
                            Key(
                                "jobs",
                            ),
                            Key(
                                "test",
                            ),
                            Key(
                                "strategy",
                            ),
                            Key(
                                "matrix",
                            ),
                            Key(
                                "include",
                            ),
                            Index(
                                0,
                            ),
                            Key(
                                "nested",
                            ),
                            Key(
                                "b",
                            ),
                        ],
                    },
                    feature_kind: Normal,
                    kind: Related,
                },
            },
        ]
        "#);

        // Ensure that we can concretize every expansion's location without error.
        for expansion in matrix.expansions().all_expansions.clone() {
            expansion.location.concretize(workflow.as_document())?;
        }

        Ok(())
    }

    #[test]
    fn test_dynamic_matrix_has_no_static_expansions() -> anyhow::Result<()> {
        let workflow_yaml = r#"
name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ fromJSON(vars.TARGETS) }}
    steps:
      - run: true
        "#;

        let workflow = Workflow::from_string(
            workflow_yaml.into(),
            InputKey::local("fakegroup".into(), "test.yml", None, None),
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
        let expansions = matrix.expansions();
        assert!(expansions.all_expansions.is_empty());

        Ok(())
    }

    #[test]
    fn test_expands_dimensions_with_dynamic_include_and_exclude() -> anyhow::Result<()> {
        let workflow_yaml = r#"
name: test
on: push
jobs:
  indirect-matrix:
    name: indirect-matrix
    runs-on: ubuntu-26.04
    container:
      image: ${{ matrix.image }}
    strategy:
      matrix:
        arch: [x86_64, aarch64]
        image:
          - ubuntu@latest
        include: ${{ fromJSON(vars.EXTRA_TARGETS) }}
        exclude: ${{ fromJSON(vars.KNOWN_BROKEN_COMBOS) }}
    steps:
      - name: Noop
        run: true
        "#;

        let workflow = Workflow::from_string(
            workflow_yaml.into(),
            InputKey::local("fakegroup".into(), "indirect-matrix.yml", None, None),
        )?;

        let job = {
            let github_actions_models::workflow::Job::NormalJob(job) =
                workflow.jobs.get("indirect-matrix").unwrap()
            else {
                panic!("Expected a normal job");
            };

            NormalJob::new("indirect-matrix", job, &workflow)
        };

        let matrix = Matrix::new(&job).unwrap();
        let expansions = matrix.expansions();

        assert_eq!(expansions.iter().count(), 3);

        Ok(())
    }
}

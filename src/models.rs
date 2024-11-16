//! Enriching/context-bearing wrappers over GitHub Actions models
//! from the `github-actions-models` crate.

use std::{collections::hash_map, iter::Enumerate, ops::Deref, path::Path};

use anyhow::{anyhow, Context, Result};
use github_actions_models::workflow::{self, job::StepBody};

use crate::finding::{Route, SymbolicLocation};

pub(crate) struct Workflow {
    pub(crate) path: String,
    pub(crate) document: yamlpath::Document,
    inner: workflow::Workflow,
}

impl Deref for Workflow {
    type Target = workflow::Workflow;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Workflow {
    pub(crate) fn from_file<P: AsRef<Path>>(p: P) -> Result<Self> {
        let raw = std::fs::read_to_string(p.as_ref())?;

        let inner = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid GitHub Actions workflow: {:?}", p.as_ref()))?;

        let document = yamlpath::Document::new(raw)?;

        Ok(Self {
            path: p
                .as_ref()
                .to_str()
                .ok_or_else(|| anyhow!("invalid workflow: path is not UTF-8"))?
                .to_string(),
            document,
            inner,
        })
    }

    pub(crate) fn filename(&self) -> &str {
        // NOTE: Unwraps are safe here since we enforce UTF-8 paths
        // and require a filename as an invariant.
        Path::new(&self.path).file_name().unwrap().to_str().unwrap()
    }

    pub(crate) fn location(&self) -> SymbolicLocation {
        SymbolicLocation {
            name: self.filename(),
            annotation: "this workflow".to_string(),
            link: None,
            route: Route::new(),
        }
    }

    pub(crate) fn jobs(&self) -> Jobs<'_> {
        Jobs::new(self)
    }
}

pub(crate) struct Job<'w> {
    pub(crate) id: &'w str,
    inner: &'w workflow::Job,
    parent: SymbolicLocation<'w>,
}

impl<'w> Deref for Job<'w> {
    type Target = &'w workflow::Job;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'w> Job<'w> {
    pub(crate) fn new(id: &'w str, inner: &'w workflow::Job, parent: SymbolicLocation<'w>) -> Self {
        Self { id, inner, parent }
    }

    pub(crate) fn location(&self) -> SymbolicLocation<'w> {
        self.parent.with_job(self)
    }

    pub(crate) fn steps(&self) -> Steps<'w> {
        Steps::new(self)
    }
}

pub(crate) struct Jobs<'w> {
    inner: hash_map::Iter<'w, String, workflow::Job>,
    location: SymbolicLocation<'w>,
}

impl<'w> Jobs<'w> {
    pub(crate) fn new(workflow: &'w Workflow) -> Self {
        Self {
            inner: workflow.jobs.iter(),
            location: workflow.location(),
        }
    }
}

impl<'w> Iterator for Jobs<'w> {
    type Item = Job<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((id, job)) => Some(Job::new(id, job, self.location.clone())),
            None => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Step<'w> {
    pub(crate) index: usize,
    inner: &'w workflow::job::Step,
    parent: SymbolicLocation<'w>,
}

impl<'w> Deref for Step<'w> {
    type Target = &'w workflow::job::Step;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'w> Step<'w> {
    pub(crate) fn new(
        index: usize,
        inner: &'w workflow::job::Step,
        parent: SymbolicLocation<'w>,
    ) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    /// Returns a [`Uses`] for this [`Step`], if it has one.
    pub(crate) fn uses(&self) -> Option<Uses<'w>> {
        let StepBody::Uses { uses, .. } = &self.inner.body else {
            return None;
        };

        Uses::from_step(uses)
    }

    /// Returns a symbolic location for this [`Step`].
    pub(crate) fn location(&self) -> SymbolicLocation<'w> {
        self.parent.with_step(self)
    }

    /// Like [`Step::location`], except with the step's `name`
    /// key as the final path component if present.
    pub(crate) fn location_with_name(&self) -> SymbolicLocation<'w> {
        match self.inner.name {
            Some(_) => self.location().with_keys(&["name".into()]),
            None => self.location(),
        }
        .annotated("this step")
    }
}

pub(crate) struct Steps<'w> {
    inner: Enumerate<std::slice::Iter<'w, github_actions_models::workflow::job::Step>>,
    location: SymbolicLocation<'w>,
}

impl<'w> Steps<'w> {
    pub(crate) fn new(job: &Job<'w>) -> Self {
        // TODO: do something less silly here.
        match &job.inner {
            workflow::Job::ReusableWorkflowCallJob(_) => {
                panic!("API misuse: can't call steps() on a reusable job")
            }
            workflow::Job::NormalJob(ref n) => Self {
                inner: n.steps.iter().enumerate(),
                location: job.location(),
            },
        }
    }
}

impl<'w> Iterator for Steps<'w> {
    type Item = Step<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(Step::new(idx, step, self.location.clone())),
            None => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct DockerUses<'a> {
    pub(crate) registry: Option<&'a str>,
    pub(crate) image: &'a str,
    pub(crate) tag: Option<&'a str>,
    pub(crate) hash: Option<&'a str>,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct RepositoryUses<'a> {
    pub(crate) owner: &'a str,
    pub(crate) repo: &'a str,
    pub(crate) subpath: Option<&'a str>,
    pub(crate) git_ref: Option<&'a str>,
}

impl<'a> RepositoryUses<'a> {
    pub(crate) fn ref_is_commit(&self) -> bool {
        match self.git_ref {
            Some(git_ref) => git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit()),
            None => false,
        }
    }

    pub(crate) fn commit_ref(&self) -> Option<&str> {
        match self.git_ref {
            Some(git_ref) if self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }

    pub(crate) fn symbolic_ref(&self) -> Option<&str> {
        match self.git_ref {
            Some(git_ref) if !self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }
}

/// Represents the components of an "action ref", i.e. the value
/// of a `uses:` clause in a normal job step or a reusable workflow job.
/// Supports Docker (`docker://`) and repository (`actions/checkout`)
/// style references, but not local (`./foo`) references.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Uses<'a> {
    Docker(DockerUses<'a>),
    Repository(RepositoryUses<'a>),
}

impl<'a> Uses<'a> {
    fn is_registry(registry: &str) -> bool {
        // https://stackoverflow.com/a/42116190
        registry == "localhost" || registry.contains('.') || registry.contains(':')
    }

    fn from_image_ref(image: &'a str) -> Option<Self> {
        let (registry, image_full) = match image.split_once('/') {
            Some((registry, image)) if Self::is_registry(registry) => (Some(registry), image),
            _ => (None, image),
        };

        if let Some(at_pos) = image_full.find('@') {
            let (image, hash) = image_full.split_at(at_pos);

            let hash = if hash.is_empty() {
                None
            } else {
                Some(&hash[1..])
            };

            Some(Self::Docker(DockerUses {
                registry,
                image,
                tag: None,
                hash,
            }))
        } else {
            let (image, tag) = match image_full.split_once(':') {
                Some((image, "")) => (image, None),
                Some((image, tag)) => (image, Some(tag)),
                _ => (image_full, None),
            };

            Some(Self::Docker(DockerUses {
                registry,
                image,
                tag,
                hash: None,
            }))
        }
    }

    fn from_common(uses: &'a str) -> Option<Self> {
        if uses.starts_with("./") {
            None
        } else if let Some(image) = uses.strip_prefix("docker://") {
            Self::from_image_ref(image)
        } else {
            // NOTE: Technically both git refs and action paths can contain `@`,
            // so this isn't guaranteed to be correct. In practice, however,
            // splitting on the last `@` is mostly reliable.
            let (path, git_ref) = match uses.rsplit_once('@') {
                Some((path, git_ref)) => (path, Some(git_ref)),
                None => (uses, None),
            };

            let components = path.splitn(3, '/').collect::<Vec<_>>();
            if components.len() < 2 {
                log::debug!("malformed `uses:` ref: {uses}");
                return None;
            }

            Some(Self::Repository(RepositoryUses {
                owner: components[0],
                repo: components[1],
                subpath: components.get(2).copied(),
                git_ref,
            }))
        }
    }

    pub(crate) fn from_step(uses: &'a str) -> Option<Self> {
        Self::from_common(uses)
    }

    /// Parse a [`Uses`] from a reusable workflow `uses:` clause.
    ///
    /// Returns only the [`RepositoryUses`] variant since Docker actions
    /// can't be used in reusable workflows.
    pub(crate) fn from_reusable(uses: &'a str) -> Option<RepositoryUses> {
        match Self::from_common(uses) {
            // Reusable workflows don't support Docker actions.
            Some(Uses::Docker(DockerUses { .. })) => None,
            // Reusable workflows require a git ref.
            Some(Uses::Repository(RepositoryUses {
                owner: _,
                repo: _,
                subpath: _,
                git_ref,
            })) if git_ref.is_none() => None,
            Some(Uses::Repository(repo)) => Some(repo),
            None => None,
        }
    }

    pub(crate) fn unpinned(&self) -> bool {
        match self {
            Uses::Docker(docker) => docker.hash.is_none() && docker.tag.is_none(),
            Uses::Repository(repo) => repo.git_ref.is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DockerUses, RepositoryUses, Uses};

    #[test]
    fn uses_from_step() {
        let vectors = [
            (
                // Valid: fully pinned.
                "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                })),
            ),
            (
                // Valid: fully pinned, subpath
                "actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "aws",
                    subpath: Some("ec2"),
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                })),
            ),
            (
                // Valid: fully pinned, complex subpath
                "example/foo/bar/baz/quux@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::Repository(RepositoryUses {
                    owner: "example",
                    repo: "foo",
                    subpath: Some("bar/baz/quux"),
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                })),
            ),
            (
                // Valid: pinned with branch/tag
                "actions/checkout@v4",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: Some("v4"),
                })),
            ),
            (
                "actions/checkout@abcd",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: Some("abcd"),
                })),
            ),
            (
                // Valid: unpinned
                "actions/checkout",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: None,
                })),
            ),
            (
                // Valid: Docker ref, implicit registry
                "docker://alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, localhost
                "docker://localhost/alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: Some("localhost"),
                    image: "alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, localhost w/ port
                "docker://localhost:1337/alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: Some("localhost:1337"),
                    image: "alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, custom registry
                "docker://ghcr.io/foo/alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io"),
                    image: "foo/alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, missing tag
                "docker://ghcr.io/foo/alpine",
                Some(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io"),
                    image: "foo/alpine",
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Invalid, but allowed: Docker ref, empty tag
                "docker://ghcr.io/foo/alpine:",
                Some(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io"),
                    image: "foo/alpine",
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, bare
                "docker://alpine",
                Some(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine",
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, hash
                "docker://alpine@hash",
                Some(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine",
                    tag: None,
                    hash: Some("hash"),
                })),
            ),
            // Invalid: missing user/repo
            ("checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", None),
            // Invalid: local action refs not supported
            (
                "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(Uses::from_step(input), expected);
        }
    }

    #[test]
    fn uses_from_reusable() {
        let vectors = [
            // Valid, as expected.
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@\
                 172239021f7ba04fe7327647b213799853a9eb89",
                Some(RepositoryUses {
                    owner: "octo-org",
                    repo: "this-repo",
                    subpath: Some(".github/workflows/workflow-1.yml"),
                    git_ref: Some("172239021f7ba04fe7327647b213799853a9eb89"),
                }),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@notahash",
                Some(RepositoryUses {
                    owner: "octo-org",
                    repo: "this-repo",
                    subpath: Some(".github/workflows/workflow-1.yml"),
                    git_ref: Some("notahash"),
                }),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@abcd",
                Some(RepositoryUses {
                    owner: "octo-org",
                    repo: "this-repo",
                    subpath: Some(".github/workflows/workflow-1.yml"),
                    git_ref: Some("abcd"),
                }),
            ),
            // Invalid: no ref at all
            ("octo-org/this-repo/.github/workflows/workflow-1.yml", None),
            // Invalid: missing user/repo
            (
                "workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
            // Invalid: local reusable workflow refs not supported
            (
                "./.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(Uses::from_reusable(input), expected);
        }
    }

    #[test]
    fn uses_ref_is_commit() {
        assert!(
            Uses::from_reusable("actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3")
                .unwrap()
                .ref_is_commit()
        );

        assert!(!Uses::from_reusable("actions/checkout@v4")
            .unwrap()
            .ref_is_commit());

        assert!(!Uses::from_reusable("actions/checkout@abcd")
            .unwrap()
            .ref_is_commit());
    }
}

//! Shared models and utilities.

use std::{
    fmt::{self, Display},
    str::FromStr,
};

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, de};

pub mod expr;

/// `permissions` for a workflow, job, or step.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum Permissions {
    /// Base, i.e. blanket permissions.
    Base(BasePermission),
    /// Fine-grained permissions.
    ///
    /// These are modeled with an open-ended mapping rather than a structure
    /// to make iteration over all defined permissions easier.
    Explicit(IndexMap<String, Permission>),
}

impl Default for Permissions {
    fn default() -> Self {
        Self::Base(BasePermission::Default)
    }
}

/// "Base" permissions, where all individual permissions are configured
/// with a blanket setting.
#[derive(Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BasePermission {
    /// Whatever default permissions come from the workflow's `GITHUB_TOKEN`.
    #[default]
    Default,
    /// "Read" access to all resources.
    ReadAll,
    /// "Write" access to all resources (implies read).
    WriteAll,
}

/// A singular permission setting.
#[derive(Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    /// Read access.
    Read,

    /// Write access.
    Write,

    /// No access.
    #[default]
    None,
}

/// An environment mapping.
pub type Env = IndexMap<String, EnvValue>;

/// Environment variable values are always strings, but GitHub Actions
/// allows users to configure them as various native YAML types before
/// internal stringification.
///
/// This type also gets used for other places where GitHub Actions
/// contextually reinterprets a YAML value as a string, e.g. trigger
/// input values.
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum EnvValue {
    // Missing values are empty strings.
    #[serde(deserialize_with = "null_to_default")]
    String(String),
    Number(f64),
    Boolean(bool),
}

impl Display for EnvValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Boolean(b) => write!(f, "{b}"),
        }
    }
}

/// A "scalar or vector" type, for places in GitHub Actions where a
/// key can have either a scalar value or an array of values.
///
/// This only appears internally, as an intermediate type for `scalar_or_vector`.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(untagged)]
enum SoV<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> From<SoV<T>> for Vec<T> {
    fn from(val: SoV<T>) -> Vec<T> {
        match val {
            SoV::One(v) => vec![v],
            SoV::Many(vs) => vs,
        }
    }
}

pub(crate) fn scalar_or_vector<'de, D, T>(de: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    SoV::deserialize(de).map(Into::into)
}

/// A bool or string. This is useful for cases where GitHub Actions contextually
/// reinterprets a YAML boolean as a string, e.g. `run: true` really means
/// `run: 'true'`.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(untagged)]
enum BoS {
    Bool(bool),
    String(String),
}

impl From<BoS> for String {
    fn from(value: BoS) -> Self {
        match value {
            BoS::Bool(b) => b.to_string(),
            BoS::String(s) => s,
        }
    }
}

/// An `if:` condition in a job or action definition.
///
/// These are either booleans or bare (i.e. non-curly) expressions.
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum If {
    Bool(bool),
    // NOTE: condition expressions can be either "bare" or "curly", so we can't
    // use `BoE` or anything else that assumes curly-only here.
    Expr(String),
}

pub(crate) fn bool_is_string<'de, D>(de: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    BoS::deserialize(de).map(Into::into)
}

fn null_to_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let key = Option::<T>::deserialize(de)?;
    Ok(key.unwrap_or_default())
}

// TODO: Bother with enum variants here?
#[derive(Debug, PartialEq)]
pub struct UsesError(String);

impl fmt::Display for UsesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed `uses` ref: {}", self.0)
    }
}

#[derive(Debug, PartialEq)]
pub enum Uses {
    /// A local `uses:` clause, e.g. `uses: ./foo/bar`.
    Local(LocalUses),

    /// A repository `uses:` clause, e.g. `uses: foo/bar`.
    Repository(RepositoryUses),

    /// A Docker image `uses: clause`, e.g. `uses: docker://ubuntu`.
    Docker(DockerUses),
}

impl FromStr for Uses {
    type Err = UsesError;

    fn from_str(uses: &str) -> Result<Self, Self::Err> {
        if uses.starts_with("./") {
            LocalUses::from_str(uses).map(Self::Local)
        } else if let Some(image) = uses.strip_prefix("docker://") {
            DockerUses::from_str(image).map(Self::Docker)
        } else {
            RepositoryUses::from_str(uses).map(Self::Repository)
        }
    }
}

/// A `uses: ./some/path` clause.
#[derive(Debug, PartialEq)]
pub struct LocalUses {
    pub path: String,
}

impl FromStr for LocalUses {
    type Err = UsesError;

    fn from_str(uses: &str) -> Result<Self, Self::Err> {
        Ok(LocalUses { path: uses.into() })
    }
}

/// A `uses: some/repo` clause.
#[derive(Debug, PartialEq)]
pub struct RepositoryUses {
    /// The repo user or org.
    pub owner: String,
    /// The repo name.
    pub repo: String,
    /// The subpath to the action or reusable workflow, if present.
    pub subpath: Option<String>,
    /// The `@<ref>` that the `uses:` is pinned to, if present.
    pub git_ref: Option<String>,
}

impl FromStr for RepositoryUses {
    type Err = UsesError;

    fn from_str(uses: &str) -> Result<Self, Self::Err> {
        // NOTE: FromStr is slightly sub-optimal, since it takes a borrowed
        // &str and results in bunch of allocs for a fully owned type.
        //
        // In theory we could do `From<String>` instead, but
        // `&mut str::split_mut` and similar don't exist yet.

        // NOTE: Both git refs and paths can contain `@`, but in practice
        // GHA refuses to run a `uses:` clause with more than one `@` in it.
        let (path, git_ref) = match uses.rsplit_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (uses, None),
        };

        let components = path.splitn(3, '/').collect::<Vec<_>>();
        if components.len() < 2 {
            return Err(UsesError(format!("owner/repo slug is too short: {uses}")));
        }

        Ok(RepositoryUses {
            owner: components[0].into(),
            repo: components[1].into(),
            subpath: components.get(2).map(ToString::to_string),
            git_ref: git_ref.map(Into::into),
        })
    }
}

/// A `uses: docker://some-image` clause.
#[derive(Debug, PartialEq)]
pub struct DockerUses {
    /// The registry this image is on, if present.
    pub registry: Option<String>,
    /// The name of the Docker image.
    pub image: String,
    /// An optional tag for the image.
    pub tag: Option<String>,
    /// An optional integrity hash for the image.
    pub hash: Option<String>,
}

impl DockerUses {
    fn is_registry(registry: &str) -> bool {
        // https://stackoverflow.com/a/42116190
        registry == "localhost" || registry.contains('.') || registry.contains(':')
    }
}

impl FromStr for DockerUses {
    type Err = UsesError;

    fn from_str(uses: &str) -> Result<Self, Self::Err> {
        let (registry, image) = match uses.split_once('/') {
            Some((registry, image)) if Self::is_registry(registry) => (Some(registry), image),
            _ => (None, uses),
        };

        // NOTE(ww): hashes aren't mentioned anywhere in Docker's own docs,
        // but appear to be an OCI thing. GitHub doesn't support them
        // yet either, but we expect them to soon (with "immutable actions").
        if let Some(at_pos) = image.find('@') {
            let (image, hash) = image.split_at(at_pos);

            let hash = if hash.is_empty() {
                None
            } else {
                Some(&hash[1..])
            };

            Ok(DockerUses {
                registry: registry.map(Into::into),
                image: image.into(),
                tag: None,
                hash: hash.map(Into::into),
            })
        } else {
            let (image, tag) = match image.split_once(':') {
                Some((image, "")) => (image, None),
                Some((image, tag)) => (image, Some(tag)),
                _ => (image, None),
            };

            Ok(DockerUses {
                registry: registry.map(Into::into),
                image: image.into(),
                tag: tag.map(Into::into),
                hash: None,
            })
        }
    }
}

/// Deserialize an ordinary step `uses:`.
pub(crate) fn step_uses<'de, D>(de: D) -> Result<Uses, D::Error>
where
    D: Deserializer<'de>,
{
    let uses = <&str>::deserialize(de)?;
    Uses::from_str(uses).map_err(de::Error::custom)
}

/// Deserialize a reusable workflow step `uses:`
pub(crate) fn reusable_step_uses<'de, D>(de: D) -> Result<Uses, D::Error>
where
    D: Deserializer<'de>,
{
    let uses = step_uses(de)?;

    match uses {
        Uses::Repository(ref repo) => {
            // Remote reusable workflows must be pinned.
            if repo.git_ref.is_none() {
                Err(de::Error::custom(
                    "repo action must have `@<ref>` in reusable workflow",
                ))
            } else {
                Ok(uses)
            }
        }
        Uses::Local(ref local) => {
            // Local reusable workflows cannot be pinned.
            // We do this with a string scan because `@` *can* occur as
            // a path component in local actions uses, just not local reusable
            // workflow uses.
            if local.path.contains('@') {
                Err(de::Error::custom(
                    "local reusable workflow reference can't specify `@<ref>`",
                ))
            } else {
                Ok(uses)
            }
        }
        // `docker://` is never valid in reusable workflow uses.
        Uses::Docker(_) => Err(de::Error::custom(
            "docker action invalid in reusable workflow `uses`",
        )),
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use serde::Deserialize;

    use crate::common::{BasePermission, Env, EnvValue, Permission};

    use super::{
        DockerUses, LocalUses, Permissions, RepositoryUses, Uses, UsesError, reusable_step_uses,
    };

    #[test]
    fn test_permissions() {
        assert_eq!(
            serde_yaml::from_str::<Permissions>("read-all").unwrap(),
            Permissions::Base(BasePermission::ReadAll)
        );

        let perm = "security-events: write";
        assert_eq!(
            serde_yaml::from_str::<Permissions>(perm).unwrap(),
            Permissions::Explicit(IndexMap::from([(
                "security-events".into(),
                Permission::Write
            )]))
        );
    }

    #[test]
    fn test_env_empty_value() {
        let env = "foo:";
        assert_eq!(
            serde_yaml::from_str::<Env>(env).unwrap()["foo"],
            EnvValue::String("".into())
        );
    }

    #[test]
    fn test_uses_parses() {
        let vectors = [
            (
                // Valid: fully pinned.
                "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Ok(Uses::Repository(RepositoryUses {
                    owner: "actions".to_owned(),
                    repo: "checkout".to_owned(),
                    subpath: None,
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3".to_owned()),
                })),
            ),
            (
                // Valid: fully pinned, subpath
                "actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Ok(Uses::Repository(RepositoryUses {
                    owner: "actions".to_owned(),
                    repo: "aws".to_owned(),
                    subpath: Some("ec2".to_owned()),
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3".to_owned()),
                })),
            ),
            (
                // Valid: fully pinned, complex subpath
                "example/foo/bar/baz/quux@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Ok(Uses::Repository(RepositoryUses {
                    owner: "example".to_owned(),
                    repo: "foo".to_owned(),
                    subpath: Some("bar/baz/quux".to_owned()),
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3".to_owned()),
                })),
            ),
            (
                // Valid: pinned with branch/tag
                "actions/checkout@v4",
                Ok(Uses::Repository(RepositoryUses {
                    owner: "actions".to_owned(),
                    repo: "checkout".to_owned(),
                    subpath: None,
                    git_ref: Some("v4".to_owned()),
                })),
            ),
            (
                "actions/checkout@abcd",
                Ok(Uses::Repository(RepositoryUses {
                    owner: "actions".to_owned(),
                    repo: "checkout".to_owned(),
                    subpath: None,
                    git_ref: Some("abcd".to_owned()),
                })),
            ),
            (
                // Valid: unpinned
                "actions/checkout",
                Ok(Uses::Repository(RepositoryUses {
                    owner: "actions".to_owned(),
                    repo: "checkout".to_owned(),
                    subpath: None,
                    git_ref: None,
                })),
            ),
            (
                // Valid: Docker ref, implicit registry
                "docker://alpine:3.8",
                Ok(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine".to_owned(),
                    tag: Some("3.8".to_owned()),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, localhost
                "docker://localhost/alpine:3.8",
                Ok(Uses::Docker(DockerUses {
                    registry: Some("localhost".to_owned()),
                    image: "alpine".to_owned(),
                    tag: Some("3.8".to_owned()),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, localhost w/ port
                "docker://localhost:1337/alpine:3.8",
                Ok(Uses::Docker(DockerUses {
                    registry: Some("localhost:1337".to_owned()),
                    image: "alpine".to_owned(),
                    tag: Some("3.8".to_owned()),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, custom registry
                "docker://ghcr.io/foo/alpine:3.8",
                Ok(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io".to_owned()),
                    image: "foo/alpine".to_owned(),
                    tag: Some("3.8".to_owned()),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, missing tag
                "docker://ghcr.io/foo/alpine",
                Ok(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io".to_owned()),
                    image: "foo/alpine".to_owned(),
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Invalid, but allowed: Docker ref, empty tag
                "docker://ghcr.io/foo/alpine:",
                Ok(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io".to_owned()),
                    image: "foo/alpine".to_owned(),
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, bare
                "docker://alpine",
                Ok(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine".to_owned(),
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, hash
                "docker://alpine@hash",
                Ok(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine".to_owned(),
                    tag: None,
                    hash: Some("hash".to_owned()),
                })),
            ),
            (
                // Valid: Local action "ref", actually part of the path
                "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89",
                Ok(Uses::Local(LocalUses {
                    path: "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89".to_owned(),
                })),
            ),
            (
                // Valid: Local action ref, unpinned
                "./.github/actions/hello-world-action",
                Ok(Uses::Local(LocalUses {
                    path: "./.github/actions/hello-world-action".to_owned(),
                })),
            ),
            // Invalid: missing user/repo
            (
                "checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Err(UsesError(
                    "owner/repo slug is too short: checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3".to_owned()
                )),
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(input.parse(), expected);
        }
    }

    #[test]
    fn test_uses_deser_reusable() {
        let vectors = [
            // Valid, as expected.
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@\
                 172239021f7ba04fe7327647b213799853a9eb89",
                Some(Uses::Repository(RepositoryUses {
                    owner: "octo-org".to_owned(),
                    repo: "this-repo".to_owned(),
                    subpath: Some(".github/workflows/workflow-1.yml".to_owned()),
                    git_ref: Some("172239021f7ba04fe7327647b213799853a9eb89".to_owned()),
                })),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@notahash",
                Some(Uses::Repository(RepositoryUses {
                    owner: "octo-org".to_owned(),
                    repo: "this-repo".to_owned(),
                    subpath: Some(".github/workflows/workflow-1.yml".to_owned()),
                    git_ref: Some("notahash".to_owned()),
                })),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@abcd",
                Some(Uses::Repository(RepositoryUses {
                    owner: "octo-org".to_owned(),
                    repo: "this-repo".to_owned(),
                    subpath: Some(".github/workflows/workflow-1.yml".to_owned()),
                    git_ref: Some("abcd".to_owned()),
                })),
            ),
            // Invalid: remote reusable workflow without ref
            ("octo-org/this-repo/.github/workflows/workflow-1.yml", None),
            // Invalid: local reusable workflow with ref
            (
                "./.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
            // Invalid: no ref at all
            ("octo-org/this-repo/.github/workflows/workflow-1.yml", None),
            (".github/workflows/workflow-1.yml", None),
            // Invalid: missing user/repo
            (
                "workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
        ];

        // Dummy type for testing deser of `Uses`.
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Dummy(#[serde(deserialize_with = "reusable_step_uses")] Uses);

        for (input, expected) in vectors {
            assert_eq!(
                serde_yaml::from_str::<Dummy>(input).map(|d| d.0).ok(),
                expected
            );
        }
    }
}

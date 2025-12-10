//! Shared models and utilities.

use std::fmt::{self, Display};

use indexmap::IndexMap;
use self_cell::self_cell;
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

impl EnvValue {
    /// Returns whether this [`EnvValue`] is a "trueish" value
    /// per C#'s `Boolean.TryParse`.
    ///
    /// This follows the semantics of C#'s `Boolean.TryParse`, where
    /// the case-insensitive string "true" is considered true, but
    /// "1", "yes", etc. are not.
    pub fn csharp_trueish(&self) -> bool {
        match self {
            EnvValue::Boolean(true) => true,
            EnvValue::String(maybe) => maybe.trim().eq_ignore_ascii_case("true"),
            _ => false,
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

impl Uses {
    /// Parse a `uses:` clause into its appropriate variant.
    pub fn parse(uses: impl Into<String>) -> Result<Self, UsesError> {
        let uses = uses.into();

        if uses.starts_with("./") {
            Ok(Self::Local(LocalUses::new(uses)))
        } else if let Some(image) = uses.strip_prefix("docker://") {
            DockerUses::parse(image).map(Self::Docker)
        } else {
            RepositoryUses::parse(uses).map(Self::Repository)
        }
    }

    /// Returns the original raw `uses:` clause.
    pub fn raw(&self) -> &str {
        match self {
            Uses::Local(local) => &local.path,
            Uses::Repository(repo) => repo.raw(),
            Uses::Docker(docker) => docker.raw(),
        }
    }
}

/// A `uses: ./some/path` clause.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub struct LocalUses {
    pub path: String,
}

impl LocalUses {
    fn new(path: String) -> Self {
        LocalUses { path }
    }
}

#[derive(Debug, PartialEq)]
struct RepositoryUsesInner<'a> {
    /// The repo user or org.
    owner: &'a str,
    /// The repo name.
    repo: &'a str,
    /// The owner/repo slug.
    slug: &'a str,
    /// The subpath to the action or reusable workflow, if present.
    subpath: Option<&'a str>,
    /// The `@<ref>` that the `uses:` is pinned to.
    git_ref: &'a str,
}

impl<'a> RepositoryUsesInner<'a> {
    fn from_str(uses: &'a str) -> Result<Self, UsesError> {
        // NOTE: Both git refs and paths can contain `@`, but in practice
        // GHA refuses to run a `uses:` clause with more than one `@` in it.
        let (path, git_ref) = match uses.rsplit_once('@') {
            Some((path, git_ref)) => (path, git_ref),
            None => return Err(UsesError(format!("missing `@<ref>` in {uses}"))),
        };

        let mut components = path.splitn(3, '/');

        if let Some(owner) = components.next()
            && let Some(repo) = components.next()
        {
            let subpath = components.next();

            let slug = if subpath.is_none() {
                path
            } else {
                &path[..owner.len() + 1 + repo.len()]
            };

            Ok(RepositoryUsesInner {
                owner,
                repo,
                slug,
                subpath,
                git_ref,
            })
        } else {
            Err(UsesError(format!("owner/repo slug is too short: {uses}")))
        }
    }
}

self_cell!(
    /// A `uses: some/repo` clause.
    pub struct RepositoryUses {
        owner: String,

        #[covariant]
        dependent: RepositoryUsesInner,
    }

    impl {Debug, PartialEq}
);

impl Display for RepositoryUses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw())
    }
}

impl RepositoryUses {
    /// Parse a `uses: some/repo` clause.
    pub fn parse(uses: impl Into<String>) -> Result<Self, UsesError> {
        RepositoryUses::try_new(uses.into(), |s| {
            let inner = RepositoryUsesInner::from_str(s)?;
            Ok(inner)
        })
    }

    /// Get the raw `uses:` string.
    pub fn raw(&self) -> &str {
        self.borrow_owner()
    }

    /// Get the owner (user or org) of this repository `uses:` clause.
    pub fn owner(&self) -> &str {
        self.borrow_dependent().owner
    }

    /// Get the repository name of this repository `uses:` clause.
    pub fn repo(&self) -> &str {
        self.borrow_dependent().repo
    }

    /// Get the owner/repo slug of this repository `uses:` clause.
    pub fn slug(&self) -> &str {
        self.borrow_dependent().slug
    }

    /// Get the optional subpath of this repository `uses:` clause.
    pub fn subpath(&self) -> Option<&str> {
        self.borrow_dependent().subpath
    }

    /// Get the git ref (branch, tag, or SHA) of this repository `uses:` clause.
    pub fn git_ref(&self) -> &str {
        self.borrow_dependent().git_ref
    }
}

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub struct DockerUsesInner<'a> {
    /// The registry this image is on, if present.
    registry: Option<&'a str>,
    /// The name of the Docker image.
    image: &'a str,
    /// An optional tag for the image.
    tag: Option<&'a str>,
    /// An optional integrity hash for the image.
    hash: Option<&'a str>,
}

impl<'a> DockerUsesInner<'a> {
    fn is_registry(registry: &str) -> bool {
        // https://stackoverflow.com/a/42116190
        registry == "localhost" || registry.contains('.') || registry.contains(':')
    }

    fn from_str(uses: &'a str) -> Result<Self, UsesError> {
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

            Ok(DockerUsesInner {
                registry,
                image,
                tag: None,
                hash,
            })
        } else {
            let (image, tag) = match image.split_once(':') {
                Some((image, "")) => (image, None),
                Some((image, tag)) => (image, Some(tag)),
                _ => (image, None),
            };

            Ok(DockerUsesInner {
                registry,
                image,
                tag,
                hash: None,
            })
        }
    }
}

self_cell!(
    /// A `uses: docker://some-image` clause.
    pub struct DockerUses {
        owner: String,

        #[covariant]
        dependent: DockerUsesInner,
    }

    impl {Debug, PartialEq}
);

impl DockerUses {
    /// Parse a `uses: docker://some-image` clause.
    pub fn parse(uses: impl Into<String>) -> Result<Self, UsesError> {
        DockerUses::try_new(uses.into(), |s| {
            let inner = DockerUsesInner::from_str(s)?;
            Ok(inner)
        })
    }

    /// Get the raw uses clause. This does not include the `docker://` prefix.
    pub fn raw(&self) -> &str {
        self.borrow_owner()
    }

    /// Get the optional registry of this Docker image.
    pub fn registry(&self) -> Option<&str> {
        self.borrow_dependent().registry
    }

    /// Get the image name of this Docker image.
    pub fn image(&self) -> &str {
        self.borrow_dependent().image
    }

    /// Get the optional tag of this Docker image.
    pub fn tag(&self) -> Option<&str> {
        self.borrow_dependent().tag
    }

    /// Get the optional hash of this Docker image.
    pub fn hash(&self) -> Option<&str> {
        self.borrow_dependent().hash
    }
}

/// Wraps a `de::Error::custom` call to log the same error as
/// a `tracing::error!` event.
///
/// This is useful when doing custom deserialization within untagged
/// enum variants, since serde loses track of the original error.
pub(crate) fn custom_error<'de, D>(msg: impl Display) -> D::Error
where
    D: Deserializer<'de>,
{
    let msg = msg.to_string();
    tracing::error!(msg);
    de::Error::custom(msg)
}

/// Deserialize a `DockerUses`.
pub(crate) fn docker_uses<'de, D>(de: D) -> Result<DockerUses, D::Error>
where
    D: Deserializer<'de>,
{
    let uses = <String>::deserialize(de)?;
    DockerUses::parse(uses).map_err(custom_error::<D>)
}

/// Deserialize an ordinary step `uses:`.
pub(crate) fn step_uses<'de, D>(de: D) -> Result<Uses, D::Error>
where
    D: Deserializer<'de>,
{
    let uses = <String>::deserialize(de)?;
    Uses::parse(uses).map_err(custom_error::<D>)
}

/// Deserialize a reusable workflow step `uses:`
pub(crate) fn reusable_step_uses<'de, D>(de: D) -> Result<Uses, D::Error>
where
    D: Deserializer<'de>,
{
    let uses = step_uses(de)?;

    match uses {
        Uses::Repository(_) => Ok(uses),
        Uses::Local(ref local) => {
            // Local reusable workflows cannot be pinned.
            // We do this with a string scan because `@` *can* occur as
            // a path component in local actions uses, just not local reusable
            // workflow uses.
            if local.path.contains('@') {
                Err(custom_error::<D>(
                    "local reusable workflow reference can't specify `@<ref>`",
                ))
            } else {
                Ok(uses)
            }
        }
        // `docker://` is never valid in reusable workflow uses.
        Uses::Docker(_) => Err(custom_error::<D>(
            "docker action invalid in reusable workflow `uses`",
        )),
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use serde::Deserialize;

    use crate::common::{BasePermission, Env, EnvValue, Permission};

    use super::{Permissions, Uses, reusable_step_uses};

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
    fn test_env_value_csharp_trueish() {
        let vectors = [
            (EnvValue::Boolean(true), true),
            (EnvValue::Boolean(false), false),
            (EnvValue::String("true".to_string()), true),
            (EnvValue::String("TRUE".to_string()), true),
            (EnvValue::String("TrUe".to_string()), true),
            (EnvValue::String(" true ".to_string()), true),
            (EnvValue::String("   \n\r\t True\n\n".to_string()), true),
            (EnvValue::String("false".to_string()), false),
            (EnvValue::String("1".to_string()), false),
            (EnvValue::String("yes".to_string()), false),
            (EnvValue::String("on".to_string()), false),
            (EnvValue::String("random".to_string()), false),
            (EnvValue::Number(1.0), false),
            (EnvValue::Number(0.0), false),
            (EnvValue::Number(666.0), false),
        ];

        for (val, expected) in vectors {
            assert_eq!(val.csharp_trueish(), expected, "failed for {val:?}");
        }
    }

    #[test]
    fn test_uses_parses() {
        // Fully pinned.
        insta::assert_debug_snapshot!(
            Uses::parse("actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3").unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                dependent: RepositoryUsesInner {
                    owner: "actions",
                    repo: "checkout",
                    slug: "actions/checkout",
                    subpath: None,
                    git_ref: "8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                },
            },
        )
        "#,
        );

        // Fully pinned, subpath.
        insta::assert_debug_snapshot!(
            Uses::parse("actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3").unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                dependent: RepositoryUsesInner {
                    owner: "actions",
                    repo: "aws",
                    slug: "actions/aws",
                    subpath: Some(
                        "ec2",
                    ),
                    git_ref: "8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                },
            },
        )
        "#
        );

        // Fully pinned, complex subpath.
        insta::assert_debug_snapshot!(
            Uses::parse("example/foo/bar/baz/quux@8f4b7f84864484a7bf31766abe9204da3cbe65b3").unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "example/foo/bar/baz/quux@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                dependent: RepositoryUsesInner {
                    owner: "example",
                    repo: "foo",
                    slug: "example/foo",
                    subpath: Some(
                        "bar/baz/quux",
                    ),
                    git_ref: "8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                },
            },
        )
        "#
        );

        // Pinned with branch/tag.
        insta::assert_debug_snapshot!(
            Uses::parse("actions/checkout@v4").unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "actions/checkout@v4",
                dependent: RepositoryUsesInner {
                    owner: "actions",
                    repo: "checkout",
                    slug: "actions/checkout",
                    subpath: None,
                    git_ref: "v4",
                },
            },
        )
        "#
        );

        insta::assert_debug_snapshot!(
            Uses::parse("actions/checkout@abcd").unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "actions/checkout@abcd",
                dependent: RepositoryUsesInner {
                    owner: "actions",
                    repo: "checkout",
                    slug: "actions/checkout",
                    subpath: None,
                    git_ref: "abcd",
                },
            },
        )
        "#
        );

        // Invalid: unpinned.
        insta::assert_debug_snapshot!(
            Uses::parse("actions/checkout").unwrap_err(),
            @r#"
        UsesError(
            "missing `@<ref>` in actions/checkout",
        )
        "#
        );

        // Valid: Docker ref, implicit registry.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://alpine:3.8").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "alpine:3.8",
                dependent: DockerUsesInner {
                    registry: None,
                    image: "alpine",
                    tag: Some(
                        "3.8",
                    ),
                    hash: None,
                },
            },
        )
        "#
        );

        // Valid: Docker ref, localhost.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://localhost/alpine:3.8").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "localhost/alpine:3.8",
                dependent: DockerUsesInner {
                    registry: Some(
                        "localhost",
                    ),
                    image: "alpine",
                    tag: Some(
                        "3.8",
                    ),
                    hash: None,
                },
            },
        )
        "#
        );

        // Valid: Docker ref, localhost with port.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://localhost:1337/alpine:3.8").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "localhost:1337/alpine:3.8",
                dependent: DockerUsesInner {
                    registry: Some(
                        "localhost:1337",
                    ),
                    image: "alpine",
                    tag: Some(
                        "3.8",
                    ),
                    hash: None,
                },
            },
        )
        "#
        );

        // Valid: Docker ref, custom registry.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://ghcr.io/foo/alpine:3.8").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "ghcr.io/foo/alpine:3.8",
                dependent: DockerUsesInner {
                    registry: Some(
                        "ghcr.io",
                    ),
                    image: "foo/alpine",
                    tag: Some(
                        "3.8",
                    ),
                    hash: None,
                },
            },
        )
        "#
        );

        // Valid: Docker ref, missing tag.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://ghcr.io/foo/alpine").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "ghcr.io/foo/alpine",
                dependent: DockerUsesInner {
                    registry: Some(
                        "ghcr.io",
                    ),
                    image: "foo/alpine",
                    tag: None,
                    hash: None,
                },
            },
        )
        "#
        );

        // Invalid, but allowed: Docker ref, empty tag
        insta::assert_debug_snapshot!(
            Uses::parse("docker://ghcr.io/foo/alpine:").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "ghcr.io/foo/alpine:",
                dependent: DockerUsesInner {
                    registry: Some(
                        "ghcr.io",
                    ),
                    image: "foo/alpine",
                    tag: None,
                    hash: None,
                },
            },
        )
        "#
        );

        // Valid: Docker ref, bare.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://alpine").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "alpine",
                dependent: DockerUsesInner {
                    registry: None,
                    image: "alpine",
                    tag: None,
                    hash: None,
                },
            },
        )
        "#
        );

        // Valid: Docker ref, with hash.
        insta::assert_debug_snapshot!(
            Uses::parse("docker://alpine@hash").unwrap(),
            @r#"
        Docker(
            DockerUses {
                owner: "alpine@hash",
                dependent: DockerUsesInner {
                    registry: None,
                    image: "alpine",
                    tag: None,
                    hash: Some(
                        "hash",
                    ),
                },
            },
        )
        "#
        );

        // Valid: Local action "ref", actually part of the path
        insta::assert_debug_snapshot!(
            Uses::parse("./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89").unwrap(),
            @r#"
        Local(
            LocalUses {
                path: "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89",
            },
        )
        "#
        );

        // Valid: Local action ref, unpinned.
        insta::assert_debug_snapshot!(
            Uses::parse("./.github/actions/hello-world-action").unwrap(),
            @r#"
        Local(
            LocalUses {
                path: "./.github/actions/hello-world-action",
            },
        )
        "#
        );

        // Invalid: missing user/repo
        insta::assert_debug_snapshot!(
            Uses::parse("checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3").unwrap_err(),
            @r#"
        UsesError(
            "owner/repo slug is too short: checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
        )
        "#
        );
    }

    #[test]
    fn test_uses_deser_reusable() {
        // Dummy type for testing deser of `Uses`.
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Dummy(#[serde(deserialize_with = "reusable_step_uses")] Uses);

        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                "octo-org/this-repo/.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89"
            )
            .map(|d| d.0)
            .unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "octo-org/this-repo/.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                dependent: RepositoryUsesInner {
                    owner: "octo-org",
                    repo: "this-repo",
                    slug: "octo-org/this-repo",
                    subpath: Some(
                        ".github/workflows/workflow-1.yml",
                    ),
                    git_ref: "172239021f7ba04fe7327647b213799853a9eb89",
                },
            },
        )
        "#
        );

        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                "octo-org/this-repo/.github/workflows/workflow-1.yml@notahash"
            ).map(|d| d.0).unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "octo-org/this-repo/.github/workflows/workflow-1.yml@notahash",
                dependent: RepositoryUsesInner {
                    owner: "octo-org",
                    repo: "this-repo",
                    slug: "octo-org/this-repo",
                    subpath: Some(
                        ".github/workflows/workflow-1.yml",
                    ),
                    git_ref: "notahash",
                },
            },
        )
        "#
        );

        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                "octo-org/this-repo/.github/workflows/workflow-1.yml@abcd"
            ).map(|d| d.0).unwrap(),
            @r#"
        Repository(
            RepositoryUses {
                owner: "octo-org/this-repo/.github/workflows/workflow-1.yml@abcd",
                dependent: RepositoryUsesInner {
                    owner: "octo-org",
                    repo: "this-repo",
                    slug: "octo-org/this-repo",
                    subpath: Some(
                        ".github/workflows/workflow-1.yml",
                    ),
                    git_ref: "abcd",
                },
            },
        )
        "#
        );

        // Invalid: remote reusable workflow without ref
        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                "octo-org/this-repo/.github/workflows/workflow-1.yml"
            ).map(|d| d.0).unwrap_err(),
            @r#"Error("malformed `uses` ref: missing `@<ref>` in octo-org/this-repo/.github/workflows/workflow-1.yml")"#
        );

        // Invalid: local reusable workflow with ref
        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                "./.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89"
            ).map(|d| d.0).unwrap_err(),
            @r#"Error("local reusable workflow reference can't specify `@<ref>`")"#
        );

        // Invalid: no ref at all
        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                ".github/workflows/workflow-1.yml"
            ).map(|d| d.0).unwrap_err(),
            @r#"Error("malformed `uses` ref: missing `@<ref>` in .github/workflows/workflow-1.yml")"#
        );

        // Invalid: missing user/repo
        insta::assert_debug_snapshot!(
            serde_yaml::from_str::<Dummy>(
                "workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89"
            ).map(|d| d.0).unwrap_err(),
            @r#"Error("malformed `uses` ref: owner/repo slug is too short: workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89")"#
        );
    }
}

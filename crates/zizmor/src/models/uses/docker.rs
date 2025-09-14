//! Patterns for Docker images (including in `uses:` clauses) and corresponding extension traits.

pub(crate) enum DockerImagePattern {
    /// Matches `registry/repo/*` or `repo/*` (in the default registry case),
    /// i.e. any image in the given repository.
    InRepo { registry: String, repo: String },
    /// Matches `registry/*`, i.e. any image in the given registry.
    InRegistry(String),
    /// Matches any image.
    Any,
}

//! Patterns for Docker images (including in `uses:` clauses) and corresponding extension traits.

use std::sync::LazyLock;

use regex::Regex;

// static DOCKER_IMAGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
//     Regex::new(
//         r#"(?xmi)                           # verbose, multi-line mode, case-insensitive
//         ^                                   # start of line
//         (?:                                 # start of optional non-capturing group for [registry/]
//             (?<registry>                    # start of capturing group for [registry]
//                 localhost|\w+\.\w+|\w+:\d+  # match localhost, domain-like, or domain:port
//             )                               # end of capturing group for [registry]
//             /                               # /
//         )?                                  # end of optional non-capturing group for [registry/]
//         (?:

//         )?
//         "#,
//     )
//     .unwrap()
// });

/// Represents a pattern for matching Docker images.
///
/// These patterns are used for both `uses:` clauses and for other
/// audits that match image references, e.g. `unpinned-images`.
pub(crate) enum DockerImagePattern {
    /// Matches `[registry/]namespace/image`, i.e. a specific image.
    ExactImage {
        registry: Option<String>,
        namespace: String,
        image: String,
    },
    /// Matches `[registry/]namespace/*`, i.e. any image in the given namespace.
    InNamespace {
        registry: Option<String>,
        namespace: String,
    },
    /// Matches `registry/*`, i.e. any image in the given registry.
    InRegistry(String),
    /// Matches any image.
    Any,
}

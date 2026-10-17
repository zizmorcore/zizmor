use std::{collections::HashSet, sync::LazyLock};

use camino::{Utf8Path, Utf8PathBuf};

/// Cached parse of the process's `GIT_CEILING_DIRECTORIES`.
static GIT_CEILING_DIRECTORIES: LazyLock<HashSet<Utf8PathBuf>> = LazyLock::new(|| {
    let Ok(raw) = std::env::var("GIT_CEILING_DIRECTORIES") else {
        return HashSet::new();
    };

    let separator = if cfg!(windows) { ';' } else { ':' };
    let mut resolve = true;
    let mut ceilings = HashSet::new();
    for entry in raw.split(separator) {
        // Per `git` docs, an empty entry means that all subsequent
        // entries are not resolved.
        // See: <https://git-scm.com/docs/git#Documentation/git.txt-GITCEILINGDIRECTORIES>
        if entry.is_empty() {
            resolve = false;
            continue;
        }
        let path = Utf8Path::new(entry);
        if !path.is_absolute() {
            continue;
        }
        let resolved = if resolve {
            path.canonicalize_utf8().ok()
        } else {
            Some(path.to_path_buf())
        };
        if let Some(p) = resolved {
            ceilings.insert(p);
        }
    }
    ceilings
});

/// Represents a Git repository root.
///
/// In `zizmor`, each [`InputGroup`] can have a [`Root`], and the
/// root is discovered relative to the group's original input request.
#[derive(Clone, Debug)]
pub(crate) struct Root {
    /// Whether the original `zizmor` input request itself points to the root
    /// repository. For example, if the user runs `zizmor .` (or `zizmor foo/`)
    /// and `./.git` (or `foo/.git`) is present, then [`Root::request_is_root`] holds.
    pub(crate) request_is_root: bool,

    /// A canonical path to the Git repository root.
    path: Utf8PathBuf,
}

impl Root {
    pub(crate) fn path(&self) -> &Utf8Path {
        self.path.as_path()
    }

    /// Given a path to an input file, attempt to discover the Git repository root that it belongs
    /// to, if any.
    ///
    /// This is a rough approximation of what `git rev-parse --show-toplevel` does.
    ///
    /// Returns `None` if the path is not within a Git repository or if the root can't be determined for any reason.
    pub(crate) fn discover(path: &Utf8Path) -> Option<Self> {
        Self::discover_with_ceilings(path, &GIT_CEILING_DIRECTORIES)
    }

    fn discover_with_ceilings(path: &Utf8Path, ceilings: &HashSet<Utf8PathBuf>) -> Option<Self> {
        // Canonicalize first; this also avoids a `parent()` of `Some("")`
        // for inputs like `foo.yml`.
        let canonical = match path.canonicalize_utf8() {
            Ok(canonical) => canonical,
            Err(_) => {
                tracing::trace!("failed to find a canonical path for {path}");
                return None;
            }
        };

        let mut candidate = if canonical.is_file() {
            canonical.as_path().parent()?
        } else {
            canonical.as_path()
        };

        loop {
            if ceilings.contains(candidate) {
                tracing::trace!("hit a GIT_CEILING_DIRECTORIES entry at {candidate}");
                break;
            }

            tracing::trace!("checking if {candidate} is a Git repository root");
            // Submodules and linked worktrees use a `.git` file instead of a directory.
            if candidate.join(".git").exists() {
                return Some(Self {
                    request_is_root: candidate == canonical,
                    path: candidate.into(),
                });
            }

            if let Some(parent) = candidate.parent() {
                candidate = parent;
            } else {
                break;
            }
        }

        tracing::trace!("no Git repository root found for {path}");
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use camino::Utf8PathBuf;

    use crate::registry::input::root::Root;

    #[test]
    fn test_discover_in_submodule() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let temp_path = Utf8PathBuf::try_from(temp_dir.path().to_path_buf())
            .unwrap()
            .canonicalize_utf8()
            .unwrap();

        std::fs::create_dir_all(temp_path.join(".git/modules/submodule")).unwrap();
        let submodule = temp_path.join("submodule");
        let child = submodule.join("subdir");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(
            submodule.join(".git"),
            "gitdir: ../.git/modules/submodule\n",
        )
        .unwrap();

        let Some(Root {
            path,
            request_is_root: false,
        }) = Root::discover_with_ceilings(&child, &HashSet::new())
        else {
            panic!();
        };

        assert_eq!(path, submodule);
    }

    #[test]
    fn test_discover_respects_ceiling() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let temp_path = Utf8PathBuf::try_from(temp_dir.path().to_path_buf())
            .unwrap()
            .canonicalize_utf8()
            .unwrap();

        std::fs::create_dir(temp_path.join(".git")).unwrap();
        let child = temp_path.join("project/subdir");
        std::fs::create_dir_all(&child).unwrap();

        // No ceiling: the walk finds the fake repo.
        let Some(Root {
            path,
            request_is_root: false,
        }) = Root::discover_with_ceilings(&child, &HashSet::new())
        else {
            panic!();
        };
        assert_eq!(path, temp_path);

        // The repo itself is a ceiling: the walk stops before examining it.
        assert!(
            Root::discover_with_ceilings(&child, &HashSet::from([temp_path.clone()]),).is_none(),
        );

        // An ancestor above the repo is the ceiling, so the repo is still found.
        let parent_ceiling = temp_path.parent().unwrap().to_path_buf();
        let Some(Root {
            path,
            request_is_root: false,
        }) = Root::discover_with_ceilings(&child, &HashSet::from([parent_ceiling]))
        else {
            panic!();
        };
        assert_eq!(path, temp_path);

        // File inputs: canonicalize then walk from the file's parent.
        let workflow_file = temp_path.join(".github/workflows/test.yml");
        std::fs::create_dir_all(workflow_file.parent().unwrap()).unwrap();
        std::fs::write(&workflow_file, "").unwrap();

        let Some(Root {
            path,
            request_is_root: false,
        }) = Root::discover_with_ceilings(&workflow_file, &HashSet::new())
        else {
            panic!();
        };
        assert_eq!(path, temp_path);
    }
}

use std::ops::Deref;

use anyhow::Context;
use github_actions_expressions::Expr;
use github_actions_models::action;
use github_actions_models::common::{DockerUses, expr::LoE};
use github_actions_models::workflow::job::{Container, StepBody};
use tree_sitter::{Language, Parser, QueryCursor, StreamingIterator as _};

use crate::audit::AuditError;
use crate::config::Config;
use crate::finding::location::{Locatable as _, SymbolicLocation};
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::workflow::{JobCommon as _, Step};
use crate::models::{AsDocument, StepCommon};
use crate::state::AuditState;
use crate::utils;

use super::{Audit, AuditLoadError, audit_meta};

/// Tree-sitter query matching `docker` and `podman` command invocations in bash.
///
/// NOTE: `@span` is required by [`utils::SpannedQuery`] and can be used in the
/// future to produce more precise finding locations within multiline scripts.
const BASH_DOCKER_CMD_QUERY: &str = r#"
(command
  name: (command_name) @cmd
  argument: (_)* @args
  (#match? @cmd "^(docker|podman)$")
) @span
"#;

/// Boolean short flags for docker pull/run/create that do NOT consume the next argument.
///
/// NOTE: `-a` is intentionally excluded — it means `--all-tags` for `pull`
/// (boolean) but `--attach` for `run`/`create` (value-consuming). Treating it
/// as value-consuming is the safer default to avoid false positives.
const BOOLEAN_SHORT_FLAGS: &[&str] = &["-d", "-i", "-t", "-P", "-q"];

/// Boolean long flags for docker pull/run/create that do NOT consume the next argument.
const BOOLEAN_LONG_FLAGS: &[&str] = &[
    "--detach",
    "--interactive",
    "--tty",
    "--rm",
    "--privileged",
    "--init",
    "--read-only",
    "--publish-all",
    "--oom-kill-disable",
    "--no-healthcheck",
    "--sig-proxy",
    "--quiet",
    "--all-tags",
    "--disable-content-trust",
];

pub(crate) struct UnpinnedImages {
    bash: Language,
    docker_cmd_query: utils::SpannedQuery,
}

impl UnpinnedImages {
    fn build_finding_for_job<'doc>(
        &self,
        location: &SymbolicLocation<'doc>,
        annotation: &'static str,
        confidence: Confidence,
        persona: Persona,
        job: &super::NormalJob<'doc>,
    ) -> Result<Finding<'doc>, AuditError> {
        let annotated_location = location.clone().annotated(annotation);
        Self::finding()
            .severity(Severity::High)
            .confidence(confidence)
            .add_location(annotated_location)
            .persona(persona)
            .build(job)
    }

    /// Extract the text content of a tree-sitter bash argument node,
    /// stripping surrounding quotes for `string` and `raw_string` nodes.
    ///
    /// In tree-sitter-bash:
    /// - `word` nodes contain bare text (no quotes)
    /// - `string` nodes are double-quoted — `utf8_text()` includes the `"`s
    /// - `raw_string` nodes are single-quoted — `utf8_text()` includes the `'`s
    fn arg_text<'a>(node: &tree_sitter::Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "string" => {
                // For double-quoted strings, extract the string_content child
                // to avoid the surrounding quotes.
                if node.named_child_count() == 1 {
                    node.named_child(0)?.utf8_text(source).ok()
                } else {
                    // Multiple children means interpolation — skip these.
                    None
                }
            }
            "raw_string" => {
                // Single-quoted: strip the surrounding quotes.
                let text = node.utf8_text(source).ok()?;
                text.strip_prefix('\'')?.strip_suffix('\'')
            }
            _ => node.utf8_text(source).ok(),
        }
    }

    /// Extract image references from docker/podman commands in a bash script
    /// using tree-sitter AST parsing.
    fn bash_docker_images(&self, script: &str) -> Result<Vec<String>, AuditError> {
        let mut parser = Parser::new();
        parser
            .set_language(&self.bash)
            .context("failed to set bash language for parser")
            .map_err(Self::err)?;

        let tree = parser
            .parse(script, None)
            .context("failed to parse `run:` body as bash")
            .map_err(Self::err)?;

        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&self.docker_cmd_query, tree.root_node(), script.as_bytes());

        let args_idx = self
            .docker_cmd_query
            .capture_index_for_name("args")
            .expect("internal error: missing capture index for 'args'");

        let mut images = vec![];

        matches.for_each(|mat| {
            let args: Vec<&str> = mat
                .captures
                .iter()
                .filter(|cap| cap.index == args_idx)
                .filter_map(|cap| Self::arg_text(&cap.node, script.as_bytes()))
                .collect();

            if let Some(image_ref) = Self::extract_docker_image(&args) {
                // Skip arguments containing shell variable expansions or
                // GitHub Actions expressions — we can't statically resolve those.
                if !image_ref.contains('$') {
                    images.push(image_ref.to_string());
                }
            }
        });

        Ok(images)
    }

    /// Extract the image reference from docker/podman command arguments.
    ///
    /// `args` contains all arguments after the command name (docker/podman).
    /// Handles global flags before the subcommand (e.g. `docker --context foo run alpine`).
    fn extract_docker_image<'a>(args: &[&'a str]) -> Option<&'a str> {
        // Skip global flags (e.g. --context, --host, --log-level) to find the subcommand.
        let mut i = 0;
        while i < args.len() {
            let arg = args[i];
            if arg.starts_with('-') {
                if arg.contains('=') {
                    // Self-contained --flag=value
                    i += 1;
                } else {
                    // Assume global flag consumes next arg as value
                    i += 2;
                }
            } else {
                // First positional arg is the subcommand.
                break;
            }
        }

        let subcommand = args.get(i)?;
        match *subcommand {
            "pull" | "run" | "create" => {
                let rest = &args[i + 1..];
                Self::first_positional_arg(rest)
            }
            _ => None,
        }
    }

    /// Find the first positional (non-flag) argument, skipping flags and
    /// their values using docker CLI conventions.
    fn first_positional_arg<'a>(args: &[&'a str]) -> Option<&'a str> {
        let mut i = 0;
        while i < args.len() {
            let arg = args[i];

            if arg == "--" {
                // Everything after `--` is positional.
                return args.get(i + 1).copied();
            }

            if arg.starts_with("--") {
                if arg.contains('=') || BOOLEAN_LONG_FLAGS.contains(&arg) {
                    // Self-contained `--flag=value` or known boolean flag.
                    i += 1;
                } else {
                    // Assume value-consuming flag, skip flag + value.
                    i += 2;
                }
            } else if arg.starts_with('-') {
                if arg.len() > 2 {
                    // Combined short flags like `-dit`, `-it` — all boolean.
                    i += 1;
                } else if BOOLEAN_SHORT_FLAGS.contains(&arg) {
                    i += 1;
                } else {
                    // Value-consuming short flag like `-e`, `-v`, `-p`.
                    i += 2;
                }
            } else {
                // First positional argument — this is the image.
                return Some(arg);
            }
        }
        None
    }

    /// Detect docker/podman image references in a run: step script body.
    fn docker_images_in_run(&self, script: &str, shell: &str) -> Result<Vec<String>, AuditError> {
        let normalized = utils::normalize_shell(shell);
        match normalized {
            // NOTE: zsh is close enough to bash for docker invocations.
            "bash" | "sh" | "zsh" => self.bash_docker_images(script),
            _ => {
                tracing::debug!(
                    "unpinned-images: shell '{shell}' ({normalized}) not supported for docker command detection"
                );
                Ok(vec![])
            }
        }
    }

    /// Check an image reference string and produce a finding if it's not
    /// properly pinned.
    fn check_image_ref<'a, 'doc>(
        image_str: &str,
        location: SymbolicLocation<'doc>,
        target: &'a impl AsDocument<'a, 'doc>,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let image = DockerUses::parse(image_str);
        match (image.tag(), image.hash()) {
            // Pinned by digest — safe.
            (_, Some(_)) => Ok(None),
            // Pinned to "latest" — bad.
            (Some("latest"), None) => Ok(Some(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(location.annotated("docker image is pinned to latest"))
                    .persona(Persona::Regular)
                    .build(target)?,
            )),
            // No tag at all — bad.
            (None, None) => Ok(Some(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(location.annotated("docker image is unpinned"))
                    .persona(Persona::Regular)
                    .build(target)?,
            )),
            // Has a tag but no digest hash — pedantic.
            (Some(_), None) => Ok(Some(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(location.annotated("docker image is not pinned to a SHA256 hash"))
                    .persona(Persona::Pedantic)
                    .build(target)?,
            )),
        }
    }
}

audit_meta!(
    UnpinnedImages,
    "unpinned-images",
    "unpinned image references"
);

#[async_trait::async_trait]
impl Audit for UnpinnedImages {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        let bash: Language = tree_sitter_bash::LANGUAGE.into();
        let mut bash_parser = Parser::new();
        bash_parser
            .set_language(&bash)
            .context("failed to load bash parser")
            .map_err(AuditLoadError::Skip)?;

        Ok(Self {
            docker_cmd_query: utils::SpannedQuery::new(BASH_DOCKER_CMD_QUERY, &bash),
            bash,
        })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let StepBody::Run { run, .. } = &step.deref().body else {
            return Ok(findings);
        };

        let shell = step.shell().map(|s| s.0).unwrap_or_else(|| {
            tracing::warn!(
                "unpinned-images: couldn't determine shell type for {workflow}:{job} step {stepno}; assuming bash",
                workflow = step.workflow().key.presentation_path(),
                job = step.parent.id(),
                stepno = step.index
            );
            "bash"
        });

        for image_str in self.docker_images_in_run(run, shell)? {
            let location = step.location().primary().with_keys(["run".into()]);

            if let Some(finding) = Self::check_image_ref(&image_str, location, step)? {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        let mut image_refs_with_locations: Vec<(&'doc LoE<DockerUses>, SymbolicLocation<'doc>)> =
            vec![];

        if let Some(Container::Container { image, .. }) = &job.container {
            image_refs_with_locations.push((
                image,
                job.location()
                    .primary()
                    .with_keys(["container".into(), "image".into()]),
            ));
        }

        for (service, config_val) in job.services.iter() {
            if let Container::Container { image, .. } = &config_val {
                image_refs_with_locations.push((
                    image,
                    job.location().primary().with_keys([
                        "services".into(),
                        service.as_str().into(),
                        "image".into(),
                    ]),
                ));
            }
        }

        // TODO: Clean this mess up.
        for (image, ref location) in image_refs_with_locations {
            match image {
                LoE::Expr(expr) => {
                    let context = match Expr::parse(expr.as_bare()).map(|e| e.inner) {
                        // Our expression is `${{ matrix.abc... }}`.
                        Ok(Expr::Context(context)) if context.child_of("matrix") => context,
                        // An invalid expression, or otherwise any expression that's
                        // more complex than a simple matrix reference.
                        // TODO: Be more precise in some of these cases.
                        _ => {
                            findings.push(self.build_finding_for_job(
                                location,
                                "container image may be unpinned",
                                Confidence::Low,
                                Persona::Regular,
                                job,
                            )?);
                            continue;
                        }
                    };

                    let Some(matrix) = job.matrix() else {
                        tracing::warn!(
                            "job references {expr} but has no matrix",
                            expr = expr.as_bare()
                        );
                        continue;
                    };

                    for expansion in matrix
                        .expansions()
                        .iter()
                        .filter(|e| context.matches(e.path.as_str()))
                    {
                        if !expansion.is_static() {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::High)
                                    .confidence(Confidence::Low)
                                    .persona(Persona::Regular)
                                    .add_location(
                                        location
                                            .clone()
                                            .primary()
                                            .annotated("container image may be unpinned"),
                                    )
                                    .add_location(expansion.location())
                                    .build(job)?,
                            );
                            break;
                        } else {
                            // Try and parse the expanded value as an image reference.
                            let image = DockerUses::parse(&expansion.value);
                            match (image.tag(), image.hash()) {
                                // Image is pinned by hash.
                                (_, Some(_)) => continue,
                                // Docker image is pinned to "latest".
                                (Some("latest"), None) => findings.push(
                                    Self::finding()
                                        .severity(Severity::High)
                                        .confidence(Confidence::High)
                                        .persona(Persona::Regular)
                                        .add_location(
                                            location
                                                .clone()
                                                .primary()
                                                .annotated("container image is pinned to latest"),
                                        )
                                        .add_location(matrix.location().key_only())
                                        .add_location(expansion.location().annotated(format!(
                                            "this expansion of {path}",
                                            path = expansion.path
                                        )))
                                        .build(job)?,
                                ),
                                // Docker image is pined to some other tag.
                                (Some(_), None) => findings.push(
                                    Self::finding()
                                        .severity(Severity::High)
                                        .confidence(Confidence::High)
                                        .persona(Persona::Pedantic)
                                        .add_location(location.clone().primary().annotated(
                                            "container image is not pinned to a SHA256 hash",
                                        ))
                                        .add_location(matrix.location().key_only())
                                        .add_location(expansion.location().annotated(format!(
                                            "this expansion of {path}",
                                            path = expansion.path
                                        )))
                                        .build(job)?,
                                ),
                                // Image is unpinned.
                                (None, None) => findings.push(
                                    Self::finding()
                                        .severity(Severity::High)
                                        .confidence(Confidence::High)
                                        .persona(Persona::Regular)
                                        .add_location(
                                            location
                                                .clone()
                                                .primary()
                                                .annotated("container image is unpinned"),
                                        )
                                        .add_location(matrix.location().key_only())
                                        .add_location(expansion.location().annotated(format!(
                                            "this expansion of {path}",
                                            path = expansion.path
                                        )))
                                        .build(job)?,
                                ),
                            }
                        }
                    }
                }
                LoE::Literal(image) => match image.hash() {
                    Some(_) => continue,
                    None => match image.tag() {
                        Some("latest") => {
                            findings.push(self.build_finding_for_job(
                                location,
                                "container image is pinned to latest",
                                Confidence::High,
                                Persona::Regular,
                                job,
                            )?);
                        }
                        None => {
                            findings.push(self.build_finding_for_job(
                                location,
                                "container image is unpinned",
                                Confidence::High,
                                Persona::Regular,
                                job,
                            )?);
                        }
                        Some(_) => {
                            findings.push(self.build_finding_for_job(
                                location,
                                "container image is not pinned to a SHA256 hash",
                                Confidence::High,
                                Persona::Pedantic,
                                job,
                            )?);
                        }
                    },
                },
            }
        }

        // Also check run: steps in this job for docker commands.
        for step in job.steps() {
            findings.extend(self.audit_step(&step, config).await?);
        }

        Ok(findings)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &super::CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let action::StepBody::Run { run, .. } = &step.body else {
            return Ok(findings);
        };

        let shell = step.shell().map(|s| s.0).unwrap_or_else(|| {
            tracing::warn!(
                "unpinned-images: couldn't determine shell type for {action} step {stepno}; assuming bash",
                action = step.action().key.presentation_path(),
                stepno = step.index
            );
            "bash"
        });

        for image_str in self.docker_images_in_run(run, shell)? {
            let location = step.location().primary().with_keys(["run".into()]);

            if let Some(finding) = Self::check_image_ref(&image_str, location, step)? {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_docker_pull() {
        // Basic pull cases
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["pull", "ubuntu"]),
            Some("ubuntu")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["pull", "ubuntu:latest"]),
            Some("ubuntu:latest")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["pull", "ubuntu:22.04"]),
            Some("ubuntu:22.04")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["pull", "ubuntu@sha256:abcdef1234567890"]),
            Some("ubuntu@sha256:abcdef1234567890")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["pull", "ghcr.io/org/image:tag"]),
            Some("ghcr.io/org/image:tag")
        );

        // Pull with flags
        assert_eq!(
            UnpinnedImages::extract_docker_image(&[
                "pull",
                "--platform",
                "linux/amd64",
                "ubuntu:22.04"
            ]),
            Some("ubuntu:22.04")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["pull", "-q", "nginx"]),
            Some("nginx")
        );

        // -a is --all-tags for pull (boolean), but we treat it as
        // value-consuming globally to avoid false positives with
        // docker run -a STDERR. For pull, this means -a skips the
        // next arg — a false negative, but safer than a false positive.
        assert_eq!(UnpinnedImages::extract_docker_image(&["pull", "-a"]), None);
    }

    #[test]
    fn test_extract_docker_run() {
        // Basic run cases
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["run", "ubuntu"]),
            Some("ubuntu")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["run", "-d", "--rm", "nginx:latest"]),
            Some("nginx:latest")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["run", "-it", "alpine"]),
            Some("alpine")
        );

        // Run with value-consuming flags
        assert_eq!(
            UnpinnedImages::extract_docker_image(&[
                "run",
                "-d",
                "--rm",
                "-v",
                "/tmp:/tmp",
                "-e",
                "FOO=bar",
                "redis:7",
            ]),
            Some("redis:7")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&[
                "run",
                "--name=mycontainer",
                "--rm",
                "postgres:15"
            ]),
            Some("postgres:15")
        );

        // Combined short flags
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["run", "-dit", "ubuntu:22.04"]),
            Some("ubuntu:22.04")
        );

        // -a/--attach consumes a value — should NOT treat STDERR as the image
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["run", "-a", "STDERR", "ubuntu"]),
            Some("ubuntu")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["run", "--attach", "STDOUT", "alpine"]),
            Some("alpine")
        );
    }

    #[test]
    fn test_extract_docker_create() {
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["create", "--name", "myapp", "node:20"]),
            Some("node:20")
        );
    }

    #[test]
    fn test_extract_with_global_flags() {
        // Global flags before subcommand
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["--context", "foo", "run", "alpine"]),
            Some("alpine")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["--log-level=debug", "pull", "nginx:latest"]),
            Some("nginx:latest")
        );
        assert_eq!(
            UnpinnedImages::extract_docker_image(&[
                "--host",
                "tcp://localhost:2375",
                "run",
                "-d",
                "redis:7",
            ]),
            Some("redis:7")
        );
    }

    #[test]
    fn test_extract_ignores_unknown_subcommands() {
        assert_eq!(UnpinnedImages::extract_docker_image(&["build", "."]), None);
        assert_eq!(
            UnpinnedImages::extract_docker_image(&["push", "myimage"]),
            None
        );
        assert_eq!(UnpinnedImages::extract_docker_image(&["images"]), None);
    }

    #[test]
    fn test_check_image_ref_pinning() {
        // Digest-pinned — safe
        let image = DockerUses::parse("ubuntu@sha256:abc123");
        assert!(image.hash().is_some());

        // latest — bad
        let image = DockerUses::parse("ubuntu:latest");
        assert_eq!(image.tag(), Some("latest"));
        assert!(image.hash().is_none());

        // No tag — bad
        let image = DockerUses::parse("ubuntu");
        assert!(image.tag().is_none());
        assert!(image.hash().is_none());

        // Tag but no digest — pedantic
        let image = DockerUses::parse("ubuntu:22.04");
        assert_eq!(image.tag(), Some("22.04"));
        assert!(image.hash().is_none());
    }

    #[test]
    fn test_bash_docker_images() {
        let audit_state = AuditState::default();
        let sut = UnpinnedImages::new(&audit_state).expect("failed to create audit");

        // Simple docker pull
        let images = sut.bash_docker_images("docker pull ubuntu:latest").unwrap();
        assert_eq!(images, vec!["ubuntu:latest"]);

        // docker run with flags
        let images = sut
            .bash_docker_images("docker run -d --rm nginx:latest")
            .unwrap();
        assert_eq!(images, vec!["nginx:latest"]);

        // Multiline script with multiple commands
        let images = sut
            .bash_docker_images("echo 'Setting up'\ndocker pull redis:7\ndocker run -d redis:7")
            .unwrap();
        assert_eq!(images, vec!["redis:7", "redis:7"]);

        // echo should NOT match
        let images = sut
            .bash_docker_images("echo \"docker pull ubuntu\"")
            .unwrap();
        assert!(images.is_empty());

        // Variable expansion should be skipped
        let images = sut.bash_docker_images("docker pull $IMAGE_NAME").unwrap();
        assert!(images.is_empty());

        // Podman support
        let images = sut.bash_docker_images("podman pull alpine:3.18").unwrap();
        assert_eq!(images, vec!["alpine:3.18"]);

        // Registry-prefixed images
        let images = sut
            .bash_docker_images("docker pull ghcr.io/org/image:v1.2.3")
            .unwrap();
        assert_eq!(images, vec!["ghcr.io/org/image:v1.2.3"]);

        // Digest-pinned (still extracted, pinning checked separately)
        let images = sut
            .bash_docker_images("docker pull ubuntu@sha256:abc123def")
            .unwrap();
        assert_eq!(images, vec!["ubuntu@sha256:abc123def"]);

        // docker build and push should not match
        let images = sut
            .bash_docker_images("docker build -t myimage . && docker push myimage")
            .unwrap();
        assert!(images.is_empty());

        // Double-quoted image argument — quotes should be stripped
        let images = sut
            .bash_docker_images(r#"docker pull "ubuntu:latest""#)
            .unwrap();
        assert_eq!(images, vec!["ubuntu:latest"]);

        // Single-quoted image argument
        let images = sut.bash_docker_images("docker pull 'alpine:3.18'").unwrap();
        assert_eq!(images, vec!["alpine:3.18"]);

        // Global flags before subcommand
        let images = sut
            .bash_docker_images("docker --context foo pull nginx:latest")
            .unwrap();
        assert_eq!(images, vec!["nginx:latest"]);
    }
}

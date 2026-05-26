use anyhow::Context as _;
use subfeature::Subfeature;
use tree_sitter::StreamingIterator as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::{
    finding::{Confidence, Finding, Severity},
    models::{StepBodyCommon, StepCommon},
    state::AuditState,
    utils,
};

const BASH_COMMAND_QUERY: &str = "(command name: (_) @cmd argument: (_)+ @args) @span";

pub(crate) struct AdhocPackages {
    bash_command_query: utils::SpannedQuery,
}

audit_meta!(
    AdhocPackages,
    "adhoc-packages",
    "ad-hoc package installation outside of a lockfile"
);

impl AdhocPackages {
    fn query<'a>(
        &self,
        query: &'a utils::SpannedQuery,
        cursor: &'a mut tree_sitter::QueryCursor,
        tree: &'a tree_sitter::Tree,
        source: &'a str,
    ) -> tree_sitter::QueryMatches<'a, 'a, &'a [u8], &'a [u8]> {
        cursor.matches(query, tree.root_node(), source.as_bytes())
    }

    /// Determine whether the given command and arguments correspond to an
    /// ad-hoc package installation, e.g. `gem install <package>`.
    fn is_adhoc_install_command<'a>(cmd: &'a str, args: impl Iterator<Item = &'a str>) -> bool {
    
    let mut args = args;
        match cmd {
            // TODO: Add support for `npm install pkg` and `pip install pkg`, etc later.
            "gem" => {
                // Looking for `gem install <pkg> ...`, where `install` is the
                // first non-flag argument and at least one package name follows.
                let mut args = args.skip_while(|arg| arg.starts_with('-'));
                if args.next() != Some("install") {
                    return false;
                }

                // Require at least one non-flag argument after `install` so we
                // don't flag malformed invocations like `gem install`.
                // Looking for `gem install <pkg> ...`, where `install` is the
                // first non-flag argument and at least one package name follows.
                args.any(|arg| arg == "install") && args.any(|arg| !arg.starts_with('-'))
            }
            _ => false,
        }
    }

    fn adhoc_install_candidates<'doc>(
        &self,
        run: &'doc str,
        shell: &str,
    ) -> Result<Vec<Subfeature<'doc>>, AuditError> {
        let normalized = utils::normalize_shell(shell);

        let mut cursor = tree_sitter::QueryCursor::new();
        let (query, tree) = match normalized {
            "bash" | "sh" | "zsh" => {
                let mut parser = utils::bash_parser();
                let tree = parser
                    .parse(run, None)
                    .context("failed to parse `run:` body as bash")
                    .map_err(Self::err)?;

                (&self.bash_command_query, tree)
            }
            // TODO: support pwsh. The tree-sitter-powershell grammar emits
            // each `command_elements` child as its own query match, which
            // breaks the multi-arg `gem install <pkg>` pattern we need to
            // detect here.
            _ => {
                tracing::debug!("unable to analyze 'run:' block: unknown shell '{normalized}'");
                return Ok(vec![]);
            }
        };

        let matches = self.query(query, &mut cursor, &tree, run);
        let cmd = query
            .capture_index_for_name("cmd")
            .expect("internal error: missing capture index for 'cmd'");
        let args = query
            .capture_index_for_name("args")
            .expect("internal error: missing capture index for 'args'");

        let mut subfeatures = vec![];
        matches.for_each(|mat| {
            let cmd = {
                let cap = mat
                    .captures
                    .iter()
                    .find(|cap| cap.index == cmd)
                    .expect("internal error: expected capture for cmd");
                cap.node
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction")
            };

            let args = mat
                .captures
                .iter()
                .filter(|cap| cap.index == args)
                .map(|cap| {
                    cap.node
                        .utf8_text(run.as_bytes())
                        .expect("impossible: capture should be UTF-8 by construction")
                });

            if Self::is_adhoc_install_command(cmd, args) {
                let span = mat
                    .captures
                    .iter()
                    .find(|cap| cap.index == query.span_idx)
                    .expect("internal error: expected capture for span");

                let span_contents = span
                    .node
                    .utf8_text(run.as_bytes())
                    .expect("impossible: capture should be UTF-8 by construction");

                subfeatures.push(Subfeature::new(span.node.start_byte(), span_contents));
            }
        });

        Ok(subfeatures)
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let StepBodyCommon::Run { run, .. } = step.body() else {
            return Ok(findings);
        };

        let shell = step.shell().map(|s| s.0).unwrap_or_else(|| {
            tracing::debug!(
                "adhoc-packages: couldn't determine shell for step {idx}; assuming bash",
                idx = step.index()
            );
            "bash"
        });

        for subfeature in self.adhoc_install_candidates(run, shell)? {
            findings.push(
                Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .add_location(step.location().hidden())
                    .add_location(
                        step.location()
                            .with_keys(["run".into()])
                            .key_only()
                            .annotated("this step"),
                    )
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["run".into()])
                            .subfeature(subfeature)
                            .annotated("installs a package outside of a lockfile"),
                    )
                    .build(step)?,
            );
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for AdhocPackages {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self {
            bash_command_query: utils::SpannedQuery::new(BASH_COMMAND_QUERY, &utils::BASH),
        })
    }

    async fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_adhoc_install_command() {
        for (args, expected) in &[
            (&["gem", "install", "rake"][..], true),
            (&["gem", "install", "rails:7.0.0"][..], true),
            (&["gem", "install", "rake", "rspec"][..], true),
            (&["gem", "install", "--no-document", "rake"][..], true),
            (&["gem", "install", "rails", "--no-document"][..], true),
            (&["gem", "install", "rake", "-v", "13.0.6"][..], true),
            (&["gem", "--silent", "install", "rake"][..], true),
            // No package, just flags
            (&["gem", "install"][..], false),
            (&["gem", "install", "--help"][..], false),
            // Other gem subcommands
            (&["gem", "build", "foo.gemspec"][..], false),
            (&["gem", "push", "foo-0.1.0.gem"][..], false),
            (&["gem", "env"][..], false),
            // `bundle install` is lockfile-aware, so it should stay false.
            (&["bundle", "install"][..], false),
            // TODO: flip to `true` once `npm install`/`npx` is covered.
            (&["npm", "install", "lodash"][..], false),
            (&["npm", "install", "oxlint@1.55.0"][..], false),
            (&["npm", "install", "--no-fund", "oxlint@1.55.0"][..], false),
            (&["npx", "-y", "lodash"][..], false),
            (&["npx", "--yes", "lodash"][..], false),
            (&["npx", "--yes", "lodash@1.2.3"][..], false),
            (&["npm", "exec", "lodash"][..], false),
            (&["npm", "exec", "lodash@1.2.3"][..], false),
            // TODO: flip to `true` once `pip install` is covered.
            (&["pip", "install", "requests"][..], false),
        ] {
            let cmd = args[0];
            let args_iter = args[1..].iter().copied();
            assert_eq!(
                super::AdhocPackages::is_adhoc_install_command(cmd, args_iter),
                *expected,
                "cmd: {cmd:?}, args: {args:?}"
            );
        }
    }
}

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
            // TODO: Add support for `pip install pkg`, etc later.
            "gem" => {
                // Require at least one non-flag argument after `install` so we
                // don't flag malformed invocations like `gem install`.
                // Looking for `gem install <pkg> ...`, where `install` is the
                // first non-flag argument and at least one package name follows.
                args.any(|arg| arg == "install") && args.any(|arg| !arg.starts_with('-'))
            }
            "npm" => {
                // Looking for `npm install <pkg>` or `npm exec <pkg>`, where
                // the subcommand is the first non-flag argument.
                let mut args = args.skip_while(|arg| arg.starts_with('-'));
                match args.next() {
                    // `npm install` and its many documented aliases. Without
                    // a package name, the command installs from
                    // package-lock.json, so it's lockfile-aware.
                    Some(
                        "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt"
                        | "isnta" | "isntal" | "isntall" | "add",
                    ) => args.any(|arg| !arg.starts_with('-')),
                    // `npm exec` triggers an install when either a package
                    // name is given positionally or via `-p`/`--package`.
                    Some("exec" | "x") => args.any(|arg| {
                        !arg.starts_with('-')
                            || matches!(arg, "-p" | "--package")
                            || arg.starts_with("-p=")
                            || arg.starts_with("--package=")
                    }),
                    _ => false,
                }
            }
            // Only hit npx if it has -y or --yes, to avoid flagging npx
            // invocations that run a package installed via lockfile.
            "npx" => {
                args.any(|arg| arg == "-y" || arg == "--yes")
                    && args.any(|arg| !arg.starts_with('-'))
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
            // `gem install` with various argument patterns that should be flagged as ad-hoc installs.
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
            // `npm install`/`npx` is also disallowed.
            (&["npm", "install", "lodash"][..], true),
            (&["npm", "install", "oxlint@1.55.0"][..], true),
            (&["npm", "install", "--no-fund", "oxlint@1.55.0"][..], true),
            // `npm install` aliases — `i`/`add` are common; `isnt` etc. are
            // documented typo-tolerant aliases.
            (&["npm", "i", "lodash"][..], true),
            (&["npm", "add", "lodash"][..], true),
            (&["npm", "isnt", "lodash"][..], true),
            (&["npm", "i", "--no-fund", "oxlint@1.55.0"][..], true),
            (&["npm", "i", "--help"][..], false),
            (&["npm", "i"][..], false),
            (&["npm", "install", "package-with-dashes"][..], true),
            (&["npx", "-y", "lodash"][..], true),
            (&["npx", "--yes", "lodash"][..], true),
            (&["npx", "--yes", "lodash@1.2.3"][..], true),
            (&["npm", "exec", "lodash"][..], true),
            (&["npm", "exec", "lodash@1.2.3"][..], true),
            // `npm x` is an alias for `npm exec`.
            (&["npm", "x", "lodash"][..], true),
            (&["npm", "x", "--package=lodash"][..], true),
            // `npm exec` with `-p`/`--package` installs the named package
            // even when only flags are present (i.e. no positional pkg).
            (&["npm", "exec", "-p", "lodash"][..], true),
            (&["npm", "exec", "--package", "lodash"][..], true),
            (&["npm", "exec", "-p=lodash"][..], true),
            (&["npm", "exec", "--package=lodash"][..], true),
            (&["npm", "exec", "--package=lodash", "--", "ls"][..], true),
            (&["npm", "exec", "--package=lodash@1.2.3"][..], true),
            (&["npm", "exec", "-p=lodash@1.2.3"][..], true),
            (&["npm", "exec", "--ws", "--", "eslint", "./*.js"][..], true),
            // npm flags without a package shouldn't be flagged.
            (&["npm", "install", "--help"][..], false),
            (&["npm", "install", "--no-fund"][..], false),
            (&["npm", "ci"][..], false),
            // `npx` without `-y` or `--yes` shouldn't be flagged, as it means they are
            // running a package that was installed already.
            (&["npx", "foobar"][..], false),
            (&["npx", "foobar@1.2.3"][..], false),
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

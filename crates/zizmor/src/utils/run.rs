//! Shell parsing for run bodies containing Actions expressions.

use std::{borrow::Cow, ops::Range};

use anyhow::{Context as _, Result};
use subfeature::Subfeature;
use tree_sitter::{Node, Query, QueryCursor, QueryMatches, Tree};

use super::{bash_parser, extract_fenced_expressions, normalize_shell, pwsh_parser};

/// A run body parsed with Actions expressions treated as opaque text.
///
/// Parsing and query predicates use a private source in which each complete
/// expression is replaced with ASCII padding of the same byte length. Newlines
/// inside expressions are also replaced so they cannot split shell statements.
/// This is an approximation of the script, not an evaluation of its expressions.
///
/// Node byte ranges refer to the original source. Row/column positions may
/// differ; use [`Self::text`] and [`Self::subfeature`] to read captures and locate
/// diagnostics in the original source.
pub(crate) struct ParsedRun<'src> {
    original: &'src str,
    parser_source: Cow<'src, str>,
    expressions: Vec<Range<usize>>,
    tree: Tree,
}

impl<'src> ParsedRun<'src> {
    /// Parse a run body using a supported shell, including shell paths and flags.
    pub(crate) fn parse(source: &'src str, shell: &str) -> Result<Self> {
        let shell = normalize_shell(shell);
        let mut parser = match shell {
            "bash" | "sh" | "zsh" => bash_parser(),
            "pwsh" | "powershell" => pwsh_parser(),
            _ => anyhow::bail!("unsupported shell '{shell}'"),
        };

        let mut parser_source = Cow::Borrowed(source);
        let mut expressions = vec![];
        for (_, span) in extract_fenced_expressions(source) {
            parser_source
                .to_mut()
                .replace_range(span.clone(), &"x".repeat(span.len()));
            expressions.push(span);
        }

        let tree = parser
            .parse(parser_source.as_bytes(), None)
            .with_context(|| format!("failed to parse `run:` body as {shell}"))?;

        Ok(Self {
            original: source,
            parser_source,
            expressions,
            tree,
        })
    }

    /// Run a query with predicates evaluated against the parser's source.
    pub(crate) fn query<'a>(
        &'a self,
        query: &'a Query,
        cursor: &'a mut QueryCursor,
    ) -> QueryMatches<'a, 'a, 'static, &'a [u8], &'a [u8]> {
        cursor.matches(query, self.tree.root_node(), self.parser_source.as_bytes())
    }

    /// Return the original text of a node captured by [`Self::query`].
    pub(crate) fn text(&self, node: Node<'_>) -> &'src str {
        node.utf8_text(self.original.as_bytes())
            .expect("impossible: capture should be UTF-8 by construction")
    }

    /// Whether a captured node overlaps a complete Actions expression.
    ///
    /// A node can contain both literal text and expressions, or cover only part
    /// of an expression. In either case its text is dynamic.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "available for audits that need to distinguish dynamic captures"
        )
    )]
    pub(crate) fn is_dynamic(&self, node: Node<'_>) -> bool {
        let span = node.byte_range();
        !span.is_empty()
            && self
                .expressions
                .iter()
                .any(|expr| span.start < expr.end && expr.start < span.end)
    }

    /// Locate a captured node using its original text and byte offset.
    pub(crate) fn subfeature(&self, node: Node<'_>) -> Subfeature<'src> {
        Subfeature::new(node.start_byte(), self.text(node))
    }
}

#[cfg(test)]
mod tests {
    use tree_sitter::StreamingIterator as _;

    use super::*;
    use crate::utils::{BASH, PWSH, SpannedQuery};

    fn command_query(shell: &str) -> SpannedQuery {
        match normalize_shell(shell) {
            "bash" | "sh" | "zsh" => {
                SpannedQuery::new("(command name: (_) @cmd argument: (_)+ @args) @span", &BASH)
            }
            "pwsh" | "powershell" => SpannedQuery::new(
                "(command name: (_) @cmd (command_argument)+ @args) @span",
                &PWSH,
            ),
            _ => panic!("unsupported test shell"),
        }
    }

    #[test]
    fn captures_preserve_original_text_and_locations() {
        let command = "npm install \"${{ '🦀}}' }}\" ${{\n env.X\n}} prefix${{ env.Y }}suffix";
        let source = format!("echo '🦀'\n{command}\necho done");

        for shell in [
            "bash",
            "sh",
            "zsh",
            "pwsh",
            "powershell",
            "/bin/bash -e {0}",
        ] {
            let run = ParsedRun::parse(&source, shell).unwrap();
            assert!(!run.tree.root_node().has_error(), "{shell}");
            let query = command_query(shell);
            let args_idx = query.capture_index_for_name("args").unwrap();
            let mut cursor = QueryCursor::new();
            let mut commands = vec![];
            let mut args = vec![];

            run.query(&query, &mut cursor).for_each(|mat| {
                let span = mat
                    .captures()
                    .iter()
                    .find(|cap| cap.index == query.span_idx)
                    .unwrap()
                    .node;
                let located = run.subfeature(span).locate_within(&source).unwrap();
                assert_eq!(located.as_range(), span.byte_range(), "{shell}");
                commands.push((run.text(span), run.is_dynamic(span)));

                args.extend(
                    mat.captures()
                        .iter()
                        .filter(|cap| cap.index == args_idx)
                        .map(|cap| (run.text(cap.node), run.is_dynamic(cap.node))),
                );
            });

            assert_eq!(
                commands,
                [("echo '🦀'", false), (command, true), ("echo done", false)],
                "{shell}"
            );
            assert_eq!(
                args,
                [
                    ("'🦀'", false),
                    ("install", false),
                    ("\"${{ '🦀}}' }}\"", true),
                    ("${{\n env.X\n}}", true),
                    ("prefix${{ env.Y }}suffix", true),
                    ("done", false),
                ],
                "{shell}"
            );
        }
    }

    #[test]
    fn predicates_do_not_match_expression_contents() {
        let source = "echo \"${{ 'ENV:GITHUB_ENV' }}\"\necho ENV:GITHUB_ENV";

        for (shell, language, query_text) in [
            (
                "bash",
                &*BASH,
                r#"(command argument: (_) @arg (#match? @arg "ENV:GITHUB_ENV")) @span"#,
            ),
            (
                "pwsh",
                &*PWSH,
                r#"(command (command_argument) @arg (#match? @arg "ENV:GITHUB_ENV")) @span"#,
            ),
        ] {
            let run = ParsedRun::parse(source, shell).unwrap();
            let query = SpannedQuery::new(query_text, language);
            let mut cursor = QueryCursor::new();
            let mut matches = vec![];
            run.query(&query, &mut cursor).for_each(|mat| {
                let span = mat
                    .captures()
                    .iter()
                    .find(|cap| cap.index == query.span_idx)
                    .unwrap()
                    .node;
                matches.push(run.text(span));
            });
            assert_eq!(matches, ["echo ENV:GITHUB_ENV"], "{shell}");
        }
    }

    #[test]
    fn incomplete_expressions_remain_original_text() {
        let source = "echo ${{ env.X";
        for shell in ["bash", "pwsh"] {
            let run = ParsedRun::parse(source, shell).unwrap();
            let node = run.tree.root_node();
            assert_eq!(run.text(node), source);
            assert!(!run.is_dynamic(node));
        }
    }
}

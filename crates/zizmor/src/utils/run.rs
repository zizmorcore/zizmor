//! Shell parsing for run bodies containing Actions expressions.

use std::borrow::Cow;

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
        for (_, span) in extract_fenced_expressions(source) {
            let padding = "x".repeat(span.len());
            parser_source.to_mut().replace_range(span, &padding);
        }

        let tree = parser
            .parse(parser_source.as_bytes(), None)
            .with_context(|| format!("failed to parse `run:` body as {shell}"))?;

        Ok(Self {
            original: source,
            parser_source,
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

    #[test]
    fn queries_use_parser_source_and_captures_use_original_source() {
        let command = "echo GITHUB_ENV ${{\n env.VALUE || '🦀}}'\n}}";
        let prefix = "echo '🦀'\necho \"${{ 'GITHUB_ENV' }}\"\n";
        let source = format!("{prefix}{command}\necho done");
        let start = prefix.len();

        for (shell, language) in [("bash", &*BASH), ("pwsh", &*PWSH)] {
            let run = ParsedRun::parse(&source, shell).unwrap();
            let query = SpannedQuery::new(
                r#"((command) @span (#match? @span "GITHUB_ENV"))"#,
                language,
            );
            let mut cursor = QueryCursor::new();
            let mut matches = vec![];
            run.query(&query, &mut cursor).for_each(|mat| {
                let node = mat.captures()[0].node;
                let location = run.subfeature(node).locate_within(&source).unwrap();
                matches.push((run.text(node), location.as_range()));
            });
            assert_eq!(
                matches,
                [(command, start..start + command.len())],
                "{shell}"
            );
        }
    }
}

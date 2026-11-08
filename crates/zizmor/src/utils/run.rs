//! Shell parsing for run bodies containing Actions expressions.

use std::borrow::Cow;

use anyhow::{Context as _, Result};
use subfeature::Subfeature;
use tree_sitter::{Node, Query, QueryCursor, QueryMatches, Tree};

use super::{bash_parser, extract_fenced_expressions, normalize_shell, pwsh_parser};

/// A run body with Actions expressions masked for shell parsing and queries.
pub(crate) struct ParsedRun<'src> {
    original: &'src str,
    parser_source: Cow<'src, str>,
    tree: Tree,
}

impl<'src> ParsedRun<'src> {
    /// Parse a run body using the given shell.
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

    /// Query the masked source.
    pub(crate) fn query<'a>(
        &'a self,
        query: &'a Query,
        cursor: &'a mut QueryCursor,
    ) -> QueryMatches<'a, 'a, 'static, &'a [u8], &'a [u8]> {
        cursor.matches(query, self.tree.root_node(), self.parser_source.as_bytes())
    }

    /// Return a node's original source text.
    pub(crate) fn text(&self, node: Node<'_>) -> &'src str {
        node.utf8_text(self.original.as_bytes())
            .expect("impossible: capture should be UTF-8 by construction")
    }

    /// Locate a node in the original source.
    pub(crate) fn subfeature(&self, node: Node<'_>) -> Subfeature<'src> {
        Subfeature::new(node.start_byte(), self.text(node))
    }
}

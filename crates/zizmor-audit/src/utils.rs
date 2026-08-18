//! Audit helper routines.

use std::{ops::Deref, sync::LazyLock};

use camino::Utf8Path;
use zizmor_core::{
    finding::location::Routable,
    models::AsDocument,
    utils::{ExtractedExpr, extract_fenced_expression},
};

pub(crate) static BASH: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_bash::LANGUAGE.into());

pub(crate) static PWSH: LazyLock<tree_sitter::Language> =
    LazyLock::new(|| tree_sitter_powershell::LANGUAGE.into());

/// Splits the given `patterns` string into one or more patterns, using
/// approximately the same rules as GitHub's `@actions/glob` package.
pub(crate) fn split_patterns(patterns: &str) -> impl Iterator<Item = &str> {
    // GitHub's pattern splitting is very basic: each line is processed in sequence,
    // with empty or comment (#) lines removed. Everything remaining is considered
    // a pattern.
    // See: https://github.com/actions/toolkit/blob/6c4e082c181a/packages/glob/src/internal-globber.ts#L161-L190

    patterns
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Like [`zizmor_core::utils::extract_fenced_expressions`], but over an
/// "routable," i.e. a document feature that has an associated route within the
/// document (which could be the entire document, like a workflow, or a fragment
/// of it).
///
/// Unlike [`zizmor_core::utils::extract_fenced_expressions`], this function
/// performs some semantic filtering over the raw input. For example, it skip
/// ignore expressions that are inside comments.
///
/// The span associated with each extracted expression is absolute,
/// i.e. relative to the start of the document, not the start of the feature.
pub(crate) fn parse_fenced_expressions_from_routable<
    'a,
    'doc,
    R: AsDocument<'a, 'doc> + Routable<'a, 'doc>,
>(
    input: &'a R,
) -> Vec<(ExtractedExpr<'doc>, std::ops::Range<usize>)> {
    let doc = input.as_document();

    let (content, feature) = {
        // NOTE: expect here because a failure in feature extraction here indicates a
        // significant internal error, not something the user can recover from.
        let feature = doc
            .query_pretty(&input.route())
            .expect("invalid route when extracting fenced expressions");
        (doc.extract(&feature), feature)
    };

    let mut exprs = vec![];
    let bias = feature.location.byte_span.0;
    let mut offset = 0;

    while let Some((expr, span)) = extract_fenced_expression(content, offset) {
        // Ignore expressions that are inside comments.
        if doc.offset_inside_comment(span.start + bias) {
            // Don't jump the entire span, since we might have an
            // actual expression accidentally captured within it.
            // Instead, just resume searching from the next character.
            offset = span.start + 1;
            continue;
        }

        exprs.push((expr, (span.start + bias..span.end + bias)));

        if span.end >= feature.location.byte_span.1 {
            break;
        } else {
            offset = span.end;
        }
    }

    exprs
}

/// Returns the name within the given `shell:` stanza.
pub(crate) fn normalize_shell(shell: &str) -> &str {
    let path = match shell.split_once(' ') {
        Some((path, _)) => path,
        None => shell,
    };

    Utf8Path::new(path).file_name().unwrap_or(path)
}

/// Holds a tree-sitter query that contains a `@span` capture that
/// covers the entire range of the query.
pub(crate) struct SpannedQuery {
    inner: tree_sitter::Query,
    pub(crate) span_idx: u32,
}

impl Deref for SpannedQuery {
    type Target = tree_sitter::Query;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub(crate) fn bash_parser() -> tree_sitter::Parser {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&BASH)
        .expect("internal error: failed to set bash language");
    parser
}

pub(crate) fn pwsh_parser() -> tree_sitter::Parser {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&PWSH)
        .expect("internal error: failed to set powershell language");
    parser
}

impl SpannedQuery {
    pub(crate) fn new(query: &'static str, language: &tree_sitter::Language) -> Self {
        let query = tree_sitter::Query::new(language, query).expect("malformed query");
        let span_idx = query
            .capture_index_for_name("span")
            .expect("internal error: missing @span capture");

        Self {
            inner: query,
            span_idx,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use zizmor_core::{
        input::{AuditInput, InputKey},
        models::{action::Action, workflow::Workflow},
    };

    use super::{normalize_shell, parse_fenced_expressions_from_routable};

    #[test]
    fn split_patterns() {
        let patterns = "
        foo
        bar
        ${{ baz }}
        internal  spaces
        **
        *
        # comment
        ## more hashes
        # internal # hashes

        # another comment
        foo/*.txt
        ";

        let pats = super::split_patterns(patterns).collect::<Vec<_>>();
        assert_eq!(
            pats,
            &[
                "foo",
                "bar",
                "${{ baz }}",
                "internal  spaces",
                "**",
                "*",
                "foo/*.txt"
            ]
        );
    }

    #[test]
    fn test_extract_fenced_expressions_from_routable() -> Result<()> {
        // Repro cases for #569; ensures we handle broken expressions that
        // are commented out. Observe that the commented expression isn't
        // terminated correctly, so the naive parse continues to the next
        // expression.
        let action = r#"
name: >-  # ${{ '' } is a hack to nest jobs under the same sidebar category
  Windows MSI${{ '' }}

description: test

runs:
  using: composite
  steps:
    - name: foo
      run: echo hello
      shell: bash
"#;

        let action = AuditInput::from(Action::from_string(
            action.into(),
            InputKey::local("fakegroup".into(), "fake", "fake".into()),
        )?);

        let exprs = parse_fenced_expressions_from_routable(&action);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].0.as_raw().to_string(), "${{ '' }}");

        let workflow = r#"
# ${{ 'don''t parse me' }}

# Observe that the expression in the comment below is invalid:
# it's missing a closing brace. This should not interfere with
# parsing the rest of the file's expressions
name: >- # ${{ 'oops' }
  custom-name-${{ github.sha }}

on:
  push:

permissions: {}

jobs:
  whops:
    runs-on: ubuntu-latest

    steps:
      - run: echo hello from ${{ github.actor }}
"#;

        let workflow = AuditInput::from(Workflow::from_string(
            workflow.into(),
            InputKey::local("fakegroup".into(), "fake", "fake".into()),
        )?);

        let exprs = parse_fenced_expressions_from_routable(&workflow)
            .into_iter()
            .map(|(expression, _)| expression.as_raw().to_string())
            .collect::<Vec<_>>();

        assert_eq!(exprs, &["${{ github.sha }}", "${{ github.actor }}"]);

        Ok(())
    }

    /// Tests that our spans are correct when we extract fenced expressions from an input,
    /// even when the input contains leading newlines.
    #[test]
    fn test_extract_fenced_expressions_from_routable_spans() -> Result<()> {
        let workflow_content = r#"
name: Test Workflow
on: push

permissions: {}

jobs:
  release-please:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0 # ... because release-please scans historical commits to build releases, so we need all the history.
          persist-credentials: false
      - id: release
        uses: ./vendor/github.com/googleapis/release-please-action
        with:
          config-file: "tools/releasing/config.release-please.json"
          manifest-file: "tools/releasing/manifest.release-please.json"
          target-branch: "${{ inputs.rp_target_branch }}"
    outputs:
      iac/terraform/attribution.tfm--release_created: ${{ 'steps.release.outputs.iac/terraform/attribution.tfm--release_created' }}
"#;

        let workflow = AuditInput::from(Workflow::from_string(
            workflow_content.into(),
            InputKey::local("fakegroup".into(), "fake", "fake".into()),
        )?);
        let exprs = parse_fenced_expressions_from_routable(&workflow)
            .into_iter()
            .map(|(expression, span)| (expression.as_raw().to_string(), span))
            .collect::<Vec<_>>();

        assert_eq!(exprs.len(), 2);
        assert_eq!(exprs[0].0, "${{ inputs.rp_target_branch }}");
        assert_eq!(exprs[0].1, 635..665);
        assert_eq!(
            &workflow_content[exprs[0].1.clone()],
            "${{ inputs.rp_target_branch }}"
        );
        assert_eq!(
            exprs[1].0,
            "${{ 'steps.release.outputs.iac/terraform/attribution.tfm--release_created' }}"
        );
        assert_eq!(exprs[1].1, 734..811);
        assert_eq!(
            &workflow_content[exprs[1].1.clone()],
            "${{ 'steps.release.outputs.iac/terraform/attribution.tfm--release_created' }}"
        );

        Ok(())
    }

    #[test]
    fn test_normalize_shell() {
        for (actual, expected) in &[
            ("bash", "bash"),
            ("/bin/bash", "bash"),
            ("/bash", "bash"),
            ("./bash", "bash"),
            ("../bash", "bash"),
            ("/./../bash", "bash"),
            ("/bin/bash -e {0}", "bash"),
        ] {
            assert_eq!(normalize_shell(actual), *expected);
        }
    }
}

//! Helper routines.

use github_actions_models::{
    common::expr::{ExplicitExpr, LoE},
    workflow::job::Matrix,
};

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

/// Parse an expression from the given free-form text, returning the
/// expression and the next offset at which to resume parsing.
///
/// Returns `None` if no expression is found, or an index past
/// the end of the text if parsing is successful but exhausted.
///
/// Adapted roughly from GitHub's `parseScalar`:
/// See: <https://github.com/actions/languageservices/blob/3a8c29c2d/workflow-parser/src/templates/template-reader.ts#L448>
fn extract_expression(text: &str) -> Option<(ExplicitExpr, usize)> {
    let start = text.find("${{")?;

    let mut end = None;
    let mut in_string = false;

    for (idx, char) in text.bytes().enumerate().skip(start) {
        if char == b'\'' {
            in_string = !in_string;
        } else if !in_string && text.as_bytes()[idx] == b'}' && text.as_bytes()[idx - 1] == b'}' {
            end = Some(idx);
            break;
        }
    }

    end.map(|end| {
        (
            ExplicitExpr::from_curly(&text[start..=end]).unwrap(),
            end + 1,
        )
    })
}

/// Extract zero or more expressions from the given free-form text.
pub(crate) fn extract_expressions(text: &str) -> Vec<ExplicitExpr> {
    let mut exprs = vec![];
    let mut view = text;

    while let Some((expr, next)) = extract_expression(view) {
        exprs.push(expr);

        if next >= text.len() {
            break;
        } else {
            view = &view[next..];
        }
    }

    exprs
}

/// Checks whether the given `expr` into `matrix` is static.
pub(crate) fn matrix_is_static(expr: &str, matrix: &Matrix) -> bool {
    // If the matrix's dimensions are an expression, then it's not static.
    let LoE::Literal(dimensions) = &matrix.dimensions else {
        return false;
    };

    // Our `expr` should be a literal path of `matrix.foo.bar.baz.etc`,
    // so we descend through the matrix based on it.
    let mut keys = expr.split('.').skip(1);

    let Some(key) = keys.next() else {
        // No path means that we're effectively expanding the entire matrix,
        // meaning *any* non-static component makes the entire expansion
        // non-static.

        // HACK: The correct way to do this is to walk `matrix.dimensions`,
        // but it could be arbitrarily deep. Instead, we YOLO the dimensions
        // back into YAML and see if the serialized equivalent has
        // any indicators of expansion (`${{ ... }}`) in it.
        // NOTE: Safe unwrap since `dimensions` was loaded directly from YAML
        let dimensions_yaml = serde_yaml::to_string(&dimensions).unwrap();
        return !(dimensions_yaml.contains("${{") && dimensions_yaml.contains("}}"));
    };

    match dimensions.get(key) {
        // This indicates a malformed matrix or matrix ref, which is
        // static for our purposes.
        None => true,
        // If our key is an expression, it's definitely not static.
        Some(LoE::Expr(_)) => false,
        Some(LoE::Literal(dim)) => {
            // TODO: This is imprecise: technically we should walk the
            // entire set of keys to determine if a specific index is
            // accessed + whether that index is an expression.
            // But doing that is hard, so we do the same YOLO reserialize
            // trick as above and consider this non-static
            // if it has any hint of a template expansion in it.
            let dim_yaml = serde_yaml::to_string(&dim).unwrap();
            !(dim_yaml.contains("${{") && dim_yaml.contains("}}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{extract_expression, extract_expressions};

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
        )
    }

    #[test]
    fn test_parse_expression() {
        let exprs = &[
            ("${{ foo }}", "foo", 10),
            ("${{ foo }}${{ bar }}", "foo", 10),
            ("leading ${{ foo }} trailing", "foo", 18),
            (
                "leading ${{ '${{ quoted! }}' }} trailing",
                "'${{ quoted! }}'",
                31,
            ),
            ("${{ 'es''cape' }}", "'es''cape'", 17),
        ];

        for (text, expected_expr, expected_idx) in exprs {
            let (actual_expr, actual_idx) = extract_expression(text).unwrap();
            assert_eq!(*expected_expr, actual_expr.as_bare());
            assert_eq!(*expected_idx, actual_idx);
        }
    }

    #[test]
    fn test_parse_expressions() {
        let expressions = r#"echo "OSSL_PATH=${{ github.workspace }}/osslcache/${{ matrix.PYTHON.OPENSSL.TYPE }}-${{ matrix.PYTHON.OPENSSL.VERSION }}-${OPENSSL_HASH}" >> $GITHUB_ENV"#;
        let exprs = extract_expressions(expressions)
            .into_iter()
            .map(|e| e.as_curly().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            exprs,
            &[
                "${{ github.workspace }}",
                "${{ matrix.PYTHON.OPENSSL.TYPE }}",
                "${{ matrix.PYTHON.OPENSSL.VERSION }}",
            ]
        )
    }
}

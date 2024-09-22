//! Helper routines.

use github_actions_models::common::Expression;

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
fn parse_expression(text: &str) -> Option<(Expression, usize)> {
    let Some(start) = text.find("${{") else {
        return None;
    };

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

    match end {
        Some(end) => Some((
            Expression::from_curly(text[start..=end].to_string()).unwrap(),
            end + 1,
        )),
        None => None,
    }
}

pub(crate) fn parse_expressions(text: &str) -> Vec<Expression> {
    let mut exprs = vec![];
    let mut view = text;

    loop {
        match parse_expression(view) {
            Some((expr, next)) => {
                exprs.push(expr);

                if next >= text.len() {
                    break;
                } else {
                    view = &view[next..];
                }
            }
            None => break,
        }
    }

    exprs
}

#[cfg(test)]
mod tests {
    use crate::utils::{parse_expression, parse_expressions};

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
            let (actual_expr, actual_idx) = parse_expression(text).unwrap();
            assert_eq!(*expected_expr, actual_expr.as_bare());
            assert_eq!(*expected_idx, actual_idx);
        }
    }

    #[test]
    fn test_parse_expressions() {
        let expressions = r#"echo "OSSL_PATH=${{ github.workspace }}/osslcache/${{ matrix.PYTHON.OPENSSL.TYPE }}-${{ matrix.PYTHON.OPENSSL.VERSION }}-${OPENSSL_HASH}" >> $GITHUB_ENV"#;
        let exprs = parse_expressions(&expressions)
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

//! Helper routines.

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

#[cfg(test)]
mod tests {
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
}

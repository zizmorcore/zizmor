//! Expression parsing and analysis.

use pest_derive::Parser;

/// A parser for GitHub Actions' expression language.
#[derive(Parser)]
#[grammar = "expr/expr.pest"]
struct ExprParser;

#[cfg(test)]
mod tests {
    use pest::Parser as _;

    use super::{ExprParser, Rule};

    #[test]
    fn test_parse_string() {
        let cases = &[
            ("'test'", "test"),
            ("'spaces are ok'", "spaces are ok"),
            ("'escaping '' works'", "escaping '' works"),
        ];

        for (case, expected) in cases {
            let s = ExprParser::parse(Rule::string, case)
                .unwrap()
                .next()
                .unwrap();

            assert_eq!(s.into_inner().next().unwrap().as_str(), *expected);
        }
    }

    #[test]
    fn test_parse_ident() {
        let cases = &[
            "foo.bar",
            "github.action_path",
            "inputs.foo-bar",
            "inputs.also--valid",
            "inputs.this__too",
            "inputs.this__too",
            "secrets.GH_TOKEN",
        ];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::context_ref, case)
                    .unwrap()
                    .next()
                    .unwrap()
                    .as_str(),
                *case
            );
        }
    }

    #[test]
    fn test_parse_call() {
        let cases = &[
            "foo()",
            "foo(bar)",
            "foo(bar())",
            "foo(1.23)",
            "foo(1,2)",
            "foo(1, 2)",
            "foo(1, 2, secret.GH_TOKEN)",
            "foo(   )",
        ];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::call, case)
                    .unwrap()
                    .next()
                    .unwrap()
                    .as_str(),
                *case
            );
        }
    }
}

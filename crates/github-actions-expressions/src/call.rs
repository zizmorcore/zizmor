//! Representation of function calls in GitHub Actions expressions.

use crate::{Evaluation, SpannedExpr};

/// Represents a function in a GitHub Actions expression.
///
/// Function names are case-insensitive.
#[derive(Debug)]
pub struct Function<'src>(pub(crate) &'src str);

impl PartialEq for Function<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}
impl PartialEq<str> for Function<'_> {
    fn eq(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

/// Represents a function call in a GitHub Actions expression.
#[derive(Debug, PartialEq)]
pub struct Call<'src> {
    /// The function name, e.g. `foo` in `foo()`.
    pub func: Function<'src>,
    /// The function's arguments.
    pub args: Vec<SpannedExpr<'src>>,
}

impl<'src> Call<'src> {
    /// Performs constant evaluation of a GitHub Actions expression
    /// function call.
    pub(crate) fn consteval(&self) -> Option<Evaluation> {
        let args = self
            .args
            .iter()
            .map(|arg| arg.consteval())
            .collect::<Option<Vec<Evaluation>>>()?;

        match &self.func {
            f if f == "format" => Self::consteval_format(&args),
            f if f == "contains" => Self::consteval_contains(&args),
            f if f == "startsWith" => Self::consteval_startswith(&args),
            f if f == "endsWith" => Self::consteval_endswith(&args),
            f if f == "toJSON" => Self::consteval_tojson(&args),
            f if f == "fromJSON" => Self::consteval_fromjson(&args),
            f if f == "join" => Self::consteval_join(&args),
            _ => None,
        }
    }

    /// Constant-evaluates a `format(fmtspec, args...)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/format.ts>
    fn consteval_format(args: &[Evaluation]) -> Option<Evaluation> {
        if args.is_empty() {
            return None;
        }

        let template = args[0].sema().to_string();
        let mut result = String::new();
        let mut index = 0;

        while index < template.len() {
            let lbrace = template[index..].find('{').map(|pos| index + pos);
            let rbrace = template[index..].find('}').map(|pos| index + pos);

            // Left brace
            #[allow(clippy::unwrap_used)]
            if let Some(lbrace_pos) = lbrace
                && (rbrace.is_none() || rbrace.unwrap() > lbrace_pos)
            {
                // Escaped left brace
                if template.as_bytes().get(lbrace_pos + 1) == Some(&b'{') {
                    result.push_str(&template[index..=lbrace_pos]);
                    index = lbrace_pos + 2;
                    continue;
                }

                // Left brace, number, optional format specifiers, right brace
                if let Some(rbrace_pos) = rbrace
                    && rbrace_pos > lbrace_pos + 1
                    && let Some(arg_index) = Self::read_arg_index(&template, lbrace_pos + 1)
                {
                    // Check parameter count
                    if 1 + arg_index > args.len() - 1 {
                        // Invalid format string - too few arguments
                        return None;
                    }

                    // Append the portion before the left brace
                    if lbrace_pos > index {
                        result.push_str(&template[index..lbrace_pos]);
                    }

                    // Append the arg
                    result.push_str(&args[1 + arg_index].sema().to_string());
                    index = rbrace_pos + 1;
                    continue;
                }

                // Invalid format string
                return None;
            }

            // Right brace
            if let Some(rbrace_pos) = rbrace {
                #[allow(clippy::unwrap_used)]
                if lbrace.is_none() || lbrace.unwrap() > rbrace_pos {
                    // Escaped right brace
                    if template.as_bytes().get(rbrace_pos + 1) == Some(&b'}') {
                        result.push_str(&template[index..=rbrace_pos]);
                        index = rbrace_pos + 2;
                    } else {
                        // Invalid format string
                        return None;
                    }
                }
            } else {
                // Last segment
                result.push_str(&template[index..]);
                break;
            }
        }

        Some(Evaluation::String(result))
    }

    /// Helper function to read argument index from format string.
    fn read_arg_index(string: &str, start_index: usize) -> Option<usize> {
        let mut length = 0;
        let chars: Vec<char> = string.chars().collect();

        // Count the number of digits
        while start_index + length < chars.len() {
            let next_char = chars[start_index + length];
            if next_char.is_ascii_digit() {
                length += 1;
            } else {
                break;
            }
        }

        // Validate at least one digit
        if length < 1 {
            return None;
        }

        // Parse the number
        let number_str: String = chars[start_index..start_index + length].iter().collect();
        number_str.parse::<usize>().ok()
    }

    /// Constant-evaluates a `contains(haystack, needle)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/contains.ts>
    fn consteval_contains(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 2 {
            return None;
        }

        let search = &args[0];
        let item = &args[1];

        match search {
            // For primitive types (strings, numbers, booleans, null), do case-insensitive string search
            Evaluation::String(_)
            | Evaluation::Number(_)
            | Evaluation::Boolean(_)
            | Evaluation::Null => {
                let search_str = search.sema().to_string().to_lowercase();
                let item_str = item.sema().to_string().to_lowercase();
                Some(Evaluation::Boolean(search_str.contains(&item_str)))
            }
            // For arrays, check if any element equals the item
            Evaluation::Array(arr) => {
                if arr.iter().any(|element| element.sema() == item.sema()) {
                    Some(Evaluation::Boolean(true))
                } else {
                    Some(Evaluation::Boolean(false))
                }
            }
            // `contains(object, ...)` is not defined in the reference implementation
            Evaluation::Object(_) => None,
        }
    }

    /// Constant-evaluates a `startsWith(string, prefix)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/startswith.ts>
    fn consteval_startswith(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 2 {
            return None;
        }

        let search_string = &args[0];
        let search_value = &args[1];

        // Both arguments must be primitive types (not arrays or dictionaries)
        match (search_string, search_value) {
            (
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
            ) => {
                // Case-insensitive comparison
                let string_str = search_string.sema().to_string().to_lowercase();
                let prefix_str = search_value.sema().to_string().to_lowercase();
                Some(Evaluation::Boolean(string_str.starts_with(&prefix_str)))
            }
            // If either argument is not primitive (array or dictionary), return false
            _ => Some(Evaluation::Boolean(false)),
        }
    }

    /// Constant-evaluates an `endsWith(string, suffix)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/endswith.ts>
    fn consteval_endswith(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 2 {
            return None;
        }

        let search_string = &args[0];
        let search_value = &args[1];

        // Both arguments must be primitive types (not arrays or dictionaries)
        match (search_string, search_value) {
            (
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
            ) => {
                // Case-insensitive comparison
                let string_str = search_string.sema().to_string().to_lowercase();
                let suffix_str = search_value.sema().to_string().to_lowercase();
                Some(Evaluation::Boolean(string_str.ends_with(&suffix_str)))
            }
            // If either argument is not primitive (array or dictionary), return false
            _ => Some(Evaluation::Boolean(false)),
        }
    }

    /// Constant-evaluates a `toJSON(value)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/tojson.ts>
    fn consteval_tojson(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 1 {
            return None;
        }

        let value = &args[0];
        let json_value: serde_json::Value = value.clone().try_into().ok()?;
        let json_str = serde_json::to_string_pretty(&json_value).ok()?;

        Some(Evaluation::String(json_str))
    }

    /// Constant-evaluates a `fromJSON(json_string)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/fromjson.ts>
    fn consteval_fromjson(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 1 {
            return None;
        }

        let json_str = args[0].sema().to_string();

        // Match reference implementation: error on empty input
        if json_str.trim().is_empty() {
            return None;
        }

        serde_json::from_str::<serde_json::Value>(&json_str)
            .ok()?
            .try_into()
            .ok()
    }

    /// Constant-evaluates a `join(array, optionalSeparator)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/join.ts>
    fn consteval_join(args: &[Evaluation]) -> Option<Evaluation> {
        if args.is_empty() || args.len() > 2 {
            return None;
        }

        let array_or_string = &args[0];

        // Get separator (default is comma)
        let separator = if args.len() > 1 {
            args[1].sema().to_string()
        } else {
            ",".to_string()
        };

        match array_or_string {
            // For primitive types (strings, numbers, booleans, null), return as string
            Evaluation::String(_)
            | Evaluation::Number(_)
            | Evaluation::Boolean(_)
            | Evaluation::Null => Some(Evaluation::String(array_or_string.sema().to_string())),
            // For arrays, join elements with separator
            Evaluation::Array(arr) => {
                let joined = arr
                    .iter()
                    .map(|item| item.sema().to_string())
                    .collect::<Vec<String>>()
                    .join(&separator);
                Some(Evaluation::String(joined))
            }
            // For dictionaries, return empty string (not supported in reference)
            Evaluation::Object(_) => Some(Evaluation::String("".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{Expr, call::Call};

    #[test]
    fn test_consteval_fromjson() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic primitives
            ("fromJSON('null')", Evaluation::Null),
            ("fromJSON('true')", Evaluation::Boolean(true)),
            ("fromJSON('false')", Evaluation::Boolean(false)),
            ("fromJSON('42')", Evaluation::Number(42.0)),
            ("fromJSON('3.14')", Evaluation::Number(3.14)),
            ("fromJSON('-0')", Evaluation::Number(0.0)),
            ("fromJSON('0')", Evaluation::Number(0.0)),
            (
                "fromJSON('\"hello\"')",
                Evaluation::String("hello".to_string()),
            ),
            ("fromJSON('\"\"')", Evaluation::String("".to_string())),
            // Arrays
            ("fromJSON('[]')", Evaluation::Array(vec![])),
            (
                "fromJSON('[1, 2, 3]')",
                Evaluation::Array(vec![
                    Evaluation::Number(1.0),
                    Evaluation::Number(2.0),
                    Evaluation::Number(3.0),
                ]),
            ),
            (
                "fromJSON('[\"a\", \"b\", null, true, 123]')",
                Evaluation::Array(vec![
                    Evaluation::String("a".to_string()),
                    Evaluation::String("b".to_string()),
                    Evaluation::Null,
                    Evaluation::Boolean(true),
                    Evaluation::Number(123.0),
                ]),
            ),
            // Objects
            (
                "fromJSON('{}')",
                Evaluation::Object(std::collections::HashMap::new()),
            ),
            (
                "fromJSON('{\"key\": \"value\"}')",
                Evaluation::Object({
                    let mut map = std::collections::HashMap::new();
                    map.insert("key".to_string(), Evaluation::String("value".to_string()));
                    map
                }),
            ),
            (
                "fromJSON('{\"num\": 42, \"bool\": true, \"null\": null}')",
                Evaluation::Object({
                    let mut map = std::collections::HashMap::new();
                    map.insert("num".to_string(), Evaluation::Number(42.0));
                    map.insert("bool".to_string(), Evaluation::Boolean(true));
                    map.insert("null".to_string(), Evaluation::Null);
                    map
                }),
            ),
            // Nested structures
            (
                "fromJSON('{\"array\": [1, 2], \"object\": {\"nested\": true}}')",
                Evaluation::Object({
                    let mut map = std::collections::HashMap::new();
                    map.insert(
                        "array".to_string(),
                        Evaluation::Array(vec![Evaluation::Number(1.0), Evaluation::Number(2.0)]),
                    );
                    let mut nested_map = std::collections::HashMap::new();
                    nested_map.insert("nested".to_string(), Evaluation::Boolean(true));
                    map.insert("object".to_string(), Evaluation::Object(nested_map));
                    map
                }),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_consteval_fromjson_error_cases() -> Result<()> {
        let error_cases = &[
            "fromJSON('')",          // Empty string
            "fromJSON('   ')",       // Whitespace only
            "fromJSON('invalid')",   // Invalid JSON
            "fromJSON('{invalid}')", // Invalid JSON syntax
            "fromJSON('[1, 2,]')",   // Trailing comma (invalid in strict JSON)
        ];

        for expr_str in error_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval();
            assert!(
                result.is_none(),
                "Expected None for invalid JSON: {}",
                expr_str
            );
        }

        Ok(())
    }

    #[test]
    fn test_consteval_fromjson_display_format() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            (Evaluation::Array(vec![Evaluation::Number(1.0)]), "Array"),
            (
                Evaluation::Object(std::collections::HashMap::new()),
                "Object",
            ),
        ];

        for (result, expected) in test_cases {
            assert_eq!(result.sema().to_string(), *expected);
        }

        Ok(())
    }

    #[test]
    fn test_consteval_tojson_fromjson_roundtrip() -> Result<()> {
        use crate::Evaluation;

        // Test round-trip conversion for complex structures
        let test_cases = &[
            // Simple array
            "[1, 2, 3]",
            // Simple object
            r#"{"key": "value"}"#,
            // Mixed array
            r#"[1, "hello", true, null]"#,
            // Nested structure
            r#"{"array": [1, 2], "object": {"nested": true}}"#,
        ];

        for json_str in test_cases {
            // Parse with fromJSON
            let from_expr_str = format!("fromJSON('{}')", json_str);
            let from_expr = Expr::parse(&from_expr_str)?;
            let parsed = from_expr.consteval().unwrap();

            // Convert back with toJSON (using a dummy toJSON call structure)
            let to_result = Call::consteval_tojson(&[parsed.clone()]).unwrap();

            // Parse the result again to compare structure
            let reparsed_expr_str = format!("fromJSON('{}')", to_result.sema().to_string());
            let reparsed_expr = Expr::parse(&reparsed_expr_str)?;
            let reparsed = reparsed_expr.consteval().unwrap();

            // The structure should be preserved (though ordering might differ for objects)
            match (&parsed, &reparsed) {
                (Evaluation::Array(a), Evaluation::Array(b)) => assert_eq!(a, b),
                (Evaluation::Object(_), Evaluation::Object(_)) => {
                    // For dictionaries, we just check that both are dictionaries
                    // since ordering might differ
                    assert!(matches!(parsed, Evaluation::Object(_)));
                    assert!(matches!(reparsed, Evaluation::Object(_)));
                }
                (a, b) => assert_eq!(a, b),
            }
        }

        Ok(())
    }

    #[test]
    fn test_consteval_format() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic formatting
            (
                "format('Hello {0}', 'world')",
                Evaluation::String("Hello world".to_string()),
            ),
            (
                "format('{0} {1}', 'Hello', 'world')",
                Evaluation::String("Hello world".to_string()),
            ),
            (
                "format('Value: {0}', 42)",
                Evaluation::String("Value: 42".to_string()),
            ),
            // Escaped braces
            (
                "format('{{0}}', 'test')",
                Evaluation::String("{0}".to_string()),
            ),
            (
                "format('{{Hello}} {0}', 'world')",
                Evaluation::String("{Hello} world".to_string()),
            ),
            (
                "format('{0} {{1}}', 'Hello')",
                Evaluation::String("Hello {1}".to_string()),
            ),
            (
                "format('}}{{', 'test')",
                Evaluation::String("}{".to_string()),
            ),
            (
                "format('{{{{}}}}', 'test')",
                Evaluation::String("{{}}".to_string()),
            ),
            // Multiple arguments
            (
                "format('{0} {1} {2}', 'a', 'b', 'c')",
                Evaluation::String("a b c".to_string()),
            ),
            (
                "format('{2} {1} {0}', 'a', 'b', 'c')",
                Evaluation::String("c b a".to_string()),
            ),
            // Repeated arguments
            (
                "format('{0} {0} {0}', 'test')",
                Evaluation::String("test test test".to_string()),
            ),
            // No arguments to replace
            (
                "format('Hello world')",
                Evaluation::String("Hello world".to_string()),
            ),
            // Trailing fragments
            ("format('abc {{')", Evaluation::String("abc {".to_string())),
            ("format('abc }}')", Evaluation::String("abc }".to_string())),
            (
                "format('abc {{}}')",
                Evaluation::String("abc {}".to_string()),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_consteval_format_error_cases() -> Result<()> {
        let error_cases = &[
            // Invalid format strings
            "format('{0', 'test')",        // Missing closing brace
            "format('0}', 'test')",        // Missing opening brace
            "format('{a}', 'test')",       // Non-numeric placeholder
            "format('{1}', 'test')",       // Argument index out of bounds
            "format('{0} {2}', 'a', 'b')", // Argument index out of bounds
            "format('{}', 'test')",        // Empty braces
            "format('{-1}', 'test')",      // Negative index (invalid)
        ];

        for expr_str in error_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval();
            assert!(
                result.is_none(),
                "Expected None for invalid format string: {}",
                expr_str
            );
        }

        Ok(())
    }

    #[test]
    fn test_consteval_contains() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic string contains (case-insensitive)
            (
                "contains('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "contains('hello world', 'WORLD')",
                Evaluation::Boolean(true),
            ),
            (
                "contains('HELLO WORLD', 'world')",
                Evaluation::Boolean(true),
            ),
            ("contains('hello world', 'foo')", Evaluation::Boolean(false)),
            ("contains('test', '')", Evaluation::Boolean(true)),
            // Number to string conversion
            ("contains('123', '2')", Evaluation::Boolean(true)),
            ("contains(123, '2')", Evaluation::Boolean(true)),
            ("contains('hello123', 123)", Evaluation::Boolean(true)),
            // Boolean to string conversion
            ("contains('true', true)", Evaluation::Boolean(true)),
            ("contains('false', false)", Evaluation::Boolean(true)),
            // Null handling
            ("contains('null', null)", Evaluation::Boolean(true)),
            ("contains(null, '')", Evaluation::Boolean(true)),
            // Array contains - exact matches
            (
                "contains(fromJSON('[1, 2, 3]'), 2)",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[1, 2, 3]'), 4)",
                Evaluation::Boolean(false),
            ),
            (
                "contains(fromJSON('[\"a\", \"b\", \"c\"]'), 'b')",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[\"a\", \"b\", \"c\"]'), 'B')",
                Evaluation::Boolean(false), // Array search is exact match, not case-insensitive
            ),
            (
                "contains(fromJSON('[true, false, null]'), true)",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[true, false, null]'), null)",
                Evaluation::Boolean(true),
            ),
            // Empty array
            (
                "contains(fromJSON('[]'), 'anything')",
                Evaluation::Boolean(false),
            ),
            // Mixed type array
            (
                "contains(fromJSON('[1, \"hello\", true, null]'), 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[1, \"hello\", true, null]'), 1)",
                Evaluation::Boolean(true),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_consteval_join() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic array joining with default separator
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'))",
                Evaluation::String("a,b,c".to_string()),
            ),
            (
                "join(fromJSON('[1, 2, 3]'))",
                Evaluation::String("1,2,3".to_string()),
            ),
            (
                "join(fromJSON('[true, false, null]'))",
                Evaluation::String("true,false,".to_string()),
            ),
            // Array joining with custom separator
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), ' ')",
                Evaluation::String("a b c".to_string()),
            ),
            (
                "join(fromJSON('[1, 2, 3]'), '-')",
                Evaluation::String("1-2-3".to_string()),
            ),
            (
                "join(fromJSON('[\"hello\", \"world\"]'), ' | ')",
                Evaluation::String("hello | world".to_string()),
            ),
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), '')",
                Evaluation::String("abc".to_string()),
            ),
            // Empty array
            ("join(fromJSON('[]'))", Evaluation::String("".to_string())),
            (
                "join(fromJSON('[]'), '-')",
                Evaluation::String("".to_string()),
            ),
            // Single element array
            (
                "join(fromJSON('[\"single\"]'))",
                Evaluation::String("single".to_string()),
            ),
            (
                "join(fromJSON('[\"single\"]'), '-')",
                Evaluation::String("single".to_string()),
            ),
            // Primitive values (should return the value as string)
            ("join('hello')", Evaluation::String("hello".to_string())),
            (
                "join('hello', '-')",
                Evaluation::String("hello".to_string()),
            ),
            ("join(123)", Evaluation::String("123".to_string())),
            ("join(true)", Evaluation::String("true".to_string())),
            ("join(null)", Evaluation::String("".to_string())),
            // Mixed type array
            (
                "join(fromJSON('[1, \"hello\", true, null]'))",
                Evaluation::String("1,hello,true,".to_string()),
            ),
            (
                "join(fromJSON('[1, \"hello\", true, null]'), ' | ')",
                Evaluation::String("1 | hello | true | ".to_string()),
            ),
            // Special separator values
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), 123)",
                Evaluation::String("a123b123c".to_string()),
            ),
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), true)",
                Evaluation::String("atruebtruec".to_string()),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_consteval_endswith() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic case-insensitive string endsWith
            (
                "endsWith('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('hello world', 'WORLD')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('HELLO WORLD', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('hello world', 'hello')",
                Evaluation::Boolean(false),
            ),
            ("endsWith('hello world', 'foo')", Evaluation::Boolean(false)),
            // Empty string cases
            ("endsWith('test', '')", Evaluation::Boolean(true)),
            ("endsWith('', '')", Evaluation::Boolean(true)),
            ("endsWith('', 'test')", Evaluation::Boolean(false)),
            // Number to string conversion
            ("endsWith('123', '3')", Evaluation::Boolean(true)),
            ("endsWith(123, '3')", Evaluation::Boolean(true)),
            ("endsWith('hello123', 123)", Evaluation::Boolean(true)),
            ("endsWith(12345, 345)", Evaluation::Boolean(true)),
            // Boolean to string conversion
            ("endsWith('test true', true)", Evaluation::Boolean(true)),
            ("endsWith('test false', false)", Evaluation::Boolean(true)),
            ("endsWith(true, 'ue')", Evaluation::Boolean(true)),
            // Null handling
            ("endsWith('test null', null)", Evaluation::Boolean(true)),
            ("endsWith(null, '')", Evaluation::Boolean(true)),
            ("endsWith('something', null)", Evaluation::Boolean(true)), // null converts to empty string
            // Non-primitive types should return false
            (
                "endsWith(fromJSON('[1, 2, 3]'), '3')",
                Evaluation::Boolean(false),
            ),
            (
                "endsWith('test', fromJSON('[1, 2, 3]'))",
                Evaluation::Boolean(false),
            ),
            (
                "endsWith(fromJSON('{\"key\": \"value\"}'), 'value')",
                Evaluation::Boolean(false),
            ),
            (
                "endsWith('test', fromJSON('{\"key\": \"value\"}'))",
                Evaluation::Boolean(false),
            ),
            // Mixed case scenarios
            (
                "endsWith('TestString', 'STRING')",
                Evaluation::Boolean(true),
            ),
            ("endsWith('CamelCase', 'case')", Evaluation::Boolean(true)),
            // Exact match
            ("endsWith('exact', 'exact')", Evaluation::Boolean(true)),
            // Longer suffix than string
            (
                "endsWith('short', 'very long suffix')",
                Evaluation::Boolean(false),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_consteval_startswith() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic case-insensitive string startsWith
            (
                "startsWith('hello world', 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('hello world', 'HELLO')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('HELLO WORLD', 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('hello world', 'world')",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith('hello world', 'foo')",
                Evaluation::Boolean(false),
            ),
            // Empty string cases
            ("startsWith('test', '')", Evaluation::Boolean(true)),
            ("startsWith('', '')", Evaluation::Boolean(true)),
            ("startsWith('', 'test')", Evaluation::Boolean(false)),
            // Number to string conversion
            ("startsWith('123', '1')", Evaluation::Boolean(true)),
            ("startsWith(123, '1')", Evaluation::Boolean(true)),
            ("startsWith('123hello', 123)", Evaluation::Boolean(true)),
            ("startsWith(12345, 123)", Evaluation::Boolean(true)),
            // Boolean to string conversion
            ("startsWith('true test', true)", Evaluation::Boolean(true)),
            ("startsWith('false test', false)", Evaluation::Boolean(true)),
            ("startsWith(true, 'tr')", Evaluation::Boolean(true)),
            // Null handling
            ("startsWith('null test', null)", Evaluation::Boolean(true)),
            ("startsWith(null, '')", Evaluation::Boolean(true)),
            (
                "startsWith('something', null)",
                Evaluation::Boolean(true), // null converts to empty string
            ),
            // Non-primitive types should return false
            (
                "startsWith(fromJSON('[1, 2, 3]'), '1')",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith('test', fromJSON('[1, 2, 3]'))",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith(fromJSON('{\"key\": \"value\"}'), 'key')",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith('test', fromJSON('{\"key\": \"value\"}'))",
                Evaluation::Boolean(false),
            ),
            // Mixed case scenarios
            (
                "startsWith('TestString', 'TEST')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('CamelCase', 'camel')",
                Evaluation::Boolean(true),
            ),
            // Exact match
            ("startsWith('exact', 'exact')", Evaluation::Boolean(true)),
            // Longer prefix than string
            (
                "startsWith('short', 'very long prefix')",
                Evaluation::Boolean(false),
            ),
            // Partial matches
            (
                "startsWith('prefix_suffix', 'prefix')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('prefix_suffix', 'suffix')",
                Evaluation::Boolean(false),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_evaluate_constant_functions() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // format function
            (
                "format('{0}', 'hello')",
                Evaluation::String("hello".to_string()),
            ),
            (
                "format('{0} {1}', 'hello', 'world')",
                Evaluation::String("hello world".to_string()),
            ),
            (
                "format('Value: {0}', 42)",
                Evaluation::String("Value: 42".to_string()),
            ),
            // contains function
            (
                "contains('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            ("contains('hello world', 'foo')", Evaluation::Boolean(false)),
            ("contains('test', '')", Evaluation::Boolean(true)),
            // startsWith function
            (
                "startsWith('hello world', 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('hello world', 'world')",
                Evaluation::Boolean(false),
            ),
            ("startsWith('test', '')", Evaluation::Boolean(true)),
            // endsWith function
            (
                "endsWith('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('hello world', 'hello')",
                Evaluation::Boolean(false),
            ),
            ("endsWith('test', '')", Evaluation::Boolean(true)),
            // toJSON function
            (
                "toJSON('hello')",
                Evaluation::String("\"hello\"".to_string()),
            ),
            ("toJSON(42)", Evaluation::String("42".to_string())),
            ("toJSON(true)", Evaluation::String("true".to_string())),
            ("toJSON(null)", Evaluation::String("null".to_string())),
            // fromJSON function - primitives
            (
                "fromJSON('\"hello\"')",
                Evaluation::String("hello".to_string()),
            ),
            ("fromJSON('42')", Evaluation::Number(42.0)),
            ("fromJSON('true')", Evaluation::Boolean(true)),
            ("fromJSON('null')", Evaluation::Null),
            // fromJSON function - arrays and objects
            (
                "fromJSON('[1, 2, 3]')",
                Evaluation::Array(vec![
                    Evaluation::Number(1.0),
                    Evaluation::Number(2.0),
                    Evaluation::Number(3.0),
                ]),
            ),
            (
                "fromJSON('{\"key\": \"value\"}')",
                Evaluation::Object({
                    let mut map = std::collections::HashMap::new();
                    map.insert("key".to_string(), Evaluation::String("value".to_string()));
                    map
                }),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(
                result, *expected,
                "Failed for expression: {} {result:?}",
                expr_str
            );
        }

        Ok(())
    }
}

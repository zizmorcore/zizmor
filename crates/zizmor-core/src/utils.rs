//! Helper routines.

use github_actions_expressions::context::{Context, ContextPattern};
use github_actions_models::common::{Env, expr::LoE};
use std::ops::Range;

pub static ZIZMOR_AGENT: &str = concat!("zizmor/", env!("CARGO_PKG_VERSION"));

macro_rules! pat {
    ($pat:expr) => {
        ContextPattern::new($pat)
    };
}

/// Default environment variables that are always present in GitHub Actions.
/// These variables are provided by the runner itself and are presumed
/// static *except* for `CI`, which can be overridden by the user.
///
/// This is stored as a four-tuple of the environment variable name,
/// its environment context equivalent, its "real" context equivalent,
/// if any, and a boolean indicating whether the variable is presumed static.
///
/// See: <https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables>
pub static DEFAULT_ENVIRONMENT_VARIABLES: &[(
    &str,
    ContextPattern,
    Option<ContextPattern>,
    bool,
)] = &[
    ("CI", pat!("env.CI"), None, false),
    (
        "GITHUB_ACTION",
        pat!("env.GITHUB_ACTION"),
        Some(pat!("github.action")),
        true,
    ),
    (
        "GITHUB_ACTION_PATH",
        pat!("env.GITHUB_ACTION_PATH"),
        Some(pat!("github.action_path")),
        true,
    ),
    (
        "GITHUB_ACTION_REPOSITORY",
        pat!("env.GITHUB_ACTION_REPOSITORY"),
        Some(pat!("github.action_repository")),
        true,
    ),
    ("GITHUB_ACTIONS", pat!("env.GITHUB_ACTIONS"), None, true),
    (
        "GITHUB_ACTOR",
        pat!("env.GITHUB_ACTOR"),
        Some(pat!("github.actor")),
        true,
    ),
    (
        "GITHUB_ACTOR_ID",
        pat!("env.GITHUB_ACTOR_ID"),
        Some(pat!("github.actor_id")),
        true,
    ),
    (
        "GITHUB_API_URL",
        pat!("env.GITHUB_API_URL"),
        Some(pat!("github.api_url")),
        true,
    ),
    (
        "GITHUB_BASE_REF",
        pat!("env.GITHUB_BASE_REF"),
        Some(pat!("github.base_ref")),
        true,
    ),
    (
        "GITHUB_ENV",
        pat!("env.GITHUB_ENV"),
        Some(pat!("github.env")),
        true,
    ),
    (
        "GITHUB_EVENT_NAME",
        pat!("env.GITHUB_EVENT_NAME"),
        Some(pat!("github.event_name")),
        true,
    ),
    (
        "GITHUB_EVENT_PATH",
        pat!("env.GITHUB_EVENT_PATH"),
        Some(pat!("github.event_path")),
        true,
    ),
    (
        "GITHUB_GRAPHQL_URL",
        pat!("env.GITHUB_GRAPHQL_URL"),
        Some(pat!("github.graphql_url")),
        true,
    ),
    (
        "GITHUB_HEAD_REF",
        pat!("env.GITHUB_HEAD_REF"),
        Some(pat!("github.head_ref")),
        true,
    ),
    (
        "GITHUB_JOB",
        pat!("env.GITHUB_JOB"),
        Some(pat!("github.job")),
        true,
    ),
    ("GITHUB_OUTPUT", pat!("env.GITHUB_OUTPUT"), None, true),
    (
        "GITHUB_PATH",
        pat!("env.GITHUB_PATH"),
        Some(pat!("github.path")),
        true,
    ),
    (
        "GITHUB_REF",
        pat!("env.GITHUB_REF"),
        Some(pat!("github.ref")),
        true,
    ),
    (
        "GITHUB_REF_NAME",
        pat!("env.GITHUB_REF_NAME"),
        Some(pat!("github.ref_name")),
        true,
    ),
    (
        "GITHUB_REF_PROTECTED",
        pat!("env.GITHUB_REF_PROTECTED"),
        Some(pat!("github.ref_protected")),
        true,
    ),
    (
        "GITHUB_REF_TYPE",
        pat!("env.GITHUB_REF_TYPE"),
        Some(pat!("github.ref_type")),
        true,
    ),
    (
        "GITHUB_REPOSITORY",
        pat!("env.GITHUB_REPOSITORY"),
        Some(pat!("github.repository")),
        true,
    ),
    (
        "GITHUB_REPOSITORY_ID",
        pat!("env.GITHUB_REPOSITORY_ID"),
        Some(pat!("github.repository_id")),
        true,
    ),
    (
        "GITHUB_REPOSITORY_OWNER",
        pat!("env.GITHUB_REPOSITORY_OWNER"),
        Some(pat!("github.repository_owner")),
        true,
    ),
    (
        "GITHUB_REPOSITORY_OWNER_ID",
        pat!("env.GITHUB_REPOSITORY_OWNER_ID"),
        Some(pat!("github.repository_owner_id")),
        true,
    ),
    (
        "GITHUB_RUN_ATTEMPT",
        pat!("env.GITHUB_RUN_ATTEMPT"),
        Some(pat!("github.run_attempt")),
        true,
    ),
    (
        "GITHUB_RUN_ID",
        pat!("env.GITHUB_RUN_ID"),
        Some(pat!("github.run_id")),
        true,
    ),
    (
        "GITHUB_RUN_NUMBER",
        pat!("env.GITHUB_RUN_NUMBER"),
        Some(pat!("github.run_number")),
        true,
    ),
    (
        "GITHUB_SERVER_URL",
        pat!("env.GITHUB_SERVER_URL"),
        Some(pat!("github.server_url")),
        true,
    ),
    (
        "GITHUB_SHA",
        pat!("env.GITHUB_SHA"),
        Some(pat!("github.sha")),
        true,
    ),
    (
        "GITHUB_TRIGGERING_ACTOR",
        pat!("env.GITHUB_TRIGGERING_ACTOR"),
        Some(pat!("github.triggering_actor")),
        true,
    ),
    (
        "GITHUB_WORKFLOW",
        pat!("env.GITHUB_WORKFLOW"),
        Some(pat!("github.workflow")),
        true,
    ),
    (
        "GITHUB_WORKFLOW_REF",
        pat!("env.GITHUB_WORKFLOW_REF"),
        Some(pat!("github.workflow_ref")),
        true,
    ),
    (
        "GITHUB_WORKFLOW_SHA",
        pat!("env.GITHUB_WORKFLOW_SHA"),
        Some(pat!("github.workflow_sha")),
        true,
    ),
    (
        "GITHUB_WORKSPACE",
        pat!("env.GITHUB_WORKSPACE"),
        Some(pat!("github.workspace")),
        true,
    ),
    (
        "RUNNER_ARCH",
        pat!("env.RUNNER_ARCH"),
        Some(pat!("runner.arch")),
        true,
    ),
    (
        "RUNNER_DEBUG",
        pat!("env.RUNNER_DEBUG"),
        Some(pat!("runner.debug")),
        true,
    ),
    (
        "RUNNER_ENVIRONMENT",
        pat!("env.RUNNER_ENVIRONMENT"),
        Some(pat!("runner.environment")),
        true,
    ),
    (
        "RUNNER_NAME",
        pat!("env.RUNNER_NAME"),
        Some(pat!("runner.name")),
        true,
    ),
    (
        "RUNNER_OS",
        pat!("env.RUNNER_OS"),
        Some(pat!("runner.os")),
        true,
    ),
    (
        "RUNNER_TEMP",
        pat!("env.RUNNER_TEMP"),
        Some(pat!("runner.temp")),
        true,
    ),
    (
        "RUNNER_TOOL_CACHE",
        pat!("env.RUNNER_TOOL_CACHE"),
        Some(pat!("runner.tool_cache")),
        true,
    ),
];

/// Represents an expression that has been extracted from some surrounding
/// text, but has not been parsed yet.
///
/// Depending on the context, this may be a "bare" expression or a "fenced"
/// expression internally.
pub struct ExtractedExpr<'a> {
    inner: &'a str,
    fenced: bool,
}

impl<'a> ExtractedExpr<'a> {
    /// Creates a new [`ExtractedExpr`] from the given expression,
    /// which may be either fenced or bare.
    pub fn new(expr: &'a str) -> Self {
        Self::from_fenced(expr).unwrap_or_else(|| Self::from_bare(expr))
    }

    /// Creates a new [`ExtractedExpr`] from a fenced expression.
    ///
    /// This expects the fencing to be exact, i.e. there should be
    /// no leading or trailing whitespace around the fences.
    pub fn from_fenced(expr: &'a str) -> Option<Self> {
        expr.strip_prefix("${{")
            .and_then(|e| e.strip_suffix("}}"))
            .map(|_| ExtractedExpr {
                inner: expr,
                fenced: true,
            })
    }

    /// Creates a new [`ExtractedExpr`] from a bare expression.
    fn from_bare(expr: &'a str) -> Self {
        ExtractedExpr {
            inner: expr,
            fenced: false,
        }
    }

    /// Returns the extracted expression as a "bare" expression,
    /// i.e. without any fencing.
    pub fn as_bare(&self) -> &'a str {
        if self.fenced {
            self.inner
                .strip_prefix("${{")
                .and_then(|e| e.strip_suffix("}}"))
                .expect("invariant violated: not a fenced expression")
        } else {
            self.inner
        }
    }

    // Returns the extracted expression exactly as it was extracted,
    // including any fencing.
    pub fn as_raw(&self) -> &'a str {
        self.inner
    }
}

/// Extract a fenced expression from the given free-form text, starting
/// at the given offset. The returned span is absolute.
///
/// Returns `None` if no expression is found, or an span past
/// the end of the text if parsing is successful but exhausted.
///
/// Adapted roughly from GitHub's `parseScalar`:
/// See: <https://github.com/actions/languageservices/blob/3a8c29c2d/workflow-parser/src/templates/template-reader.ts#L448>
pub fn extract_fenced_expression(
    text: &str,
    offset: usize,
) -> Option<(ExtractedExpr<'_>, Range<usize>)> {
    let view = &text[offset..];
    let start = view.find("${{")?;

    let mut end = None;
    let mut in_string = false;

    for (idx, char) in view.bytes().enumerate().skip(start) {
        if char == b'\'' {
            in_string = !in_string;
        } else if !in_string && view.as_bytes()[idx] == b'}' && view.as_bytes()[idx - 1] == b'}' {
            end = Some(idx);
            break;
        }
    }

    end.map(|end| {
        (
            ExtractedExpr::from_fenced(&view[start..=end]).expect("impossible"),
            start + offset..end + offset + 1,
        )
    })
}

/// Extract zero or more fenced expressions from the given free-form text.
pub fn extract_fenced_expressions(text: &str) -> Vec<(ExtractedExpr<'_>, Range<usize>)> {
    let mut exprs = vec![];
    let mut offset = 0;

    while let Some((expr, span)) = extract_fenced_expression(text, offset) {
        exprs.push((expr, (span.start..span.end)));

        if span.end >= text.len() {
            break;
        } else {
            offset = span.end;
        }
    }

    exprs
}

/// Returns whether the given `env.name` environment access is "static,"
/// i.e. is not influenced by another expression.
///
/// NOTE: This function assumes that you pass it an `env`-prefixed
/// context, e.g. `env.FOOBAR` or `env['FOOBAR']`. Passing it any other
/// context does not have well-defined behavior.
pub fn env_is_static(env_ctx: &Context, envs: &[&LoE<Env>]) -> bool {
    // First, see if this environment context matches any of the default
    // non-static environment variables.
    for (_, env_ctx_pat, _, is_static) in DEFAULT_ENVIRONMENT_VARIABLES {
        if env_ctx_pat.matches(env_ctx) {
            return *is_static;
        }
    }

    let Some(env_name) = env_ctx.single_tail() else {
        // We expect exactly one tail, e.g. `env.FOOBAR` or `env['FOOBAR']`.
        // Anything other than that suggests that the user has given us
        // a semantically invalid env context, so we assume it's not static.
        return false;
    };

    for env in envs {
        match env {
            // Any `env:` that is wholly an expression cannot be static.
            LoE::Expr(_) => return false,
            LoE::Literal(env) => {
                // TODO: We probably need to do a case-insensitive lookup here.
                let Some(value) = env.get(env_name) else {
                    continue;
                };

                // A present `env:` value is static if it has no interior expressions.
                // TODO: We could instead return the interior expressions here
                // for further analysis, to further eliminate false positives
                // e.g. `env.foo: ${{ something-safe }}`.
                return extract_fenced_expressions(&value.to_string()).is_empty();
            }
        }
    }

    // If we don't have an explicit `env:` block containing this variable
    // and it isn't a default variable, then we assume it's not static.
    // This is probably slightly over sensitive, but assuming the opposite
    // would leave open `GITHUB_ENV` interactions that we can't otherwise
    // reason about.
    false
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::Expr;

    use crate::utils::{env_is_static, extract_fenced_expression, extract_fenced_expressions};

    #[test]
    fn test_extract_fenced_expression() {
        let exprs = &[
            ("${{ foo }}", " foo ", 0..10),
            ("${{ foo }}${{ bar }}", " foo ", 0..10),
            ("leading ${{ foo }} trailing", " foo ", 8..18),
            (
                "leading ${{ '${{ quoted! }}' }} trailing",
                " '${{ quoted! }}' ",
                8..31,
            ),
            ("${{ 'es''cape' }}", " 'es''cape' ", 0..17),
        ];

        for (text, expected_expr, expected_span) in exprs {
            let (actual_expr, actual_span) = extract_fenced_expression(text, 0).unwrap();
            assert_eq!(*expected_expr, actual_expr.as_bare());
            assert_eq!(*expected_span, actual_span);
        }
    }

    #[test]
    fn test_extract_fenced_expressions() {
        let multiple = r#"echo "OSSL_PATH=${{ github.workspace }}/osslcache/${{ matrix.PYTHON.OPENSSL.TYPE }}-${{ matrix.PYTHON.OPENSSL.VERSION }}-${OPENSSL_HASH}" >> $GITHUB_ENV"#;

        {
            let (raw, expected) = &(
                multiple,
                [
                    "${{ github.workspace }}",
                    "${{ matrix.PYTHON.OPENSSL.TYPE }}",
                    "${{ matrix.PYTHON.OPENSSL.VERSION }}",
                ]
                .as_slice(),
            );
            let exprs = extract_fenced_expressions(raw)
                .into_iter()
                .map(|(e, _)| e.as_raw().to_string())
                .collect::<Vec<_>>();

            assert_eq!(exprs, *expected)
        }
    }

    #[test]
    fn test_env_is_static_default() {
        for (env_ctx, is_static) in &[
            // CI is not static
            ("env.CI", false),
            // all other default environment contexts are static
            ("env.GITHUB_ACTION", true),
            ("env['GITHUB_ACTION']", true),
            ("env.GITHUB_ACTIONS", true),
            ("env.RUNNER_OS", true),
            ("env.runner_os", true),
            ("env['runner_os']", true),
            // anything else not known by default is not static
            ("env.UNKNOWN", false),
            ("env['UNKNOWN']", false),
        ] {
            let Expr::Context(ctx) = &*Expr::parse(env_ctx).unwrap() else {
                panic!("expected a context expression for {env_ctx}");
            };

            assert_eq!(env_is_static(ctx, &[]), *is_static, "for {env_ctx}");
        }
    }
}

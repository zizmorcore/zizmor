use github_actions_expressions::Expr;

use crate::{
    finding::{Confidence, Feature, Fix, Location, Severity},
    utils::parse_expressions_from_input,
};

use super::{Audit, AuditInput, AuditLoadError, AuditState, audit_meta};

pub(crate) struct OverprovisionedSecrets;

audit_meta!(
    OverprovisionedSecrets,
    "overprovisioned-secrets",
    "excessively provisioned secrets"
);

impl OverprovisionedSecrets {
    /// Create a fix for toJSON(secrets) usage
    fn create_tojson_fix() -> Fix {
        Fix {
            title: "Replace toJSON(secrets) with individual secret references".to_string(),
            description: "Replace 'toJSON(secrets)' with explicit references to individual secrets. \
                Instead of exposing the entire secrets context, access only the specific secrets you need: \
                'secrets.SECRET_NAME'. This reduces the attack surface and follows the principle of least privilege.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // For toJSON(secrets), we provide guidance but don't auto-replace
                // since we don't know which specific secrets are needed
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix for dynamic secret access
    fn create_dynamic_access_fix() -> Fix {
        Fix {
            title: "Replace dynamic secret access with explicit secret names".to_string(),
            description: "Replace dynamic secret access (e.g., 'secrets[variable]') with explicit secret references. \
                Use specific secret names like 'secrets.MY_SECRET' instead of computed keys. \
                If you need conditional secret access, use explicit conditionals with known secret names.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // For dynamic access, we provide guidance but don't auto-replace
                // since we don't know which specific secrets are intended
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that suggests using environment variables
    fn create_env_var_alternative_fix() -> Fix {
        Fix {
            title: "Use explicit environment variables instead of secret injection".to_string(),
            description: "Instead of injecting secrets directly into expressions, set them as environment variables \
                at the job or step level using explicit secret names. For example: \
                'env: MY_VAR: ${{ secrets.MY_SECRET }}'. This makes secret usage more explicit and auditable.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Provide guidance on using environment variables
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that removes the problematic expression
    fn create_remove_expression_fix() -> Fix {
        Fix {
            title: "Remove overly broad secret access".to_string(),
            description: "Remove the expression that accesses too many secrets at once. \
                Consider whether this broad secret access is actually necessary, and if so, \
                refactor to use only the specific secrets that are required."
                .to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // For removal, we'd need more context about the specific location
                // For now, just provide guidance
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Determine the type of overprovisioned secret usage
    fn classify_secret_issue(expr: &Expr) -> SecretIssueType {
        match expr {
            Expr::Call { func, args } => {
                if func == "toJSON"
                    && args
                        .iter()
                        .any(|arg| matches!(arg, Expr::Context(ctx) if ctx == "secrets"))
                {
                    SecretIssueType::ToJsonSecrets
                } else {
                    // Check recursively in arguments
                    for arg in args {
                        let issue_type = Self::classify_secret_issue(arg);
                        if !matches!(issue_type, SecretIssueType::None) {
                            return issue_type;
                        }
                    }
                    SecretIssueType::None
                }
            }
            Expr::Context(ctx) => {
                match (ctx.parts.first(), ctx.parts.get(1)) {
                    (Some(Expr::Identifier(ident)), Some(Expr::Index(idx)))
                        if ident == "secrets" && !matches!(idx.as_ref(), Expr::String(_)) =>
                    {
                        SecretIssueType::DynamicAccess
                    }
                    _ => {
                        // Check recursively in context parts
                        for part in &ctx.parts {
                            let issue_type = Self::classify_secret_issue(part);
                            if !matches!(issue_type, SecretIssueType::None) {
                                return issue_type;
                            }
                        }
                        SecretIssueType::None
                    }
                }
            }
            Expr::BinOp { lhs, rhs, .. } => {
                let lhs_type = Self::classify_secret_issue(lhs);
                if !matches!(lhs_type, SecretIssueType::None) {
                    return lhs_type;
                }
                Self::classify_secret_issue(rhs)
            }
            Expr::UnOp { expr, .. } => Self::classify_secret_issue(expr),
            Expr::Index(expr) => Self::classify_secret_issue(expr),
            _ => SecretIssueType::None,
        }
    }

    /// Get appropriate fixes based on the type of secret issue
    fn get_fixes_for_issue_type(issue_type: SecretIssueType) -> Vec<Fix> {
        match issue_type {
            SecretIssueType::ToJsonSecrets => vec![
                Self::create_tojson_fix(),
                Self::create_env_var_alternative_fix(),
                Self::create_remove_expression_fix(),
            ],
            SecretIssueType::DynamicAccess => vec![
                Self::create_dynamic_access_fix(),
                Self::create_env_var_alternative_fix(),
                Self::create_remove_expression_fix(),
            ],
            SecretIssueType::None => vec![],
        }
    }

    fn secrets_expansions(expr: &Expr) -> Vec<()> {
        let mut results = vec![];

        match expr {
            Expr::Call { func, args } => {
                // TODO: Consider any function call that accepts bare `secrets`
                // to be a finding? Are there any other functions that users
                // would plausibly call with the entire `secrets` object?
                if func == "toJSON"
                    && args
                        .iter()
                        .any(|arg| matches!(arg, Expr::Context(ctx) if ctx == "secrets"))
                {
                    results.push(());
                } else {
                    results.extend(args.iter().flat_map(Self::secrets_expansions));
                }
            }
            Expr::Index(expr) => results.extend(Self::secrets_expansions(expr)),
            Expr::Context(ctx) => {
                match (ctx.parts.first(), ctx.parts.get(1)) {
                    // Look for `secrets[...]` accesses where the index component
                    // is not a string literal.
                    (Some(Expr::Identifier(ident)), Some(Expr::Index(idx)))
                        if ident == "secrets" && !matches!(idx.as_ref(), Expr::String(_)) =>
                    {
                        results.push(())
                    }
                    _ => results.extend(ctx.parts.iter().flat_map(Self::secrets_expansions)),
                }
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                results.extend(Self::secrets_expansions(lhs));
                results.extend(Self::secrets_expansions(rhs));
            }
            Expr::UnOp { op: _, expr } => results.extend(Self::secrets_expansions(expr)),
            _ => (),
        }

        results
    }
}

#[derive(Debug, PartialEq)]
enum SecretIssueType {
    ToJsonSecrets,
    DynamicAccess,
    None,
}

impl Audit for OverprovisionedSecrets {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'doc>(
        &self,
        input: &'doc AuditInput,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        let mut findings = vec![];

        for (expr, span) in parse_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            if !Self::secrets_expansions(&parsed).is_empty() {
                let issue_type = Self::classify_secret_issue(&parsed);
                let fixes = Self::get_fixes_for_issue_type(issue_type);

                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .add_raw_location(Location::new(
                        input
                            .location()
                            .annotated("injects the entire secrets context into the runner")
                            .primary(),
                        Feature::from_span(&span, input),
                    ));

                // Add fixes for this issue
                for fix in fixes {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(input)?);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use github_actions_expressions::Expr;

    #[test]
    fn test_secrets_expansions() {
        for (case, expected) in &[
            ("toJSON(secrets)", true),
            ("toJSON(secrets.foo)", false),
            ("secrets[format('foo_{0}', matrix.bar)]", true),
            ("secrets[format_thing]", true),
            ("secrets.MY_SECRET", false),
            ("secrets['MY_SECRET']", false),
            ("not_secrets[variable]", false),
            ("secrets", false),
        ] {
            let parsed = Expr::parse(case).unwrap();
            let expansions = OverprovisionedSecrets::secrets_expansions(&parsed);
            assert_eq!(
                expansions.is_empty(),
                !expected,
                "Failed for: {case}, got: {expansions:?}"
            );
        }
    }

    #[test]
    fn test_classify_secret_issue() {
        for (case, expected_type) in &[
            ("toJSON(secrets)", SecretIssueType::ToJsonSecrets),
            (
                "secrets[format('foo_{0}', matrix.bar)]",
                SecretIssueType::DynamicAccess,
            ),
            ("secrets[variable]", SecretIssueType::DynamicAccess),
            ("secrets['literal']", SecretIssueType::None),
            ("secrets.MY_SECRET", SecretIssueType::None),
            ("not_secrets[variable]", SecretIssueType::None),
        ] {
            let parsed = Expr::parse(case).unwrap();
            let issue_type = OverprovisionedSecrets::classify_secret_issue(&parsed);
            assert_eq!(
                issue_type, *expected_type,
                "Failed for: {case}, got: {issue_type:?}"
            );
        }
    }

    #[test]
    fn test_get_fixes_for_issue_type() {
        // Test toJSON(secrets) fixes
        let tojson_fixes =
            OverprovisionedSecrets::get_fixes_for_issue_type(SecretIssueType::ToJsonSecrets);
        assert_eq!(tojson_fixes.len(), 3);
        assert!(tojson_fixes[0].title.contains("toJSON(secrets)"));

        // Test dynamic access fixes
        let dynamic_fixes =
            OverprovisionedSecrets::get_fixes_for_issue_type(SecretIssueType::DynamicAccess);
        assert_eq!(dynamic_fixes.len(), 3);
        assert!(dynamic_fixes[0].title.contains("dynamic secret access"));

        // Test no fixes for None type
        let no_fixes = OverprovisionedSecrets::get_fixes_for_issue_type(SecretIssueType::None);
        assert_eq!(no_fixes.len(), 0);
    }

    #[test]
    fn test_fix_descriptions() {
        let tojson_fix = OverprovisionedSecrets::create_tojson_fix();
        assert!(
            tojson_fix
                .description
                .contains("explicit references to individual secrets")
        );
        assert!(tojson_fix.description.contains("secrets.SECRET_NAME"));

        let dynamic_fix = OverprovisionedSecrets::create_dynamic_access_fix();
        assert!(
            dynamic_fix
                .description
                .contains("explicit secret references")
        );
        assert!(dynamic_fix.description.contains("secrets.MY_SECRET"));

        let env_fix = OverprovisionedSecrets::create_env_var_alternative_fix();
        assert!(env_fix.description.contains("environment variables"));
        assert!(env_fix.description.contains("env: MY_VAR"));

        let remove_fix = OverprovisionedSecrets::create_remove_expression_fix();
        assert!(remove_fix.description.contains("Remove the expression"));
    }

    #[test]
    fn test_fix_application() {
        let yaml_content = r#"name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
        env:
          SECRETS: ${{ toJSON(secrets) }}
"#;

        let tojson_fix = OverprovisionedSecrets::create_tojson_fix();
        let result = tojson_fix.apply_to_content(yaml_content).unwrap();

        // The fix should return the content (since we provide guidance rather than automatic changes)
        assert!(result.is_some());
        assert_eq!(result.unwrap(), yaml_content);

        let dynamic_fix = OverprovisionedSecrets::create_dynamic_access_fix();
        let result = dynamic_fix.apply_to_content(yaml_content).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), yaml_content);
    }
}

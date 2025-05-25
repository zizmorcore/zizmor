use github_actions_expressions::{Expr, context::Context};

use crate::{
    Confidence, Severity,
    finding::{Feature, Fix, Location},
    utils::parse_expressions_from_input,
};

use super::{Audit, AuditLoadError, AuditState, audit_meta};

pub(crate) struct UnredactedSecrets;

audit_meta!(
    UnredactedSecrets,
    "unredacted-secrets",
    "leaked secret values"
);

impl Audit for UnredactedSecrets {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'doc>(
        &self,
        input: &'doc super::AuditInput,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        for (expr, span) in parse_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            let leakages = Self::secret_leakages(&parsed);
            for leakage in leakages {
                let fixes = Self::create_fixes_for_leakage(&leakage, input);

                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .add_raw_location(Location::new(
                        input
                            .location()
                            .annotated("bypasses secret redaction")
                            .primary(),
                        Feature::from_span(&span, input),
                    ));

                for fix in fixes {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(input)?);
            }
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone)]
struct SecretLeakage {
    /// The type of leakage detected
    leakage_type: LeakageType,
    /// The original expression that causes the leakage
    original_expr: String,
    /// The secret context being leaked (e.g., "secrets.foo")
    secret_context: String,
}

#[derive(Debug, Clone)]
enum LeakageType {
    /// fromJSON(secrets.foo) - JSON parsing of secrets
    FromJson,
    // Future: other types of secret manipulation that bypass redaction
}

impl UnredactedSecrets {
    /// Normalize a secret name by replacing special characters with underscores
    /// and converting to uppercase for consistency with GitHub Actions conventions
    fn normalize_secret_name(name: &str) -> String {
        // First, clean up any expression-like formatting that might be present
        let cleaned = name
            .replace("fromJSON(", "")
            .replace("secrets.", "")
            .replace(")", "")
            .replace("(", "")
            .replace("\"", "");

        cleaned
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn secret_leakages(expr: &Expr) -> Vec<SecretLeakage> {
        let mut results = vec![];

        // We're looking for patterns like `fromJSON(secrets.foo)`,
        // since these mutate the secret value (e.g. by JSON decoding it)
        // and therefore bypass GitHub's redaction mechanism.

        match expr {
            Expr::Call { func, args } => {
                if func == "fromJSON" {
                    for arg in args {
                        if let Expr::Context(ctx) = arg {
                            if ctx.child_of("secrets") {
                                results.push(SecretLeakage {
                                    leakage_type: LeakageType::FromJson,
                                    original_expr: format!("fromJSON({:?})", ctx),
                                    secret_context: format!("{:?}", ctx),
                                });
                            }
                        }
                    }
                }
                // Recursively check arguments for nested expressions
                for arg in args {
                    results.extend(Self::secret_leakages(arg));
                }
            }
            Expr::Index(expr) => results.extend(Self::secret_leakages(expr)),
            Expr::Context(Context { parts, .. }) => {
                results.extend(parts.iter().flat_map(Self::secret_leakages))
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                results.extend(Self::secret_leakages(lhs));
                results.extend(Self::secret_leakages(rhs));
            }
            Expr::UnOp { op: _, expr } => results.extend(Self::secret_leakages(expr)),
            _ => (),
        }

        results
    }

    /// Create fixes for a detected secret leakage
    fn create_fixes_for_leakage(leakage: &SecretLeakage, _input: &super::AuditInput) -> Vec<Fix> {
        let mut fixes = vec![];

        match leakage.leakage_type {
            LeakageType::FromJson => {
                // Fix 1: Replace with individual secret fields
                fixes.push(Self::create_individual_secrets_fix(leakage));

                // Fix 2: Guidance on secret structure
                fixes.push(Self::create_secret_structure_guidance_fix(leakage));

                // Fix 3: Alternative approaches
                fixes.push(Self::create_alternative_approaches_fix(leakage));
            }
        }

        fixes
    }

    /// Create a fix that suggests using individual secret fields instead of JSON parsing
    fn create_individual_secrets_fix(leakage: &SecretLeakage) -> Fix {
        let secret_name = leakage
            .secret_context
            .strip_prefix("secrets.")
            .unwrap_or(&leakage.secret_context);

        let normalized_name = Self::normalize_secret_name(secret_name);

        Fix {
            title: "Use individual secret fields instead of JSON parsing".to_string(),
            description: format!(
                "Instead of using '{}', store individual fields as separate secrets. \
                For example, if '{}' contains JSON like {{\"username\": \"user\", \"password\": \"pass\"}}, \
                create separate secrets like 'secrets.{}_USERNAME' and 'secrets.{}_PASSWORD'. \
                This ensures each field is properly redacted in logs.",
                leakage.original_expr, secret_name, normalized_name, normalized_name
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // This is a manual fix that requires restructuring secrets
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that provides guidance on proper secret structure
    fn create_secret_structure_guidance_fix(leakage: &SecretLeakage) -> Fix {
        Fix {
            title: "Restructure secrets to avoid JSON parsing".to_string(),
            description: format!(
                "The expression '{}' bypasses GitHub's secret redaction because the parsed JSON fields \
                are not recognized as secret values. To fix this:\n\
                1. Avoid storing structured data (JSON, YAML) in secrets\n\
                2. Store each sensitive value as a separate secret\n\
                3. Use descriptive secret names like 'DATABASE_USERNAME', 'DATABASE_PASSWORD'\n\
                4. Access secrets directly: ${{{{ secrets.DATABASE_USERNAME }}}}\n\n\
                This ensures all sensitive values are properly redacted in workflow logs.",
                leakage.original_expr
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Guidance-only fix
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that suggests alternative approaches
    fn create_alternative_approaches_fix(leakage: &SecretLeakage) -> Fix {
        Fix {
            title: "Consider alternative approaches for structured secrets".to_string(),
            description: format!(
                "If you need to use structured secret data, consider these alternatives to '{}':\n\
                1. Use environment files: Store secrets in a file and load them at runtime\n\
                2. Use a secret management service: Azure Key Vault, AWS Secrets Manager, etc.\n\
                3. Use GitHub's environment secrets with different scopes\n\
                4. Pass secrets as separate environment variables to your application\n\n\
                These approaches maintain security while avoiding the redaction bypass issue.",
                leakage.original_expr
            ),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Guidance-only fix
                Ok(Some(content.to_string()))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use github_actions_expressions::Expr;

    use crate::audit::unredacted_secrets;

    #[test]
    fn test_secret_leakages() {
        for (expr, count) in &[
            ("secrets", 0),
            ("secrets.foo", 0),
            ("fromJSON(notsecrets)", 0),
            ("fromJSON(notsecrets.secrets)", 0),
            ("fromJSON(secrets)", 1),
            ("fromjson(SECRETS)", 1),
            ("fromJSON(secrets.foo)", 1),
            ("fromJSON(secrets.foo).bar", 1),
            ("fromJSON(secrets.foo).bar.baz", 1),
            ("fromJSON(secrets.foo) && fromJSON(secrets.bar)", 2),
        ] {
            let expr = Expr::parse(expr).unwrap();
            assert_eq!(
                unredacted_secrets::UnredactedSecrets::secret_leakages(&expr).len(),
                *count
            );
        }
    }

    #[test]
    fn test_secret_leakage_details() {
        let expr = Expr::parse("fromJSON(secrets.my_secret)").unwrap();
        let leakages = unredacted_secrets::UnredactedSecrets::secret_leakages(&expr);

        assert_eq!(leakages.len(), 1);
        let leakage = &leakages[0];

        assert!(matches!(
            leakage.leakage_type,
            unredacted_secrets::LeakageType::FromJson
        ));
        assert!(leakage.secret_context.contains("secrets"));
        assert!(leakage.secret_context.contains("my_secret"));
        assert!(leakage.original_expr.contains("fromJSON"));
        assert!(leakage.original_expr.contains("secrets"));
        assert!(leakage.original_expr.contains("my_secret"));
    }

    #[test]
    fn test_normalize_secret_name() {
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name("database_config"),
            "DATABASE_CONFIG"
        );
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name("api-config"),
            "API_CONFIG"
        );
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name("my.secret.name"),
            "MY_SECRET_NAME"
        );
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name("config@prod"),
            "CONFIG_PROD"
        );
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name("test-123_config"),
            "TEST_123_CONFIG"
        );

        // Test expressions with parentheses and function calls
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name(
                "fromJSON(secrets.api-config)"
            ),
            "API_CONFIG"
        );
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name("secrets.db.config"),
            "DB_CONFIG"
        );
        assert_eq!(
            unredacted_secrets::UnredactedSecrets::normalize_secret_name(
                "fromJSON(\"secrets.MyApp-Config_v2\")"
            ),
            "MYAPP_CONFIG_V2"
        );
    }

    #[test]
    fn test_individual_secrets_fix() {
        let leakage = unredacted_secrets::SecretLeakage {
            leakage_type: unredacted_secrets::LeakageType::FromJson,
            original_expr: "fromJSON(secrets.database_config)".to_string(),
            secret_context: "secrets.database_config".to_string(),
        };

        let fix = unredacted_secrets::UnredactedSecrets::create_individual_secrets_fix(&leakage);

        assert_eq!(
            fix.title,
            "Use individual secret fields instead of JSON parsing"
        );
        assert!(fix.description.contains("DATABASE_CONFIG_USERNAME"));
        assert!(fix.description.contains("DATABASE_CONFIG_PASSWORD"));
        assert!(
            fix.description
                .contains("fromJSON(secrets.database_config)")
        );
    }

    #[test]
    fn test_individual_secrets_fix_with_special_chars() {
        let leakage = unredacted_secrets::SecretLeakage {
            leakage_type: unredacted_secrets::LeakageType::FromJson,
            original_expr: "fromJSON(secrets.api-config)".to_string(),
            secret_context: "secrets.api-config".to_string(),
        };

        let fix = unredacted_secrets::UnredactedSecrets::create_individual_secrets_fix(&leakage);

        assert_eq!(
            fix.title,
            "Use individual secret fields instead of JSON parsing"
        );
        assert!(fix.description.contains("API_CONFIG_USERNAME"));
        assert!(fix.description.contains("API_CONFIG_PASSWORD"));
        assert!(fix.description.contains("fromJSON(secrets.api-config)"));
    }

    #[test]
    fn test_secret_structure_guidance_fix() {
        let leakage = unredacted_secrets::SecretLeakage {
            leakage_type: unredacted_secrets::LeakageType::FromJson,
            original_expr: "fromJSON(secrets.api_config)".to_string(),
            secret_context: "secrets.api_config".to_string(),
        };

        let fix =
            unredacted_secrets::UnredactedSecrets::create_secret_structure_guidance_fix(&leakage);

        assert_eq!(fix.title, "Restructure secrets to avoid JSON parsing");
        assert!(
            fix.description
                .contains("bypasses GitHub's secret redaction")
        );
        assert!(
            fix.description
                .contains("Store each sensitive value as a separate secret")
        );
        assert!(fix.description.contains("fromJSON(secrets.api_config)"));
    }

    #[test]
    fn test_alternative_approaches_fix() {
        let leakage = unredacted_secrets::SecretLeakage {
            leakage_type: unredacted_secrets::LeakageType::FromJson,
            original_expr: "fromJSON(secrets.config)".to_string(),
            secret_context: "secrets.config".to_string(),
        };

        let fix =
            unredacted_secrets::UnredactedSecrets::create_alternative_approaches_fix(&leakage);

        assert_eq!(
            fix.title,
            "Consider alternative approaches for structured secrets"
        );
        assert!(fix.description.contains("secret management service"));
        assert!(fix.description.contains("Azure Key Vault"));
        assert!(fix.description.contains("AWS Secrets Manager"));
    }
}

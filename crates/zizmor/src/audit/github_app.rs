use std::{collections::HashSet, sync::LazyLock};

use github_actions_models::common::{EnvValue, RepositoryUses, Uses, expr::LoE};
use indexmap::IndexMap;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{
        StepBodyCommon, StepCommon, action::CompositeStep, uses::RepositoryUsesExt as _,
        workflow::Step,
    },
    state::AuditState,
    utils::ExtractedExpr,
};

/// Permissions that only affect organization access, not access within repositories.
///
/// When these (and only these) are present, we skip our presence requirement for
/// the `repositories` key, since it's superfluous when the app only works on
/// org-level resources.
///
/// See #2219 for more context.
static ORG_ONLY_PERMISSIONS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    // See: https://github.com/actions/create-github-app-token/blob/main/action.yml
    // TODO: More permissions to add here?
    [
        "permission-custom-properties-for-organizations",
        "permission-enterprise-custom-properties-for-organizations",
        "permission-members",
        "permission-organization-administration",
        "permission-organization-announcement-banners",
        "permission-organization-copilot-seat-management",
        "permission-organization-custom-org-roles",
        "permission-organization-custom-properties",
        "permission-organization-custom-roles",
        "permission-organization-events",
        "permission-organization-hooks",
        "permission-organization-packages",
        "permission-organization-personal-access-token-requests",
        "permission-organization-personal-access-tokens",
        "permission-organization-plan",
        "permission-organization-projects",
        "permission-organization-secrets",
        "permission-organization-self-hosted-runners",
        "permission-organization-user-blocking",
    ]
    .into_iter()
    .collect()
});

pub(crate) struct GitHubApp;

audit_meta!(
    GitHubApp,
    "github-app",
    "dangerous use of GitHub App tokens"
);

impl GitHubApp {
    /// Test whether the given `permissions` are a subset of [`ORG_ONLY_PERMISSIONS`].
    fn permissions_are_org_only(permissions: &HashSet<&str>) -> bool {
        // No explicit permissions means the app's default permissions, which
        // we have to assume are broader than org-only.
        if permissions.is_empty() {
            return false;
        }

        permissions.is_subset(&ORG_ONLY_PERMISSIONS)
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        }) = step.body()
        else {
            return Ok(vec![]);
        };

        let findings = if uses.matches("actions/create-github-app-token") {
            self.process_create_github_app_token(step, uses, with)?
        } else {
            // TODO: Maybe check tibdex/github-app-token as well?
            // TODO: Flag getsentry/action-github-app-token as well? It doesn't support any of
            //       the scoping that create-github-app-token does, so we could perhaps
            //       nudge users away from it.
            // TODO: Flag wow-actions/use-app-token for similar reasons.
            vec![]
        };

        Ok(findings)
    }

    fn process_create_github_app_token<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        uses: &'doc RepositoryUses,
        with: &'doc LoE<IndexMap<String, EnvValue>>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let LoE::Literal(with) = with else {
            // The user did `with: ${{ expr }}`, which we can't analyze at the moment.
            // This gets flagged separately in `obfuscation`.
            tracing::debug!("skipping analysis of non-literal `with` for create-github-app-token");
            return Ok(findings);
        };

        // `skip-token-revoke: true` means the user has explicitly disabled
        // the action's default token revocation behavior.
        if let Some(skip_token_revoke) = with.get("skip-token-revoke") {
            match skip_token_revoke.actions_toolkit_bool() {
                Some(true) => findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::High)
                        .persona(Persona::Regular)
                        .add_location(
                            step.location()
                                .with_keys(["uses".into()])
                                .subfeature(Subfeature::new(0, uses.raw()))
                                .annotated("app token requested here"),
                        )
                        .add_location(
                            step.location()
                                .with_keys(["with".into(), "skip-token-revoke".into()])
                                .annotated("token revocation disabled here")
                                .primary(),
                        )
                        .build(step)?,
                ),
                Some(false) => (),
                None => {
                    // The user might have done `skip-token-revoke: ${{ expr }}`.
                    if let EnvValue::String(skip_token_revoke) = skip_token_revoke
                        && ExtractedExpr::from_fenced(skip_token_revoke).is_some()
                    {
                        findings.push(
                            Self::finding()
                                .confidence(Confidence::Low)
                                .severity(Severity::High)
                                .persona(Persona::Regular)
                                .add_location(
                                    step.location()
                                        .with_keys(["uses".into()])
                                        .subfeature(Subfeature::new(0, uses.raw()))
                                        .annotated("app token requested here"),
                                )
                                .add_location(
                                    step.location()
                                        .with_keys(["with".into(), "skip-token-revoke".into()])
                                        .annotated("token revocation conditionally disabled here")
                                        .primary(),
                                )
                                .build(step)?,
                        );
                    }
                }
            }
        }

        let permissions: HashSet<&str> = with
            .keys()
            .map(|k| k.as_str())
            .filter(|k| k.starts_with("permission-"))
            .collect();

        tracing::trace!("permissions: {permissions:?}");

        // `owner: ...` without `repositories: ...` grants the app token access to all
        // repositories in the owner's account, which is likely more access than the
        // user intended.
        //
        // We only flag this if the user doesn't specify permissions explicitly or does
        // specify them explicitly to include permissions outside of managing organiztion
        // resources.
        if with.contains_key("owner")
            && !with.contains_key("repositories")
            && !Self::permissions_are_org_only(&permissions)
        {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .persona(Persona::Regular)
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("app token requested here"),
                    )
                    .add_location(
                        step.location()
                            .with_keys(["with".into(), "owner".into()])
                            .annotated("token granted access to all repositories for this owner's app installation")
                            .primary(),
                    )
                    .tip("use `repositories: 'repo1,repo2'` to scope the token to specific repositories")
                    .build(step)?,
            );
        }

        // If the user doesn't specify at least one `permission-<name>` input,
        // then the action defaults to granting the token all installation permissions,
        // which can be very broad.
        if !with.keys().any(|k| k.starts_with("permission-")) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .persona(Persona::Regular)
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("app token inherits blanket installation permissions"),
                    )
                    .tip("specify at least one `permission-<name>` input to limit the token's permissions")
                    .build(step)?,
            );
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for GitHubApp {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }
}

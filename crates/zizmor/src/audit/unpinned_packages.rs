use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Severity},
    models::{StepBodyCommon, StepCommon, action::CompositeStep, workflow::Step},
    state::AuditState,
    utils::once::static_regex,
};

audit_meta!(
    UnpinnedPackages,
    "unpinned-packages",
    "package installation outside the context of a lockfile"
);

static_regex!(NPM_INSTALL_PKG, r"(?mi)\bnpm\s+install\s+\S");
static_regex!(PIP_INSTALL_PKG, r"(?mi)\bpip(?:\d+(?:\.\d+)?)?\s+install\s+\S");
static_regex!(GEM_INSTALL_PKG, r"(?mi)\bgem\s+install\s+\S");
static_regex!(NPX_EXEC, r"(?mi)\bnpx\s+(?:-y|--yes)\b");
static_regex!(COMPOSER_REQUIRE, r"(?mi)\bcomposer\s+require\s+\S");

pub(crate) struct UnpinnedPackages;

impl UnpinnedPackages {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let StepBodyCommon::Run { run, .. } = step.body() else {
            return Ok(findings);
        };

        if NPM_INSTALL_PKG.is_match(run) {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::Medium)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["run".into()])
                            .annotated("npm install with package argument outside lockfile context"),
                    )
                    .tip("add the package to your package.json and use `npm ci` or `npm install` without arguments instead")
                    .build(step)?,
            );
        }

        if NPX_EXEC.is_match(run) {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::Medium)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["run".into()])
                            .annotated("npx executed with --yes/-y flag, skipping install prompt"),
                    )
                    .tip("add the package to your package.json and use `npx` without `-y` or via a script instead")
                    .build(step)?,
            );
        }

        if PIP_INSTALL_PKG.is_match(run) {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::Medium)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["run".into()])
                            .annotated("pip install outside the context of a lockfile or requirements file"),
                    )
                    .tip("pin dependencies in a requirements.txt or pyproject.toml and use `pip install -r requirements.txt` instead")
                    .build(step)?,
            );
        }

        if GEM_INSTALL_PKG.is_match(run) {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::Medium)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["run".into()])
                            .annotated("gem install outside the context of a Gemfile"),
                    )
                    .tip("add the gem to your Gemfile and use `bundle exec` or `bundle install` instead")
                    .build(step)?,
            );
        }

        if COMPOSER_REQUIRE.is_match(run) {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::Medium)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["run".into()])
                            .annotated("composer require outside the context of a lockfile"),
                    )
                    .tip("add the package to your composer.json and use `composer install` instead")
                    .build(step)?,
            );
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedPackages {
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

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        models::{workflow::Workflow},
        registry::input::InputKey,
        state::AuditState,
    };

    /// Macro for testing workflow audits with common boilerplate
    macro_rules! test_workflow_audit {
        ($audit_type:ty, $filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local("fakegroup".into(), $filename, None::<&str>);
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit
                .audit_workflow(&workflow, &Config::default())
                .await
                .unwrap();

            $test_fn(&workflow, findings)
        }};
    }

    #[tokio::test]
    async fn test_npm_install_package() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm install some-package
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_npm_install.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(!findings.is_empty(), "Expected findings but got none");
            }
        );
    }

    #[tokio::test]
    async fn test_npm_install_no_args_no_finding() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_npm_install_no_args.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(findings.is_empty());
            }
        );
    }

    #[tokio::test]
    async fn test_npm_ci_no_finding() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_npm_ci.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(findings.is_empty());
            }
        );
    }

    #[tokio::test]
    async fn test_gem_install() {
        let workflow_content = r#"
on: push

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gem install gem-release
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_gem_install.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(!findings.is_empty(), "Expected findings but got none");
            }
        );
    }

    #[tokio::test]
    async fn test_npx_yes() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npx -y some-tool
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_npx_yes.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(!findings.is_empty(), "Expected findings but got none");
            }
        );
    }

    #[tokio::test]
    async fn test_pip_install() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pip install requests
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_pip_install.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(!findings.is_empty(), "Expected findings but got none");
            }
        );
    }

    #[tokio::test]
    async fn test_composer_require() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: composer require vendor/package
"#;

        test_workflow_audit!(
            UnpinnedPackages,
            "test_composer_require.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert!(!findings.is_empty(), "Expected findings but got none");
            }
        );
    }
}

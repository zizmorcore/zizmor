use std::sync::LazyLock;

use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, audit_meta},
    finding::{Confidence, Persona, Severity},
    models::coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle},
};

#[allow(clippy::unwrap_used)]
static UNSAFE_ACTIONS_CHECKOUT: LazyLock<ActionCoordinate> =
    LazyLock::new(|| ActionCoordinate::Configurable {
        uses_pattern: "actions/checkout".parse().unwrap(),
        control: ControlExpr::field(
            Toggle::OptIn,
            "allow-unsafe-pr-checkout",
            ControlFieldType::Boolean,
            false,
        ),
    });

pub(crate) struct DangerousCheckout;

audit_meta!(DangerousCheckout, "unsafe-checkout", "unsafe Git checkout");

impl DangerousCheckout {
    async fn process_step<'doc>(
        &self,
        step: &impl crate::models::StepCommon<'doc>,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, super::AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(vec![]);
        };

        let Some(usage) = UNSAFE_ACTIONS_CHECKOUT.usage(step) else {
            return Ok(vec![]);
        };

        let (confidence, annotation) = match usage {
            crate::models::coordinate::Usage::Enabled(_) => {
                (Confidence::High, "enables unsafe checkouts here")
            }
            crate::models::coordinate::Usage::Conditional(_) => (
                Confidence::Low,
                "conditionally enables unsafe checkouts here",
            ),
            // Our coordinate is not trivial, so this never occurs.
            crate::models::coordinate::Usage::Always => unreachable!(),
        };

        Ok(vec![
            Self::finding()
                .confidence(confidence)
                .severity(Severity::High)
                .persona(Persona::Regular)
                .add_location(step.location().hidden())
                .add_location(
                    step.location()
                        .with_keys(["uses".into()])
                        .subfeature(Subfeature::new(0, uses.raw()))
                        .annotated("this checkout"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(["with".into(), "allow-unsafe-pr-checkout".into()])
                        .annotated(annotation),
                )
                .build(step)?,
        ])
    }
}

#[async_trait::async_trait]
impl Audit for DangerousCheckout {
    fn new(_state: &crate::state::AuditState) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &crate::models::workflow::Step<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, super::AuditError> {
        self.process_step(step).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &crate::models::action::CompositeStep<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, super::AuditError> {
        self.process_step(step).await
    }
}

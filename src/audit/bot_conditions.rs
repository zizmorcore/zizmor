use std::ops::Deref;

use github_actions_models::workflow::Job;

use super::{audit_meta, Audit};

pub(crate) struct BotConditions;

audit_meta!(BotConditions, "bot-conditions", "spoofable bot actor check");

impl Audit for BotConditions {
    fn new(_state: super::AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(
        &self,
        job: &super::Job<'w>,
    ) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let Job::NormalJob(normal) = job.deref() else {
            return Ok(vec![]);
        };

        todo!()
    }
}

use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;
use typomania::{
    AuthorSet, Corpus, Harness, Package,
    checks::{Omitted, SwappedWords, Typos},
};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, FindingBuilder, Persona, Severity, location::Locatable},
    github::Client,
    models::{
        StepCommon as _,
        action::CompositeStep,
        workflow::{ReusableWorkflowCallJob, Step},
    },
    state::AuditState,
};

const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789-_./";

// Keyboard-adjacency substitutions plus a handful of visual confusables
// (e.g. `m` -> `rn`, `1` -> `l`). Lifted from typomania's example, which
// in turn comes from the crates.io typosquat checker.
static TYPOS: &[(char, &[&str])] = &[
    ('1', &["2", "q", "i", "l"]),
    ('2', &["1", "q", "w", "3"]),
    ('3', &["2", "w", "e", "4"]),
    ('4', &["3", "e", "r", "5"]),
    ('5', &["4", "r", "t", "6", "s"]),
    ('6', &["5", "t", "y", "7"]),
    ('7', &["6", "y", "u", "8"]),
    ('8', &["7", "u", "i", "9"]),
    ('9', &["8", "i", "o", "0"]),
    ('0', &["9", "o", "p", "-"]),
    ('-', &["_", "0", "p", ".", ""]),
    ('_', &["-", "0", "p", ".", ""]),
    ('q', &["1", "2", "w", "a"]),
    ('w', &["2", "3", "e", "s", "a", "q", "vv"]),
    ('e', &["3", "4", "r", "d", "s", "w"]),
    ('r', &["4", "5", "t", "f", "d", "e"]),
    ('t', &["5", "6", "y", "g", "f", "r"]),
    ('y', &["6", "7", "u", "h", "t", "i"]),
    ('u', &["7", "8", "i", "j", "y", "v"]),
    ('i', &["1", "8", "9", "o", "l", "k", "j", "u", "y"]),
    ('o', &["9", "0", "p", "l", "i"]),
    ('p', &["0", "-", "o"]),
    ('a', &["q", "w", "s", "z"]),
    ('s', &["w", "d", "x", "z", "a", "5"]),
    ('d', &["e", "r", "f", "c", "x", "s"]),
    ('f', &["r", "g", "v", "c", "d"]),
    ('g', &["t", "h", "b", "v", "f"]),
    ('h', &["y", "j", "n", "b", "g"]),
    ('j', &["u", "i", "k", "m", "n", "h"]),
    ('k', &["i", "o", "l", "m", "j"]),
    ('l', &["i", "o", "p", "k", "1"]),
    ('z', &["a", "s", "x"]),
    ('x', &["z", "s", "d", "c"]),
    ('c', &["x", "d", "f", "v"]),
    ('v', &["c", "f", "g", "b", "u"]),
    ('b', &["v", "g", "h", "n"]),
    ('n', &["b", "h", "j", "m"]),
    ('m', &["n", "j", "k", "rn"]),
    ('.', &["-", "_", ""]),
    ('/', &["-", "_"]),
];

static HARNESS: LazyLock<Harness<PopularActions>> = LazyLock::new(|| {
    let corpus = PopularActions::load();
    Harness::builder()
        .with_check(Omitted::new(ALPHABET))
        .with_check(SwappedWords::new("-_/"))
        .with_check(Typos::new(TYPOS.iter().map(|(c, typos)| {
            (*c, typos.iter().map(|s| s.to_string()).collect())
        })))
        .build(corpus)
});

struct PopularActions(HashMap<String, ActionOwner>);

impl PopularActions {
    fn load() -> Self {
        Self(
            include_str!("../../data/popular-actions.txt")
                .lines()
                .filter(|l| !l.is_empty())
                .map(|slug| (slug.to_lowercase(), ActionOwner::new(slug)))
                .collect(),
        )
    }
}

impl Corpus for PopularActions {
    fn contains_name(&self, name: &str) -> typomania::Result<bool> {
        Ok(self.0.contains_key(name))
    }

    fn get(&self, name: &str) -> typomania::Result<Option<&dyn Package>> {
        Ok(self.0.get(name).map(|p| p as &dyn Package))
    }
}

struct ActionOwner {
    owner: String,
}

impl ActionOwner {
    fn new(owner: &str) -> Self {
        Self {
            owner: owner.to_owned(),
        }
    }
}

impl Package for ActionOwner {
    fn authors(&self) -> &dyn AuthorSet {
        self
    }

    fn description(&self) -> Option<&str> {
        None
    }

    fn shared_authors(&self, other: &dyn AuthorSet) -> bool {
        other.contains(&self.owner)
    }
}

impl AuthorSet for ActionOwner {
    fn contains(&self, author: &str) -> bool {
        self.owner == author
    }
}

pub(crate) struct TyposquatUses {
    client: Option<Client>,
}

audit_meta!(
    TyposquatUses,
    "typosquat-uses",
    "action reference resembles a popular action"
);

impl TyposquatUses {
    async fn uses_is_typosquat<'doc>(
        &self,
        uses: &RepositoryUses,
    ) -> Option<(FindingBuilder<'doc>, String)> {
        let candidate: Box<dyn Package> = Box::new(ActionOwner::new(uses.owner()));
        let slug = uses.slug();
        let squats = HARNESS.check_package(slug, candidate).ok()?;
        let squat = squats.into_iter().next()?;

        let mut finding = Self::finding()
            .severity(Severity::High)
            .persona(Persona::Regular);

        let (confidence, annotation) = match &self.client {
            Some(client) => match client.repo_exists(uses.owner(), uses.repo()).await {
                Ok(true) => (
                    Confidence::High,
                    format!("{slug} {squat} and resolves to a live repository"),
                ),
                Ok(false) => (
                    Confidence::Low,
                    format!("{slug} {squat} (currently unregistered)"),
                ),
                Err(_) => (Confidence::Low, format!("{slug} {squat}")),
            },
            None => {
                finding = finding.tip(
                    "run with a GitHub token to check whether this repository actually exists",
                );
                (Confidence::Low, format!("{slug} {squat}"))
            }
        };

        Some((finding.confidence(confidence), annotation))
    }
}

#[async_trait::async_trait]
impl Audit for TyposquatUses {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let client = if state.no_online_audits {
            None
        } else {
            state.gh_client.clone()
        };

        Ok(Self { client })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses()
            && let Some((finding, annotation)) = self.uses_is_typosquat(uses).await
        {
            findings.push(
                finding
                    .add_location(step.location_with_grip())
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.slug()))
                            .annotated(annotation)
                            .primary(),
                    )
                    .build(step)?,
            )
        }

        Ok(findings)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses()
            && let Some((finding, annotation)) = self.uses_is_typosquat(uses).await
        {
            findings.push(
                finding
                    .add_location(step.location_with_grip())
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.slug()))
                            .annotated(annotation)
                            .primary(),
                    )
                    .build(step)?,
            )
        }

        Ok(findings)
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Uses::Repository(uses) = &job.uses
            && let Some((finding, annotation)) = self.uses_is_typosquat(uses).await
        {
            findings.push(
                finding
                    .add_location(job.location_with_grip())
                    .add_location(
                        job.location()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.slug()))
                            .annotated(annotation)
                            .primary(),
                    )
                    .build(job)?,
            )
        }

        Ok(findings)
    }
}

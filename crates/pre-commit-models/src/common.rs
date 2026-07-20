//! Shared models and utilities.

use serde::{Deserialize, Deserializer, de::Error as _};

pub(crate) fn default_minimum_pre_commit_version() -> String {
    "0".into()
}

pub(crate) fn non_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let vec = Vec::<T>::deserialize(deserializer)?;
    if vec.is_empty() {
        Err(D::Error::custom("expected at least one item in list"))
    } else {
        Ok(vec)
    }
}

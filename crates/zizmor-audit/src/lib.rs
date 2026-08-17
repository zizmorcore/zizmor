#![warn(clippy::all, clippy::dbg_macro)]

use zizmor_core::{github, input, models};

mod utils {
    pub(crate) use zizmor_core::utils::*;

    pub(crate) mod once {
        macro_rules! once {
            ($expression:expr) => {{
                static ONCE: std::sync::Once = std::sync::Once::new();
                ONCE.call_once(|| {
                    $expression;
                });
            }};
        }

        macro_rules! warn_once {
            ($($arg:tt)+) => ({
                crate::utils::once::once!(tracing::warn!($($arg)+))
            });
        }

        macro_rules! static_regex {
            ($ident:ident, $pattern:literal) => {
                static $ident: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
                    regex::Regex::new($pattern).expect(concat!(
                        "internal error: invalid regex pattern for ",
                        stringify!($ident)
                    ))
                });
            };
        }

        pub(crate) use once;
        pub(crate) use static_regex;
        pub(crate) use warn_once;
    }
}

pub mod audit;
pub mod finding;
pub mod registry;
pub mod state;

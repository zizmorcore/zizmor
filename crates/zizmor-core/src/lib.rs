#![warn(clippy::all, clippy::dbg_macro)]

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
        once!(tracing::warn!($($arg)+))
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

pub mod finding;
pub mod github;
pub mod input;
pub mod models;
pub mod utils;

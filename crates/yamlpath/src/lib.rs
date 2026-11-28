//! Source-preserving YAML routes and locations.
#![deny(missing_docs)]

use serde::Serialize;
use std::borrow::Cow;

mod document;
pub use document::{Document, QueryError};

/// A route into some YAML document.
///
/// Internally, a route is zero or more "component" selectors, each of which
/// is either a mapping key or list index to descend through. An empty
/// route corresponds to the top-most document feature.
///
/// For example, with the following YAML document:
///
/// ```yaml
/// foo:
///   bar:
///     baz:
///       - [a, b, c]
///       - [d, e, f]
/// ```
///
/// The sub-list member `e` would be identified via the path
/// `foo`, `bar`, `baz`, `1`, `1`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Route<'a> {
    /// The individual top-down components of this route.
    route: Vec<Component<'a>>,
}

impl<'a> Route<'a> {
    /// Mapping keys and sequence indices in traversal order.
    pub fn components(&self) -> &[Component<'a>] {
        &self.route
    }

    /// Create a new route from this route, with the given component
    /// added to the end.
    pub fn with_key(&self, component: impl Into<Component<'a>>) -> Self {
        let mut components = self.route.clone();
        components.push(component.into());

        Self::from(components)
    }

    /// Create a new route from this route, with the given components
    /// added to the end.
    pub fn with_keys(&self, components: impl IntoIterator<Item = Component<'a>>) -> Self {
        let mut new_route = self.route.clone();
        new_route.extend(components);

        Self::from(new_route)
    }
}

/// Convenience builder for constructing a `Route`.
#[macro_export]
macro_rules! route {
    ($($key:expr),* $(,)?) => {
        $crate::Route::from(
            vec![$($crate::Component::from($key)),*]
        )
    };
    () => {
        $crate::Route::default()
    };
}

impl<'a> From<Vec<Component<'a>>> for Route<'a> {
    fn from(route: Vec<Component<'a>>) -> Self {
        Self { route }
    }
}

/// A single `Route` component.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Component<'a> {
    /// A YAML key.
    Key(Cow<'a, str>),

    /// An index into a YAML array.
    Index(usize),
}

impl From<usize> for Component<'_> {
    fn from(index: usize) -> Self {
        Component::Index(index)
    }
}

impl<'a> From<&'a str> for Component<'a> {
    fn from(key: &'a str) -> Self {
        Component::Key(key.into())
    }
}

impl From<String> for Component<'_> {
    fn from(key: String) -> Self {
        Component::Key(key.into())
    }
}

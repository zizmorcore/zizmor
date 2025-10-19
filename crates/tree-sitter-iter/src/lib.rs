//! A very simple pre-order iterator for tree-sitter CSTs.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![allow(clippy::redundant_field_names)]
#![forbid(unsafe_code)]

use tree_sitter::{Node, Tree, TreeCursor};

/// A pre-order iterator over the nodes of a tree-sitter syntax tree.
pub struct TreeIter<'tree> {
    cursor: Option<TreeCursor<'tree>>,
}

impl<'tree> TreeIter<'tree> {
    /// Creates a new `TreeSitterIter` for the given syntax tree.
    pub fn new(tree: &'tree Tree) -> Self {
        Self {
            cursor: Some(tree.root_node().walk()),
        }
    }
}

impl<'tree> Iterator for TreeIter<'tree> {
    type Item = Node<'tree>;

    fn next(&mut self) -> Option<Self::Item> {
        let cursor = match &mut self.cursor {
            Some(cursor) => cursor,
            None => return None,
        };

        let node = cursor.node();

        if cursor.goto_first_child() || cursor.goto_next_sibling() {
            return Some(node);
        }

        loop {
            if !cursor.goto_parent() {
                // If we can't go to the parent, the walk will be
                // complete *after* the current node.
                self.cursor = None;
                break;
            }

            if cursor.goto_next_sibling() {
                break;
            }
        }

        Some(node)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_iter_is_total() {
        let anchors = r#"
jobs:
  job1:
    env: &env_vars # Define the anchor on first use
      NODE_ENV: production
      DATABASE_URL: ${{ secrets.DATABASE_URL }}
    steps:
      - run: echo "Using production settings"

  job2:
    env: *env_vars # Reuse the environment variables
    steps:
      - run: echo "Same environment variables here"
        "#;

        // NOTE(ww): These node counts will probably change if
        // tree-sitter-yaml changes its node structure. Hopefully
        // that doesn't happen often.
        let testcases = &[
            ("foo:", 9),
            ("foo: # comment", 10),
            ("foo: bar", 12),
            ("foo: bar # comment", 13),
            ("foo: []", 13),
            ("foo: [] # comment", 14),
            (anchors, 100),
        ];

        for (src, expected_count) in testcases {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_yaml::LANGUAGE.into())
                .expect("Error loading YAML grammar");
            let tree = parser.parse(src, None).expect("Failed to parse source");

            let node_count = tree.root_node().descendant_count();
            let iter_count = super::TreeIter::new(&tree).count();

            assert_eq!(node_count, *expected_count);
            assert_eq!(node_count, iter_count);
        }
    }
}

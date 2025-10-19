# tree-sitter-iter

[![zizmor](https://img.shields.io/badge/%F0%9F%8C%88-zizmor-white?labelColor=white)](https://zizmor.sh/)
[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/tree-sitter-iter)](https://crates.io/crates/tree-sitter-iter)
[![docs.rs](https://img.shields.io/docsrs/tree-sitter-iter)](https://docs.rs/tree-sitter-iter)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

A very simple pre-order iterator for tree-sitter CSTs.

This library is part of [zizmor].

## Usage

Given a `tree_sitter::Tree`, you can create a `TreeIter` to iterate
over its nodes in pre-order:

```rust
use tree_sitter_iter::TreeIter;

let tree: tree_sitter::Tree = parse(); // Your parsing logic here.

for node in TreeIter::new(&tree) {
    println!("Node kind: {}", node.kind());
}
```

`TreeIter` implements the standard `Iterator` trait, meaning that
you can use any of the normal iterator combinators. For example, to
filter only to nodes of a specific kind:

```rust
for node in TreeIter::new(&tree).filter(|n| n.kind() == "call") {
    // Do something with each "call" node.
}
```

`tree-sitter-iter`'s space and time performance is equivalent to a
walk of the tree using the `TreeCursor` APIs. In other words, it's
exactly the same as using a `TreeCursor` manually, but with a more ergonomic
iterator interface.


See the [documentation] for more details.

[documentation]: https://docs.rs/tree-sitter-iter
[zizmor]: https://zizmor.sh


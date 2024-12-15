# Contributing to `zizmor`

Thank you for your interest in contributing to `zizmor`!

This is intended to be a "high-level" guide with some suggestions
for ways to contribute. Once you've picked a contribution idea,
please see our [development docs]
for concrete guidance on specific development tasks and style prescriptions.

## How to contribute

Here's a short list of steps you can follow to contribute:

1. *Figure out what you want to contribute.* See the
   [contribution ideas](#contribution-ideas) section below if you're looking
   for ideas!
2. *File or reply to an issue, if appropriate.* Some contributions require
   new issues (like new bugs), while others involve an existing issue
   (like known documentation defects). Others don't require an issue at all,
   like small typo fixes. In general, if you aren't sure, *error on the side
   of making or replying to an issue* &mdash; it helps maintain shared
   development context.
3. *Hack away.* Once you know what you're working on, refer to our
   [development docs] for help with specific development tasks. And don't be
   afraid to ask for help!

## Contribution ideas

Here are some ways that you can contribute to `zizmor`. These aren't the only
ways; they're just for inspiration.

### Good first issues

We use the ["good first issue"] label to track issues that we think are
(somewhat) easy and/or straightforward, making them good choices for an
early contribution.

To work on one of these, **please leave a comment** on its issue before opening
a pull request to make sure nobody else duplicates your work!

["good first issue"]: https://github.com/woodruffw/zizmor/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22

### Writing documentation

One of the best ways to help us with `zizmor` is to help us improve our
documentation!

Here are some things we could use help with:

* Improving our [CLI usage recipes](https://woodruffw.github.io/zizmor/usage/).
* Improving the detail in our
  [audit documentation pages](https://woodruffw.github.io/zizmor/audits/).
* Improving our internal (Rust API) documentation, especially in conjunction
  with more unit tests.

More generally, see [issues labeled with `documentation`] for a potential
list of documentation efforts to contribute on.

[issues labeled with `documentation`]: https://github.com/woodruffw/zizmor/issues?q=is%3Aissue+is%3Aopen+label%3Adocumentation

### Writing unit tests

We can always use more unit tests! Pick a part of the Rust codebase and
start testing.

Keep the cardinal rule of unit testing in mind: a unit test must test
**a single unit** of behavior. If it tests more than one unit, then
consider making it an integration test instead.

### Reducing false positives/negatives in audits

Static analysis is inherently imprecise, and `zizmor` is no exception.

We track imprecision bugs with the ["false positive"] and ["false negative"]
labels. These can sometimes be tricky to address, so we recommend
(but don't require) leaving an explanatory comment on the issue before
beginning a pull request.

["false positive"]: https://github.com/woodruffw/zizmor/issues?q=is%3Aopen+label%3Afalse-positive

["false negative"]: https://github.com/woodruffw/zizmor/issues?q=is%3Aopen+label%3Afalse-negative

[development docs]: https://woodruffw.github.io/zizmor/development/


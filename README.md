# zizmor

A tool for finding security issues in GitHub Actions CI/CD setups.

At the moment, `zizmor` only supports workflow definitions, and only
detects a small subset of known issues. See the [Roadmap](#roadmap)
for details on our plans.

## Usage

```bash
cargo build
./target/debug/zizmor --help
```

## Roadmap

- [ ] Auditing of action definitions (i.e. `action.yml`)
- [ ] Accidental credential persistence
    - [x] "[ArtiPACKED]"
- [ ] Insecure/fundamentally dangerous workflow triggers
    - [ ] `pull_request_target`
- [ ] Insecure/excessive permissions

## The name?

*[Now you can have beautiful clean workflows!]*

[Now you can have beautiful clean workflows!]: https://www.youtube.com/watch?v=ol7rxFCvpy8

[ArtiPACKED]: https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/

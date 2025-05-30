# 🌈 zizmor

[![CI](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/zizmorcore/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/zizmor)](https://crates.io/crates/zizmor)
[![Packaging status](https://repology.org/badge/tiny-repos/zizmor.svg)](https://repology.org/project/zizmor/versions)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.com/invite/PGU3zGZuGG)

`zizmor` is a static analysis tool for GitHub Actions.

It can find many common security issues in typical GitHub Actions CI/CD setups,
including:

* Template injection vulnerabilities, leading to attacker-controlled code execution
* Accidental credential persistence and leakage
* Excessive permission scopes and credential grants to runners
* Impostor commits and confusable `git` references
* ...[and much more]!

[and much more]: https://docs.zizmor.sh/audits/

![zizmor demo](https://raw.githubusercontent.com/zizmorcore/zizmor/main/docs/assets/zizmor-demo.gif)

See [`zizmor`'s documentation](https://docs.zizmor.sh/)
for [installation steps], as well as a [quickstart] and
[detailed usage recipes].

[please file them]: https://github.com/zizmorcore/zizmor/issues/new?assignees=&labels=bug%2Ctriage&projects=&template=bug-report.yml&title=%5BBUG%5D%3A+

[installation steps]: https://docs.zizmor.sh/installation/

[quickstart]: https://docs.zizmor.sh/quickstart/

[detailed usage recipes]: https://docs.zizmor.sh/usage/

## License

`zizmor` is licensed under the [MIT License](./LICENSE).

## Contributing

See [our contributing guide!](./CONTRIBUTING.md)

## The name?

*[Now you can have beautiful clean workflows!]*

[Now you can have beautiful clean workflows!]: https://www.youtube.com/watch?v=ol7rxFCvpy8

## Sponsors 💖

`zizmor`'s development is supported by these amazing sponsors!

<!-- @@begin-sponsors@@ -->
<table width="100%">
<caption>Logo-level sponsors</caption>
<tbody>
<tr>
<td align="center" valign="top" width="15%">
<a href="https://astral.sh/">
<img src="https://avatars.githubusercontent.com/u/115962839?s=100&v=4" width="100px">
<br>
Astral
</a>
</td>
</tr>
</tbody>
</table>
<hr align="center">
<table width="100%">
<caption>Name-level sponsors</caption>
<tbody>
<tr>
<td align="center" valign="top">
<a href="http://tenki.cloud/">
Tenki Cloud
</a>
</td>
</tr>
</tbody>
</table>
<!-- @@end-sponsors@@ -->

## Star History

<a href="https://star-history.com/#zizmorcore/zizmor&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=zizmorcore/zizmor&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=zizmorcore/zizmor&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=zizmorcore/zizmor&type=Date" />
 </picture>
</a>

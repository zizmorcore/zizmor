# 🌈 zizmor

[![CI](https://github.com/woodruffw/zizmor/actions/workflows/ci.yml/badge.svg)](https://github.com/woodruffw/zizmor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/zizmor)](https://crates.io/crates/zizmor)
[![Packaging status](https://repology.org/badge/tiny-repos/zizmor.svg)](https://repology.org/project/zizmor/versions)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/woodruffw?style=flat&logo=githubsponsors&labelColor=white&color=white)](https://github.com/sponsors/woodruffw)

`zizmor` is a static analysis tool for GitHub Actions.

It can find many common security issues in typical GitHub Actions CI/CD setups,
including:

* Template injection vulnerabilities, leading to attacker-controlled code execution
* Accidental credential persistence and leakage
* Excessive permission scopes and credential grants to runners
* Impostor commits and confusable `git` references
* ...[and much more]!

[and much more]: https://woodruffw.github.io/zizmor/audits/

![zizmor demo](https://raw.githubusercontent.com/woodruffw/zizmor/main/docs/assets/zizmor-demo.gif)

See [`zizmor`'s documentation](https://woodruffw.github.io/zizmor/)
for [installation steps], as well as a [quickstart] and
[detailed usage recipes].

[please file them]: https://github.com/woodruffw/zizmor/issues/new?assignees=&labels=bug%2Ctriage&projects=&template=bug-report.yml&title=%5BBUG%5D%3A+

[installation steps]: https://woodruffw.github.io/zizmor/installation/

[quickstart]: https://woodruffw.github.io/zizmor/quickstart/

[detailed usage recipes]: https://woodruffw.github.io/zizmor/usage/

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
<table>
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
<!-- @@end-sponsors@@ -->

## Star History

<a href="https://star-history.com/#woodruffw/zizmor&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=woodruffw/zizmor&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=woodruffw/zizmor&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=woodruffw/zizmor&type=Date" />
 </picture>
</a>

# Code signing policy

Free code signing for the Windows `rustinel.exe` release binary is provided by [SignPath.io](https://signpath.io/), with a certificate from the [SignPath Foundation](https://signpath.org/).

## What is signed

Only `rustinel.exe` from official releases of [Karib0u/rustinel](https://github.com/Karib0u/rustinel) is signed.
The binary is built by the [release workflow](https://github.com/Karib0u/rustinel/blob/main/.github/workflows/release.yml) on GitHub-hosted runners from the tagged source.
SignPath verifies that the submitted file was built by that workflow in that repository.
Every signing request is approved manually before a release is published.

Rustinel contains no proprietary code and signs no third-party binaries.
Linux and macOS release binaries are not signed with this certificate.
Rule packs are verified with a separate minisign key, see [Security model](security.md#downloads).

Signed binaries carry the product name `Rustinel` and the release version in their file properties.

## Team roles

| Role | Responsibility | Members |
| --- | --- | --- |
| Authors | Commit changes without extra review | [Karib0u](https://github.com/Karib0u) |
| Reviewers | Review every change from contributors who cannot commit, such as pull requests | [Karib0u](https://github.com/Karib0u) |
| Approvers | Approve each signing request | [Karib0u](https://github.com/Karib0u) |

Everyone with access to the source repository or to SignPath uses multi-factor authentication.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

Rustinel writes alerts, logs, and telemetry counters to local files and sends nothing home.
Network access happens only when an operator runs a command that asks for it, such as downloading a rule pack from the [rustinel-rules](https://github.com/Karib0u/rustinel-rules) releases.
Alert forwarding to a SIEM is done by the operator's own log pipeline, outside the agent.
Rule packs are fetched from GitHub, whose [privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement) applies to those requests.

## Reporting a problem

Report suspected misuse of the signing certificate to the maintainers through [GitHub private disclosure](https://github.com/Karib0u/rustinel/security/advisories/new), or to SignPath at support@signpath.io.

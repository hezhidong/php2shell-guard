# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

Documentation.

- README (en/zh) now cites both scoring scales for the two CVEs: the PHP security
  team's **CVSS v4.0 9.2** (GHSA vector strings) and NVD's independent **CVSS v3.1**
  reassessments (9.8 for CVE-2026-109618, 8.1 for CVE-2026-109619), noting the gap
  comes from differing attack-complexity assumptions (AC:H vs AC:L).

## [1.2.0] - 2026-10-23

Added.

- **Bilingual UI (English / 中文) with automatic OS-locale detection.** Language
  resolution order: `--lang en|zh` / `PHP2SHELL_LANG` > `LC_ALL`/`LC_MESSAGES`/`LANG`
  > Windows user locale > English fallback.
- Every human-facing string (scan report, verify conclusions, `fix` messages, wizard,
  `--help`) goes through the translation table; reports and the wizard now render in the
  resolved language.
- JSON output: added top-level `language` field and a language-neutral `detail_key` per
  install so automation is unaffected by display language.
- Status keywords remain stable English tokens (`VULNERABLE`, `EOL-VULNERABLE`, `FIXED`,
  `ACTIVE` / `NOT ACTIVE`) for grep/CI regardless of UI language.

## [1.1.0] - 2026-10-23

Added.

- **Interactive three-step wizard** — running the program with no arguments (or `wizard`)
  now launches a guided flow: (1) detect vulnerable PHP installs, (2) choose and apply a
  fix (package-manager upgrade or temporary ini mitigations, with confirmation prompts),
  (3) re-verify and report whether the vulnerability is fully closed or only mitigated.
- The wizard writes a full timestamped log (`php2shell-guard-YYYYmmdd-HHMMSS.log`) in the
  working directory and prints its path at the end.
- `--version` flag.
- Non-interactive invocations (pipes, CI) of the wizard exit with guidance instead of
  hanging on prompts; the `scan` / `fix` / `verify` subcommands remain unchanged for
  automation.

## [1.0.0] - 2026-10-22

Initial release.

- Cross-platform (Windows / Linux / macOS), zero-dependency single-file Python 3.7+ tool.
- `scan` — read-only detection of all local PHP installations (PATH, Windows uninstall
  registry, common install directories, Homebrew Cellar, scoop shims); classification
  against fixed releases 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 with separate EOL-branch
  handling; reports running PHP processes and PHP containers in Docker; JSON output and
  CI-friendly exit codes.
- `fix --apply` — upgrade via winget / brew / apt / dnf / apk.
- `fix --harden-only` — documented temporary ini mitigations with backup and idempotent
  marked block when no PHP scan directory exists.
- `verify` — re-check versions and confirm live mitigation values after worker restarts.
- Built-in 14-case self-test for the version decision matrix.

[1.2.0]: https://github.com/hezhidong/php2shell-guard/releases/tag/v1.2.0
[1.1.0]: https://github.com/hezhidong/php2shell-guard/releases/tag/v1.1.0
[1.0.0]: https://github.com/hezhidong/php2shell-guard/releases/tag/v1.0.0

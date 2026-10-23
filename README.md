# php2shell-guard

**Language: [English](README.md) · [简体中文](README.zh-CN.md)**

Cross-platform, single-file tool to handle **PHP2Shell** — two critical
unauthenticated Remote Code Execution vulnerabilities in PHP itself:

- **CVE-2026-109618** — RCE via out-of-memory corruption during request setup
  (exploit demonstrated against Apache `mod_php` *before any application code runs*).
- **CVE-2026-109619** — RCE via stale global state reused by a later request on
  the same worker (the default-enabled `session.upload_progress` is one confirmed path).

Both score **CVSS v4.0 9.2 (Critical)** and are already being exploited in the
wild. Vulnerable: every version before **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**.
PHP 8.1 and older (back to 5.x) have no patches on the branch — upgrading to a
supported branch is the only fix.

## Features

- **Zero dependencies** — Python 3.7+ standard library only. One file, works on
  Windows, Linux and macOS; copy and run.
- **Read-only by default** — `scan` never modifies your system.
- **Full remediation loop** — detect → fix (upgrade or temporary mitigations) → verify.
- **Broad PHP discovery** — full `PATH` scan, Windows uninstall registry keys,
  common install dirs, Homebrew Cellar, scoop shims.
- Also surfaces **running PHP processes** (which must be restarted after upgrade)
  and **PHP containers in Docker** (host patching does not fix containers).
- `--json` output for CI / fleet checks. Exit code `0` = no vulnerable install,
  `2` = vulnerable install found.

## Quick start

```bash
# 1. Detect (read-only — always run this first)
python3 php2shell_guard.py scan
python3 php2shell_guard.py scan --json          # machine-readable

# 2. Fix — choose one
python3 php2shell_guard.py fix --apply          # upgrade via the system package manager
#   Windows: winget upgrade --id PHP.PHP -e
#   macOS:   brew upgrade php
#   Debian/Ubuntu: apt-get update && apt-get install --only-upgrade php-cli php-fpm ...
#   RHEL/Fedora:   dnf/yum upgrade 'php*'
#   Alpine:        apk upgrade php8
python3 php2shell_guard.py fix --harden-only    # temporary ini mitigations if you cannot upgrade yet
#   Writes: memory_limit=-1
#           session.upload_progress.enabled=0
#           fatal_error_backtraces=0
#   Preferred target: 99-php2shell-mitigations.ini in the PHP scan dir.
#   Without a scan dir: backs up php.ini to *.php2shell_bak, then appends a
#   clearly marked, idempotent block (running twice does not duplicate it).

# 3. Verify (after restarting php-fpm / Apache workers)
python3 php2shell_guard.py verify

# Built-in self-test of the version decision logic (14 version cases)
python3 php2shell_guard.py --self-test
```

Every write action defaults to a dry-run preview; pass `-y` to actually apply it.

## What the output means

| Status | Meaning |
|---|---|
| `[!!] EOL-VULNERABLE` | End-of-life branch (PHP 5/7/8.0/8.1) — no patch exists, upgrade the branch |
| `[!] VULNERABLE` | Supported branch below the fixed release — upgrade immediately |
| `[OK] FIXED` | At or above the first patched release |

## Important limitations (please read)

1. **Mitigations are not a fix.** `--harden-only` only reduces exposure; the only
   complete remediation is upgrading. After hardening, `verify` still reports the
   version as vulnerable — that is correct behavior.
2. **Apache `mod_php` is the highest-risk SAPI**: the attack completes below the
   application layer, so application auth and most WAF rules cannot stop it.
   php-fpm is harder to exploit but not immune.
3. **Docker containers** must be fixed at the image level — rebuild on
   `php:8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+` base tags. Host-level upgrades
   and mitigations do nothing for containers. The tool lists running PHP
   containers to remind you.
4. On Windows without `winget`, or for manually unzipped PHP installs,
   `--apply` cannot auto-upgrade and points you to
   <https://windows.php.net/download/>.
5. Front-end mitigations for CVE-2026-109618 (request-body size limits, rate
   limiting, container memory caps) still leave allocation-failure paths open —
   patch as soon as you can.

## References

- <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- <https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/>
- <https://www.php.net/index.php#2026-10-21-5>

## License

MIT — see [LICENSE](LICENSE).

#!/usr/bin/env python3
"""
php2shell_guard.py — cross-platform PHP2Shell (CVE-2026-109618 / CVE-2026-109619) tool

Three-step loop:
  1. scan    detect all local PHP installs and classify exposure (read-only)
  2. fix     --apply upgrades via the system package manager;
             --harden-only writes temporary ini mitigations
  3. verify  re-check versions and whether mitigations are live

Runs on Windows / Linux / macOS, Python 3.7+ standard library only.

Interactive mode (default, no arguments): a guided three-step wizard.
Output language auto-follows the OS locale and can be forced:
  --lang en|zh   or   environment variable PHP2SHELL_LANG=en|zh

Usage:
  python3 php2shell_guard.py                     # interactive wizard
  python3 php2shell_guard.py scan                # read-only scan
  python3 php2shell_guard.py verify              # re-verify
  python3 php2shell_guard.py fix --harden-only   # temporary mitigations
  python3 php2shell_guard.py fix --apply [-y]    # package-manager upgrade
  python3 php2shell_guard.py scan --json         # machine-readable
  python3 php2shell_guard.py --self-test         # built-in tests
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

CVE1 = "CVE-2026-109618"  # OOM corruption -> RCE
CVE2 = "CVE-2026-109619"  # stale global state -> RCE
VERSION = "1.2.0"

# First patched release per 8.x branch
FIXED = {2: 35, 3: 36, 4: 27, 5: 12}  # 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
SUPPORTED_BRANCHES = (2, 3, 4, 5)

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

# ---------------------------------------------------------------- i18n

LANG = "en"

TEXTS = {
    "en": {
        # report
        "scan_time": " scan time: %s   host: %s",
        "no_php": " No PHP installation found (checked PATH / registry / common directories).",
        "report_line": " %s %s  PHP %s  (sapi: %s)",
        "ini_line": "      ini: %s",
        "mit_fmt": "      mitigation %-42s %s",
        "mit_active": "ACTIVE",
        "mit_inactive": "NOT ACTIVE",
        "running_header": " Running PHP processes (all must be restarted after upgrade):",
        "docker_header": " PHP containers in Docker (fix at image level and rebuild; host upgrade does not help):",
        "summary": " Summary: %d install(s), %d vulnerable, %d fixed",
        "next_apply": " Next: python3 php2shell_guard.py fix --apply      (upgrade)",
        "next_harden": "       python3 php2shell_guard.py fix --harden-only (temporary mitigation)",
        "next_verify": "       then: python3 php2shell_guard.py verify",
        "all_patched": " All local PHP installs already include the patch.",
        # classification
        "unknown": "Could not parse version",
        "eol_non8": "PHP %d.%d is end-of-life; the flaw dates back to 5.4 - upgrade to a supported branch",
        "eol_branch": "PHP 8.%d is end-of-life with no official patch - upgrade to 8.2.35+/8.3.36+/8.4.27+/8.5.12+",
        "fixed": "8.%d.%d >= 8.%d.%d - patched",
        "vulnerable": "8.%d.%d < 8.%d.%d - affected by %s/%s",
        # verify conclusions
        "verify_still": "\nVerification: vulnerable installs remain - remediation incomplete.",
        "verify_pass": "\nVerification: PASSED. Make sure every php-fpm/Apache worker has been restarted.",
        "verify_nophp": "\nVerification: no PHP on this host. Check Docker containers separately if used.",
        # fix usage
        "fix_choose": "Choose a fix method:",
        "fix_apply_help": "  --apply         upgrade via the system package manager (winget/brew/apt/dnf/apk)",
        "fix_harden_help": "  --harden-only   only write temporary ini mitigations (memory_limit=-1 etc.)",
        "fix_platform": "\nPlatform method: %s",
        "fix_will_run": "Will run: %s",
        "fix_docker_note": "\nNote: Docker containers need base image tags 8.2.35/8.3.36/8.4.27/8.5.12 and a rebuild.",
        "fix_nothing": "No PHP installation to process.",
        "dryrun_will_write": "[dry-run] Would write to %s:\n%s",
        "dryrun_no_ini": "[dry-run] No ini directory located",
        "harden_written": "Mitigation written: %s",
        "harden_no_ini": "Could not locate an ini directory for %s; manually add to php.ini:\n%s",
        "restart_hint": "\nRestart the web server / php-fpm, then run verify.",
        "no_auto_title": "Automatic upgrade is not available on this host (%s). Install manually:",
        "no_auto_url": "  https://windows.php.net/download/  (pick 8.2.35+/8.3.36+ or newer)",
        "then_rerun": "Then run scan / verify again.",
        "will_execute": "About to run: %s",
        "confirm_y": "Confirm? type y to continue: ",
        "cancelled": "Cancelled.",
        "cmd_failed": "Command failed (rc=%s); check the package manager output.",
        "upgrade_done": "\nPHP packages upgraded. Restart services:",
        "restart_apache_deb": "  Apache (Debian): sudo systemctl restart apache2",
        "restart_fpm": "  nginx+php-fpm:    sudo systemctl restart php*-fpm",
        "restart_httpd": "  httpd (RHEL):     sudo systemctl restart httpd php-fpm",
        "then_verify": "Then run: python3 php2shell_guard.py verify",
        # wizard
        "wiz_non_tty": "Not an interactive terminal. Run with no arguments for the wizard,\nor use scan / fix --apply|--harden-only / verify in scripts and automation.",
        "wiz_title": "#  PHP2Shell remediation wizard  (v%s)",
        "wiz_cve": "#  %s (OOM corruption RCE) / %s (stale-state RCE)",
        "wiz_readonly": "#  Scans are read-only; the system is changed only after you confirm in step 2.",
        "wiz_start": "#  Started: %s",
        "phase": "  Step %d/3  %s",
        "p1_title": "Check whether local PHP is vulnerable",
        "p2_title": "Fix the vulnerability",
        "p3_title": "Re-check whether the vulnerability remains",
        "no_php_wiz": "\nNo PHP installed - nothing to remediate.",
        "docker_wiz": "PHP containers were found in Docker; handle them at the image level (see README).",
        "all_fixed_wiz": "\nAll PHP installs are already patched - nothing to do.",
        "found_vuln": "\n%d vulnerable PHP install(s) found.",
        "choose_method": "Choose a fix:",
        "opt_upgrade_auto": "  [1] Upgrade to the official fixed release now (recommended, only complete fix)",
        "opt_via": "      This host will use %s: %s",
        "opt_harden": "  [2] Cannot upgrade yet - write temporary mitigations (reduces risk, not a fix)",
        "opt_upgrade_manual": "  [1] Upgrade now (cannot be automated on this host: %s)",
        "opt_manual_url": "      Download manually: https://windows.php.net/download/",
        "opt_quit": "  [q] Quit (no changes)",
        "your_choice": "Your choice [1]: ",
        "invalid_choice": "  Please enter: %s",
        "quit_nochange": "Quit; no changes made.",
        "manual_upgrade_first": "\nUpgrade manually to 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+, then run this wizard again.",
        "upgrade_intro": "\nPHP will be upgraded via the system package manager; you may be asked for a sudo password.",
        "confirm_upgrade": "Proceed with the upgrade? [y/N]: ",
        "cancelled_back": "Upgrade cancelled, back to choices.",
        "upgrade_failed_offer": "The command failed. You can switch to option [2] (temporary mitigations) and upgrade later.",
        "ask_fallback_harden": "\nApply temporary mitigations instead? [y/N]: ",
        "upgrade_done_wiz": "\nUpgrade finished.",
        "restart_required": "IMPORTANT: restart the web service / php-fpm workers - old processes still run vulnerable code:",
        "press_enter_verify": "\nPress Enter after the restart to continue verification ...",
        "harden_intro": "\nThe following will be written for every vulnerable install:",
        "harden_ini_note": "Preferred target: 99-php2shell-mitigations.ini in the PHP scan dir;",
        "harden_ini_note2": "without a scan dir, php.ini is backed up then appended idempotently.",
        "confirm_harden": "Write temporary mitigations? [y/N]: ",
        "harden_cancelled_back": "Cancelled, back to choices.",
        "harden_arrow": "  %s -> %s",
        "harden_no_ini_short": "no ini located",
        "harden_done": "\nMitigations written. Restart the web service / php-fpm before re-verification:",
        "result_closed": "  RESULT: vulnerability closed. All PHP installs are at a fixed release.",
        "result_mitigated": "  RESULT: versions are still below fixed releases, but all temporary mitigations are ACTIVE.",
        "result_mitigated2": "  Risk is reduced; schedule the upgrade for a complete fix as soon as possible.",
        "result_still": "  RESULT: %d install(s) remain vulnerable and mitigations are not fully active - check the output above.",
        "log_saved": "\nThe full session (detection results and actions at every step) was written to:",
        "log_file": "Log file:\n  %s",
        "self_expected": "(expected %s)",
        "self_result_ok": "\nSelf-test: all passed",
        "self_result_fail": "\nSelf-test: FAILURES present",
        # argparse
        "cli_desc": "PHP2Shell (%s/%s) detect-fix-verify tool",
        "help_selftest": "run built-in self-tests",
        "help_lang": "force output language: en or zh (default: follow OS locale)",
        "help_wizard": "interactive three-step wizard (also the default with no arguments)",
        "help_scan": "read-only detection",
        "help_verify": "post-fix verification",
        "help_fix": "fix (requires --apply or --harden-only)",
        "help_apply": "upgrade PHP via the system package manager",
        "help_harden": "only write temporary mitigation ini",
        "help_yes": "skip confirmation",
        "help_json": "JSON output",
        "lang_detected": "(detected language: %s; override with --lang en|zh or PHP2SHELL_LANG)",
    },
    "zh": {
        "scan_time": " 扫描时间: %s   主机: %s",
        "no_php": " 未发现本机安装 PHP (PATH / 注册表 / 常见目录均无)。",
        "report_line": " %s %s  PHP %s  (SAPI: %s)",
        "ini_line": "      ini: %s",
        "mit_fmt": "      缓解项 %-38s %s",
        "mit_active": "生效",
        "mit_inactive": "未生效",
        "running_header": " 运行中的 PHP 进程 (升级后必须全部重启):",
        "docker_header": " Docker 中的 PHP 容器 (需在镜像层面升级并重建, 本机升级无效):",
        "summary": " 汇总: %d 个安装, %d 个受影响, %d 个已修复",
        "next_apply": " 下一步: python3 php2shell_guard.py fix --apply      (升级)",
        "next_harden": "         python3 php2shell_guard.py fix --harden-only (临时缓解)",
        "next_verify": "         升级后: python3 php2shell_guard.py verify",
        "all_patched": " 本机 PHP 均已含补丁。",
        "unknown": "无法解析版本号",
        "eol_non8": "PHP %d.%d 已停止支持, 漏洞可追溯至 5.4, 必须升级到受支持分支",
        "eol_branch": "PHP 8.%d 已停止支持, 无官方补丁, 必须升级到 8.2.35+/8.3.36+/8.4.27+/8.5.12+",
        "fixed": "8.%d.%d >= 8.%d.%d, 已含补丁",
        "vulnerable": "8.%d.%d < 8.%d.%d, 存在 %s/%s",
        "verify_still": "\n复检结论: 仍有受影响安装, 修复未完成。",
        "verify_pass": "\n复检结论: 通过。建议确认所有 php-fpm/Apache worker 已重启。",
        "verify_nophp": "\n复检结论: 本机无 PHP。若使用 Docker 请检查容器。",
        "fix_choose": "请指定修复方式:",
        "fix_apply_help": "  --apply         调用系统包管理器升级 (winget/brew/apt/dnf/apk)",
        "fix_harden_help": "  --harden-only   只写临时缓解 ini (memory_limit=-1 等)",
        "fix_platform": "\n本机平台方案: %s",
        "fix_will_run": "将执行: %s",
        "fix_docker_note": "\n注意: Docker 容器需换基础镜像标签 (8.2.35/8.3.36/8.4.27/8.5.12) 后重建。",
        "fix_nothing": "没有可处理的 PHP 安装。",
        "dryrun_will_write": "[预演] 将写入 %s:\n%s",
        "dryrun_no_ini": "[预演] 未定位到 ini 目录",
        "harden_written": "已写入缓解配置: %s",
        "harden_no_ini": "无法定位 %s 的 ini 目录, 请手动在 php.ini 加入:\n%s",
        "restart_hint": "\n请重启 Web 服务器/php-fpm 后运行 verify。",
        "no_auto_title": "本机无法自动升级 (%s)。请手动安装:",
        "no_auto_url": "  https://windows.php.net/download/  (选择含修复版本的 8.2.35+/8.3.36+ 等)",
        "then_rerun": "升级后重新运行 scan / verify。",
        "will_execute": "将执行: %s",
        "confirm_y": "确认? 输入 y 继续: ",
        "cancelled": "已取消。",
        "cmd_failed": "命令失败 (rc=%s), 请检查包管理器输出。",
        "upgrade_done": "\nPHP 包已升级。请重启服务:",
        "restart_apache_deb": "  Apache (Debian): sudo systemctl restart apache2",
        "restart_fpm": "  nginx+php-fpm:    sudo systemctl restart php*-fpm",
        "restart_httpd": "  httpd (RHEL):     sudo systemctl restart httpd php-fpm",
        "then_verify": "然后运行: python3 php2shell_guard.py verify",
        "wiz_non_tty": "当前不是交互式终端。请直接运行不带参数的命令进入向导，\n或在脚本/自动化中使用: scan / fix --apply|--harden-only / verify",
        "wiz_title": "#  PHP2Shell 修复向导  (v%s)",
        "wiz_cve": "#  %s (OOM 损坏 RCE) / %s (过期状态 RCE)",
        "wiz_readonly": "#  全程只读检查；只有你在步骤 2 明确确认后才会改动系统。",
        "wiz_start": "#  开始时间: %s",
        "phase": "  步骤 %d/3  %s",
        "p1_title": "检查本机 PHP 是否存在漏洞",
        "p2_title": "修复漏洞",
        "p3_title": "再次检查漏洞是否仍然存在",
        "no_php_wiz": "\n本机未安装 PHP, 无需修复。",
        "docker_wiz": "检测到 Docker 中的 PHP 容器, 需在镜像层面处理 (见 README)。",
        "all_fixed_wiz": "\n所有 PHP 安装均已含补丁, 无需操作。",
        "found_vuln": "\n发现 %d 个受影响的 PHP 安装。",
        "choose_method": "请选择修复方式:",
        "opt_upgrade_auto": "  [1] 立即升级到官方修复版本 (推荐, 唯一彻底修复)",
        "opt_via": "      本机将通过 %s 执行: %s",
        "opt_harden": "  [2] 暂时无法升级 —— 先写入临时缓解配置 (降低风险, 不等于修复)",
        "opt_upgrade_manual": "  [1] 立即升级 (本机无法自动执行: %s)",
        "opt_manual_url": "      需手动下载安装: https://windows.php.net/download/",
        "opt_quit": "  [q] 退出向导 (不做任何改动)",
        "your_choice": "你的选择 [1]: ",
        "invalid_choice": "  请输入: %s",
        "quit_nochange": "已退出, 未做任何改动。",
        "manual_upgrade_first": "\n请手动升级到 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+ 后重新运行本向导。",
        "upgrade_intro": "\n即将以系统包管理器升级 PHP, 过程中可能要求输入 sudo 密码。",
        "confirm_upgrade": "确认执行升级? [y/N]: ",
        "cancelled_back": "已取消升级, 返回选择。",
        "upgrade_failed_offer": "命令执行失败。可改用选项 [2] 临时缓解, 修复包管理器后再升级。",
        "ask_fallback_harden": "\n是否改用临时缓解? [y/N]: ",
        "upgrade_done_wiz": "\n升级命令已完成。",
        "restart_required": "重要: 必须重启 Web 服务/php-fpm worker, 旧进程仍加载着有漏洞的代码:",
        "press_enter_verify": "\n重启完成后按回车继续复检 …",
        "harden_intro": "\n将为每个受影响安装写入:",
        "harden_ini_note": "优先写入 scan 目录的 99-php2shell-mitigations.ini;",
        "harden_ini_note2": "无 scan 目录时备份 php.ini 后幂等追加。",
        "confirm_harden": "确认写入临时缓解? [y/N]: ",
        "harden_cancelled_back": "已取消, 返回选择。",
        "harden_arrow": "  %s -> %s",
        "harden_no_ini_short": "未能定位 ini",
        "harden_done": "\n缓解配置已写入。请重启 Web 服务/php-fpm 后再复检:",
        "result_closed": "  结果: 漏洞已修补完成。所有 PHP 安装均已达到修复版本。",
        "result_mitigated": "  结果: 版本仍低于修复版, 但临时缓解已全部生效。",
        "result_mitigated2": "  当前风险已降低; 请尽快安排升级完成彻底修复。",
        "result_still": "  结果: 仍有 %d 个安装受影响且缓解未完全生效, 请检查上方输出。",
        "log_saved": "\n本次完整执行过程 (含每一步的检测结果与操作) 已写入日志:",
        "log_file": "日志文件:\n  %s",
        "self_expected": "(期望 %s)",
        "self_result_ok": "\n自测结果: 全部通过",
        "self_result_fail": "\n自测结果: 存在失败",
        "cli_desc": "PHP2Shell (%s/%s) 检测-修复-复检工具",
        "help_selftest": "运行内置自测",
        "help_lang": "强制输出语言: en 或 zh (默认跟随系统区域)",
        "help_wizard": "交互式三步向导 (不带参数时默认进入)",
        "help_scan": "只读检测",
        "help_verify": "修复后复检",
        "help_fix": "修复 (需 --apply 或 --harden-only)",
        "help_apply": "用系统包管理器升级 PHP",
        "help_harden": "只写临时缓解 ini",
        "help_yes": "跳过确认",
        "help_json": "输出 JSON",
        "lang_detected": "(当前语言: %s; 可用 --lang en|zh 或环境变量 PHP2SHELL_LANG 覆盖)",
    },
}


def t(key, *args):
    msg = TEXTS.get(LANG, TEXTS["en"]).get(key) or TEXTS["en"].get(key, key)
    if args:
        try:
            return msg % args
        except Exception:
            return msg
    return msg


def detect_lang():
    """Determine UI language: PHP2SHELL_LANG > LC_*/LANG > Windows locale > en."""
    forced = os.environ.get("PHP2SHELL_LANG", "").strip().lower().replace("_", "-")
    if forced:
        if forced.startswith("zh"):
            return "zh"
        if forced.startswith("en"):
            return "en"
    # An explicitly set POSIX locale wins over the OS UI language: zh* -> zh,
    # any other concrete value (en_*, C, POSIX, ...) -> en.
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        v = os.environ.get(var, "").strip()
        if v:
            return "zh" if v.lower().replace("_", "-").startswith("zh") else "en"
    if IS_WIN:
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(85)
            if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85) \
                    and buf.value.lower().startswith("zh"):
                return "zh"
        except Exception:
            pass
        try:
            import locale
            if (locale.getdefaultlocale()[0] or "").lower().startswith("zh"):
                return "zh"
        except Exception:
            pass
    return "en"


# ---------------------------------------------------------------- basics

def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or ""), p.stderr or ""
    except FileNotFoundError:
        return 127, "", ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


# ---------------------------------------------------------------- version

def parse_version(text):
    m = re.search(r"PHP\s+(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def classify(ver):
    """Return (status_key, branch, detail_key, fmt_args)."""
    if not ver:
        return "unknown", None, "unknown", ()
    major, minor, patch = ver
    if major != 8:
        return "eol-vulnerable", minor, "eol_non8", (major, minor)
    if minor not in SUPPORTED_BRANCHES:
        return "eol-vulnerable", minor, "eol_branch", (minor,)
    fixed_patch = FIXED[minor]
    if patch >= fixed_patch:
        return "fixed", minor, "fixed", (minor, patch, minor, fixed_patch)
    return "vulnerable", minor, "vulnerable", (
        minor, patch, minor, fixed_patch, CVE1, CVE2)


def detail_text(detail_key, args):
    return t(detail_key, *args) if args else t(detail_key)


# ---------------------------------------------------------------- discovery

def _which_all(name):
    found, seen = [], set()
    if IS_WIN:
        exts = [e for e in os.environ.get("PATHEXT", ".EXE;.CMD;.BAT").split(os.pathsep) if e]
        candidates = [name + e for e in exts]
    else:
        candidates = [name]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        for cname in candidates:
            cand = os.path.join(d, cname)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                real = os.path.normcase(os.path.realpath(cand))
                if real not in seen:
                    seen.add(real)
                    found.append(cand)
    return found


def find_php_windows_registry():
    out = []
    try:
        import winreg
    except ImportError:
        return out
    roots = [(winreg.HKEY_LOCAL_MACHINE,
              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_LOCAL_MACHINE,
              r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")]
    for root, path in roots:
        try:
            key = winreg.OpenKey(root, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.EnumKey(key, i)
                sk = winreg.OpenKey(key, sub)
                try:
                    name = winreg.QueryValueEx(sk, "DisplayName")[0]
                except OSError:
                    name = ""
                try:
                    loc = winreg.QueryValueEx(sk, "InstallLocation")[0]
                except OSError:
                    loc = ""
                if "php" in (name + loc).lower() and loc and os.path.isdir(loc):
                    cand = os.path.join(loc, "php.exe")
                    if os.path.isfile(cand):
                        out.append(cand)
            except OSError:
                continue
    return out


def discover_php():
    cands = _which_all("php")
    if IS_WIN:
        cands += find_php_windows_registry()
        for d in (r"C:\php", r"C:\PHP", r"C:\tools\php",
                  r"C:\Program Files\PHP", r"C:\Program Files (x86)\PHP"):
            c = os.path.join(d, "php.exe")
            if os.path.isfile(c):
                cands.append(c)
        scoop = os.path.expanduser(r"~\scoop\apps")
        if os.path.isdir(scoop):
            for sub in os.listdir(scoop):
                if sub.lower().startswith("php"):
                    c = os.path.join(scoop, sub, "current", "php.exe")
                    if os.path.isfile(c):
                        cands.append(c)
    else:
        for d in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin",
                  "/usr/local/php/bin", "/opt/php/bin"):
            c = os.path.join(d, "php")
            if os.path.isfile(c):
                cands.append(c)
        for cellar in ("/opt/homebrew/Cellar", "/usr/local/Cellar"):
            if os.path.isdir(cellar):
                for sub in os.listdir(cellar):
                    if sub.lower().startswith("php"):
                        c = os.path.join(cellar, sub, "bin", "php")
                        if os.path.isfile(c):
                            cands.append(c)
    uniq, seen = [], set()
    for c in cands:
        k = os.path.normcase(os.path.realpath(c))
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return uniq


def php_ini_paths(php_exe):
    rc, out, _ = run([php_exe, "--ini"], timeout=20)
    if rc != 0:
        return None, None
    loaded = scan_dir = None
    m = re.search(r"Loaded Configuration File:\s*(.+)", out)
    if m and "none" not in m.group(1).lower():
        loaded = m.group(1).strip()
    sm = re.search(r"Scan for additional \.ini files in:\s*(.+)", out)
    if sm and "none" not in sm.group(1).lower():
        d = sm.group(1).strip()
        if os.path.isdir(d):
            scan_dir = d
    return loaded, scan_dir


def sapi_info(php_exe):
    rc, out, _ = run([php_exe, "-r", "echo PHP_SAPI;"], timeout=15)
    return out.strip() if rc == 0 else "?"


# ---------------------------------------------------------------- runtime traces

def find_running_php():
    procs = []
    if IS_WIN:
        rc, out, _ = run(["wmic", "process", "where",
                          "name like '%php%'", "get", "ProcessId,CommandLine",
                          "/format:list"], timeout=30)
        if rc == 0:
            for block in out.split("\n\n"):
                m = re.search(r"CommandLine=(.+)", block)
                if m and m.group(1).strip():
                    procs.append(m.group(1).strip()[:200])
    else:
        rc, out, _ = run(["ps", "-eo", "args="], timeout=20)
        if rc == 0:
            for line in out.splitlines():
                low = line.lower()
                if ("php" in low and ("php-fpm" in low or "php-cgi" in low
                                      or "mod_php" in low or "php " in low
                                      or line.strip().startswith("php"))) \
                        and "php2shell_guard" not in low:
                    procs.append(line.strip()[:200])
    return procs[:20]


def find_docker_php():
    if not shutil.which("docker"):
        return []
    rc, out, _ = run(["docker", "ps", "--format", "{{.Image}}\t{{.Names}}"], timeout=30)
    if rc != 0:
        return []
    return [line.strip() for line in out.splitlines() if "php" in line.lower()]


# ---------------------------------------------------------------- mitigations

BEGIN_MARK = "; >>> php2shell_guard mitigations >>>"
END_MARK = "; <<< php2shell_guard mitigations <<<"


def _mitigation_block():
    lines = [BEGIN_MARK,
             "; temporary mitigations for %s / %s - %s"
             % (CVE1, CVE2, datetime.now(timezone.utc).isoformat()),
             "; REDUCES exposure but DOES NOT replace patching.",
             "memory_limit = -1",
             "session.upload_progress.enabled = 0",
             "fatal_error_backtraces = 0",
             END_MARK]
    return "\n".join(lines) + "\n"


def harden(php_exe, apply_write=True):
    """Return (path_or_None, content, backup_path_or_None)."""
    loaded, scan_dir = php_ini_paths(php_exe)
    content = _mitigation_block()
    if not apply_write:
        return (scan_dir or loaded), content, None
    if scan_dir:
        path = os.path.join(scan_dir, "99-php2shell-mitigations.ini")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        return path, content, None
    if loaded and os.path.isfile(loaded):
        bak = loaded + ".php2shell_bak"
        if not os.path.exists(bak):
            shutil.copy2(loaded, bak)
        with open(loaded, "r", encoding="utf-8", errors="replace") as f:
            old = f.read()
        if BEGIN_MARK in old:
            stripped = re.sub(re.escape(BEGIN_MARK) + r".*?" + re.escape(END_MARK)
                              + r"\n?", "", old, flags=re.S)
            with open(loaded, "w", encoding="utf-8", newline="\n") as f:
                f.write(stripped.rstrip("\n") + "\n" + content)
        else:
            with open(loaded, "a", encoding="utf-8", newline="\n") as f:
                if not old.endswith("\n"):
                    f.write("\n")
                f.write(content)
        return loaded, content, bak
    return None, content, None


def check_hardening(php_exe):
    checks = {}
    code = ("echo json_encode(["
            "'memory_limit'=>ini_get('memory_limit'),"
            "'sup'=>ini_get('session.upload_progress.enabled'),"
            "'feb'=>ini_get('fatal_error_backtraces')]);")
    rc, out, _ = run([php_exe, "-r", code], timeout=15)
    if rc == 0:
        try:
            j = json.loads(out.strip().splitlines()[-1])
            checks["memory_limit=-1"] = (j.get("memory_limit") == "-1")
            checks["session.upload_progress.enabled=0"] = (str(j.get("sup")) == "0"
                                                          or j.get("sup") in (False, ""))
            checks["fatal_error_backtraces=0"] = (str(j.get("feb")) in ("0", "", "None"))
        except Exception:  # noqa: BLE001
            pass
    return checks


# ---------------------------------------------------------------- upgrade

def upgrade_plan():
    if IS_WIN:
        if shutil.which("winget"):
            return "windows-winget", ["winget", "upgrade", "--id", "PHP.PHP", "-e"], True
        return "windows-manual", [], False
    if IS_MAC:
        if shutil.which("brew"):
            return "macos-brew", ["brew", "upgrade", "php"], True
        return "macos-manual", [], False
    if os.path.isfile("/etc/debian_version"):
        return "debian-apt", ["sudo", "apt-get", "update"], True
    if os.path.isfile("/etc/redhat-release"):
        if shutil.which("dnf"):
            return "rhel-dnf", ["sudo", "dnf", "upgrade", "-y", "php*"], True
        return "rhel-yum", ["sudo", "yum", "update", "-y", "php*"], True
    if shutil.which("apk"):
        return "alpine-apk", ["sudo", "apk", "upgrade", "--no-cache", "php8"], True
    return "unknown", [], False


# ---------------------------------------------------------------- scan core

def inspect(php_exe):
    rc, out, _ = run([php_exe, "-v"], timeout=20)
    ver = parse_version(out)
    status, branch, detail_key, detail_args = classify(ver)
    loaded, scan_dir = php_ini_paths(php_exe)
    hardening = check_hardening(php_exe) \
        if status in ("vulnerable", "eol-vulnerable") else {}
    return {
        "path": php_exe,
        "version": "%d.%d.%d" % ver if ver else None,
        "sapi": sapi_info(php_exe),
        "status": status,
        "detail_key": detail_key,
        "detail": detail_text(detail_key, detail_args),
        "ini_loaded": loaded,
        "ini_scan_dir": scan_dir,
        "hardening": hardening,
    }


def do_scan():
    phps = discover_php()
    installs = [inspect(p) for p in phps]
    n_vuln = sum(1 for i in installs if i["status"] in ("vulnerable", "eol-vulnerable"))
    n_fixed = sum(1 for i in installs if i["status"] == "fixed")
    return {
        "tool": "php2shell_guard",
        "version": VERSION,
        "language": LANG,
        "time": datetime.now(timezone.utc).isoformat(),
        "host": sys.platform,
        "cves": [CVE1, CVE2],
        "fixed_versions": {"8.2": "8.2.35", "8.3": "8.3.36",
                           "8.4": "8.4.27", "8.5": "8.5.12"},
        "installs_found": len(installs),
        "vulnerable": n_vuln,
        "fixed": n_fixed,
        "installs": installs,
        "running_php_processes": find_running_php(),
        "docker_php_containers": find_docker_php(),
    }


# ---------------------------------------------------------------- display

ICON = {"vulnerable": "[!]", "eol-vulnerable": "[!!]",
        "fixed": "[OK]", "unknown": "[?]"}


def print_report(r):
    print("=" * 68)
    print(" PHP2Shell guard  -  %s / %s" % (CVE1, CVE2))
    print(t("scan_time", r["time"][:19], r["host"]))
    print("=" * 68)
    if not r["installs"]:
        print(t("no_php"))
    for i in r["installs"]:
        print(t("report_line", ICON.get(i["status"], " ? "),
                i["path"], i["version"] or "?", i["sapi"]))
        print("      -> %s: %s" % (i["status"].upper(), i["detail"]))
        if i["ini_loaded"]:
            print(t("ini_line", i["ini_loaded"]))
        if i["hardening"]:
            for k, v in i["hardening"].items():
                print(t("mit_fmt", k, t("mit_active") if v else t("mit_inactive")))
    if r["running_php_processes"]:
        print("-" * 68)
        print(t("running_header"))
        for p in r["running_php_processes"][:10]:
            print("   - %s" % p)
    if r["docker_php_containers"]:
        print("-" * 68)
        print(t("docker_header"))
        for d in r["docker_php_containers"]:
            print("   - %s" % d)
    print("-" * 68)
    print(t("summary", r["installs_found"], r["vulnerable"], r["fixed"]))
    if r["vulnerable"]:
        print(t("next_apply"))
        print(t("next_harden"))
        print(t("next_verify"))
    elif r["installs_found"]:
        print(t("all_patched"))
    print("=" * 68)


# ---------------------------------------------------------------- subcommands

def cmd_scan(args):
    r = do_scan()
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print_report(r)
    return 2 if r["vulnerable"] else 0


def cmd_verify(args):
    r = do_scan()
    r["phase"] = "verify"
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print_report(r)
        if r["vulnerable"]:
            print(t("verify_still"))
        elif r["installs_found"]:
            print(t("verify_pass"))
        else:
            print(t("verify_nophp"))
    return 2 if r["vulnerable"] else 0


def cmd_fix(args):
    r = do_scan()
    vuln = [i for i in r["installs"] if i["status"] in ("vulnerable", "eol-vulnerable")]
    if not args.apply and not args.harden_only:
        print(t("fix_choose"))
        print(t("fix_apply_help"))
        print(t("fix_harden_help"))
        label, plan, _auto = upgrade_plan()
        print(t("fix_platform", label))
        if plan:
            print(t("fix_will_run", " ".join(plan)))
        print(t("fix_docker_note"))
        return 1

    if args.harden_only:
        targets = vuln or r["installs"]
        if not targets:
            print(t("fix_nothing"))
            return 0
        for i in targets:
            path, content, _bak = harden(i["path"], apply_write=args.yes)
            if not args.yes:
                where = path
                print(t("dryrun_will_write", where or t("dryrun_no_ini"), content))
            elif path:
                print(t("harden_written", path))
            else:
                print(t("harden_no_ini", i["path"], content))
        if args.yes:
            print(t("restart_hint"))
        return 0

    if args.apply:
        label, plan, auto = upgrade_plan()
        if not auto:
            print(t("no_auto_title", label))
            print(t("no_auto_url"))
            print(t("then_rerun"))
            return 1
        if not args.yes:
            print(t("will_execute", " ".join(plan)))
            if input(t("confirm_y")).strip().lower() != "y":
                print(t("cancelled"))
                return 1
        cmds = ([[ "sudo", "apt-get", "update"],
                 ["sudo", "apt-get", "install", "--only-upgrade", "-y",
                  "php-cli", "php-fpm", "libapache2-mod-php", "php-cgi"]]
                if label == "debian-apt" else [plan])
        for c in cmds:
            print("$ %s" % " ".join(c))
            p = subprocess.run(c)
            if p.returncode != 0:
                print(t("cmd_failed", p.returncode))
                return p.returncode
        print(t("upgrade_done"))
        print(t("restart_apache_deb"))
        print(t("restart_fpm"))
        print(t("restart_httpd"))
        print(t("then_verify"))
        return 0
    return 0


# ---------------------------------------------------------------- wizard

class _Tee:
    def __init__(self, log_path):
        self.term = sys.stdout
        self.log = open(log_path, "w", encoding="utf-8")
    def write(self, s):
        self.term.write(s)
        self.log.write(s)
    def flush(self):
        self.term.flush()
        self.log.flush()
    def close(self):
        try:
            self.log.close()
        except Exception:
            pass


def _ask(prompt, choices=None, default=None):
    while True:
        ans = input(prompt).strip().lower()
        if not ans and default is not None:
            return default
        if not choices or ans in choices:
            return ans
        print(t("invalid_choice", " / ".join(choices)))


def _vuln_installs(r):
    return [i for i in r["installs"]
            if i["status"] in ("vulnerable", "eol-vulnerable")]


def _phase_banner(n, title):
    print("\n" + "=" * 68)
    print(t("phase", n, title))
    print("=" * 68)


def wizard():
    if not sys.stdin.isatty():
        print(t("wiz_non_tty"))
        return 1
    return _wizard_run()


def _wizard_run():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.abspath("php2shell-guard-%s.log" % stamp)
    tee = _Tee(log_path)
    old_out = sys.stdout
    sys.stdout = tee
    code = 0
    try:
        print("#" * 68)
        print(t("wiz_title", VERSION))
        print(t("wiz_cve", CVE1, CVE2))
        print(t("wiz_readonly"))
        print(t("wiz_start", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        print("#" * 68)

        # Step 1 - detect
        _phase_banner(1, t("p1_title"))
        r = do_scan()
        print_report(r)

        if not r["installs"]:
            print(t("no_php_wiz"))
            if r["docker_php_containers"]:
                print(t("docker_wiz"))
            print(t("log_saved"))
            print("  %s" % log_path)
            return 0

        vuln = _vuln_installs(r)
        if not vuln:
            print(t("all_fixed_wiz"))
            print(t("log_saved"))
            print("  %s" % log_path)
            return 0

        print(t("found_vuln", len(vuln)))

        # Step 2 - fix
        while True:
            _phase_banner(2, t("p2_title"))
            label, plan, auto = upgrade_plan()
            print(t("choose_method"))
            if auto:
                print(t("opt_upgrade_auto"))
                print(t("opt_via", label, " ".join(plan)))
                print(t("opt_harden"))
            else:
                print(t("opt_upgrade_manual", label))
                print(t("opt_manual_url"))
                print(t("opt_harden"))
            print(t("opt_quit"))
            choice = _ask(t("your_choice"), choices=("1", "2", "q"), default="1")

            if choice == "q":
                print(t("quit_nochange"))
                print(t("log_file", log_path))
                return 1

            if choice == "1":
                if not auto:
                    print(t("manual_upgrade_first"))
                    print(t("log_file", log_path))
                    return 1
                print(t("upgrade_intro"))
                if _ask(t("confirm_upgrade"), choices=("y", "n", ""), default="n") != "y":
                    print(t("cancelled_back"))
                    continue
                cmds = ([["sudo", "apt-get", "update"],
                         ["sudo", "apt-get", "install", "--only-upgrade", "-y",
                          "php-cli", "php-fpm", "libapache2-mod-php", "php-cgi"]]
                        if label == "debian-apt" else [plan])
                failed = False
                for c in cmds:
                    print("\n$ %s" % " ".join(c))
                    if subprocess.run(c).returncode != 0:
                        print(t("upgrade_failed_offer"))
                        failed = True
                        break
                if failed:
                    if _ask(t("ask_fallback_harden"),
                            choices=("y", "n", ""), default="n") != "y":
                        print(t("log_file", log_path))
                        return 1
                    choice = "2"
                else:
                    print(t("upgrade_done_wiz"))
                    print(t("restart_required"))
                    print(t("restart_apache_deb"))
                    print(t("restart_fpm"))
                    print(t("restart_httpd"))
                    input(t("press_enter_verify"))
                    break

            if choice == "2":
                print(t("harden_intro"))
                print("  memory_limit = -1")
                print("  session.upload_progress.enabled = 0")
                print("  fatal_error_backtraces = 0   (PHP 8.5)")
                print(t("harden_ini_note"))
                print(t("harden_ini_note2"))
                if _ask(t("confirm_harden"),
                        choices=("y", "n", ""), default="n") != "y":
                    print(t("harden_cancelled_back"))
                    continue
                for i in vuln:
                    path, _content, _bak = harden(i["path"], apply_write=True)
                    print(t("harden_arrow", i["path"],
                            path or t("harden_no_ini_short")))
                print(t("harden_done"))
                print("  sudo systemctl restart apache2  /  php*-fpm  /  httpd")
                input(t("press_enter_verify"))
                break

        # Step 3 - verify
        _phase_banner(3, t("p3_title"))
        r2 = do_scan()
        print_report(r2)
        vuln2 = _vuln_installs(r2)

        print("\n" + "-" * 68)
        if not vuln2:
            print(t("result_closed"))
            code = 0
        else:
            hardened_ok = all(all(i.get("hardening", {}).values()) for i in vuln2)
            if hardened_ok:
                print(t("result_mitigated"))
                print(t("result_mitigated2"))
            else:
                print(t("result_still", len(vuln2)))
            code = 2

        print(t("log_saved"))
        print("  %s" % log_path)
        print("-" * 68)
        return code
    finally:
        sys.stdout = old_out
        tee.close()


# ---------------------------------------------------------------- self-test

def self_test():
    cases = [
        ((8, 1, 30), "eol-vulnerable"),
        ((7, 4, 33), "eol-vulnerable"),
        ((5, 6, 40), "eol-vulnerable"),
        ((8, 0, 30), "eol-vulnerable"),
        ((8, 2, 34), "vulnerable"),
        ((8, 2, 35), "fixed"),
        ((8, 3, 35), "vulnerable"),
        ((8, 3, 36), "fixed"),
        ((8, 4, 26), "vulnerable"),
        ((8, 4, 27), "fixed"),
        ((8, 5, 11), "vulnerable"),
        ((8, 5, 12), "fixed"),
        ((9, 0, 0), "eol-vulnerable"),
    ]
    ok = True
    for ver, want in cases:
        got = classify(ver)[0]
        mark = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print("  [%s] %d.%d.%d -> %s %s"
              % (mark, ver[0], ver[1], ver[2], got, t("self_expected", want)))
    sample = "PHP 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 (cli)\nCopyright..."
    v = parse_version(sample)
    mark = "PASS" if v == (8, 3, 36) else "FAIL"
    if v != (8, 3, 36):
        ok = False
    print("  [%s] parse_version('8.3.36...') -> %s" % (mark, v))
    print(t("self_result_ok") if ok else t("self_result_fail"))
    return 0 if ok else 1


# ---------------------------------------------------------------- entrypoint

def main():
    global LANG

    # Resolve language before building the parser so --help is localized too.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", choices=("en", "zh"), default=None)
    pre_args, _rest = pre.parse_known_args()
    LANG = pre_args.lang or detect_lang()

    ap = argparse.ArgumentParser(
        description=t("cli_desc", CVE1, CVE2))
    ap.add_argument("--self-test", action="store_true", help=t("help_selftest"))
    ap.add_argument("--version", action="version",
                    version="php2shell-guard " + VERSION)
    ap.add_argument("--lang", choices=("en", "zh"), default=None,
                    help=t("help_lang"))
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("wizard", help=t("help_wizard"))
    p_scan = sub.add_parser("scan", help=t("help_scan"))
    p_scan.add_argument("--json", action="store_true", help=t("help_json"))
    p_ver = sub.add_parser("verify", help=t("help_verify"))
    p_ver.add_argument("--json", action="store_true", help=t("help_json"))
    fx = sub.add_parser("fix", help=t("help_fix"))
    fx.add_argument("--apply", action="store_true", help=t("help_apply"))
    fx.add_argument("--harden-only", action="store_true", help=t("help_harden"))
    fx.add_argument("-y", "--yes", action="store_true", help=t("help_yes"))
    args = ap.parse_args()

    if args.lang:
        LANG = args.lang

    if args.self_test:
        sys.exit(self_test())
    if args.cmd in (None, "wizard"):
        sys.exit(wizard())
    if args.cmd == "scan":
        sys.exit(cmd_scan(args))
    if args.cmd == "verify":
        sys.exit(cmd_verify(args))
    if args.cmd == "fix":
        sys.exit(cmd_fix(args))
    ap.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()

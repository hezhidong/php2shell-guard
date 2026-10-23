#!/usr/bin/env python3
"""
php2shell_guard.py — 跨平台 PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 处置工具

三步闭环:
  1. scan    检测本机所有 PHP 安装并判定是否受漏洞影响 (只读, 不改任何东西)
  2. fix     修复: --apply 走系统包管理器升级; --harden-only 写临时缓解 ini
  3. verify  复检: 重新判定版本 + 校验缓解项是否生效

支持: Windows / Linux / macOS, 仅依赖 Python 3.7+ 标准库。

用法:
  python3 php2shell_guard.py scan                 # 只读检测 (建议先跑)
  python3 php2shell_guard.py verify               # 复检
  python3 php2shell_guard.py fix --harden-only    # 仅写临时缓解配置 (无法立刻升级时)
  python3 php2shell_guard.py fix --apply [-y]     # 调用系统包管理器升级 PHP
  python3 php2shell_guard.py scan --json          # 机器可读输出
  python3 php2shell_guard.py --self-test          # 内置判定逻辑自测

作者: Hermes (小马子) for M — 2026-10
参考:
  https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

CVE1 = "CVE-2026-109618"  # OOM corruption -> RCE
CVE2 = "CVE-2026-109619"  # stale global state -> RCE

# 各分支首个修复版本
FIXED = {
    2: 35,   # 8.2.35
    3: 36,   # 8.3.36
    4: 27,   # 8.4.27
    5: 12,   # 8.5.12
}
SUPPORTED_BRANCHES = (2, 3, 4, 5)

# ---------------------------------------------------------------- 基础工具

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
EXE = "php.exe" if IS_WIN else "php"


def run(cmd, timeout=30):
    """运行命令, 返回 (rc, out, err); 找不到命令时 rc=127。"""
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


# ---------------------------------------------------------------- 版本判定

def parse_version(text):
    m = re.search(r"PHP\s+(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def classify(ver):
    """
    返回 (status, branch, detail)
    status: fixed / vulnerable / eol-vulnerable / unknown-branch
    """
    if not ver:
        return "unknown", None, "无法解析版本号"
    major, minor, patch = ver
    if major != 8:
        # 漏洞代码存在十余年, PHP 5/7 及更早均视为受影响且无补丁
        return "eol-vulnerable", minor, f"PHP {major}.{minor} 已停止支持, 漏洞可追溯至 5.4, 必须升级到受支持分支"
    if minor not in SUPPORTED_BRANCHES:
        return "eol-vulnerable", minor, f"PHP 8.{minor} 已停止支持, 无官方补丁, 必须升级到 8.2.35+/8.3.36+/8.4.27+/8.5.12+"
    fixed_patch = FIXED[minor]
    if patch >= fixed_patch:
        return "fixed", minor, f"8.{minor}.{patch} >= 8.{minor}.{fixed_patch}, 已含补丁"
    return "vulnerable", minor, f"8.{minor}.{patch} < 8.{minor}.{fixed_patch}, 存在 {CVE1}/{CVE2}"


# ---------------------------------------------------------------- 发现 PHP

def _which_all(name):
    """PATH 中所有同名可执行 (which -a 的跨平台实现)。"""
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


def common_dirs():
    dirs = []
    if IS_WIN:
        for base in (r"C:\php", r"C:\PHP", r"C:\tools\php",
                     r"C:\Program Files\PHP", r"C:\Program Files (x86)\PHP",
                     os.path.expanduser(r"~\scoop\apps")):
            dirs.append(base)
    else:
        for base in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin",
                     "/usr/local/php/bin", "/opt/php/bin", "/snap/bin"):
            dirs.append(base)
    return dirs


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
    """返回去重后的 php 可执行路径列表。"""
    cands = []
    cands += _which_all("php")
    if IS_WIN:
        cands += find_php_windows_registry()
        for d in (r"C:\php", r"C:\PHP", r"C:\tools\php",
                  r"C:\Program Files\PHP", r"C:\Program Files (x86)\PHP"):
            c = os.path.join(d, "php.exe")
            if os.path.isfile(c):
                cands.append(c)
        # scoop: ~/scoop/apps/php*/current/php.exe
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
        # homebrew cellar
        for cellar in ("/opt/homebrew/Cellar", "/usr/local/Cellar"):
            if os.path.isdir(cellar):
                for sub in os.listdir(cellar):
                    if sub.lower().startswith("php"):
                        c = os.path.join(cellar, sub, "bin", "php")
                        if os.path.isfile(c):
                            cands.append(c)
    # 去重 (realpath 大小写不敏感)
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
    loaded = None
    scan_dir = None
    m = re.search(r"Loaded Configuration File:\s*(.+)", out)
    if m and "none" not in m.group(1).lower():
        loaded = m.group(1).strip()
    sm = re.search(r"Scan for additional \.ini files in:\s*(.+)", out)
    if sm and "none" not in sm.group(1).lower():
        d = sm.group(1).strip()
        if os.path.isdir(d):
            scan_dir = d
    return loaded, scan_dir


def ini_value(php_exe, key):
    rc, out, _ = run([php_exe, "-n", "-r",
                      f"echo ini_get('{key}');"], timeout=15)
    return out.strip() if rc == 0 else None


def sapi_info(php_exe):
    rc, out, _ = run([php_exe, "-r",
                      "echo PHP_SAPI;"], timeout=15)
    return out.strip() if rc == 0 else "?"


# ---------------------------------------------------------------- 运行痕迹

def find_running_php():
    """查找运行中的 php 进程, 返回命令行列表 (尽力而为)。"""
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
    hits = []
    for line in out.splitlines():
        if "php" in line.lower():
            hits.append(line.strip())
    return hits


# ---------------------------------------------------------------- 缓解配置

BEGIN_MARK = "; >>> php2shell_guard mitigations >>>"
END_MARK = "; <<< php2shell_guard mitigations <<<"


def _mitigation_block():
    lines = [BEGIN_MARK,
             "; temporary mitigations for %s / %s — %s"
             % (CVE1, CVE2, datetime.now(timezone.utc).isoformat()),
             "; REDUCES exposure but DOES NOT replace patching.",
             "memory_limit = -1",
             "session.upload_progress.enabled = 0",
             "fatal_error_backtraces = 0",
             END_MARK]
    return "\n".join(lines) + "\n"


def harden(php_exe, apply_write=True):
    loaded, scan_dir = php_ini_paths(php_exe)
    content = _mitigation_block()
    if not apply_write:
        where = scan_dir or loaded
        return None, content, where
    if scan_dir:
        path = os.path.join(scan_dir, "99-php2shell-mitigations.ini")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        return path, content, path
    if loaded and os.path.isfile(loaded):
        # 无 scan 目录: 备份后向现有 php.ini 幂等追加
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
        return loaded, content, loaded + "  (备份: %s)" % bak
    return None, content, None


def check_hardening(php_exe):
    """用默认 ini (不带 -n) 检查缓解项实际生效值。"""
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


# ---------------------------------------------------------------- 升级

def upgrade_plan():
    """返回 (平台标签, [命令], 是否可自动)。"""
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


# ---------------------------------------------------------------- 扫描核心

def inspect(php_exe):
    rc, out, _ = run([php_exe, "-v"], timeout=20)
    ver = parse_version(out)
    status, branch, detail = classify(ver)
    loaded, scan_dir = php_ini_paths(php_exe)
    return {
        "path": php_exe,
        "version": "%d.%d.%d" % ver if ver else None,
        "sapi": sapi_info(php_exe),
        "status": status,
        "detail": detail,
        "ini_loaded": loaded,
        "ini_scan_dir": scan_dir,
        "hardening": check_hardening(php_exe)
        if status in ("vulnerable", "eol-vulnerable") else {},
    }


def do_scan():
    phps = discover_php()
    installs = [inspect(p) for p in phps]
    running = find_running_php()
    docker = find_docker_php()
    n_vuln = sum(1 for i in installs if i["status"] in ("vulnerable", "eol-vulnerable"))
    n_fixed = sum(1 for i in installs if i["status"] == "fixed")
    return {
        "tool": "php2shell_guard",
        "time": datetime.now(timezone.utc).isoformat(),
        "host": sys.platform,
        "cves": [CVE1, CVE2],
        "fixed_versions": {"8.2": "8.2.35", "8.3": "8.3.36",
                           "8.4": "8.4.27", "8.5": "8.5.12"},
        "installs_found": len(installs),
        "vulnerable": n_vuln,
        "fixed": n_fixed,
        "installs": installs,
        "running_php_processes": running,
        "docker_php_containers": docker,
    }


# ---------------------------------------------------------------- 展示

ICON = {"vulnerable": "[!]", "eol-vulnerable": "[!!]",
        "fixed": "[OK]", "unknown": "[?]"}


def print_report(r):
    print("=" * 68)
    print(" PHP2Shell guard  —  %s / %s" % (CVE1, CVE2))
    print(" scan time: %s   host: %s" % (r["time"][:19], r["host"]))
    print("=" * 68)
    if not r["installs"]:
        print(" 未发现本机安装 PHP (PATH / 注册表 / 常见目录均无)。")
    for i in r["installs"]:
        print(" %s %s  PHP %s  (sapi: %s)" % (ICON.get(i["status"], " ? "),
              i["path"], i["version"] or "?", i["sapi"]))
        print("      -> %s: %s" % (i["status"].upper(), i["detail"]))
        if i["ini_loaded"]:
            print("      ini: %s" % i["ini_loaded"])
        if i["hardening"]:
            for k, v in i["hardening"].items():
                print("      mitigation %-40s %s" % (k, "生效" if v else "未生效"))
    if r["running_php_processes"]:
        print("-" * 68)
        print(" 运行中的 PHP 进程 (升级后必须全部重启):")
        for p in r["running_php_processes"][:10]:
            print("   • %s" % p)
    if r["docker_php_containers"]:
        print("-" * 68)
        print(" Docker 中的 PHP 容器 (需在镜像层面升级并重建, 本机升级无效):")
        for d in r["docker_php_containers"]:
            print("   • %s" % d)
    print("-" * 68)
    print(" 汇总: %d 个安装, %d 个受影响, %d 个已修复"
          % (r["installs_found"], r["vulnerable"], r["fixed"]))
    if r["vulnerable"]:
        print(" 下一步: python3 php2shell_guard.py fix --apply   (升级)")
        print("         python3 php2shell_guard.py fix --harden-only (临时缓解)")
        print("         升级后: python3 php2shell_guard.py verify")
    elif r["installs_found"]:
        print(" 本机 PHP 均已含补丁。")
    print("=" * 68)


# ---------------------------------------------------------------- 命令

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
            print("\n复检结论: 仍有受影响安装, 修复未完成。")
        elif r["installs_found"]:
            print("\n复检结论: 通过。建议确认所有 php-fpm/Apache worker 已重启。")
        else:
            print("\n复检结论: 本机无 PHP。若使用 Docker 请检查容器。")
    return 2 if r["vulnerable"] else 0


def cmd_fix(args):
    r = do_scan()
    vuln = [i for i in r["installs"] if i["status"] in ("vulnerable", "eol-vulnerable")]
    if not args.apply and not args.harden_only:
        print("请指定修复方式:")
        print("  --apply         调用系统包管理器升级 (Windows 用 winget, macOS 用 brew,")
        print("                  Debian/Ubuntu 用 apt, RHEL 用 dnf/yum, Alpine 用 apk)")
        print("  --harden-only   不升级, 仅写临时缓解 ini (memory_limit=-1 等)")
        label, plan, auto = upgrade_plan()
        print("\n本机平台方案: %s" % label)
        if plan:
            print("将执行: %s" % " ".join(plan))
        print("\n注意: Docker 容器需换基础镜像标签 (8.2.35/8.3.36/8.4.27/8.5.12) 后重建。")
        return 1

    if args.harden_only:
        targets = vuln or r["installs"]
        if not targets:
            print("没有可处理的 PHP 安装。")
            return 0
        for i in targets:
            path, content, where = harden(i["path"], apply_write=args.yes)
            if not args.yes:
                print("[dry-run] 将写入 %s:\n%s" % (where or "(未定位到 ini 目录)", content))
            elif path:
                print("已写入缓解配置: %s" % path)
            else:
                print("无法定位 %s 的 ini 目录, 请手动创建 php.ini 加入:\n%s"
                      % (i["path"], content))
        if args.yes:
            print("\n请重启 Web 服务器/php-fpm 后运行 verify。")
        return 0

    if args.apply:
        label, plan, auto = upgrade_plan()
        if not auto:
            print("本机无法自动升级 (%s)。请手动安装:" % label)
            print("  https://windows.php.net/download/  (选择含修复版本的 8.2.35+/8.3.36+ 等)")
            print("升级后重新运行 scan / verify。")
            return 1
        if not args.yes:
            print("将执行: %s" % " ".join(plan))
            ans = input("确认? 输入 y 继续: ").strip().lower()
            if ans != "y":
                print("已取消。")
                return 1
        if label == "debian-apt":
            cmds = [["sudo", "apt-get", "update"],
                    ["sudo", "apt-get", "install", "--only-upgrade", "-y",
                     "php-cli", "php-fpm", "libapache2-mod-php", "php-cgi"]]
        else:
            cmds = [plan]
        for c in cmds:
            print("$ %s" % " ".join(c))
            p = subprocess.run(c)
            if p.returncode != 0:
                print("命令失败 (rc=%s), 请检查包管理器输出。" % p.returncode)
                return p.returncode
        print("\nPHP 包已升级。请重启服务:")
        print("  Apache (Debian): sudo systemctl restart apache2")
        print("  nginx+php-fpm:   sudo systemctl restart php*-fpm")
        print("  httpd (RHEL):    sudo systemctl restart httpd php-fpm")
        print("然后运行: python3 php2shell_guard.py verify")
        return 0
    return 0


# ---------------------------------------------------------------- 自测

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
        print("  [%s] %d.%d.%d -> %s (期望 %s)"
              % (mark, ver[0], ver[1], ver[2], got, want))
    # 版本字符串解析
    sample = "PHP 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 (cli)\nCopyright..."
    v = parse_version(sample)
    mark = "PASS" if v == (8, 3, 36) else "FAIL"
    if v != (8, 3, 36):
        ok = False
    print("  [%s] parse_version('%s...') -> %s" % (mark, "8.3.36", v))
    print("\n自测结果: %s" % ("全部通过" if ok else "存在失败"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="PHP2Shell (CVE-2026-109618/109619) 检测-修复-复检工具")
    ap.add_argument("--self-test", action="store_true", help="运行内置判定自测")
    sub = ap.add_subparsers(dest="cmd")
    p_scan = sub.add_parser("scan", help="只读检测")
    p_scan.add_argument("--json", action="store_true", help="输出 JSON")
    p_ver = sub.add_parser("verify", help="修复后复检")
    p_ver.add_argument("--json", action="store_true", help="输出 JSON")
    fx = sub.add_parser("fix", help="修复 (需 --apply 或 --harden-only)")
    fx.add_argument("--apply", action="store_true", help="用系统包管理器升级 PHP")
    fx.add_argument("--harden-only", action="store_true", help="只写临时缓解 ini")
    fx.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
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

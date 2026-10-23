# php2shell-guard

**语言: [English](README.md) · [简体中文](README.zh-CN.md)**

跨平台单文件工具，用于处置 PHP2Shell 两个严重 RCE 漏洞：

- **CVE-2026-109618** — 内存分配失败后的清理逻辑 RCE（mod_php 已证实，无需认证，应用层之下）
- **CVE-2026-109619** — worker 复用过期全局状态 RCE（session.upload_progress 默认开启即中招）

CVSS v4.0 均为 **9.2**。受影响：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 之前所有版本；8.1 及更早（含 5.x/7.x）无补丁，必须升级分支。

## 特点

- **零依赖**：仅需 Python 3.7+ 标准库，Windows / Linux / macOS 通用，一个文件拷走即用
- **默认只读**：`scan` 不改动系统任何内容
- **闭环**：检测 → 修复（升级或临时缓解）→ 复检
- 多来源发现 PHP：PATH 全量扫描、Windows 注册表卸载项、常见安装目录、Homebrew Cellar、scoop
- 额外发现：运行中的 php 进程（升级后需重启）、Docker 里的 php 容器
- `--json` 输出便于 CI / 批量巡检；退出码 0=无受影响，2=发现受影响版本

## 用法

### 交互式三步向导（推荐，无需记参数）

直接运行，按提示操作即可：

```bash
python3 php2shell_guard.py
```

1. **检查**——扫描本机所有 PHP 安装，显示哪些存在漏洞；
2. **修复**——由你选择：用系统包管理器升级（推荐），或暂时写入临时缓解配置；未经你确认不会改动系统；
3. **复检**——再次扫描，明确告知漏洞已彻底修复，还是仅做了临时缓解。

整个过程会在当前目录生成带时间戳的日志
（`php2shell-guard-YYYYmmdd-HHMMSS.log`），结束时显示完整路径，可事后查看全过程。
非交互式环境（管道/CI）运行向导会直接给出提示并退出，自动化请使用下面的子命令。

### 输出语言（中文 / English）

面向用户的输出内置中英双语，按以下优先级自动选择：

1. 任意命令加 `--lang en` 或 `--lang zh`（最高优先级），或环境变量
   `PHP2SHELL_LANG=en|zh`；
2. 否则看 POSIX 区域变量 `LC_ALL` / `LC_MESSAGES` / `LANG`；
3. Windows 上没有上述变量时，跟随系统区域设置（`GetUserDefaultLocaleName`）；
4. 都无法判断时回退英文。

报告中的状态词保持英文稳定不变（`VULNERABLE`、`EOL-VULNERABLE`、`FIXED`、`ACTIVE`），
方便检索；JSON 顶层增加 `language` 字段、每个安装项增加语言无关的 `detail_key`。示例：

```bash
python3 php2shell_guard.py --lang en scan   # 强制英文
PHP2SHELL_LANG=zh python3 php2shell_guard.py # 为本终端强制中文
```

### 子命令（脚本 / 自动化）

```bash
# 第 1 步：检测（只读，强烈建议先跑）
python3 php2shell_guard.py scan
python3 php2shell_guard.py scan --json        # 机器可读

# 第 2 步：修复，二选一
python3 php2shell_guard.py fix --apply        # 走系统包管理器升级
#   Windows: winget upgrade --id PHP.PHP -e
#   macOS:   brew upgrade php
#   Debian/Ubuntu: apt-get update && apt-get install --only-upgrade php-cli php-fpm ...
#   RHEL:    dnf/yum upgrade 'php*'     Alpine: apk upgrade php8
python3 php2shell_guard.py fix --harden-only  # 无法立刻升级时：写临时缓解 ini
#   内容: memory_limit=-1 / session.upload_progress.enabled=0 / fatal_error_backtraces=0
#   优先写入 scan-dir 的 99-php2shell-mitigations.ini；
#   无 scan-dir 时备份 php.ini 为 *.php2shell_bak 后幂等追加（带标记块，重复执行不叠加）

# 第 3 步：复检（重启 php-fpm/Apache worker 之后）
python3 php2shell_guard.py verify

# 内置判定逻辑自测（14 个版本用例）
python3 php2shell_guard.py --self-test
```

所有写操作都支持先不带 `-y` 做 dry-run 预览。

## 重要限制（请读）

1. **临时缓解 ≠ 修复**。`--harden-only` 只降低暴露面，官方明确唯一彻底修复是升级；缓解生效后 `verify` 仍会把版本判为受影响（这是正确行为）。
2. **Apache mod_php 风险最高**，攻击在任何应用代码之前完成，应用鉴权/WAF 拦不住。php-fpm 较难利用但不免疫。
3. **Docker 容器**：主机升级无效，必须把基础镜像换成 `php:8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+` 标签后重建。工具会列出运行中的 php 容器提醒你。
4. Windows 无 winget、或 PHP 为手工 zip 解压安装时，`--apply` 无法自动升级，会给出 https://windows.php.net/download/ 手动指引。
5. EOL 分支（PHP 5/7/8.0/8.1）没有安全包，只能升级到受支持分支。

## 参考

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/

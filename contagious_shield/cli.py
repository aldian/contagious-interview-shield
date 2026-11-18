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

"""Command-line interface for Contagious Interview Shield."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .scanner import (
    scan_eml_bytes,
    scan_remote_target,
    scan_text_or_code,
    scan_zip_bytes,
)


def _format_human_report(result: Dict[str, Any]) -> str:
    """Format a structured scan result into a concise terminal report."""
    lines = [
        f"Contagious Interview Shield v{__version__}",
        f"Target:     {result['target']} ({result['target_type']})",
        f"Verdict:    {result['verdict']} (Risk Score: {result['risk_score']}/100)",
        f"Summary:    {result['summary']}",
    ]
    if result["iocs_matched"]:
        lines.append(f"\nMatched Threat Intel IOCs ({result['iocs_count']}):")
        for ioc in result["iocs_matched"]:
            lines.append(f"  - [{ioc['type'].upper()}] {ioc['value']}: {ioc['attribution']}")
    if result["findings"]:
        lines.append(f"\nSecurity Findings ({result['findings_count']}):")
        for finding in result["findings"]:
            lines.append(
                f"  - [{finding['severity']}] {finding['title']} @ {finding['location']} "
                f"({finding['rule_id']})"
            )
            lines.append(f"    {finding['detail']}")
            if finding.get("evidence"):
                lines.append(f"    Evidence: {finding['evidence']}")
    lines.append("\nRecommended Actions:")
    for step in result["remediation"]:
        lines.append(f"  * {step}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="contagious-shield",
        description="Zero-execution static scanner for Git hooks, VS Code auto-tasks, recruiter emails, and Contagious Interview malware.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="",
        help="Path to a .zip/.eml/code file, or a URL, domain, email, wallet, or SHA-256 hash.",
    )
    parser.add_argument("--json", action="store_true", help="Emit raw JSON report.")
    parser.add_argument(
        "--no-remote",
        action="store_true",
        help="Disable outbound network queries for Notion, GitHub, RDAP, and Firebase metadata.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint returning exit code 0 (SAFE), 1 (SUSPICIOUS+), or 2 (error)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.target and sys.stdin.isatty():
        parser.print_help()
        return 2

    if args.target and os.path.isfile(args.target):
        path = args.target
        with open(path, "rb") as fh:
            raw = fh.read()
        lower = path.lower()
        if lower.endswith(".zip"):
            result = scan_zip_bytes(raw, filename=os.path.basename(path))
        elif lower.endswith(".eml"):
            result = scan_eml_bytes(raw, filename=os.path.basename(path), fetch_remote=not args.no_remote)
        else:
            result = scan_text_or_code(raw.decode("utf-8", errors="replace"), source_name=path)
    elif args.target:
        result = scan_remote_target(args.target, fetch_remote=not args.no_remote)
    else:
        stdin_text = sys.stdin.read()
        result = scan_text_or_code(stdin_text, source_name="stdin")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_format_human_report(result))

    return 1 if result["risk_score"] >= 20 else 0


if __name__ == "__main__":
    raise SystemExit(main())

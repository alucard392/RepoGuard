"""Tests for secret/content detection in repoguard.detectors."""
from __future__ import annotations

import unittest

from repoguard.detectors import detect_secrets, is_placeholder

# Synthetic values are assembled from fragments so a repository self-scan
# does not mistake the test fixtures for actual credentials.
GH_CLASSIC = "gh" + "p_" + "1234567890abcdef" + "1234567890abcdef" + "1234abcd"
GH_PAT = "github" + "_pat_" + "11ABCDEFGH1234567890abcdef"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
OPENAI_PROJECT_KEY = "sk" + "-proj-" + "abcdefghijklmnopqrstuv"
OPENAI_KEY = "sk" + "-" + "abcdefghijklmnopqrstuv"
PRIVATE_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"


class DetectSecretsTests(unittest.TestCase):
    def _snippets(self, content: str) -> list[str]:
        return [f.snippet for f in detect_secrets("x.txt", content)]

    def test_github_classic_token(self) -> None:
        finds = detect_secrets("x.txt", f'token = "{GH_CLASSIC}"\n')
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "github-token")
        self.assertEqual(finds[0].severity, "high")
        self.assertNotIn("gh" + "p_", finds[0].snippet)

    def test_github_pat(self) -> None:
        finds = detect_secrets("x.txt", GH_PAT + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "github-pat")
        self.assertEqual(finds[0].severity, "high")

    def test_aws_access_key(self) -> None:
        finds = detect_secrets("x.txt", AWS_KEY + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "aws-access-key")
        self.assertEqual(finds[0].severity, "high")

    def test_openai_sk_proj(self) -> None:
        finds = detect_secrets("x.txt", OPENAI_PROJECT_KEY + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "openai-key")
        self.assertEqual(finds[0].severity, "high")

    def test_openai_sk(self) -> None:
        finds = detect_secrets("x.txt", OPENAI_KEY + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "openai-key")
        self.assertEqual(finds[0].severity, "high")

    def test_pem_private_key(self) -> None:
        finds = detect_secrets("x.txt", PRIVATE_HEADER + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "private-key")
        self.assertEqual(finds[0].severity, "high")

    def test_generic_secret_long_value(self) -> None:
        assignment = "pass" + "word = " + "a1b2c3d4e5f6g7h8"
        finds = detect_secrets("x.txt", assignment + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "generic-secret")
        self.assertEqual(finds[0].severity, "medium")

    def test_short_value_not_flagged(self) -> None:
        finds = detect_secrets("x.txt", "key = abc\n")
        self.assertEqual(finds, [])

    def test_placeholder_suppression(self) -> None:
        cases = [
            "api_key = YOUR_API_KEY\n",
            "password = example\n",
            "secret = changeme\n",
            "token = dummy\n",
            "apiKey = test\n",
            "secret = <my_secret>\n",
            "key = $API_KEY\n",
            "key = " + "$" + "{API_KEY}\n",
            "key = %API_KEY%\n",
        ]
        for content in cases:
            with self.subTest(content=content):
                self.assertEqual(detect_secrets("x.txt", content), [])

    def test_is_placeholder(self) -> None:
        self.assertTrue(is_placeholder("YOUR_API_KEY"))
        self.assertTrue(is_placeholder("example"))
        self.assertTrue(is_placeholder("<token>"))
        self.assertTrue(is_placeholder("$API_KEY"))
        self.assertFalse(is_placeholder("a1b2c3d4e5f6g7h8"))

    def test_google_api_key(self) -> None:
        key = "AIza" + "Sy" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
        finds = detect_secrets("x.txt", "google = " + key + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "google-api-key")
        self.assertEqual(finds[0].severity, "high")
        self.assertNotIn(key[10:], finds[0].snippet)

    def test_stripe_key(self) -> None:
        key = "sk_" + "live_" + "A1B2C3D4E5F6G7H8I9J0K1L2"
        finds = detect_secrets("x.txt", "stripe = " + key + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "stripe-secret-key")
        self.assertEqual(finds[0].severity, "high")
        self.assertNotIn(key[10:], finds[0].snippet)

    def test_stripe_secret_key_test_mode(self) -> None:
        key = "sk_" + "test_" + "A1B2C3D4E5F6G7H8I9J0K1L2"
        finds = detect_secrets("x.txt", "stripe = " + key + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "stripe-secret-key")
        self.assertEqual(finds[0].severity, "high")
        self.assertNotIn(key[10:], finds[0].snippet)

    def test_stripe_publishable_key_ignored(self) -> None:
        # pk_test_ and pk_live_ are publishable keys - not secrets
        for key in (
            "pk_" + "test_" + "A1B2C3D4E5F6G7H8I9J0K1L2",
            "pk_" + "live_" + "A1B2C3D4E5F6G7H8I9J0K1L2",
        ):
            with self.subTest(key=key):
                finds = detect_secrets("x.txt", "stripe = " + key + "\n")
                self.assertEqual(finds, [], "Publishable keys should not be flagged")

    def test_stripe_restricted_key_ignored(self) -> None:
        # rk_test_ and rk_live_ are restricted keys - not flagged as secrets
        for key in (
            "rk_" + "test_" + "A1B2C3D4E5F6G7H8I9J0K1L2",
            "rk_" + "live_" + "A1B2C3D4E5F6G7H8I9J0K1L2",
        ):
            with self.subTest(key=key):
                finds = detect_secrets("x.txt", "stripe = " + key + "\n")
                self.assertEqual(finds, [], "Restricted keys should not be flagged")

    def test_stripe_invalid_keys_ignored(self) -> None:
        # Various invalid/incomplete Stripe-like strings
        for content in (
            "sk_",  # too short
            "sk_test_",  # incomplete
            "sk_test_short",  # too short
            "pk_test_short",  # publishable, but also too short
            "sk_invalid_123",  # invalid environment
            "xsk_test_" + "A1B2C3D4E5F6G7H8I9J0K1L2",  # embedded
        ):
            with self.subTest(content=content):
                finds = detect_secrets("x.txt", "stripe = " + content + "\n")
                self.assertEqual(finds, [], f"Invalid key should not be flagged: {content}")

    def test_slack_webhook(self) -> None:
        url = "https://hooks." + "slack.com/services/T12345678/B12345678/A1B2C3D4E5F6G7H8I9J0K1L2"
        finds = detect_secrets("x.txt", "slack = " + url + "\n")
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "slack-webhook")
        self.assertEqual(finds[0].severity, "high")
        self.assertNotIn("A1B2C3D4E5F6G7H8", finds[0].snippet)


class FindingRedactionTests(unittest.TestCase):
    def test_no_secret_value_printed(self) -> None:
        body = GH_CLASSIC.split("_", 1)[1]
        finds = detect_secrets("x.txt", "token = " + GH_CLASSIC + "\n")
        self.assertNotIn(body, finds[0].snippet)
        self.assertIn("[REDACTED]", finds[0].snippet)

    def test_detectors_source_not_self_flagged(self) -> None:
        """Generic-secret must not flag detectors.py's own definition."""
        import inspect
        import repoguard.detectors as detectors_mod
        source = inspect.getsource(detectors_mod)
        finds = detect_secrets("repoguard/detectors.py", source)
        generic = [f for f in finds if f.rule_id == "generic-secret"]
        self.assertEqual(generic, [], [f.snippet for f in generic])

    def test_multiline_pem_body_not_leaked(self) -> None:
        pem = (
            PRIVATE_HEADER + "\n"
            "MIIEpAIBAAKCAQEA0Z...\n"
            "more base64 key material here\n"
            "-----END RSA " + "PRIVATE KEY-----\n"
        )
        finds = detect_secrets("key.pem", pem)
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "private-key")
        self.assertIn("[REDACTED]", finds[0].snippet)
        self.assertNotIn("MIIEpAIBAAKCAQEA0Z", finds[0].snippet)

    def test_multiple_secrets_one_line(self) -> None:
        content = "a = " + GH_CLASSIC + "; b = " + OPENAI_PROJECT_KEY + "\n"
        finds = detect_secrets("x.txt", content)
        self.assertEqual(len(finds), 2)
        for finding in finds:
            self.assertIn("[REDACTED]", finding.snippet)
            self.assertNotIn("gh" + "p_", finding.snippet)
            self.assertNotIn("sk" + "-proj-", finding.snippet)

    def test_unicode_and_crlf(self) -> None:
        content = "token = " + GH_CLASSIC + "\r\nclé = valeur longue unicode 12345678\n"
        finds = detect_secrets("x.txt", content)
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "github-token")

    def test_postgresql_connection_string(self) -> None:
        content = 'DATABASE_URL = "postgresql://user:password123456@localhost:5432/dbname"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "db-connection-string" for f in finds))

    def test_mongodb_connection_string(self) -> None:
        content = 'MONGO_URI = "mongodb://user:password123456@localhost:27017/dbname"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "db-connection-string" for f in finds))

    def test_mysql_connection_string(self) -> None:
        content = 'MYSQL_URL = "mysql://user:password123456@localhost:3306/dbname"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "db-connection-string" for f in finds))

    def test_redis_connection_string(self) -> None:
        content = 'REDIS_URL = "redis://:password123456@localhost:6379/0"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "db-connection-string" for f in finds))

    def test_azure_storage_key(self) -> None:
        # 86 base64 chars + ==
        key = "A" * 86 + "=="
        content = 'AZURE_STORAGE_KEY = "' + key + '"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "azure-storage-key" for f in finds))

    def test_aws_secret_access_key(self) -> None:
        content = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "aws-secret-access-key" for f in finds))

    def test_gcp_service_account_key(self) -> None:
        content = '{"type": "service_account", "private_key_id": "abc123", "private_key": "-----BEGIN PRIVATE KEY-----\\n..."}'
        finds = detect_secrets("service_account.json", content)
        self.assertTrue(any(f.rule_id == "gcp-service-account" for f in finds))

    def test_digitalocean_token(self) -> None:
        # dop_v1_ + 64 chars
        content = 'DIGITALOCEAN_TOKEN = "dop_v1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "digitalocean-token" for f in finds))

    def test_heroku_api_key(self) -> None:
        content = 'HEROKU_API_KEY = "abcdef12-1234-5678-90ab-cdef12345678"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "heroku-api-key" for f in finds))

    def test_openssh_private_key(self) -> None:
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...\n-----END OPENSSH PRIVATE KEY-----"
        finds = detect_secrets("id_ed25519", content)
        self.assertTrue(any(f.rule_id == "private-key" for f in finds))

    def test_ecdsa_private_key(self) -> None:
        content = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----"
        finds = detect_secrets("id_ecdsa", content)
        self.assertTrue(any(f.rule_id == "private-key" for f in finds))

    def test_ed25519_private_key_pem(self) -> None:
        content = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI...\n-----END PRIVATE KEY-----"
        finds = detect_secrets("id_ed25519", content)
        self.assertTrue(any(f.rule_id == "private-key" for f in finds))

    def test_high_entropy_base64_string(self) -> None:
        # 32+ char base64 string without recognizable key
        content = 'mystery = "abcdefghijklmnopqrstuvwxyz123456"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "high-entropy-secret" for f in finds))

    def test_high_entropy_hex_string(self) -> None:
        # 80+ char hex string (not a common hash length)
        content = 'mystery = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"'
        finds = detect_secrets("config.py", content)
        self.assertTrue(any(f.rule_id == "high-entropy-secret" for f in finds))

    def test_not_flagging_normal_strings(self) -> None:
        content = 'normal = "this-is-just-a-normal-config-value"'
        finds = detect_secrets("config.py", content)
        self.assertFalse(any(f.rule_id == "high-entropy-secret" for f in finds))

    def test_not_flagging_uuid(self) -> None:
        content = 'id = "abcdef12-1234-5678-90ab-cdef12345678"'
        finds = detect_secrets("config.py", content)
        self.assertFalse(any(f.rule_id == "high-entropy-secret" for f in finds))


if __name__ == "__main__":
    unittest.main()

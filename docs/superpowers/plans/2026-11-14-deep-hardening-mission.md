# RepoGuard Deep Hardening Mission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deep harden RepoGuard's security scanner, improve architecture, enhance CLI/GUI, add comprehensive tests, verify packaging, and prepare for release readiness.

**Architecture:** Incremental improvements across all modules while maintaining backward compatibility. All changes follow TDD - write failing tests first, then implement minimal fixes. Tests run after each task group.

**Tech Stack:** Python 3.10+, standard library only, Tkinter for GUI, setuptools for packaging.

**Spec:** This plan implements the requirements from the autonomous engineering mission for RepoGuard deep hardening.

## Global Constraints

- **Offline-first:** No network dependencies, no telemetry, no cloud APIs.
- **Standard library only:** No third-party runtime dependencies.
- **Python 3.10+** compatibility required.
- **Redaction mandatory:** No secret values in any output (CLI, GUI, logs, JSON).
- **TDD mandatory:** Every change starts with a failing test.
- **Preserve existing functionality:** 65 tests must continue passing.
- **Type hints where meaningful:** Add to public interfaces.
- **Documentation sync:** Update README, AUDIT.md, FIXES.md, ARCHITECTURE.md as changes are made.

## Review Focus

1. **Database connection strings in config files** — Generic-secret regex may miss common formats like `postgresql://user:pass@host/db` or `mongodb://...`. Add targeted patterns.
2. **SSH private keys beyond PEM** — Current detector only catches `-----BEGIN *PRIVATE KEY-----`. OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`) is caught but test shows it works. Verify Ed25519, ECDSA, etc.
3. **High-entropy strings without key context** — Generic secret requires a recognizable key name. Consider entropy-based fallback for obvious secrets.
4. **Windows symlink handling** — `followlinks=False` in os.walk, but is_symlink checks may behave differently on Windows. Verify.
5. **Large file memory pressure** — READ_LIMIT_BYTES = 10 MiB prevents loading huge files, but verify multiple large files don't cause memory accumulation.

---

### Task 1: Expand Secret Detection - Database Connection Strings

**Files:**
- Modify: `repoguard/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Consumes: `detect_secrets(path: str, content: str) -> list[Finding]`
- Produces: Additional high-severity findings for DB connection strings

- [ ] **Step 1: Write failing tests for database connection strings**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_detectors.py::DetectSecretsTests::test_postgresql_connection_string -v`
Expected: FAIL (rule_id "db-connection-string" not found)

- [ ] **Step 3: Add database connection string patterns to detectors.py**

Add regex patterns for common database connection string formats (postgresql, mysql, mongodb, redis, mssql, oracle). Add to `_TOKEN_SPECS` with rule_id "db-connection-string", severity "high", and appropriate fix message.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_detectors.py::DetectSecretsTests::test_postgresql_connection_string -v`
Expected: PASS

- [ ] **Step 5: Run full detector test suite**

Run: `python -m pytest tests/test_detectors.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/detectors.py tests/test_detectors.py
git commit -m "feat(detectors): add database connection string detection"
```

---

### Task 2: Expand Secret Detection - Cloud Provider Keys

**Files:**
- Modify: `repoguard/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Consumes: `detect_secrets(path: str, content: str) -> list[Finding]`
- Produces: Additional high-severity findings for cloud provider keys

- [ ] **Step 1: Write failing tests for cloud provider keys**

```python
def test_azure_storage_key(self) -> None:
    content = 'AZURE_STORAGE_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF=="'
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
    content = 'DIGITALOCEAN_TOKEN = "dop_v1_abcdefghijklmnopqrstuvwxyz1234567890"'
    finds = detect_secrets("config.py", content)
    self.assertTrue(any(f.rule_id == "digitalocean-token" for f in finds))

def test_heroku_api_key(self) -> None:
    content = 'HEROKU_API_KEY = "abcdefgh-1234-5678-90ab-cdef12345678"'
    finds = detect_secrets("config.py", content)
    self.assertTrue(any(f.rule_id == "heroku-api-key" for f in finds))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_detectors.py -k "azure_storage_key or aws_secret or gcp_service or digitalocean or heroku" -v`
Expected: FAIL

- [ ] **Step 3: Add cloud provider key patterns to detectors.py**

Add regex patterns for:
- Azure Storage Account keys (base64, 88 chars ending with ==)
- AWS Secret Access Keys (40 chars, base64-like)
- GCP Service Account JSON (detect by structure)
- DigitalOcean Personal Access Tokens (dop_v1_ prefix)
- Heroku API Keys (UUID format)

Add to `_TOKEN_SPECS` with appropriate rule_ids, severity "high", and fix messages.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_detectors.py -k "azure_storage_key or aws_secret or gcp_service or digitalocean or heroku" -v`
Expected: PASS

- [ ] **Step 5: Run full detector test suite**

Run: `python -m pytest tests/test_detectors.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/detectors.py tests/test_detectors.py
git commit -m "feat(detectors): add cloud provider key detection"
```

---

### Task 3: Expand Secret Detection - SSH and Additional Private Key Formats

**Files:**
- Modify: `repoguard/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Consumes: `detect_secrets(path: str, content: str) -> list[Finding]`
- Produces: High-severity findings for SSH private keys

- [ ] **Step 1: Write failing tests for SSH key formats**

```python
def test_openssh_private_key(self) -> None:
    content = "-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAA..."
    finds = detect_secrets("id_ed25519", content)
    self.assertTrue(any(f.rule_id == "ssh-private-key" for f in finds))

def test_ecdsa_private_key(self) -> None:
    content = "-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEEI..."
    finds = detect_secrets("id_ecdsa", content)
    self.assertTrue(any(f.rule_id == "ssh-private-key" for f in finds))

def test_ed25519_private_key_pem(self) -> None:
    content = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEI..."
    finds = detect_secrets("id_ed25519", content)
    self.assertTrue(any(f.rule_id == "ssh-private-key" for f in finds))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_detectors.py -k "openssh or ecdsa or ed25519" -v`
Expected: FAIL

- [ ] **Step 3: Add SSH private key patterns to detectors.py**

Extend the existing `PEM_PRIVATE_KEY` pattern or add new patterns to catch:
- OpenSSH format: `-----BEGIN OPENSSH PRIVATE KEY-----`
- EC private key: `-----BEGIN EC PRIVATE KEY-----`
- Generic PRIVATE KEY (already partially covered but verify Ed25519)

Add to `_TOKEN_SPECS` with rule_id "ssh-private-key", severity "high".

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_detectors.py -k "openssh or ecdsa or ed25519" -v`
Expected: PASS

- [ ] **Step 5: Run full detector test suite**

Run: `python -m pytest tests/test_detectors.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/detectors.py tests/test_detectors.py
git commit -m "feat(detectors): add SSH private key format detection"
```

---

### Task 4: Add Generic High-Entropy Fallback Detection

**Files:**
- Modify: `repoguard/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Consumes: `detect_secrets(path: str, content: str) -> list[Finding]`
- Produces: Medium-severity findings for high-entropy strings without known keys

- [ ] **Step 1: Write failing tests for high-entropy detection**

```python
def test_high_entropy_base64_string(self) -> None:
    # 32+ char base64 string without recognizable key
    content = 'mystery = "abcdefghijklmnopqrstuvwxyz123456"'
    finds = detect_secrets("config.py", content)
    self.assertTrue(any(f.rule_id == "high-entropy-secret" for f in finds))

def test_high_entropy_hex_string(self) -> None:
    # 64+ char hex string
    content = 'mystery = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"'
    finds = detect_secrets("config.py", content)
    self.assertTrue(any(f.rule_id == "high-entropy-secret" for f in finds))

def test_not_flagging_normal_strings(self) -> None:
    content = 'normal = "this-is-just-a-normal-config-value"'
    finds = detect_secrets("config.py", content)
    self.assertFalse(any(f.rule_id == "high-entropy-secret" for f in finds))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_detectors.py -k "high_entropy" -v`
Expected: FAIL

- [ ] **Step 3: Implement entropy-based detection in detectors.py**

Add a function `calculate_shannon_entropy(s: str) -> float` and a pattern that flags strings with:
- Length >= 32 characters
- Shannon entropy > 4.0 (indicating high randomness)
- Not matching known patterns (to avoid double-reporting)
- Not being obvious non-secrets (UUIDs, hashes, etc.)

Add to detection pipeline with rule_id "high-entropy-secret", severity "medium", and fix message suggesting investigation.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_detectors.py -k "high_entropy" -v`
Expected: PASS

- [ ] **Step 5: Run full detector test suite**

Run: `python -m pytest tests/test_detectors.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/detectors.py tests/test_detectors.py
git commit -m "feat(detectors): add high-entropy fallback detection"
```

---

### Task 5: Improve Sensitive File Detection

**Files:**
- Modify: `repoguard/files.py`
- Test: `tests/test_files.py`

**Interfaces:**
- Consumes: `file_checks(rel_path: str, size: int, max_size_bytes: int) -> list[Finding]`
- Produces: Additional findings for sensitive file types

- [ ] **Step 1: Write failing tests for additional sensitive files**

```python
def test_docker_config_json(self) -> None:
    finds = file_checks("docker/config.json", 100, 5*1024*1024)
    self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

def test_kubeconfig(self) -> None:
    finds = file_checks(".kube/config", 100, 5*1024*1024)
    self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

def test_aws_credentials(self) -> None:
    finds = file_checks(".aws/credentials", 100, 5*1024*1024)
    self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

def test_terraform_state(self) -> None:
    finds = file_checks("terraform.tfstate", 100, 5*1024*1024)
    self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

def test_backup_files(self) -> None:
    for name in ["config.bak", "config.backup", "config~", "config.old", "config.orig"]:
        finds = file_checks(name, 100, 5*1024*1024)
        self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_files.py -k "docker or kubeconfig or aws or terraform or backup" -v`
Expected: FAIL

- [ ] **Step 3: Extend SENSITIVE_FILENAMES and _is_sensitive_name in files.py**

Add to `SENSITIVE_FILENAMES`:
- `docker/config.json`, `.docker/config.json`
- `.kube/config`
- `.aws/credentials`, `.aws/config`
- `terraform.tfstate`, `terraform.tfstate.backup`
- Backup patterns: `*.bak`, `*.backup`, `*~`, `*.old`, `*.orig`

Update `_is_sensitive_name` to check basename patterns for backup files.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_files.py -k "docker or kubeconfig or aws or terraform or backup" -v`
Expected: PASS

- [ ] **Step 5: Run full files test suite**

Run: `python -m pytest tests/test_files.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/files.py tests/test_files.py
git commit -m "feat(files): expand sensitive filename detection"
```

---

### Task 6: Architecture Review - Split Large Modules

**Files:**
- Modify: `repoguard/detectors.py` (consider splitting)
- Modify: `repoguard/gui.py` (consider splitting)
- Create: `repoguard/patterns.py` (new module for regex patterns)
- Create: `repoguard/reporting.py` (new module for output formatting)

**Interfaces:**
- Maintains backward compatibility

- [ ] **Step 1: Extract regex patterns to separate module**

Create `repoguard/patterns.py` containing all regex constants and pattern specifications. Update imports in detectors.py.

- [ ] **Step 2: Extract output formatting to reporting.py**

Move `format_text`, `format_json`, `format_error_json` to `repoguard/reporting.py`. Update imports in output.py and cli.

- [ ] **Step 3: Run full test suite to verify no regressions**

Run: `python -m pytest tests/ -v`
Expected: All 65+ tests PASS

- [ ] **Step 4: Commit**

```bash
git add repoguard/patterns.py repoguard/reporting.py repoguard/detectors.py repoguard/output.py repoguard/__main__.py
git commit -m "refactor(arch): extract patterns and reporting to separate modules"
```

---

### Task 7: CLI Enhancements - Add Verbose and Quiet Modes

**Files:**
- Modify: `repoguard/__main__.py`
- Modify: `repoguard/output.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: argparse arguments
- Produces: Modified output behavior

- [ ] **Step 1: Write failing tests for verbose/quiet modes**

```python
def test_verbose_mode_shows_warnings(self) -> None:
    # Create repo with warnings (e.g., unreadable dir)
    res = run_cli(["scan", "--verbose", str(self.root)])
    self.assertIn("warning", res.stderr.lower())

def test_quiet_mode_suppresses_all_output_on_clean(self) -> None:
    (self.root / "README.md").write_text("# hi\n")
    (self.root / "LICENSE").write_text("MIT\n")
    (self.root / ".gitignore").write_text("*.pyc\n")
    res = run_cli(["scan", "--quiet", str(self.root)])
    self.assertEqual(res.stdout.strip(), "")
    self.assertEqual(res.returncode, 0)

def test_quiet_mode_still_shows_findings(self) -> None:
    (self.root / "cfg.py").write_text('token = "ghp_1234567890abcdef1234567890abcdef1234abcd"\n')
    res = run_cli(["scan", "--quiet", str(self.root)])
    self.assertIn("github-token", res.stdout)
    self.assertEqual(res.returncode, 1)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -k "verbose or quiet" -v`
Expected: FAIL

- [ ] **Step 3: Implement --verbose and --quiet flags in __main__.py**

Add arguments to scan parser. Modify output logic to respect these flags.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -k "verbose or quiet" -v`
Expected: PASS

- [ ] **Step 5: Run full CLI test suite**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/__main__.py repoguard/output.py tests/test_cli.py
git commit -m "feat(cli): add --verbose and --quiet modes"
```

---

### Task 8: CLI Enhancement - Add Summary-Only Output

**Files:**
- Modify: `repoguard/__main__.py`
- Modify: `repoguard/output.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: argparse arguments
- Produces: Summary-only text/JSON output

- [ ] **Step 1: Write failing test for --summary-only**

```python
def test_summary_only_text(self) -> None:
    (self.root / "cfg.py").write_text('token = "ghp_1234567890abcdef1234567890abcdef1234abcd"\n')
    res = run_cli(["scan", "--format", "text", "--summary-only", str(self.root)])
    self.assertIn("1 finding", res.stdout)
    self.assertNotIn("token =", res.stdout)  # No detail lines

def test_summary_only_json(self) -> None:
    (self.root / "cfg.py").write_text('token = "ghp_1234567890abcdef1234567890abcdef1234abcd"\n')
    res = run_cli(["scan", "--format", "json", "--summary-only", str(self.root)])
    data = json.loads(res.stdout)
    self.assertEqual(data["summary"]["total"], 1)
    self.assertNotIn("findings", data) or self.assertEqual(data["findings"], [])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -k "summary_only" -v`
Expected: FAIL

- [ ] **Step 3: Implement --summary-only flag**

Add argument to scan parser. Modify output formatters to support summary-only mode.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -k "summary_only" -v`
Expected: PASS

- [ ] **Step 5: Run full CLI test suite**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add repoguard/__main__.py repoguard/output.py tests/test_cli.py
git commit -m "feat(cli): add --summary-only output mode"
```

---

### Task 9: GUI Improvements - Visual Polish

**Files:**
- Modify: `repoguard/gui.py`
- Test: `tests/test_gui.py`

**Interfaces:**
- Consumes: Tkinter widgets
- Produces: Improved visual hierarchy, colors, spacing

- [ ] **Step 1: Write failing tests for GUI visual elements**

```python
def test_severity_colors_consistent(self) -> None:
    # Verify color constants match across the GUI
    from repoguard.gui import HIGH_COLOR, MEDIUM_COLOR, LOW_COLOR
    self.assertEqual(HIGH_COLOR, "#b91c1c")
    self.assertEqual(MEDIUM_COLOR, "#b45309")
    self.assertEqual(LOW_COLOR, "#047857")

def test_tree_view_has_correct_columns(self) -> None:
    # Test that treeview columns are correctly configured
    pass  # GUI tests are hard to unit test without display
```

- [ ] **Step 2: Improve visual hierarchy in gui.py**

- Increase padding and spacing in cards and sections
- Improve font sizing consistency
- Enhance color contrast for accessibility
- Add hover effects for buttons
- Improve empty state messaging

- [ ] **Step 3: Run GUI smoke tests**

Run: `python -m pytest tests/test_gui.py -v`
Expected: All tests PASS

- [ ] **Step 4: Manual verification checklist**

Verify visually:
- [ ] Layout at normal and narrow window sizes
- [ ] Welcome/quick-start instructions visible
- [ ] How to use dialog scrolls and closes cleanly
- [ ] About shows version, privacy, license
- [ ] Browse selects folder, updates staged availability
- [ ] Staged scan disabled outside Git, works inside
- [ ] Search and severity filters update visible count
- [ ] Row selection shows severity, rule, path, redacted evidence, remediation
- [ ] Copy path/fix provide feedback; clipboard failures handled
- [ ] No-findings state is clear
- [ ] Cancel requests cancellation, returns controls to ready
- [ ] Resize/minimize/restore doesn't clip controls
- [ ] Close during scan exits cleanly
- [ ] Missing Tk display produces clear CLI error, exit code 2

- [ ] **Step 5: Commit**

```bash
git add repoguard/gui.py tests/test_gui.py
git commit -m "feat(gui): visual polish and UX improvements"
```

---

### Task 10: GUI Improvements - Background Scanning Reliability

**Files:**
- Modify: `repoguard/gui.py`
- Test: `tests/test_gui.py`

**Interfaces:**
- Consumes: ScanController, threading
- Produces: Reliable background scanning with proper cancellation

- [ ] **Step 1: Write failing test for scan cancellation**

```python
def test_cancel_during_scan(self) -> None:
    controller = ScanController()
    # Start a scan that will take time
    # Cancel it
    # Verify cancelled state
    pass
```

- [ ] **Step 2: Enhance ScanController reliability**

- Ensure queue is fully drained on cancel
- Add timeout protection for stuck scans
- Improve error handling for thread exceptions
- Ensure proper resource cleanup on window close

- [ ] **Step 3: Run GUI tests**

Run: `python -m pytest tests/test_gui.py -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add repoguard/gui.py tests/test_gui.py
git commit -m "feat(gui): improve background scanning reliability"
```

---

### Task 11: Performance and Memory Testing

**Files:**
- Create: `tests/test_performance.py`
- Modify: `repoguard/files.py` (if optimizations needed)

**Interfaces:**
- Consumes: walk_files, read_text, detect_secrets
- Produces: Performance benchmarks and memory profiles

- [ ] **Step 1: Create performance test suite**

```python
def test_scan_large_repository(self) -> None:
    # Create temp repo with 1000 files
    # Measure scan time < 5 seconds
    pass

def test_memory_usage_large_files(self) -> None:
    # Create files near READ_LIMIT_BYTES
    # Verify memory doesn't grow unbounded
    pass

def test_deeply_nested_directories(self) -> None:
    # Create 100 level deep directory structure
    # Verify no recursion issues
    pass
```

- [ ] **Step 2: Run performance tests**

Run: `python -m pytest tests/test_performance.py -v`
Expected: Tests pass with reasonable benchmarks

- [ ] **Step 3: Profile and optimize if needed**

If any performance issues found, optimize file traversal or content reading.

- [ ] **Step 4: Commit**

```bash
git add tests/test_performance.py
git commit -m "test(perf): add performance benchmarks"
```

---

### Task 12: Packaging and Installation Verification

**Files:**
- Verify: `pyproject.toml`
- Verify: `MANIFEST.in`
- Verify: Build outputs

**Interfaces:**
- Consumes: setuptools, build
- Produces: Verified wheel and sdist

- [ ] **Step 1: Build distributions**

Run: `python -m build --no-isolation`
Expected: wheel and sdist created in dist/

- [ ] **Step 2: Inspect distribution contents**

Run: `python -c "import zipfile; z=zipfile.ZipFile('dist/repoguard-0.1.0-py3-none-any.whl'); print(z.namelist())"`
Expected: Contains repoguard/ package, py.typed, no __pycache__, no tests

- [ ] **Step 3: Fresh virtual environment install**

```bash
python -m venv /tmp/test-env
/tmp/test-env/bin/pip install dist/repoguard-0.1.0-py3-none-any.whl
/tmp/test-env/bin/repoguard --version
/tmp/test-env/bin/repoguard scan --help
```

Expected: CLI works outside source tree

- [ ] **Step 4: Verify GUI launch from installed package**

```bash
/tmp/test-env/bin/python -m repoguard gui --help
```

Expected: GUI module importable

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml MANIFEST.in  # if modified
git commit -m "chore(packaging): verify build and installation"
```

---

### Task 13: GitHub Infrastructure and Documentation

**Files:**
- Verify: `.github/workflows/ci.yml`
- Verify: `README.md`
- Verify: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
- Verify: `docs/index.html`
- Create: `ARCHITECTURE.md`

**Interfaces:**
- Consumes: GitHub Actions, markdown, HTML
- Produces: Complete open-source readiness

- [ ] **Step 1: Verify CI workflow**

Check that `.github/workflows/ci.yml` tests on Ubuntu, Windows, macOS with Python 3.10-3.13.

- [ ] **Step 2: Update README with all current features**

Ensure README documents:
- All detector types (new ones added)
- CLI options (verbose, quiet, summary-only)
- GUI features
- Exit codes
- Privacy guarantees

- [ ] **Step 3: Create ARCHITECTURE.md**

Document:
- Main modules and responsibilities
- Application entry points (CLI, GUI)
- Scanner pipeline
- Detection architecture
- Configuration
- Testing architecture

- [ ] **Step 4: Verify all documentation is consistent**

Run: `python -m repoguard --help` and compare to README
Run: `python -m repoguard scan --help` and compare
Check docs/index.html matches README

- [ ] **Step 5: Commit**

```bash
git add README.md ARCHITECTURE.md docs/index.html  # etc
git commit -m "docs: update all documentation for release readiness"
```

---

### Task 14: Self-Scan and Security Validation

**Files:**
- Verify: `.repoguardignore` (if needed)
- Update: `AUDIT.md`, `FIXES.md`

**Interfaces:**
- Consumes: RepoGuard scanner
- Produces: Clean self-scan with explainable findings

- [ ] **Step 1: Run self-scan**

Run: `python -m repoguard scan . --format json`
Expected: 0 findings OR only explainable findings (test fixtures)

- [ ] **Step 2: Investigate any findings**

For each finding, determine if it's:
- Genuine issue → fix
- Legitimate test fixture → add to .repoguardignore
- Harmless example → add to .repoguardignore
- False positive → improve detection rules
- Code/config change needed → fix

- [ ] **Step 3: Update AUDIT.md and FIXES.md**

Document all changes made during this mission.

- [ ] **Step 4: Commit**

```bash
git add .repoguardignore AUDIT.md FIXES.md
git commit -m "chore(self-scan): validate and document self-scan results"
```

---

### Task 15: Final Quality Gate

**Files:**
- All project files

**Interfaces:**
- Complete verification

- [ ] **Step 1: Run complete test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS (target: 80+ tests)

- [ ] **Step 2: Run compileall**

Run: `python -m compileall -q repoguard tests`
Expected: No syntax errors

- [ ] **Step 3: Build package**

Run: `python -m build --no-isolation`
Expected: Success

- [ ] **Step 4: Fresh venv install and test**

Run: Full install verification in fresh venv

- [ ] **Step 5: CLI verification**

Run: `repoguard scan .`, `repoguard scan --staged .` (in git repo), `repoguard scan --format json .`

- [ ] **Step 6: GUI startup verification**

Run: `python -m repoguard gui .` (headless test)

- [ ] **Step 7: Dependency review**

Run: `pip list` in fresh venv, verify only stdlib

- [ ] **Step 8: Git diff review**

Run: `git diff HEAD~15..HEAD` (or since mission start)
Look for: accidental modifications, unnecessary files, broken imports, debugging code, TODOs, inconsistent docs

- [ ] **Step 9: Create TEST_REPORT.md**

Document test results, coverage, performance, known limitations.

- [ ] **Step 10: Final commit**

```bash
git add TEST_REPORT.md
git commit -m "chore(release): final quality gate passed"
```

---

### Task 16: Final Summary Report

**Files:**
- Create final summary message

**Interfaces:**
- Consumes: All work done
- Produces: Evidence-based summary

- [ ] **Step 1: Compile final summary**

Include:
1. What was wrong before (reference AUDIT.md initial state)
2. What was actually changed (reference FIXES.md)
3. Most important improvements (top 5)
4. Test count and pass rate
5. What was actually verified (commands and outputs)
6. What remains unfinished
7. Next engineering priority
8. Relevant file paths
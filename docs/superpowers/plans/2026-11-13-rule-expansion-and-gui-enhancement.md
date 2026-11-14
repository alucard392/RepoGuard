# RepoGuard Rule Expansion & GUI Enhancement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add high-value secret token patterns and transform the Tkinter desktop GUI into a beautiful, modern, and user-friendly dashboard with rich formatted results and export functionality.

**Architecture:** Extended regex pattern matching in `detectors.py` integrated into the existing redacted pipeline. The Tkinter GUI will be modernized via custom styling, visual tags for colored severity blocks in a scrollable Text detail view, and a new export JSON feature.

**Tech Stack:** Python 3.10+, Tkinter, unittest.

**Spec:** Redesign the GUI's aesthetics with enhanced dashboard card colors, custom fonts, styled details pane, and Slack/Google/Stripe key detection patterns.

## Global Constraints
- Run locally, offline. No external dependencies, standard library only.
- findings must always be redacted. No plain-text secrets printed or displayed.
- Desktop GUI must launch normally via `python -m repoguard gui` on available displays.

## Review Focus
- High-severity false positives: Ensure valid strings matching key patterns but having common placeholder structures are correctly suppressed by `is_placeholder`.
- Export behavior: Exported JSON should contain redacted findings and be fully valid.

---

### Task 1: Rule Expansion in detectors.py

**Files:**
- Modify: `repoguard/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Consumes: Existing regex scanner pipeline.
- Produces: Findings for "google-api-key", "stripe-key", and "slack-webhook".

- [ ] **Step 1: Add tests for the new token patterns**
Add tests to `tests/test_detectors.py` confirming detection of simulated Google, Stripe, and Slack webhooks, and ensuring they get properly redacted.

- [ ] **Step 2: Run tests to verify they fail**
Run: `python -m unittest tests/test_detectors.py` and verify new tests fail.

- [ ] **Step 3: Implement pattern regexes and register in `_TOKEN_SPECS`**
Update `_TOKEN_SPECS` and compile patterns in `repoguard/detectors.py` for Stripe API Keys, Google API Keys, and Slack Incoming Webhooks.

- [ ] **Step 4: Run tests to verify they pass**
Run: `python -m unittest tests/test_detectors.py` and verify all pass.

- [ ] **Step 5: Commit changes**

---

### Task 2: GUI Prettification, Formatted Detail View, and JSON Export

**Files:**
- Modify: `repoguard/gui.py`

**Interfaces:**
- Consumes: `Finding` and `ScanResult` classes.
- Produces: Enhanced GUI with stylized cards, interactive text widget with custom tags (headers, code snippets, remediation actions), and an "Export JSON" button.

- [ ] **Step 1: Enhance GUI stylesheet and Card styles**
Update card backgrounds and border colors. Apply a gorgeous, rounded, or color-themed layout to severity badges and count labels in the summary dashboard.

- [ ] **Step 2: Redesign Detail view with styled headers**
Modify `_show_detail` to insert content with rich text tags (bold headers, monospace boxes, and colored blockquotes) in `self.detail_text`.

- [ ] **Step 3: Implement JSON Export in detail frame**
Add an "Export to JSON..." button in the action bar, allowing the user to save all scan findings to a selected JSON file with `filedialog.asksaveasfilename`.

- [ ] **Step 4: Verify Tk GUI starts up correctly**
Start with `python -m repoguard gui` or verify by invoking `run_gui` in a test.

- [ ] **Step 5: Commit changes**

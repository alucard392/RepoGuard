# GUI Manual Test Checklist

Run with python -m repoguard gui. Use a disposable test repository containing no real credentials.

## Automated local smoke coverage completed

- Window construction and widget initialization.
- How to use dialog creation and scrollable content availability.
- About callback.
- Working-tree scan starts and result is delivered to the UI.
- Search and severity filter update the displayed findings.
- Window closes cleanly after the scan.

## Still requiring manual visual verification

- [ ] Inspect the overall layout visually at normal and narrow window sizes.
- [ ] App opens and shows welcome/quick-start instructions.
- [ ] How to use opens, scrolls, explains workflows and closes cleanly.
- [ ] About shows version, privacy and license information.
- [ ] Browse selects a folder and updates staged-scan availability.
- [ ] Staged scan is disabled outside Git and works inside a Git repository.
- [ ] Staged scan reports only index content, not unstaged edits.
- [ ] Search and severity filters update the visible count correctly.
- [ ] Selecting a row displays severity, rule, path, redacted evidence and remediation.
- [ ] Copy path and Copy fix provide feedback; clipboard failures are handled.
- [ ] No-findings state is clear and does not look like a broken blank table.
- [ ] Cancel requests cancellation and returns controls to the ready state.
- [ ] Resize/minimize/restore does not clip critical controls.
- [ ] Close during a scan exits without a Tcl error or hang.
- [ ] Missing Tk display produces a clear CLI error and exit code 2.

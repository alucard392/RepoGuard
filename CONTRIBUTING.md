# Contributing

Thanks for considering a contribution. Keep changes focused, testable and safe.

## Development setup

- Python 3.10+
- Git for staged-scan integration tests
- Tkinter for manual GUI testing
- No third-party runtime dependencies

    python -m unittest discover -s tests -v
    python -m compileall -q repoguard tests
    python -m repoguard --help
    python -m repoguard --version
    python -m build

## Pull requests

- Explain the problem and intended behavior.
- Add regression tests for bug fixes and tests for new behavior.
- Update README and CHANGELOG when user-visible behavior changes.
- Keep secret fixtures synthetic and construct recognizable test strings from fragments.
- Never commit credentials, local paths, personal data, build output or generated caches.
- Do not add runtime dependencies without compelling reason and discussion.
- Do not add network access, telemetry, uploads, or automatic repository modifications.

## Detector changes

Add positive and negative tests. Cover placeholders, redaction, multiple findings on one line, and false-positive boundaries. Never put an actual credential in a test fixture.

## GUI changes

Keep all Tk calls on the main thread. Run scanning work in the worker/controller and deliver results through its queue. Update GUI_TESTING.md when behavior changes.

## Reporting

Use issue templates for bugs and feature requests. Security-sensitive bypasses belong in private reporting, not public issues.

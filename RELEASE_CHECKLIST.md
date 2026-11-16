# First Public Release Checklist

## Source and verification

- [x] Review tracked source, tests, workflows and docs for credentials, private data and local fixtures; public self-scan is clean.
- [x] Exclude caches, build outputs, virtual environments and internal planning notes from the public branch.
- [x] Run complete tests, compilation, CLI/staged integration, package build and installed-wheel checks.
- [ ] Complete manual GUI_TESTING.md visual/interaction review on a supported desktop platform.
- [x] Include MIT license; runtime dependencies are standard-library only.
- [x] Verify README installation and CLI instructions against the published project.
- [ ] Establish and verify a private security-reporting contact/process.

## GitHub repository setup

- [x] Create public repository: https://github.com/alucard392/RepoGuard (default branch: main).
- [ ] Protect the default branch: require pull requests and passing CI checks; restrict direct pushes where appropriate.
- [ ] Enable private vulnerability reporting and security advisories where available.
- [ ] Verify Dependabot alerts/security updates are enabled; weekly update configuration is committed.
- [ ] Enable GitHub secret scanning and push protection where available for the plan.
- [ ] Configure labels used by issue templates (bug and enhancement).
- [ ] Enable Discussions only if maintainers will monitor them.
- [ ] Add maintainers and define review responsibility.
- [ ] Enable GitHub Pages only after reviewing docs/index.html and selecting the intended publishing source.

## Release

- [x] Version 0.1.0 and CHANGELOG are present.
- [x] Run tests and build from the published commit; GitHub Actions passes on Ubuntu, Windows and macOS with Python 3.10–3.13.
- [x] Inspect package contents; wheel and sdist were built and a fresh wheel install was verified.
- [ ] Create and push a v0.1.0 tag and GitHub Release after manual GUI review.
- [ ] Publish to PyPI only after deciding to distribute a package.
- [x] Document known limitations; never claim perfect secret detection.

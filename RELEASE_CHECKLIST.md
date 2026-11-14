# First Public Release Checklist

## Before creating a public repository

- [ ] Review source, tests, workflows and docs for credentials, private data, machine-specific paths and personal information.
- [ ] Remove inspect/debug scripts, caches, egg-info, dist and temporary build artifacts.
- [ ] Run complete tests, compile, CLI, staged integration, package build and installed-wheel checks.
- [ ] Complete GUI_TESTING.md on at least one supported desktop platform.
- [ ] Review license and third-party attributions.
- [ ] Verify README instructions against actual CLI and GUI.
- [ ] Confirm security reporting route and maintainers' private contact channel.

## GitHub repository setup

- [ ] Create repository manually and choose visibility intentionally.
- [ ] Protect the default branch: require pull requests and passing CI checks; restrict direct pushes where appropriate.
- [ ] Enable private vulnerability reporting and security advisories where available.
- [ ] Enable Dependabot alerts/security updates; the repository includes a weekly Dependabot update configuration.
- [ ] Enable GitHub secret scanning and push protection where available for the plan.
- [ ] Configure labels used by issue templates (bug and enhancement).
- [ ] Enable Discussions only if maintainers will monitor them.
- [ ] Add maintainers and define review responsibility.
- [ ] Enable GitHub Pages after reviewing docs/index.html; select the default branch and /docs folder as the publishing source if desired.

## Release

- [ ] Update version and CHANGELOG.
- [ ] Run tests and build from a clean checkout.
- [ ] Inspect wheel and sdist contents.
- [ ] Create a tagged release only after checks pass.
- [ ] Publish notes with known limitations; never claim perfect secret detection.

# Contributing

## Git Workflow

### Branches

- **`main`** is the production branch. Never push directly to main.
- All changes go through feature branches merged via Pull Request.
- Branch naming conventions:
  - `feat/description` — new features
  - `fix/description` — bug fixes
  - `chore/description` — maintenance, CI, docs

### Pull Requests

1. Create a feature branch from `main`
2. Make your changes and push
3. Open a PR targeting `main`
4. CI must pass (green check) before merge
5. Squash-merge or rebase-merge preferred

### Tests

Tests must pass before merging. CI runs automatically on every push and PR.

```bash
pip install -e ".[test]"
pytest tests/ -v
```

Conformance tests against the [Proof Specification](https://github.com/ark-forge/proof-spec) run as part of the suite. If you modify the chain hash algorithm or proof structure, update the spec and test vectors first.

### Code Style

- Python 3.11 (as in CI and the Dockerfile), type hints where helpful
- `ruff check` (config in `ruff.toml`) runs in CI on the `.py` files changed by a PR or push, not on the whole repository — match existing style elsewhere
- Keep functions short, no deep nesting
- No comments unless the logic is non-obvious

### Security

If you discover a security vulnerability, **do not open a public issue**. Email [contact@arkforge.tech](mailto:contact@arkforge.tech) with details.

### Releases

Releases follow [semver](https://semver.org/). The version is decided in the pull request: bump `trust_layer/__init__.py` and add a `## [x.y.z]` entry to `CHANGELOG.md`. Once merged with green CI, the maintainer runs `scripts/deploy_trust_layer_prod.sh`, which deploys and pushes the `vX.Y.Z` tag. Never push a tag by hand.

The tag triggers the release workflow which:
1. Runs the full test suite (gate)
2. Creates a GitHub Release with auto-generated changelog

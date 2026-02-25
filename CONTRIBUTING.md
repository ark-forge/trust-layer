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

### Releases

Releases follow [semver](https://semver.org/). To create a release:

```bash
git tag v0.2.0
git push origin v0.2.0
```

This triggers the release workflow which:
1. Runs the full test suite (gate)
2. Creates a GitHub Release with auto-generated changelog

### Branch Protection

Branch protection rules on `main` will be enforced once the repository is public (GitHub Free limitation). Until then, these conventions apply by agreement.

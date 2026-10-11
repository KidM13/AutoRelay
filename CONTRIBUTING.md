# Contributing to AutoRelay

## 1. Branching

- `main`: Stable, reviewed code.
- `dev`: Integration branch.
- `feature/<name>`: Individual features and documentation changes.

Create feature branches from the latest `dev` branch.

## 2. Workflow

1. Pull the latest changes from `dev`.
2. Create a feature branch.
3. Implement the assigned change and its tests.
4. Run relevant tests and review your changes.
5. Push the feature branch.
6. Open a pull request targeting `dev`.
7. Address review feedback before merging.

Only merge `dev` into `main` through a pull request when the integrated version is reviewed and tested.

## 3. Coding Guidelines

- Use clear names and small, focused functions.
- Keep modules within their assigned responsibilities.
- Follow the shared contracts in `docs/MODULE_INTERFACES.md`.
- Handle errors explicitly.
- Never commit credentials, tokens, or sensitive assessment output.

## 4. Testing

Run the relevant tests before opening a pull request. Add tests for new functionality and for important failure cases. Use mocks for protocol behavior when possible, and perform integration testing only in an authorized lab.

## 5. Pull Requests

Each pull request should explain:

- What changed and why.
- Which modules or interfaces were affected.
- Which tests were run and their results.
- Any known limitations or follow-up work.

Keep pull requests focused and request review before merging.
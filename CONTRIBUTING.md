# Contributing to MatterSwift

Thank you for your interest in contributing to MatterSwift!

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run tests: `swift test`
5. Submit a pull request

## Development Guide

See [MAINTENANCE.md](MAINTENANCE.md) for detailed instructions on:

- Building and testing
- Code generation from Matter XML specs
- CI enforcement and test requirements
- Project structure and conventions

## Code Style

- Follow existing patterns in the codebase
- Use Swift Testing framework (`import Testing`, `@Suite`, `@Test`)
- Add `// MARK: - Section Name` section markers
- Include copyright headers: `// FileName.swift\n// Copyright 2026 Monagle Pty Ltd`

## Pull Request Process

1. Ensure `swift build` and `swift test` pass locally
2. Update documentation if your change affects public API
3. Keep PRs focused — one feature or fix per PR
4. Describe what changed and why in the PR description

## Reporting Issues

- **Bugs**: Use the [bug report template](https://github.com/acumen-dev/matter-swift/issues/new?template=bug_report.md)
- **Features**: Use the [feature request template](https://github.com/acumen-dev/matter-swift/issues/new?template=feature_request.md)
- **Security**: See [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE.md).

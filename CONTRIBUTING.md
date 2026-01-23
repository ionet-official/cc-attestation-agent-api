# Contributing to Remote Attestation Service

Thank you for your interest in contributing to this project. This document provides guidelines for contributing.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Use the issue templates provided
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Submitting Changes

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the code style guidelines below
3. **Add tests** for any new functionality
4. **Ensure all tests pass** locally
5. **Submit a pull request** using the PR template

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cc-attestation-agent-api.git
cd cc-attestation-agent-api

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linting
pylint *.py
```

### Code Style

- Follow PEP 8 for Python code
- Use type hints where applicable
- Keep functions focused and well-documented
- Maximum line length: 100 characters

### Commit Messages

Use clear, descriptive commit messages:

- Start with a verb in imperative mood (Add, Fix, Update, Remove)
- Keep the first line under 50 characters
- Add a blank line before detailed description if needed

Examples:
```
Add nonce validation for attestation requests

Fix certificate chain parsing for multi-GPU setups

Update FastAPI to address security advisory
```

### Pull Request Guidelines

- Fill out the PR template completely
- Link related issues using keywords (Fixes #123, Closes #456)
- Keep PRs focused on a single change
- Respond to review feedback promptly
- Ensure CI checks pass before requesting review

### Testing Requirements

- All new code must have test coverage
- Tests must pass locally and in CI
- For attestation features, mock the hardware interfaces appropriately

### Review Process

1. A maintainer will review your PR
2. Address any requested changes
3. Once approved, a maintainer will merge your PR

## Development Notes

### Testing Without Hardware

Since this service requires TDX-enabled CPUs and NVIDIA H200 GPUs, tests use mocked hardware interfaces. See `tests/` for examples of how to mock:

- TDX quote generation (`/sys/kernel/config/tsm/report`)
- NVIDIA attestation SDK calls

### Security Considerations

When contributing, keep in mind:

- This code runs inside confidential VMs handling sensitive attestation
- Never log or expose cryptographic keys or quotes inappropriately
- Validate all inputs, especially nonces
- Follow secure coding practices

## Questions?

Open a GitHub Discussion or reach out to the maintainers.

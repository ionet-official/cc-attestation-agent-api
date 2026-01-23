# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously, especially given this project deals with confidential computing and remote attestation.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Private Vulnerability Reporting**: Use [GitHub's private vulnerability reporting](https://github.com/ionet-official/cc-attestation-agent-api/security/advisories/new) to submit a report directly.

2. **Email**: Send details to security@io.net

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., buffer overflow, authentication bypass, cryptographic weakness)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment and potential attack scenarios

### Response Timeline

- **Initial Response**: Within 48 hours of submission
- **Status Update**: Within 7 days with an assessment of the vulnerability
- **Resolution Target**: Critical vulnerabilities within 30 days, others within 90 days

### Disclosure Policy

- We follow coordinated disclosure practices
- We will credit reporters in security advisories (unless anonymity is requested)
- We ask that you give us reasonable time to address the issue before public disclosure

## Security Considerations

This service handles cryptographic attestation in confidential computing environments. Key security considerations:

- The service must only run inside a properly configured TDX confidential VM
- Attestation quotes should be verified against Intel and NVIDIA roots of trust
- Nonces must be used to ensure freshness of attestation quotes
- TLS should be used for all network communication in production

## Security Features

- SBOM generation and attestation for supply chain transparency
- Sigstore signing for artifact integrity
- SLSA Level 3 provenance for build verification
- Dependency vulnerability scanning in CI/CD pipeline

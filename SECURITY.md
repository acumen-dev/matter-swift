# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MatterSwift, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following methods:

1. **GitHub Security Advisories** (preferred): Navigate to the [Security Advisories](https://github.com/acumen-dev/matter-swift/security/advisories/new) page and create a new advisory.
2. **Email**: Send details to the repository maintainers via the email listed on the GitHub organization profile.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, but we aim for prompt resolution

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older releases | Best effort |

## Security Considerations

MatterSwift implements cryptographic protocols (SPAKE2+, CASE/Sigma, AES-128-CCM) as defined by the Matter specification. While we follow the spec closely and use well-established cryptographic libraries (CryptoKit, swift-crypto), this implementation has not undergone a formal security audit. Use in production environments should account for this.

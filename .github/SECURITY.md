# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

We take security bugs seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please DO NOT file a public issue for security vulnerabilities.**

Instead, please report security vulnerabilities by:

1. **Email**: Send a detailed report to [security@ucid.org](mailto:security@ucid.org)
2. **GitHub Security Advisory**: Use [GitHub's private vulnerability reporting](https://github.com/ucid-foundation/ucid/security/advisories/new)

### What to Include

Please include as much of the following information as possible:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting)
- Full paths of source file(s) related to the manifestation of the issue
- Location of affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Target**: Within 90 days for critical issues

### Security Update Process

1. The security team will acknowledge your report
2. We will investigate and validate the issue
3. We will develop and test a fix
4. We will coordinate disclosure with you
5. We will release the fix and publish a security advisory

### Safe Harbor

We consider security research conducted consistent with this policy to constitute "authorized" conduct. We will not pursue civil or criminal action against researchers who:

- Make a good faith effort to avoid privacy violations
- Only access data necessary to demonstrate the vulnerability
- Do not exploit the vulnerability beyond demonstration
- Report vulnerabilities promptly

## Security Best Practices

When using UCID in production:

1. **Always use the latest version** - We regularly release security updates
2. **Validate all input** - Especially UCID strings from external sources
3. **Use HTTPS** - When using the API, always use encrypted connections
4. **Review dependencies** - Regularly audit your dependency tree

## Contact

- Security Team: security@ucid.org
- PGP Key: Available upon request

# Security Policy

## Supported Versions

pfBlockerNG maintains two release channels. We provide security updates and vulnerability fixes for the following versions:

| Version   | Branch   | Supported          | Recommended For         | Notes |
|-----------|----------|--------------------|-------------------------|-------|
| 4.0.x     | `main`   | :white_check_mark: | Production use          | Stable releases (starting v4.0.0) |
| 4.0.x     | `devel`  | :white_check_mark: | Testing and development | Development releases |
| 3.2.x     | -        | :white_check_mark: | Production use          | Current version in pfSense ports (3.2.15) |
| < 3.2     | -        | :x:                | -                       | No longer supported |

> **Note**: Starting with version **v4.0.0**, pfBlockerNG follows [Semantic Versioning](https://semver.org/). All future releases on both the `main` and `devel` branches will use this versioning scheme.

## Reporting a Vulnerability

We take the security of pfBlockerNG seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### Preferred Reporting Method

We strongly encourage reporting vulnerabilities through **GitHub Private Security Advisories**:

1. Go to the [Security Advisories](https://github.com/pfBlockerNG/pfBlockerNG/security/advisories) page.
2. Click **"Report a vulnerability"**.
3. Provide as much detail as possible.

This is our preferred method as it allows private communication, proper tracking, and coordinated disclosure (including the option to publish a CVE).

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions and branch (`main` or `devel`)
- Potential impact
- Any suggested fixes or mitigations (if known)

### Response Timeline

- We will acknowledge receipt of your report **within 48 hours**.
- We aim to provide an initial assessment **within 7 days**.
- We will work with you to understand and resolve the issue as quickly as possible.
- Once a fix is ready, we will coordinate a disclosure timeline with you.

## Scope

This security policy applies to:

- The **pfBlockerNG core application** source code
- Official releases published under the `pfBlockerNG` GitHub organization
- Both the `main` (stable) and `devel` branches

This policy does **not** apply to:

- Packages distributed through the pfSense package manager (these are built and maintained by Netgate)
- Issues in the underlying pfSense operating system or other pfSense packages
- Third-party blocklists, feeds, or external data sources

## Attribution

We appreciate responsible security research. Reporters of valid security issues may be publicly acknowledged (with their permission) after the issue has been resolved.

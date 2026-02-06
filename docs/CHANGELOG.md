# Changelog

All notable changes to ButtF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- GraphQL-specific vulnerability testing
- WebSocket security analysis
- Machine learning-based anomaly detection
- Integration with vulnerability databases
- Custom rule engine for organization-specific tests

## [1.0.0] - 2026-02-07

### Added

#### Core Scanner
- Initial release of ButtF security scanner
- Multi-threaded scanning engine with configurable thread count
- Eight comprehensive detection modules:
  - Backend misconfiguration detection
  - Business logic flaw analysis
  - Known CVE pattern matching
  - Authentication and authorization testing
  - Injection vulnerability scanning
  - Sensitive data exposure detection
  - Rate limiting validation
  - CORS misconfiguration analysis

#### Misconfiguration Detection
- Exposed configuration files (.env, config.json)
- Git repository exposure detection
- Admin panel accessibility checks
- API documentation leak detection (Swagger, GraphQL)
- Database backup exposure scanning
- Cloud credential leak detection (.aws/credentials)
- Server configuration file exposure

#### Logic Flaw Detection
- Insecure Direct Object Reference (IDOR) testing
- Mass assignment vulnerability detection
- Workflow bypass identification
- State manipulation attack detection

#### CVE Detection
- Log4Shell (CVE-2021-44228) detection
- Spring4Shell (CVE-2022-22965) detection
- Pattern-based vulnerability matching
- Framework signature identification

#### Authentication Testing
- JWT security validation
- Session management analysis
- Password policy enforcement testing
- Token manipulation tests
- Cookie security configuration checks

#### Injection Testing
- SQL injection detection with multiple payloads
- Command injection testing
- Cross-Site Scripting (XSS) vulnerability scanning
- Payload reflection analysis

#### Threat Analysis
- Advanced threat analysis engine
- MITRE ATT&CK framework mapping
- CVSS-style risk scoring
- Attack scenario generation
- Compliance impact assessment (PCI-DSS, GDPR, HIPAA, SOC2, ISO27001)
- Exploitability assessment
- Business impact analysis
- HTML report generation
- JSON report export

#### Reporting
- Text-based vulnerability reports
- JSON output for automation
- Severity-based categorization (CRITICAL, HIGH, MEDIUM, LOW)
- Evidence collection and documentation
- Remediation guidance
- CVE reference linking

#### Configuration
- Customizable scan parameters
- Thread count configuration
- Request timeout settings
- Custom payload support
- Module-specific configuration
- User-agent customization

#### Documentation
- Comprehensive README with usage examples
- Installation instructions
- Module descriptions
- Command-line argument reference
- Example usage scenarios
- Security best practices
- Troubleshooting guide

#### Developer Tools
- Example scripts demonstrating various scenarios
- Configuration templates
- Contribution guidelines
- Code of conduct
- Security policy

### Technical Details
- Python 3.7+ compatibility
- Requests library for HTTP operations
- Connection pooling for performance
- Adaptive timeout mechanisms
- Error handling and logging
- Vulnerability dataclass structure

### Security Features
- Input sanitization
- Timeout mechanisms
- Rate limiting awareness
- Minimal privilege requirements
- Secure defaults

## Version Numbering

This project uses [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for added functionality in a backwards compatible manner
- **PATCH** version for backwards compatible bug fixes

## Release Types

### Major Releases (X.0.0)
- Significant architectural changes
- Breaking API changes
- Major feature additions

### Minor Releases (0.X.0)
- New detection modules
- New features
- Enhancements to existing functionality
- Non-breaking changes

### Patch Releases (0.0.X)
- Bug fixes
- Security patches
- Documentation updates
- Performance improvements

## Upgrade Guide

### From Pre-release to 1.0.0

First official release - no upgrade necessary.

## Deprecation Policy

Features marked as deprecated will:
1. Be announced in release notes
2. Remain functional for at least 2 minor versions
3. Generate warnings when used
4. Be removed in the next major version

## Support Policy

- **Current Major Version**: Full support with security and bug fixes
- **Previous Major Version**: Security fixes only for 6 months
- **Older Versions**: No longer supported

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on contributing to ButtF.

## Security

See [SECURITY.md](SECURITY.md) for information on reporting security vulnerabilities.

---

**Legend:**
- `Added` for new features
- `Changed` for changes in existing functionality
- `Deprecated` for soon-to-be removed features
- `Removed` for removed features
- `Fixed` for bug fixes
- `Security` for security-related changes

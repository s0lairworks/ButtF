# Security Policy

## Supported Versions

The following versions of ButtF are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

### Security Contact

If you discover a security vulnerability in ButtF, please report it responsibly.

**DO NOT** create public GitHub issues for security vulnerabilities.

**Email:** security@s0lairworks@gmail.com  
**PGP Key:** Available upon request

### Information to Include

When reporting a vulnerability, please provide:

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact and severity assessment
3. **Reproduction**: Step-by-step instructions to reproduce
4. **Proof of Concept**: Code or commands demonstrating the issue
5. **Suggested Fix**: If you have recommendations
6. **Disclosure Timeline**: Your preferred disclosure timeline

### Example Report

```
Subject: [SECURITY] SQL Injection in Module X

Description:
The scanner module X contains an SQL injection vulnerability when 
processing user-supplied target URLs.

Impact:
An attacker could inject malicious SQL code that executes on the 
scanner's database, potentially leading to information disclosure.

Reproduction Steps:
1. Run: python buttf.py -u "https://evil.com' OR 1=1--" -m module_x
2. Observe SQL error in output
3. Database query executed: SELECT * FROM targets WHERE url='...'

Proof of Concept:
[Attach PoC code or commands]

Suggested Fix:
Implement parameterized queries using prepared statements.

Disclosure Timeline:
I request 90 days for patch development before public disclosure.
```

## Response Process

### Timeline

- **Acknowledgment**: Within 48 hours of report
- **Initial Assessment**: Within 5 business days
- **Status Updates**: Every 7 days until resolution
- **Patch Development**: Varies by severity
- **Coordinated Disclosure**: Agreed upon with reporter

### Severity Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| **Critical** | Remote code execution, authentication bypass | 24-48 hours |
| **High** | Privilege escalation, significant data exposure | 3-7 days |
| **Medium** | Information disclosure, DoS conditions | 7-14 days |
| **Low** | Minor information leaks, configuration issues | 14-30 days |

### Assessment Criteria

Vulnerabilities are assessed using the following criteria:

- **Exploitability**: How easily can the vulnerability be exploited?
- **Impact**: What is the potential damage?
- **Scope**: How many users or systems are affected?
- **Context**: Is exploitation likely in real-world scenarios?

## Disclosure Process

### Coordinated Disclosure

We follow coordinated vulnerability disclosure:

1. **Private Reporting**: Researcher reports vulnerability privately
2. **Validation**: We confirm and assess the vulnerability
3. **Development**: We develop and test a fix
4. **Notification**: We notify affected users (if applicable)
5. **Release**: We release patched version
6. **Public Disclosure**: We publish security advisory
7. **Credit**: We acknowledge the researcher (if desired)

### Public Disclosure Timeline

- **Critical/High**: 90 days from report or patch release (whichever is sooner)
- **Medium**: 120 days from report
- **Low**: 180 days from report

Researchers may request earlier or later disclosure based on circumstances.

## Security Advisories

Security advisories will be published:

- GitHub Security Advisories
- Project documentation
- Release notes
- Security mailing list (if established)

### Advisory Format

```markdown
## Advisory ID: BUTTF-2026-001

**Title**: [Vulnerability Name]
**Severity**: [Critical/High/Medium/Low]
**CVE**: CVE-YYYY-XXXXX
**Affected Versions**: x.x.x - y.y.y
**Fixed Versions**: z.z.z

### Description
[Detailed description of vulnerability]

### Impact
[Description of potential impact]

### Mitigation
[Temporary mitigation steps if applicable]

### Resolution
Update to version z.z.z or apply patch from [URL]

### Credit
[Researcher name/handle if permission granted]

### Timeline
- YYYY-MM-DD: Vulnerability reported
- YYYY-MM-DD: Vulnerability confirmed
- YYYY-MM-DD: Fix developed
- YYYY-MM-DD: Version z.z.z released
- YYYY-MM-DD: Public disclosure
```

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest version
2. **Review Permissions**: Only grant necessary permissions
3. **Secure Environment**: Run in isolated/controlled environments
4. **Configuration**: Review and secure configuration files
5. **Access Control**: Restrict access to ButtF and its output
6. **Logging**: Monitor logs for suspicious activity

### For Contributors

1. **Input Validation**: Validate all user input
2. **Parameterized Queries**: Use prepared statements for database queries
3. **Least Privilege**: Request minimum necessary permissions
4. **Secure Dependencies**: Keep dependencies updated
5. **Code Review**: Security-focused code reviews
6. **Testing**: Include security test cases

## Known Security Considerations

### By Design

The following are intentional design decisions:

1. **Network Requests**: ButtF makes HTTP requests to target systems
2. **File System Access**: ButtF reads/writes configuration and reports
3. **External Libraries**: ButtF uses third-party dependencies

### User Responsibilities

Users are responsible for:

1. **Authorization**: Obtaining permission before scanning systems
2. **Legal Compliance**: Following applicable laws and regulations
3. **Ethical Use**: Using the tool for legitimate security testing only
4. **Data Protection**: Securing scan results containing sensitive information

## Dependencies

### Monitoring

We monitor dependencies for known vulnerabilities using:

- GitHub Dependabot
- Snyk vulnerability scanning
- OWASP Dependency-Check

### Updates

Dependencies are updated:

- **Critical vulnerabilities**: Within 48 hours
- **High severity**: Within 7 days
- **Medium/Low severity**: Within 30 days
- **Regular updates**: Monthly review cycle

### Vulnerability Notifications

Users can subscribe to notifications about:

- Security advisories
- Critical updates
- Dependency vulnerabilities

## Compliance

### Legal Framework

This tool is designed for:

- Authorized security testing
- Vulnerability research
- Educational purposes
- Compliance validation

### Prohibited Uses

This tool must NOT be used for:

- Unauthorized system access
- Malicious purposes
- Violation of laws or regulations
- Testing without explicit permission

## Security Features

### Current Protections

- Input sanitization for user-provided URLs
- Timeout mechanisms to prevent resource exhaustion
- Rate limiting to avoid DoS conditions
- Secure configuration defaults
- Minimal privilege requirements

### Planned Enhancements

- [ ] Enhanced input validation
- [ ] Sandboxed execution environment
- [ ] Encrypted credential storage
- [ ] Audit logging
- [ ] Role-based access control

## Hall of Fame

We acknowledge security researchers who have responsibly disclosed vulnerabilities:

*To be populated as researchers contribute*

## Contact

For security-related questions:

- **Security Issues**: security@buttf.example.com
- **General Questions**: Via GitHub Discussions
- **Bug Reports**: Via GitHub Issues (non-security bugs only)

## PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key to be added]
-----END PGP PUBLIC KEY BLOCK-----
```

## Acknowledgments

We thank the security research community for their contributions to improving ButtF's security posture.

---

Last Updated: February 2026

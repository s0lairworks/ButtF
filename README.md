# ButtF - Backend Misconfiguration & Logic Flaw Exploitation Tool

## Overview

ButtF is a comprehensive security testing framework designed for penetration testers and security researchers to identify backend misconfigurations, business logic flaws, and known vulnerabilities in web applications.

## Features

### Core Detection Modules

1. **Misconfiguration Detection (`misconfig`)**
   - Exposed configuration files (.env, config.json)
   - Git repository exposure
   - Admin panel accessibility
   - API documentation leaks (Swagger, GraphQL)
   - Database backup exposure
   - Cloud credential leaks

2. **Logic Flaw Detection (`logic`)**
   - Insecure Direct Object Reference (IDOR)
   - Mass assignment vulnerabilities
   - Workflow bypass detection
   - State manipulation attacks

3. **CVE Detection (`cve`)**
   - Log4Shell (CVE-2021-44228)
   - Spring4Shell (CVE-2022-22965)
   - Pattern-based vulnerability matching
   - Framework signature detection

4. **Authentication Testing (`auth`)**
   - JWT security validation
   - Session management issues
   - Password policy enforcement
   - Token manipulation tests

5. **Injection Testing (`injection`)**
   - SQL injection detection
   - Command injection testing
   - Cross-Site Scripting (XSS)
   - Payload reflection analysis

6. **Data Exposure Detection (`exposure`)**
   - Sensitive endpoint enumeration
   - API data leakage
   - Debug information disclosure
   - Internal endpoint exposure

7. **Rate Limiting Validation (`rate`)**
   - Brute force protection testing
   - API rate limit enforcement
   - DDoS vulnerability assessment

8. **CORS Misconfiguration (`cors`)**
   - Origin validation testing
   - Credential exposure via CORS
   - Wildcard origin detection

## Installation

### Requirements
- Python 3.7+
- pip

### Setup
```bash
# Clone or download ButtF
git clone <repository-url>
cd buttf

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/Mac)
chmod +x buttf.py
```

## Usage

### Basic Scan
```bash
python buttf.py -u https://example.com -m all
```

### Targeted Module Scan
```bash
python buttf.py -u https://api.example.com -m misconfig,logic,cve
```

### Custom Configuration
```bash
python buttf.py -u https://example.com -m auth,injection --threads 20 --timeout 15
```

### JSON Output
```bash
python buttf.py -u https://example.com -m all -o json -f report.json
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-u, --url` | Target URL (required) | - |
| `-m, --modules` | Comma-separated modules or "all" | - |
| `-t, --threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 10 |
| `-o, --output` | Output format (text/json) | text |
| `-f, --file` | Save report to file | - |

## Available Modules

| Module | Description |
|--------|-------------|
| `misconfig` | Backend misconfiguration detection |
| `logic` | Business logic flaw detection |
| `cve` | Known CVE pattern matching |
| `auth` | Authentication/authorization testing |
| `injection` | Injection vulnerability testing |
| `exposure` | Sensitive data exposure detection |
| `rate` | Rate limiting validation |
| `cors` | CORS misconfiguration detection |
| `all` | Run all modules |

## Output Examples

### Text Report
```
================================================================================
ButtF Security Scan Report
================================================================================

Target: https://example.com
Total Vulnerabilities: 5

Severity Breakdown:
  CRITICAL: 2
  HIGH: 1
  MEDIUM: 2

--------------------------------------------------------------------------------

[1] HIGH - Information Disclosure
Endpoint: /robots.txt
Description: Exposed robots.txt
Evidence: Status: 200, Size: 1234 bytes
Remediation: Restrict access to /robots.txt or remove it from public access
```

### JSON Report
```json
[
  {
    "severity": "HIGH",
    "category": "Information Disclosure",
    "endpoint": "/robots.txt",
    "description": "Exposed robots.txt",
    "evidence": "Status: 200, Size: 1234 bytes",
    "cve_id": null,
    "remediation": "Restrict access to /robots.txt or remove it from public access"
  }
]
```

## Vulnerability Severity Levels

- **CRITICAL**: Immediate exploitation possible, severe impact
- **HIGH**: Exploitable with moderate effort, significant impact
- **MEDIUM**: Exploitable under certain conditions, moderate impact
- **LOW**: Limited exploitability, minimal impact

## Advanced Usage

### Custom Payloads

Modify the scanner to include custom payloads:

```python
scanner = ButtF('https://example.com')
scanner.custom_sql_payloads = ["' OR 1=1--", "admin'--"]
scanner.scan(['injection'])
```

### Integration with CI/CD

```bash
#!/bin/bash
python buttf.py -u $TARGET_URL -m all -o json -f scan_results.json

if [ $(jq '.[] | select(.severity=="CRITICAL")' scan_results.json | wc -l) -gt 0 ]; then
    echo "Critical vulnerabilities found!"
    exit 1
fi
```

## Security Considerations

### Legal Notice
ButtF is designed for authorized security testing only. Users must:
- Obtain explicit permission before testing any system
- Comply with applicable laws and regulations
- Use responsibly and ethically

### Best Practices
- Test in isolated environments first
- Use reasonable thread counts to avoid DoS
- Monitor target system impact
- Document all findings thoroughly

## Threat Analysis Capabilities

ButtF provides comprehensive threat analysis through:

1. **Vulnerability Categorization**: Organizes findings by attack vector
2. **Severity Assessment**: Prioritizes risks based on exploitability and impact
3. **Evidence Collection**: Captures proof of vulnerability existence
4. **Remediation Guidance**: Provides actionable fix recommendations

## CVE Detection Strategy

The tool employs multiple CVE detection methods:

1. **Pattern Matching**: Identifies framework signatures
2. **Version Fingerprinting**: Detects vulnerable software versions
3. **Behavior Analysis**: Tests for known vulnerability behaviors
4. **Error Message Analysis**: Extracts version info from error responses

## Performance Optimization

- **Multi-threading**: Parallel request execution
- **Connection Pooling**: Reuses HTTP connections
- **Smart Timeout**: Adaptive timeout based on response patterns
- **Request Throttling**: Prevents target overload

## Troubleshooting

### Common Issues

**Issue**: Connection timeouts
```bash
# Increase timeout value
python buttf.py -u https://example.com -m all --timeout 30
```

**Issue**: Too many concurrent requests
```bash
# Reduce thread count
python buttf.py -u https://example.com -m all --threads 5
```

**Issue**: SSL certificate errors
```python
# Modify session to disable SSL verification (use cautiously)
scanner.session.verify = False
```

## Contribution Guidelines

Contributions are welcome. To add new detection modules:

1. Create detection method following naming convention `_scan_module_name()`
2. Add vulnerability objects using the `Vulnerability` dataclass
3. Register module in the `scan_functions` dictionary
4. Document the module in README
5. Add example test cases

## Roadmap

- [ ] Additional CVE signatures
- [ ] Machine learning-based anomaly detection
- [ ] GraphQL-specific vulnerability testing
- [ ] WebSocket security analysis
- [ ] Enhanced reporting with executive summaries
- [ ] Integration with vulnerability databases
- [ ] Custom rule engine for organization-specific tests

## License

This tool is provided for educational and authorized security testing purposes.

## Disclaimer

The authors are not responsible for misuse or damage caused by this tool. Users assume all responsibility for compliance with applicable laws and ethical guidelines.


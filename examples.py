#!/usr/bin/env python3

#ButtF Example Usage - Demonstrates various scanning scenarios

import sys
import os

#Example 1: Basic vulnerability scan
print("="*80)
print("Example 1: Basic Vulnerability Scan")
print("="*80)
print("""
python buttf.py -u https://example.com -m all

This performs a comprehensive scan using all available modules:
- Backend misconfiguration detection
- Logic flaw analysis
- Known CVE detection
- Authentication testing
- Injection vulnerability scanning
- Data exposure checks
- Rate limiting validation
- CORS misconfiguration detection
""")

#Example 2: Targeted assessment
print("\n" + "="*80)
print("Example 2: Targeted Security Assessment")
print("="*80)
print("""
python buttf.py -u https://api.example.com -m misconfig,cve,auth

Focuses on specific attack vectors:
- Checks for exposed configuration files
- Scans for known CVE signatures
- Tests authentication mechanisms
""")

#Example 3: Logic flaw hunting
print("\n" + "="*80)
print("Example 3: Business Logic Flaw Detection")
print("="*80)
print("""
python buttf.py -u https://app.example.com -m logic,auth

Specialized scan for application logic issues:
- IDOR (Insecure Direct Object Reference)
- Mass assignment vulnerabilities
- Workflow bypass attempts
- Authentication/authorization flaws
""")

#Example 4: High-performance scan
print("\n" + "="*80)
print("Example 4: High-Performance Scan")
print("="*80)
print("""
python buttf.py -u https://example.com -m all --threads 20 --timeout 5

Optimized for speed:
- 20 concurrent threads
- 5-second timeout
- Faster enumeration
""")

#Example 5: JSON export for automation
print("\n" + "="*80)
print("Example 5: Automated Security Testing")
print("="*80)
print("""
python buttf.py -u https://example.com -m all -o json -f results.json

Perfect for CI/CD integration:
- JSON output format
- Machine-readable results
- Easy integration with other tools
""")

#Example 6: Threat analysis integration
print("\n" + "="*80)
print("Example 6: Advanced Threat Analysis")
print("="*80)
print("""
# Run scan
python buttf.py -u https://example.com -m all -o json -f scan_results.json

# Generate threat analysis report
python -c "
from buttf import ButtF
from threat_analyzer import ThreatAnalyzer
import json

# Load scan results
with open('scan_results.json', 'r') as f:
    vulns = json.load(f)

# Convert to vulnerability objects
from buttf import Vulnerability
vuln_objects = [Vulnerability(**v) for v in vulns]

# Generate threat analysis
analyzer = ThreatAnalyzer(vuln_objects)
analyzer.export_report('threat_report.html', 'html')
"

This provides:
- Attack scenario modeling
- Risk scoring (CVSS-style)
- Compliance impact assessment
- Mitigation priorities
- Executive-level HTML report
""")

#Example 7: Custom configuration
print("\n" + "="*80)
print("Example 7: Using Custom Configuration")
print("="*80)
print("""
# Edit config.json with custom settings
{
  "modules": {
    "misconfig": {
      "custom_paths": [
        "/.gitlab-ci.yml",
        "/custom-config.php"
      ]
    },
    "injection": {
      "custom_sql_payloads": [
        "'; DROP TABLE users--"
      ]
    }
  }
}

# Run with custom payloads
python buttf.py -u https://example.com -m misconfig,injection
""")

#Example 8: API security testing
print("\n" + "="*80)
print("Example 8: REST API Security Assessment")
print("="*80)
print("""
python buttf.py -u https://api.example.com -m logic,auth,injection,exposure

API-focused security testing:
- Endpoint enumeration
- Parameter tampering (mass assignment)
- API authentication bypass
- Data exposure in API responses
- Injection in API parameters
""")

#Example 9: CVE hunting
print("\n" + "="*80)
print("Example 9: Known Vulnerability Detection")
print("="*80)
print("""
python buttf.py -u https://example.com -m cve,misconfig

Searches for:
- Log4Shell (CVE-2021-44228)
- Spring4Shell (CVE-2022-22965)
- Exposed version information
- Known vulnerable frameworks
""")

#Real-world scenario
print("\n" + "="*80)
print("RW Scenario: Bug Bounty Workflow")
print("="*80)
print("""
#Step 1: Initial reconnaissance
python buttf.py -u https://target.com -m misconfig,exposure -f recon.txt

#Step 2: Deep vulnerability analysis
python buttf.py -u https://target.com -m logic,injection,auth -f vulns.txt

#Step 3: CVE verification
python buttf.py -u https://target.com -m cve -f cves.txt

#Step 4: Generate comprehensive report
python buttf.py -u https://target.com -m all -o json -f final_report.json

#Step 5: Threat analysis for high-impact findings
python threat_analyzer.py final_report.json --output threat_analysis.html
""")

print("\n" + "="*80)
print("Security testing best practices")
print("="*80)
print("""
1.Always obtain written authorization before testing
2.Use responsible disclosure for findings
3.Test in isolated environments first
4.Monitor target system load
5.Document all findings thoroughly
6.Respect rate limits and system resources
7.Follow legal and ethical guidelines
8.Never exploit vulnerabilities maliciously

For more information, refer to:
-OWASP Testing Guide
-Bug Bounty Platform Guidelines
-Responsible Disclosure Policies
""")

print("\n" + "="*80)
print("For full documentation, see README.md")
print("="*80)

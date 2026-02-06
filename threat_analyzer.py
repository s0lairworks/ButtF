#!/usr/bin/env python3

#ButtF Threat Analyzer - Advanced threat analysis and reporting module

import json
from typing import List, Dict
from datetime import datetime
from collections import defaultdict

class ThreatAnalyzer:
    #Advanced threat analysis for discovered vulnerabilities
    
    def __init__(self, vulnerabilities: List):
        self.vulnerabilities = vulnerabilities
        self.threat_matrix = self._build_threat_matrix()
    
    def _build_threat_matrix(self) -> Dict:
        #Build MITRE ATT&CK-style threat matrix
        matrix = {
            'SQL Injection': {
                'tactic': 'Initial Access',
                'technique': 'T1190 - Exploit Public-Facing Application',
                'impact': 'Data Breach, System Compromise',
                'likelihood': 'High',
                'attack_vector': 'Network'
            },
            'IDOR': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1068 - Exploitation for Privilege Escalation',
                'impact': 'Unauthorized Data Access',
                'likelihood': 'High',
                'attack_vector': 'Network'
            },
            'Mass Assignment': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1068 - Exploitation for Privilege Escalation',
                'impact': 'Account Takeover, Privilege Escalation',
                'likelihood': 'Medium',
                'attack_vector': 'Network'
            },
            'Command Injection': {
                'tactic': 'Execution',
                'technique': 'T1059 - Command and Scripting Interpreter',
                'impact': 'Remote Code Execution, System Compromise',
                'likelihood': 'Critical',
                'attack_vector': 'Network'
            },
            'XSS': {
                'tactic': 'Execution',
                'technique': 'T1059.007 - JavaScript',
                'impact': 'Session Hijacking, Data Theft',
                'likelihood': 'High',
                'attack_vector': 'Network'
            },
            'CORS Misconfiguration': {
                'tactic': 'Credential Access',
                'technique': 'T1539 - Steal Web Session Cookie',
                'impact': 'Session Hijacking, Data Theft',
                'likelihood': 'Medium',
                'attack_vector': 'Network'
            },
            'JWT Security': {
                'tactic': 'Credential Access',
                'technique': 'T1552 - Unsecured Credentials',
                'impact': 'Authentication Bypass',
                'likelihood': 'High',
                'attack_vector': 'Network'
            },
            'Data Exposure': {
                'tactic': 'Collection',
                'technique': 'T1213 - Data from Information Repositories',
                'impact': 'Information Disclosure',
                'likelihood': 'Medium',
                'attack_vector': 'Network'
            },
            'Known CVE': {
                'tactic': 'Initial Access',
                'technique': 'T1190 - Exploit Public-Facing Application',
                'impact': 'System Compromise',
                'likelihood': 'Critical',
                'attack_vector': 'Network'
            }
        }
        return matrix
    
    def calculate_risk_score(self, vulnerability) -> float:
        #Calculate CVSS-style risk score#
        severity_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MEDIUM': 5.0,
            'LOW': 2.0
        }
        
        base_score = severity_scores.get(vulnerability.severity, 0)
        
        #Adjust based on category
        exploitability_factors = {
            'SQL Injection': 1.0,
            'Command Injection': 1.0,
            'Known CVE': 0.95,
            'IDOR': 0.85,
            'XSS': 0.80,
            'Mass Assignment': 0.75,
            'CORS Misconfiguration': 0.70,
            'Data Exposure': 0.65
        }
        
        factor = exploitability_factors.get(vulnerability.category, 0.5)
        return min(10.0, base_score * factor)
    
    def generate_threat_report(self) -> Dict:
        #Generate comprehensive threat analysis report
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'tool': 'ButtF Threat Analyzer'
            },
            'summary': self._generate_summary(),
            'attack_scenarios': self._generate_attack_scenarios(),
            'mitigation_priorities': self._generate_mitigation_priorities(),
            'compliance_impact': self._assess_compliance_impact(),
            'detailed_findings': self._format_detailed_findings()
        }
        return report
    
    def _generate_summary(self) -> Dict:
        #Generate executive summary
        severity_dist = defaultdict(int)
        category_dist = defaultdict(int)
        total_risk = 0
        
        for vuln in self.vulnerabilities:
            severity_dist[vuln.severity] += 1
            category_dist[vuln.category] += 1
            total_risk += self.calculate_risk_score(vuln)
        
        avg_risk = total_risk / len(self.vulnerabilities) if self.vulnerabilities else 0
        
        return {
            'severity_distribution': dict(severity_dist),
            'category_distribution': dict(category_dist),
            'average_risk_score': round(avg_risk, 2),
            'total_risk_score': round(total_risk, 2),
            'critical_findings': severity_dist['CRITICAL'],
            'high_findings': severity_dist['HIGH']
        }
    
    def _generate_attack_scenarios(self) -> List[Dict]:
        #Generate potential attack scenarios based on findings
        scenarios = []
        
        #Group vulnerabilities by attack chain potential
        vuln_categories = defaultdict(list)
        for vuln in self.vulnerabilities:
            vuln_categories[vuln.category].append(vuln)
        
        #Scenario no.1: Data breach via SQL injection
        if 'SQL Injection' in vuln_categories:
            scenarios.append({
                'name': 'Database Compromise Attack Chain',
                'severity': 'CRITICAL',
                'steps': [
                    'Attacker identifies SQL injection vulnerability',
                    'Extracts database schema information',
                    'Dumps sensitive user data including credentials',
                    'Escalates privileges using extracted admin credentials',
                    'Establishes persistent access'
                ],
                'affected_assets': [v.endpoint for v in vuln_categories['SQL Injection']],
                'business_impact': 'Complete database compromise, regulatory violations, customer data breach'
            })
        
        #Scenario no.2: Account takeover via IDOR + weak auth
        if 'IDOR' in vuln_categories and 'JWT Security' in vuln_categories:
            scenarios.append({
                'name': 'Account Takeover Chain',
                'severity': 'HIGH',
                'steps': [
                    'Attacker exploits IDOR to access other user profiles',
                    'Leverages weak JWT implementation to forge tokens',
                    'Takes over high-privilege accounts',
                    'Accesses sensitive business data'
                ],
                'affected_assets': list(set([v.endpoint for v in vuln_categories['IDOR']] + 
                                           [v.endpoint for v in vuln_categories['JWT Security']])),
                'business_impact': 'Customer account compromise, reputation damage, financial fraud'
            })
        
        #Scenario no.3: RCE via command injection
        if 'Command Injection' in vuln_categories:
            scenarios.append({
                'name': 'Remote Code Execution Attack',
                'severity': 'CRITICAL',
                'steps': [
                    'Attacker identifies command injection point',
                    'Executes arbitrary system commands',
                    'Downloads additional malware/tools',
                    'Establishes reverse shell',
                    'Lateral movement to internal systems'
                ],
                'affected_assets': [v.endpoint for v in vuln_categories['Command Injection']],
                'business_impact': 'Complete system compromise, data destruction, ransomware deployment'
            })
        
        #Scenario no.4: Data exfiltration via exposed endpoints
        if 'Data Exposure' in vuln_categories or 'Information Disclosure' in vuln_categories:
            exposed = vuln_categories.get('Data Exposure', []) + vuln_categories.get('Information Disclosure', [])
            scenarios.append({
                'name': 'Sensitive Data Exfiltration',
                'severity': 'HIGH',
                'steps': [
                    'Attacker discovers exposed sensitive endpoints',
                    'Scrapes API keys, credentials, and tokens',
                    'Uses credentials to access cloud resources',
                    'Exfiltrates confidential business data'
                ],
                'affected_assets': [v.endpoint for v in exposed],
                'business_impact': 'Intellectual property theft, cloud resource abuse, compliance violations'
            })
        
        return scenarios
    
    def _generate_mitigation_priorities(self) -> List[Dict]:
        #Generate prioritized mitigation recommendations
        priorities = []
        
        #Group by severity and calculate impact
        critical_vulns = [v for v in self.vulnerabilities if v.severity == 'CRITICAL']
        high_vulns = [v for v in self.vulnerabilities if v.severity == 'HIGH']
        
        if critical_vulns:
            priorities.append({
                'priority': 1,
                'action': 'Immediate Remediation Required',
                'timeframe': '24-48 hours',
                'vulnerabilities': len(critical_vulns),
                'categories': list(set([v.category for v in critical_vulns])),
                'recommendation': 'Deploy emergency patches, implement WAF rules, or take affected services offline'
            })
        
        if high_vulns:
            priorities.append({
                'priority': 2,
                'action': 'Urgent Remediation',
                'timeframe': '1 week',
                'vulnerabilities': len(high_vulns),
                'categories': list(set([v.category for v in high_vulns])),
                'recommendation': 'Develop and test patches, implement compensating controls'
            })
        
        #Add strategic recommendations
        priorities.append({
            'priority': 3,
            'action': 'Security Architecture Review',
            'timeframe': '2-4 weeks',
            'vulnerabilities': len(self.vulnerabilities),
            'categories': ['All'],
            'recommendation': 'Conduct comprehensive security review, implement SDLC security gates, deploy SAST/DAST tools'
        })
        
        return priorities
    
    def _assess_compliance_impact(self) -> Dict:
        #Assess impact on regulatory compliance
        compliance_issues = {
            'PCI-DSS': [],
            'GDPR': [],
            'HIPAA': [],
            'SOC2': [],
            'ISO27001': []
        }
        
        for vuln in self.vulnerabilities:
            #SQL Injection affects all
            if vuln.category == 'SQL Injection':
                compliance_issues['PCI-DSS'].append('Requirement 6.5.1 - Injection flaws')
                compliance_issues['GDPR'].append('Article 32 - Security of processing')
                compliance_issues['HIPAA'].append('164.312(a)(1) - Access Control')
                compliance_issues['SOC2'].append('CC6.1 - Logical and Physical Access Controls')
            
            #Data exposure
            if vuln.category in ['Data Exposure', 'Information Disclosure']:
                compliance_issues['GDPR'].append('Article 32 - Security of processing')
                compliance_issues['HIPAA'].append('164.312(a)(2)(iv) - Encryption')
                compliance_issues['PCI-DSS'].append('Requirement 3.4 - Render PAN unreadable')
            
            #Authentication issues
            if vuln.category in ['JWT Security', 'Session Management', 'Password Policy']:
                compliance_issues['PCI-DSS'].append('Requirement 8 - Identify and authenticate access')
                compliance_issues['SOC2'].append('CC6.1 - Logical and Physical Access Controls')
                compliance_issues['ISO27001'].append('A.9.2 - User access management')
        
        return {k: list(set(v)) for k, v in compliance_issues.items() if v}
    
    def _format_detailed_findings(self) -> List[Dict]:
        #Format detailed findings with threat intelligence
        detailed = []
        
        for vuln in self.vulnerabilities:
            threat_info = self.threat_matrix.get(vuln.category, {})
            
            finding = {
                'vulnerability': {
                    'severity': vuln.severity,
                    'category': vuln.category,
                    'endpoint': vuln.endpoint,
                    'description': vuln.description,
                    'evidence': vuln.evidence,
                    'cve_id': vuln.cve_id,
                    'remediation': vuln.remediation
                },
                'threat_intelligence': threat_info,
                'risk_score': self.calculate_risk_score(vuln),
                'exploitability': self._assess_exploitability(vuln),
                'business_impact': self._assess_business_impact(vuln)
            }
            detailed.append(finding)
        
        return sorted(detailed, key=lambda x: x['risk_score'], reverse=True)
    
    def _assess_exploitability(self, vuln) -> Dict:
        #Assess how easily the vulnerability can be exploited
        exploitability_map = {
            'SQL Injection': {'level': 'High', 'skill_required': 'Low', 'tools_available': 'Many'},
            'Command Injection': {'level': 'High', 'skill_required': 'Low', 'tools_available': 'Many'},
            'Known CVE': {'level': 'Very High', 'skill_required': 'Very Low', 'tools_available': 'Many'},
            'IDOR': {'level': 'High', 'skill_required': 'Low', 'tools_available': 'Few'},
            'XSS': {'level': 'Medium', 'skill_required': 'Medium', 'tools_available': 'Many'},
            'Mass Assignment': {'level': 'Medium', 'skill_required': 'Medium', 'tools_available': 'Few'},
            'CORS Misconfiguration': {'level': 'Medium', 'skill_required': 'Medium', 'tools_available': 'Few'},
            'Data Exposure': {'level': 'High', 'skill_required': 'Very Low', 'tools_available': 'None needed'}
        }
        
        return exploitability_map.get(vuln.category, 
                                     {'level': 'Unknown', 'skill_required': 'Unknown', 'tools_available': 'Unknown'})
    
    def _assess_business_impact(self, vuln) -> Dict:
        #Assess business impact of successful exploitation
        impact_map = {
            'SQL Injection': {
                'confidentiality': 'High',
                'integrity': 'High',
                'availability': 'High',
                'financial': 'Severe',
                'reputational': 'Severe'
            },
            'Command Injection': {
                'confidentiality': 'High',
                'integrity': 'High',
                'availability': 'High',
                'financial': 'Severe',
                'reputational': 'Severe'
            },
            'Known CVE': {
                'confidentiality': 'High',
                'integrity': 'High',
                'availability': 'High',
                'financial': 'High',
                'reputational': 'High'
            },
            'IDOR': {
                'confidentiality': 'High',
                'integrity': 'Medium',
                'availability': 'Low',
                'financial': 'High',
                'reputational': 'High'
            },
            'Data Exposure': {
                'confidentiality': 'High',
                'integrity': 'Low',
                'availability': 'Low',
                'financial': 'High',
                'reputational': 'High'
            }
        }
        
        return impact_map.get(vuln.category, {
            'confidentiality': 'Medium',
            'integrity': 'Medium',
            'availability': 'Low',
            'financial': 'Medium',
            'reputational': 'Medium'
        })
    
    def export_report(self, filename: str, format_type: str = 'json'):
        #Export threat analysis report
        report = self.generate_threat_report()
        
        if format_type == 'json':
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
        
        elif format_type == 'html':
            html = self._generate_html_report(report)
            with open(filename, 'w') as f:
                f.write(html)
        
        print(f"[+] Threat analysis report exported to {filename}")
    
    def _generate_html_report(self, report: Dict) -> str:
        #Generate HTML threat analysis report
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ButtF Threat Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #1976d2; margin-top: 30px; }}
        .critical {{ background: #f44336; color: white; padding: 5px 10px; border-radius: 3px; }}
        .high {{ background: #ff9800; color: white; padding: 5px 10px; border-radius: 3px; }}
        .medium {{ background: #ffc107; color: black; padding: 5px 10px; border-radius: 3px; }}
        .low {{ background: #4caf50; color: white; padding: 5px 10px; border-radius: 3px; }}
        .metric {{ background: #e3f2fd; padding: 15px; margin: 10px 0; border-left: 4px solid #1976d2; }}
        .scenario {{ background: #fff3e0; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #1976d2; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .footer {{ margin-top: 30px; text-align: center; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ ButtF Threat Analysis Report</h1>
        <p><strong>Generated:</strong> {report['metadata']['generated_at']}</p>
        
        <h2>Executive Summary</h2>
        <div class="metric">
            <strong>Total Vulnerabilities:</strong> {report['summary']['total_risk_score']}<br>
            <strong>Average Risk Score:</strong> {report['summary']['average_risk_score']}/10<br>
            <strong>Critical Findings:</strong> <span class="critical">{report['summary'].get('critical_findings', 0)}</span>
            <strong>High Findings:</strong> <span class="high">{report['summary'].get('high_findings', 0)}</span>
        </div>
        
        <h2>Attack Scenarios</h2>
        {''.join([f'''
        <div class="scenario">
            <h3>{scenario['name']} <span class="{scenario['severity'].lower()}">{scenario['severity']}</span></h3>
            <p><strong>Business Impact:</strong> {scenario['business_impact']}</p>
            <p><strong>Attack Steps:</strong></p>
            <ol>{''.join([f'<li>{step}</li>' for step in scenario['steps']])}</ol>
        </div>
        ''' for scenario in report['attack_scenarios']])}
        
        <h2>Mitigation Priorities</h2>
        <table>
            <tr>
                <th>Priority</th>
                <th>Action</th>
                <th>Timeframe</th>
                <th>Vulnerabilities</th>
            </tr>
            {''.join([f'''
            <tr>
                <td><strong>P{priority['priority']}</strong></td>
                <td>{priority['action']}</td>
                <td>{priority['timeframe']}</td>
                <td>{priority['vulnerabilities']}</td>
            </tr>
            ''' for priority in report['mitigation_priorities']])}
        </table>
        
        <div class="footer">
            <p>Generated by ButtF Threat Analyzer v1.0</p>
        </div>
    </div>
</body>
</html>
        """
        return html


if __name__ == '__main__':
    print("ButtF Threat Analyzer - Use with main ButtF scanner")

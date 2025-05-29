from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, has_request_context, make_response
from flask_apscheduler import APScheduler
from flask_talisman import Talisman  # Add import for security headers
import requests
from bs4 import BeautifulSoup
import hashlib
import os
import json
import difflib
import socket
import dns.resolver
import whois
import ssl
import OpenSSL
import datetime
import subprocess
import re
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from PIL import Image, ImageChops
import io
import time
import uuid
import threading
import queue
import base64
import ipaddress
from pyngrok import ngrok
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import signal
import sys
import shutil
import asyncio
import aiohttp
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
import csv
from xml.etree.ElementTree import Element, SubElement, tostring
import xml.dom.minidom
import certifi
from typing import List, Dict, Any, Optional

app = Flask(__name__)
app.secret_key = 'wasp_super_secret_key'
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Add Talisman for security headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
        'style-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:"],
        'font-src': ["'self'", "cdnjs.cloudflare.com"],
        'connect-src': ["'self'"]
    },
    force_https=False,  # Set to True in production
    session_cookie_secure=False,  # Set to True in production
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'"
    }
)

# Global configurations
CONFIG_DIR = 'config'
REPORTS_DIR = 'reports'
SCREENSHOTS_DIR = 'screenshots'
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
LAST_CHECKS_FILE = os.path.join(CONFIG_DIR, 'last_checks.json')
STATIC_DIR = 'static'
IMG_DIR = os.path.join(STATIC_DIR, 'img')
SCAN_STATUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_status')
CLOUDFLARE_URL_FILE = os.path.join(CONFIG_DIR, 'cloudflare_url.txt')
CLOUDFLARE_PID_FILE = os.path.join(CONFIG_DIR, 'cloudflare_pid.txt')

# Ensure directories exist
for directory in [CONFIG_DIR, REPORTS_DIR, SCREENSHOTS_DIR, STATIC_DIR, IMG_DIR, SCAN_STATUS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Default configuration
default_config = {
    'pushover_user_key': '',
    'pushover_api_token': '',
    'monitored_urls': [],
    'custom_message': '',
    'ignore_patterns': [],
    'change_threshold': 0.05,
    'scan_depth': 2,  # Default scan depth for crawling
    'max_urls_per_scan': 100,  # Maximum URLs to scan in one go
    'timeout': 30,  # Request timeout in seconds
    'user_agent': 'WASSp Scanner/1.0',  # Default user agent
    'concurrency': 5,  # Number of concurrent threads for scanning
    'ipqs_api_key': '',  # IP Quality Score API key
    'openai_api_key': '',  # OpenAI API key
    'enable_ai_features': False,  # Enable/disable AI features
    'ai_model': 'gpt-3.5-turbo',  # Default AI model
    'enable_visual_diff': True,  # Enable visual diff analysis
    'screenshot_width': 1920,  # Screenshot width in pixels
    'screenshot_height': 1080,  # Screenshot height in pixels
    'notify_on_scan_complete': False,  # Notify when scans complete
    'notify_on_vulnerabilities': True,  # Notify when vulnerabilities are found
    'enable_cloudflare': True,  # Enable Cloudflare tunnels
    'enable_ngrok': True,  # Enable Ngrok tunnels
    'subdomain_wordlist': 'wordlists/subdomains.txt',  # Path to subdomain wordlist
    'api_wordlist': 'wordlists/api_endpoints.txt',  # Path to API endpoint wordlist
}

# Initialize session cleanup
@app.before_request
def initialize_session():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(hours=2)  # Session expiry

# Session and resources cleanup
@app.teardown_appcontext
def cleanup_after_request(exception=None):
    # Only access session if in a request context
    if has_request_context():
        # Clean up any temporary files or resources here
        screenshots_to_clean = session.get('temp_screenshots', [])
        for file_path in screenshots_to_clean:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
        
        session.pop('temp_screenshots', None)

# Load configuration
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return default_config

# Save configuration
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Initialize configuration
config = load_config()

# NEW: Subdomain Enumeration Component
class SubdomainEnumerator:
    """Advanced subdomain enumeration using multiple techniques"""
    
    def __init__(self, config):
        self.config = config
        self.found_subdomains = set()
        
    async def enumerate_all(self, domain: str) -> List[str]:
        """Enumerate subdomains using all available methods"""
        tasks = [
            self.dns_bruteforce(domain),
            self.crtsh_enumeration(domain),
            self.dns_zone_transfer(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine all results
        for result in results:
            if isinstance(result, list):
                self.found_subdomains.update(result)
        
        return list(self.found_subdomains)
    
    async def dns_bruteforce(self, domain: str) -> List[str]:
        """Bruteforce common subdomains"""
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'cdn',
            'dev', 'staging', 'test', 'portal', 'secure', 'vpn', 'remote',
            'webmail', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'forum', 'news',
            'download', 'uploads', 'static', 'media', 'assets', 'img', 'images',
            'css', 'js', 'email', 'ww1', 'www2', 'www3', 'support', 'help',
            'docs', 'document', 'files', 'backup', 'demo', 'beta', 'alpha',
            'internal', 'private', 'public', 'cache', 'db', 'database', 'mysql',
            'git', 'svn', 'jenkins', 'gitlab', 'jira', 'confluence', 'wiki'
        ]
        
        # Load additional wordlist if configured
        if self.config.get('subdomain_wordlist') and os.path.exists(self.config['subdomain_wordlist']):
            try:
                with open(self.config['subdomain_wordlist'], 'r') as f:
                    common_subdomains.extend([line.strip() for line in f if line.strip()])
            except:
                pass
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                # Try to resolve the subdomain
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    subdomains.append(full_domain)
                    print(f"[+] Found subdomain: {full_domain}")
            except:
                pass
        
        return subdomains
    
    async def crtsh_enumeration(self, domain: str) -> List[str]:
        """Enumerate subdomains using certificate transparency logs"""
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Extract all domains from the certificate
                            for line in name_value.split('\n'):
                                if line and '*' not in line:  # Skip wildcards
                                    subdomain = line.strip().lower()
                                    if subdomain.endswith(domain) and subdomain != domain:
                                        subdomains.append(subdomain)
        except Exception as e:
            print(f"Error in crt.sh enumeration: {e}")
        
        return list(set(subdomains))
    
    async def dns_zone_transfer(self, domain: str) -> List[str]:
        """Attempt DNS zone transfer"""
        subdomains = []
        try:
            # Get name servers
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_str = str(ns).rstrip('.')
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, domain))
                    if zone:
                        for name, node in zone.nodes.items():
                            subdomain = str(name) + '.' + domain
                            if subdomain != domain:
                                subdomains.append(subdomain)
                        print(f"[!] Zone transfer successful on {ns_str}")
                except:
                    pass
        except:
            pass
        
        return subdomains

# NEW: Enhanced Technology Fingerprinting
class TechnologyFingerprinter:
    """Advanced technology detection beyond JavaScript frameworks"""
    
    def __init__(self):
        self.technologies = {
            'web_servers': {
                'nginx': ['nginx', 'Nginx'],
                'apache': ['Apache', 'apache'],
                'iis': ['Microsoft-IIS', 'IIS'],
                'litespeed': ['LiteSpeed'],
                'tomcat': ['Apache-Coyote', 'Tomcat'],
            },
            'programming_languages': {
                'php': ['X-Powered-By: PHP', '.php', 'PHPSESSID'],
                'asp.net': ['ASP.NET', 'X-AspNet-Version', '.aspx'],
                'java': ['JSESSIONID', 'java', '.jsp', '.do'],
                'python': ['wsgiserver', 'gunicorn', 'werkzeug'],
                'ruby': ['Phusion Passenger', 'mod_rails', 'mod_rack', 'Ruby'],
                'node.js': ['Express', 'X-Powered-By: Express', 'node.js'],
            },
            'cms': {
                'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json', 'WordPress'],
                'drupal': ['/sites/default/', 'Drupal', 'X-Drupal-Cache'],
                'joomla': ['/components/', '/modules/', 'Joomla'],
                'magento': ['/skin/frontend/', 'Magento', 'Mage'],
                'shopify': ['Shopify', 'shopify.com'],
                'wix': ['X-Wix-', 'wixsite.com'],
                'squarespace': ['Squarespace'],
            },
            'frameworks': {
                'laravel': ['laravel_session', 'Laravel'],
                'django': ['csrftoken', 'django'],
                'rails': ['_rails_session', 'Rails'],
                'spring': ['Spring', 'springframework'],
                'angular': ['ng-version', 'angular'],
                'react': ['_react', 'react'],
                'vue': ['vue', '__vue__'],
            },
            'analytics': {
                'google_analytics': ['google-analytics.com', 'gtag', '_ga', 'UA-'],
                'google_tag_manager': ['googletagmanager.com', 'GTM-'],
                'matomo': ['matomo', 'piwik'],
                'hotjar': ['hotjar.com', '_hjid'],
                'mixpanel': ['mixpanel.com'],
            },
            'cdn': {
                'cloudflare': ['CF-RAY', 'cloudflare'],
                'akamai': ['Akamai', 'akamaihd.net'],
                'fastly': ['Fastly', 'fastly.net'],
                'cloudfront': ['CloudFront', 'cloudfront.net'],
                'maxcdn': ['MaxCDN', 'maxcdn.com'],
            },
            'security': {
                'waf': ['X-WAF-', 'WAF', 'Web Application Firewall'],
                'sucuri': ['Sucuri', 'X-Sucuri-'],
                'wordfence': ['Wordfence'],
                'cloudflare_waf': ['cf-ray', 'CF-Cache-Status'],
            }
        }
    
    def fingerprint(self, url: str, headers: dict, content: str) -> Dict[str, List[str]]:
        """Perform comprehensive technology fingerprinting"""
        detected_tech = {category: [] for category in self.technologies.keys()}
        
        # Check headers
        headers_str = str(headers).lower()
        
        # Check content
        content_lower = content.lower()
        
        for category, technologies in self.technologies.items():
            for tech_name, signatures in technologies.items():
                for signature in signatures:
                    if signature.lower() in headers_str or signature.lower() in content_lower:
                        if tech_name not in detected_tech[category]:
                            detected_tech[category].append(tech_name)
                        break
        
        # Special checks for version detection
        detected_tech['versions'] = self._detect_versions(headers, content)
        
        # Remove empty categories
        return {k: v for k, v in detected_tech.items() if v}
    
    def _detect_versions(self, headers: dict, content: str) -> Dict[str, str]:
        """Detect specific version information"""
        versions = {}
        
        # Check headers for version info
        for header, value in headers.items():
            if 'version' in header.lower():
                versions[header] = value
            elif header.lower() == 'server':
                # Extract version from server header
                import re
                version_match = re.search(r'(\d+\.[\d\.]+)', value)
                if version_match:
                    versions['server_version'] = version_match.group(1)
        
        # Check meta tags for versions
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(content, 'html.parser')
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag and generator_tag.get('content'):
            versions['generator'] = generator_tag['content']
        
        return versions

# NEW: API Security Testing Component
class APISecurityTester:
    """Test API endpoints for security vulnerabilities"""
    
    def __init__(self, config):
        self.config = config
        self.common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/rest',
            '/graphql', '/api/graphql', '/query',
            '/swagger', '/swagger.json', '/api-docs', '/api/docs',
            '/openapi.json', '/swagger-ui', '/redoc',
            '/.well-known/openapi.json', '/api/swagger.json'
        ]
        
        # Load additional API paths if configured
        if config.get('api_wordlist') and os.path.exists(config['api_wordlist']):
            try:
                with open(config['api_wordlist'], 'r') as f:
                    self.common_api_paths.extend([line.strip() for line in f if line.strip()])
            except:
                pass
    
    def test_api_security(self, base_url: str) -> Dict[str, Any]:
        """Perform comprehensive API security testing"""
        results = {
            'endpoints_found': [],
            'vulnerabilities': [],
            'authentication': {},
            'rate_limiting': {},
            'documentation': {}
        }
        
        # Discover API endpoints
        endpoints = self._discover_endpoints(base_url)
        results['endpoints_found'] = endpoints
        
        # Test each endpoint
        for endpoint in endpoints:
            # Test authentication
            auth_results = self._test_authentication(endpoint)
            results['authentication'][endpoint] = auth_results
            
            # Test rate limiting
            rate_limit_results = self._test_rate_limiting(endpoint)
            results['rate_limiting'][endpoint] = rate_limit_results
            
            # Test for common API vulnerabilities
            vulns = self._test_api_vulnerabilities(endpoint)
            results['vulnerabilities'].extend(vulns)
        
        # Check for API documentation
        results['documentation'] = self._check_api_documentation(base_url)
        
        return results
    
    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover API endpoints"""
        discovered = []
        
        for path in self.common_api_paths:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=self.config['timeout'], allow_redirects=False)
                if response.status_code in [200, 401, 403]:
                    discovered.append(url)
                    
                    # If we found swagger/openapi, parse it
                    if 'swagger' in path or 'openapi' in path:
                        self._parse_api_documentation(response.text, base_url, discovered)
            except:
                pass
        
        return discovered
    
    def _parse_api_documentation(self, content: str, base_url: str, discovered: List[str]):
        """Parse Swagger/OpenAPI documentation for endpoints"""
        try:
            api_spec = json.loads(content)
            
            # Parse paths from OpenAPI/Swagger spec
            if 'paths' in api_spec:
                for path in api_spec['paths']:
                    full_url = urljoin(base_url, path)
                    if full_url not in discovered:
                        discovered.append(full_url)
        except:
            pass
    
    def _test_authentication(self, endpoint: str) -> Dict[str, Any]:
        """Test API authentication mechanisms"""
        results = {
            'requires_auth': False,
            'auth_methods': [],
            'vulnerabilities': []
        }
        
        # Test without authentication
        try:
            response = requests.get(endpoint, timeout=self.config['timeout'])
            if response.status_code == 401:
                results['requires_auth'] = True
            elif response.status_code == 200:
                results['vulnerabilities'].append({
                    'type': 'Missing Authentication',
                    'severity': 'High',
                    'description': f'API endpoint {endpoint} is accessible without authentication'
                })
        except:
            pass
        
        # Test common authentication bypass techniques
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
        ]
        
        for headers in bypass_headers:
            try:
                response = requests.get(endpoint, headers=headers, timeout=self.config['timeout'])
                if response.status_code == 200 and results['requires_auth']:
                    results['vulnerabilities'].append({
                        'type': 'Authentication Bypass',
                        'severity': 'Critical',
                        'description': f'Authentication bypass possible using headers: {headers}'
                    })
                    break
            except:
                pass
        
        return results
    
    def _test_rate_limiting(self, endpoint: str) -> Dict[str, Any]:
        """Test for rate limiting"""
        results = {
            'has_rate_limiting': False,
            'requests_before_limit': 0,
            'limit_response_code': None
        }
        
        # Send rapid requests to test rate limiting
        for i in range(100):
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 429:
                    results['has_rate_limiting'] = True
                    results['requests_before_limit'] = i
                    results['limit_response_code'] = 429
                    break
                elif response.status_code >= 500:
                    # Server error, stop testing
                    break
            except:
                break
        
        if not results['has_rate_limiting']:
            results['vulnerability'] = {
                'type': 'Missing Rate Limiting',
                'severity': 'Medium',
                'description': f'No rate limiting detected on {endpoint} after 100 requests'
            }
        
        return results
    
    def _test_api_vulnerabilities(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for common API vulnerabilities"""
        vulnerabilities = []
        
        # Test for API versioning issues
        if '/v1' in endpoint or '/v2' in endpoint:
            # Try older versions
            older_version = endpoint.replace('/v2', '/v1').replace('/v1', '/v0')
            try:
                response = requests.get(older_version, timeout=self.config['timeout'])
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Deprecated API Version',
                        'severity': 'Medium',
                        'description': f'Older API version accessible at {older_version}'
                    })
            except:
                pass
        
        # Test for GraphQL introspection
        if 'graphql' in endpoint:
            introspection_query = {
                'query': '{ __schema { types { name } } }'
            }
            try:
                response = requests.post(endpoint, json=introspection_query, timeout=self.config['timeout'])
                if response.status_code == 200 and '__schema' in response.text:
                    vulnerabilities.append({
                        'type': 'GraphQL Introspection Enabled',
                        'severity': 'Medium',
                        'description': 'GraphQL introspection is enabled, exposing the API schema'
                    })
            except:
                pass
        
        # Test for XXE in XML endpoints
        if endpoint.endswith('.xml') or 'xml' in endpoint:
            xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root>&xxe;</root>'''
            
            try:
                response = requests.post(
                    endpoint, 
                    data=xxe_payload, 
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.config['timeout']
                )
                if 'root:' in response.text:
                    vulnerabilities.append({
                        'type': 'XXE Vulnerability',
                        'severity': 'Critical',
                        'description': 'XML External Entity (XXE) vulnerability detected'
                    })
            except:
                pass
        
        return vulnerabilities
    
    def _check_api_documentation(self, base_url: str) -> Dict[str, Any]:
        """Check for exposed API documentation"""
        documentation = {
            'found': False,
            'urls': [],
            'type': None
        }
        
        doc_paths = [
            '/swagger', '/swagger-ui', '/swagger.json',
            '/api-docs', '/api/docs', '/docs',
            '/openapi.json', '/.well-known/openapi.json',
            '/redoc', '/graphql/playground', '/graphiql'
        ]
        
        for path in doc_paths:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=self.config['timeout'], allow_redirects=True)
                if response.status_code == 200:
                    documentation['found'] = True
                    documentation['urls'].append(url)
                    
                    if 'swagger' in path:
                        documentation['type'] = 'Swagger'
                    elif 'openapi' in path:
                        documentation['type'] = 'OpenAPI'
                    elif 'graphql' in path or 'graphiql' in path:
                        documentation['type'] = 'GraphQL'
            except:
                pass
        
        return documentation

# NEW: Cookie Security Analyzer
class CookieSecurityAnalyzer:
    """Analyze cookies for security issues"""
    
    def analyze_cookies(self, url: str) -> Dict[str, Any]:
        """Analyze all cookies from a URL for security issues"""
        results = {
            'cookies': [],
            'vulnerabilities': [],
            'security_score': 100
        }
        
        try:
            # Use a session to collect cookies
            session = requests.Session()
            response = session.get(url, timeout=30)
            
            # Analyze each cookie
            for cookie in session.cookies:
                cookie_analysis = self._analyze_single_cookie(cookie, url)
                results['cookies'].append(cookie_analysis)
                
                # Deduct points for each security issue
                if not cookie_analysis['secure'] and 'https' in url:
                    results['security_score'] -= 20
                if not cookie_analysis['httponly'] and cookie_analysis['name'].lower() in ['sessionid', 'session', 'token']:
                    results['security_score'] -= 25
                if cookie_analysis['samesite'] == 'none' or not cookie_analysis['samesite']:
                    results['security_score'] -= 15
                
                # Add vulnerabilities
                results['vulnerabilities'].extend(cookie_analysis['vulnerabilities'])
            
            # Test for session fixation
            fixation_result = self._test_session_fixation(url, session)
            if fixation_result:
                results['vulnerabilities'].append(fixation_result)
                results['security_score'] -= 30
        
        except Exception as e:
            results['error'] = str(e)
        
        results['security_score'] = max(0, results['security_score'])
        return results
    
    def _analyze_single_cookie(self, cookie, url: str) -> Dict[str, Any]:
        """Analyze a single cookie for security attributes"""
        analysis = {
            'name': cookie.name,
            'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
            'domain': cookie.domain,
            'path': cookie.path,
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'),
            'samesite': cookie.get_nonstandard_attr('SameSite'),
            'expires': cookie.expires,
            'vulnerabilities': []
        }
        
        # Check for security issues
        if 'https' in url and not cookie.secure:
            analysis['vulnerabilities'].append({
                'type': 'Missing Secure Flag',
                'severity': 'High',
                'description': f'Cookie "{cookie.name}" is missing the Secure flag on HTTPS site',
                'cookie': cookie.name
            })
        
        if cookie.name.lower() in ['sessionid', 'session', 'token', 'auth'] and not analysis['httponly']:
            analysis['vulnerabilities'].append({
                'type': 'Missing HttpOnly Flag',
                'severity': 'High',
                'description': f'Session cookie "{cookie.name}" is missing HttpOnly flag, vulnerable to XSS',
                'cookie': cookie.name
            })
        
        if not analysis['samesite']:
            analysis['vulnerabilities'].append({
                'type': 'Missing SameSite Attribute',
                'severity': 'Medium',
                'description': f'Cookie "{cookie.name}" is missing SameSite attribute, potentially vulnerable to CSRF',
                'cookie': cookie.name
            })
        elif analysis['samesite'].lower() == 'none' and not cookie.secure:
            analysis['vulnerabilities'].append({
                'type': 'Insecure SameSite=None',
                'severity': 'High',
                'description': f'Cookie "{cookie.name}" has SameSite=None without Secure flag',
                'cookie': cookie.name
            })
        
        # Check for overly permissive domain
        if cookie.domain and cookie.domain.startswith('.'):
            analysis['vulnerabilities'].append({
                'type': 'Overly Permissive Domain',
                'severity': 'Low',
                'description': f'Cookie "{cookie.name}" is set for entire domain {cookie.domain}',
                'cookie': cookie.name
            })
        
        return analysis
    
    def _test_session_fixation(self, url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """Test for session fixation vulnerability"""
        # Get initial session cookie
        initial_cookies = {c.name: c.value for c in session.cookies}
        
        # Try to set a known session ID
        test_session_id = 'wassp_test_session_12345'
        
        for cookie_name in ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'sessionid', 'session']:
            if cookie_name in initial_cookies:
                # Try to override the session
                session.cookies.set(cookie_name, test_session_id)
                
                # Make another request
                response = session.get(url)
                
                # Check if our session ID was accepted
                if session.cookies.get(cookie_name) == test_session_id:
                    return {
                        'type': 'Session Fixation',
                        'severity': 'High',
                        'description': f'Application accepts externally set session IDs for cookie "{cookie_name}"',
                        'cookie': cookie_name
                    }
        
        return None

# NEW: Comprehensive Report Exporter
class ReportExporter:
    """Export scan results in multiple formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
    
    def export_pdf(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Export scan results as PDF"""
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        
        # Title
        title_style = self.styles['Title']
        story.append(Paragraph("WASSp Security Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        
        # Count vulnerabilities
        vuln_count = 0
        for url, result in scan_results.get('results', {}).items():
            if 'vulnerabilities' in result:
                vuln_count += len(result['vulnerabilities'])
        
        summary_text = f"""
        Target URL: {scan_results.get('url', 'N/A')}<br/>
        Scan Date: {scan_results.get('timestamp', 'N/A')}<br/>
        Scan Type: {scan_results.get('scan_type', 'N/A')}<br/>
        URLs Scanned: {len(scan_results.get('target_urls', []))}<br/>
        Vulnerabilities Found: {vuln_count}<br/>
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Vulnerability Summary
        if vuln_count > 0:
            story.append(Paragraph("Vulnerabilities Found", self.styles['Heading1']))
            
            # Create vulnerability table
            vuln_data = [['URL', 'Type', 'Severity', 'Description']]
            for url, result in scan_results.get('results', {}).items():
                if 'vulnerabilities' in result:
                    for vuln in result['vulnerabilities']:
                        vuln_data.append([
                            url[:50] + '...' if len(url) > 50 else url,
                            vuln.get('type', 'N/A'),
                            vuln.get('severity', 'N/A'),
                            vuln.get('description', 'N/A')[:100] + '...'
                        ])
            
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
            story.append(PageBreak())
        
        # Detailed Results
        story.append(Paragraph("Detailed Scan Results", self.styles['Heading1']))
        
        for url, result in scan_results.get('results', {}).items():
            story.append(Paragraph(f"Results for: {url}", self.styles['Heading2']))
            
            # Add various result sections
            if 'dns_records' in result:
                story.append(Paragraph("DNS Records", self.styles['Heading3']))
                dns_text = "<br/>".join([f"{k}: {v}" for k, v in result['dns_records'].items() if v])
                story.append(Paragraph(dns_text, self.styles['Normal']))
                story.append(Spacer(1, 6))
            
            if 'ssl_info' in result and not result['ssl_info'].get('error'):
                story.append(Paragraph("SSL Certificate Information", self.styles['Heading3']))
                ssl_text = f"""
                Issuer: {result['ssl_info'].get('issuer', {}).get('CN', 'N/A')}<br/>
                Valid Until: {result['ssl_info'].get('not_after', 'N/A')}<br/>
                Expired: {'Yes' if result['ssl_info'].get('has_expired') else 'No'}<br/>
                """
                story.append(Paragraph(ssl_text, self.styles['Normal']))
                story.append(Spacer(1, 6))
            
            story.append(PageBreak())
        
        # Build PDF
        doc.build(story)
        return filename
    
    def export_json(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Export scan results as JSON"""
        with open(filename, 'w') as f:
            json.dump(scan_results, f, indent=2, default=str)
        return filename
    
    def export_csv(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Export vulnerabilities as CSV"""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['URL', 'Vulnerability Type', 'Severity', 'Description', 'Remediation']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for url, result in scan_results.get('results', {}).items():
                if 'vulnerabilities' in result:
                    for vuln in result['vulnerabilities']:
                        writer.writerow({
                            'URL': url,
                            'Vulnerability Type': vuln.get('type', 'N/A'),
                            'Severity': vuln.get('severity', 'N/A'),
                            'Description': vuln.get('description', 'N/A'),
                            'Remediation': vuln.get('remediation', 'N/A')
                        })
        
        return filename
    
    def export_html(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Export scan results as standalone HTML"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WASSp Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #2e7d32; }
                h2 { color: #4caf50; }
                .vulnerability { 
                    border: 1px solid #ddd; 
                    padding: 10px; 
                    margin: 10px 0;
                    border-radius: 5px;
                }
                .high { background-color: #ffebee; }
                .medium { background-color: #fff3e0; }
                .low { background-color: #f3e5f5; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #4caf50; color: white; }
            </style>
        </head>
        <body>
            <h1>WASSp Security Scan Report</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Target URL:</strong> {url}</p>
                <p><strong>Scan Date:</strong> {timestamp}</p>
                <p><strong>URLs Scanned:</strong> {urls_scanned}</p>
                <p><strong>Vulnerabilities Found:</strong> {vuln_count}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
            {vulnerabilities_html}
            
            <h2>Technology Stack</h2>
            {tech_stack_html}
        </body>
        </html>
        """
        
        # Count vulnerabilities
        vuln_count = 0
        vulnerabilities_html = ""
        
        for url, result in scan_results.get('results', {}).items():
            if 'vulnerabilities' in result:
                for vuln in result['vulnerabilities']:
                    vuln_count += 1
                    severity_class = vuln.get('severity', 'low').lower()
                    vulnerabilities_html += f"""
                    <div class="vulnerability {severity_class}">
                        <h3>{vuln.get('type', 'Unknown')}</h3>
                        <p><strong>URL:</strong> {url}</p>
                        <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                        <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                    </div>
                    """
        
        if vuln_count == 0:
            vulnerabilities_html = "<p>No vulnerabilities found!</p>"
        
        # Technology stack
        tech_stack_html = "<table><tr><th>Category</th><th>Technologies</th></tr>"
        main_result = scan_results.get('results', {}).get(scan_results.get('url', ''), {})
        if 'technology_stack' in main_result:
            for category, techs in main_result['technology_stack'].items():
                if techs:
                    tech_stack_html += f"<tr><td>{category}</td><td>{', '.join(techs)}</td></tr>"
        tech_stack_html += "</table>"
        
        # Fill in the template
        html_content = html_template.format(
            url=scan_results.get('url', 'N/A'),
            timestamp=scan_results.get('timestamp', 'N/A'),
            urls_scanned=len(scan_results.get('target_urls', [])),
            vuln_count=vuln_count,
            vulnerabilities_html=vulnerabilities_html,
            tech_stack_html=tech_stack_html
        )
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
    
    def export_sarif(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Export scan results in SARIF format for CI/CD integration"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "WASSp",
                        "version": "1.0",
                        "informationUri": "https://github.com/yourusername/wassp",
                        "rules": []
                    }
                },
                "results": []
            }]
        }
        
        # Add vulnerabilities as results
        rule_index = 0
        for url, result in scan_results.get('results', {}).items():
            if 'vulnerabilities' in result:
                for vuln in result['vulnerabilities']:
                    # Add rule if not exists
                    rule_id = vuln.get('type', 'UNKNOWN').replace(' ', '_').upper()
                    
                    sarif['runs'][0]['tool']['driver']['rules'].append({
                        "id": rule_id,
                        "name": vuln.get('type', 'Unknown Vulnerability'),
                        "shortDescription": {
                            "text": vuln.get('description', '')[:100]
                        },
                        "fullDescription": {
                            "text": vuln.get('description', '')
                        },
                        "defaultConfiguration": {
                            "level": self._sarif_level(vuln.get('severity', 'medium'))
                        }
                    })
                    
                    # Add result
                    sarif['runs'][0]['results'].append({
                        "ruleId": rule_id,
                        "level": self._sarif_level(vuln.get('severity', 'medium')),
                        "message": {
                            "text": vuln.get('description', 'Vulnerability detected')
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": url
                                }
                            }
                        }]
                    })
        
        with open(filename, 'w') as f:
            json.dump(sarif, f, indent=2)
        
        return filename
    
    def _sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity.lower(), 'warning')

# Enhanced Scanner with all new components
class URLScanner:
    def __init__(self, config):
        self.config = config
        self.results = {}
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.current_depth = 0
        self.stop_event = threading.Event()
        
        # Initialize new components
        self.subdomain_enumerator = SubdomainEnumerator(config)
        self.tech_fingerprinter = TechnologyFingerprinter()
        self.api_tester = APISecurityTester(config)
        self.cookie_analyzer = CookieSecurityAnalyzer()
    
    def scan_url(self, url):
        """Scan a single URL and gather information about it"""
        try:
            result = {
                'url': url,
                'timestamp': datetime.datetime.now().isoformat(),
                'status': 'success',
                'dns_records': self.get_dns_records(url),
                'whois_info': self.get_whois_info(url),
                'ssl_info': self.get_ssl_info(url),
                'headers': self.get_headers(url),
                'content_info': self.get_content_info(url),
                'ip_quality_check': self.check_ip_quality(url),
                'vulnerabilities': self.check_vulnerabilities(url),
                # NEW: Enhanced features
                'technology_stack': {},
                'cookie_security': {},
                'api_endpoints': {}
            }
            
            # NEW: Technology fingerprinting
            if result['headers'] and result['content_info']:
                content = self._get_page_content(url)
                if content:
                    result['technology_stack'] = self.tech_fingerprinter.fingerprint(
                        url, result['headers'], content
                    )
            
            # NEW: Cookie security analysis
            result['cookie_security'] = self.cookie_analyzer.analyze_cookies(url)
            
            # NEW: API security testing (only if it looks like an API)
            if self._is_api_endpoint(url):
                result['api_endpoints'] = self.api_tester.test_api_security(url)
            
            # Add cookie vulnerabilities to main vulnerabilities list
            if result['cookie_security'].get('vulnerabilities'):
                result['vulnerabilities'].extend(result['cookie_security']['vulnerabilities'])
            
            return result
        except Exception as e:
            return {
                'url': url,
                'timestamp': datetime.datetime.now().isoformat(),
                'status': 'error',
                'error_message': str(e)
            }
    
    def _get_page_content(self, url):
        """Get the full HTML content of a page"""
        try:
            response = requests.get(url, timeout=self.config['timeout'])
            return response.text
        except:
            return ""
    
    def _is_api_endpoint(self, url):
        """Check if URL appears to be an API endpoint"""
        api_indicators = ['/api', '/v1', '/v2', '/rest', '/graphql', '.json', '.xml']
        return any(indicator in url.lower() for indicator in api_indicators)
    
    async def enumerate_subdomains(self, domain):
        """Enumerate subdomains for a domain"""
        return await self.subdomain_enumerator.enumerate_all(domain)
    
    def get_domain_from_url(self, url):
        """Extract domain from URL"""
        parsed_url = urlparse(url)
        return parsed_url.netloc
    
    def get_dns_records(self, url):
        """Get DNS records for a domain"""
        domain = self.get_domain_from_url(url)
        result = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[record_type] = [str(answer) for answer in answers]
            except Exception:
                result[record_type] = []
        
        try:
            ip = socket.gethostbyname(domain)
            result['IP'] = ip
        except:
            result['IP'] = None
            
        return result
    
    def get_whois_info(self, url):
        """Get WHOIS information for a domain"""
        domain = self.get_domain_from_url(url)
        try:
            w = whois.whois(domain)
            # Convert date objects to strings for JSON serialization
            result = {}
            for key, value in w.items():
                if isinstance(value, datetime.datetime):
                    result[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime.datetime):
                    result[key] = [d.isoformat() for d in value]
                else:
                    result[key] = value
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def get_ssl_info(self, url):
        """Get SSL certificate information for a domain"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        port = 443 if parsed_url.scheme == 'https' else 80
        
        if parsed_url.scheme != 'https':
            return {"error": "Not an HTTPS URL"}
        
        try:
            cert = ssl.get_server_certificate((domain, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Extract information from the certificate
            result = {
                "subject": dict(x509.get_subject().get_components()),
                "issuer": dict(x509.get_issuer().get_components()),
                "version": x509.get_version(),
                "serial_number": x509.get_serial_number(),
                "not_before": x509.get_notBefore().decode('utf-8'),
                "not_after": x509.get_notAfter().decode('utf-8'),
                "has_expired": x509.has_expired()
            }
            
            # Convert bytes to strings in the dictionaries
            for key in ["subject", "issuer"]:
                result[key] = {k.decode('utf-8'): v.decode('utf-8') for k, v in result[key].items()}
                
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def get_headers(self, url):
        """Get HTTP headers from a URL"""
        try:
            headers = {
                'User-Agent': self.config['user_agent']
            }
            response = requests.head(url, headers=headers, timeout=self.config['timeout'], allow_redirects=True)
            return dict(response.headers)
        except Exception as e:
            return {"error": str(e)}
    
    def get_content_info(self, url):
        """Get information about the content of a URL"""
        try:
            headers = {
                'User-Agent': self.config['user_agent']
            }
            response = requests.get(url, headers=headers, timeout=self.config['timeout'])
            
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            title = soup.title.string if soup.title else None
            
            # Extract meta tags
            meta_tags = {}
            for tag in soup.find_all('meta'):
                name = tag.get('name') or tag.get('property')
                if name:
                    meta_tags[name] = tag.get('content')
            
            # Count links
            links = soup.find_all('a')
            internal_links = 0
            external_links = 0
            domain = self.get_domain_from_url(url)
            
            for link in links:
                href = link.get('href')
                if href:
                    if href.startswith('#') or not href.strip():
                        continue
                    if href.startswith('/') or domain in href:
                        internal_links += 1
                    else:
                        external_links += 1
            
            # Check for potential JavaScript frameworks
            js_frameworks = []
            scripts = soup.find_all('script')
            frameworks = {
                'jquery': 'jQuery',
                'react': 'React',
                'vue': 'Vue',
                'angular': 'Angular',
                'bootstrap': 'Bootstrap'
            }
            
            for script in scripts:
                src = script.get('src', '')
                content = script.string if script.string else ''
                for key, framework in frameworks.items():
                    if key in src.lower() or (content and key in content.lower()):
                        js_frameworks.append(framework)
            
            # Remove duplicates
            js_frameworks = list(set(js_frameworks))
            
            # Get content hash
            content_hash = hashlib.sha256(response.content).hexdigest()
            
            return {
                "title": title,
                "meta_tags": meta_tags,
                "internal_links": internal_links,
                "external_links": external_links,
                "js_frameworks": js_frameworks,
                "content_length": len(response.content),
                "content_type": response.headers.get('Content-Type'),
                "content_hash": content_hash,
                "status_code": response.status_code
            }
        except Exception as e:
            return {"error": str(e)}
    
    def check_ip_quality(self, url):
        """Check IP quality using IP Quality Score API"""
        if not self.config.get('ipqs_api_key'):
            return {"error": "IP Quality Score API key not configured"}
        
        domain = self.get_domain_from_url(url)
        api_key = self.config.get('ipqs_api_key')
        
        try:
            api_url = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{urllib.parse.quote_plus(url)}"
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def check_vulnerabilities(self, url):
        """Basic vulnerability checks"""
        vulnerabilities = []
        
        try:
            # Check for XSS vulnerabilities
            xss_vulnerability = self.check_xss(url)
            if xss_vulnerability:
                vulnerabilities.append(xss_vulnerability)
            
            # Check for SQL Injection vulnerabilities
            sqli_vulnerability = self.check_sqli(url)
            if sqli_vulnerability:
                vulnerabilities.append(sqli_vulnerability)
            
            # Check for open directories
            open_dir_vulnerability = self.check_open_directories(url)
            if open_dir_vulnerability:
                vulnerabilities.append(open_dir_vulnerability)
            
            # Check for common misconfigurations
            misconfig_vulnerability = self.check_misconfigurations(url)
            if misconfig_vulnerability:
                vulnerabilities.append(misconfig_vulnerability)
            
            return vulnerabilities
        except Exception as e:
            return [{"type": "error", "description": f"Error during vulnerability check: {str(e)}"}]
    
    def check_xss(self, url):
        """Simple check for XSS vulnerabilities"""
        # Look for URL parameters to test
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return None
        
        test_payloads = ["<script>alert(1)</script>", "javascript:alert(1)"]
        
        try:
            for payload in test_payloads:
                params = urllib.parse.parse_qs(parsed_url.query)
                for param in params:
                    # Create a test URL with the XSS payload
                    test_params = params.copy()
                    test_params[param] = [payload]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))
                    
                    # Send the request
                    headers = {'User-Agent': self.config['user_agent']}
                    response = requests.get(test_url, headers=headers, timeout=self.config['timeout'])
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        return {
                            "type": "XSS",
                            "description": f"Potential XSS vulnerability found in parameter: {param}",
                            "url": test_url,
                            "severity": "High"
                        }
            
            return None
        except Exception as e:
            return {
                "type": "XSS Check Error",
                "description": f"Error checking for XSS: {str(e)}",
                "severity": "Info"
            }
    
    def check_sqli(self, url):
        """Simple check for SQL Injection vulnerabilities"""
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return None
        
        test_payloads = ["'", "1' OR '1'='1", "1' AND '1'='2"]
        error_patterns = [
            "sql syntax", 
            "mysql error", 
            "sql server error",
            "ORA-", 
            "postgresql error",
            "sqlite error"
        ]
        
        try:
            for payload in test_payloads:
                params = urllib.parse.parse_qs(parsed_url.query)
                for param in params:
                    # Create a test URL with the SQLi payload
                    test_params = params.copy()
                    test_params[param] = [payload]
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        query_string,
                        parsed_url.fragment
                    ))
                    
                    # Send the request
                    headers = {'User-Agent': self.config['user_agent']}
                    response = requests.get(test_url, headers=headers, timeout=self.config['timeout'])
                    
                    # Check for SQL error patterns in the response
                    response_text = response.text.lower()
                    for pattern in error_patterns:
                        if pattern in response_text:
                            return {
                                "type": "SQL Injection",
                                "description": f"Potential SQL Injection vulnerability found in parameter: {param}",
                                "url": test_url,
                                "severity": "High"
                            }
            
            return None
        except Exception as e:
            return {
                "type": "SQLi Check Error",
                "description": f"Error checking for SQL Injection: {str(e)}",
                "severity": "Info"
            }
    
    def check_open_directories(self, url):
        """Check for open directories with improved error handling"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        directories_to_check = [
            "/admin/",
            "/backup/",
            "/config/",
            "/db/",
            "/logs/",
        ]
        
        try:
            headers = {'User-Agent': self.config['user_agent']}
            for directory in directories_to_check:
                try:
                    test_url = urljoin(base_url, directory)
                    response = requests.get(test_url, headers=headers, timeout=self.config['timeout'])
                    
                    # Check if the directory listing is enabled
                    if response.status_code == 200 and ("Index of" in response.text or "Directory Listing" in response.text):
                        return {
                            "type": "Open Directory",
                            "description": f"Directory listing enabled at: {directory}",
                            "url": test_url,
                            "severity": "Medium"
                        }
                except requests.Timeout:
                    # Skip this directory on timeout, but continue checking others
                    continue
                except Exception as dir_error:
                    # Log the error but continue with other directories
                    print(f"Error checking directory {directory}: {str(dir_error)}")
                    continue
            
            return None
        except Exception as e:
            return {
                "type": "Directory Check Error",
                "description": f"Error checking for open directories: {str(e)}",
                "severity": "Info"
            }

    def check_misconfigurations(self, url):
        """Check for common misconfigurations with improved error handling"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        files_to_check = [
            "/.git/config",
            "/.env",
            "/wp-config.php",
            "/config.php",
            "/phpinfo.php",
            "/info.php"
        ]
        
        try:
            headers = {'User-Agent': self.config['user_agent']}
            for file_path in files_to_check:
                try:
                    test_url = urljoin(base_url, file_path)
                    response = requests.get(test_url, headers=headers, timeout=self.config['timeout'])
                    
                    if response.status_code == 200:
                        # Check specific patterns for each file
                        if file_path == "/.git/config" and "[core]" in response.text:
                            return {
                                "type": "Git Repository Exposure",
                                "description": "Git repository configuration is publicly accessible",
                                "url": test_url,
                                "severity": "High"
                            }
                        elif file_path == "/.env" and "DB_" in response.text:
                            return {
                                "type": "Environment File Exposure",
                                "description": "Environment configuration file is publicly accessible",
                                "url": test_url,
                                "severity": "Critical"
                            }
                        elif ("wp-config" in file_path or "config.php" in file_path) and "DB_NAME" in response.text:
                            return {
                                "type": "Configuration File Exposure",
                                "description": "PHP configuration file with sensitive information is publicly accessible",
                                "url": test_url,
                                "severity": "Critical"
                            }
                        elif ("phpinfo" in file_path or "info.php" in file_path) and "PHP Version" in response.text:
                            return {
                                "type": "PHP Info Exposure",
                                "description": "PHP information is publicly accessible",
                                "url": test_url,
                                "severity": "Medium"
                            }
                except requests.Timeout:
                    # Skip this file on timeout, but continue checking others
                    continue
                except Exception as file_error:
                    # Log the error but continue with other files
                    print(f"Error checking file {file_path}: {str(file_error)}")
                    continue
            
            return None
        except Exception as e:
            return {
                "type": "Misconfiguration Check Error",
                "description": f"Error checking for misconfigurations: {str(e)}",
                "severity": "Info"
            }
    
    def crawl_site(self, url, max_depth=2, max_urls=100):
        """Crawl a website to find all URLs to scan"""
        self.visited_urls = set()
        self.url_queue = queue.Queue()
        self.current_depth = 0
        self.stop_event.clear()
        
        # Parse the starting URL to get the base domain
        parsed_start_url = urlparse(url)
        base_domain = parsed_start_url.netloc
        
        # Add the starting URL to the queue
        self.url_queue.put((url, 0))  # (url, depth)
        
        discovered_urls = []
        
        while not self.url_queue.empty() and len(discovered_urls) < max_urls and not self.stop_event.is_set():
            current_url, depth = self.url_queue.get()
            
            if current_url in self.visited_urls or depth > max_depth:
                continue
            
            self.visited_urls.add(current_url)
            discovered_urls.append(current_url)
            
            if depth < max_depth:
                try:
                    headers = {'User-Agent': self.config['user_agent']}
                    response = requests.get(current_url, headers=headers, timeout=self.config['timeout'])
                    
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        for link in soup.find_all('a'):
                            href = link.get('href')
                            if not href:
                                continue
                            
                            # Convert relative URL to absolute URL
                            absolute_url = urljoin(current_url, href)
                            parsed_url = urlparse(absolute_url)
                            
                            # Make sure we stay on the same domain
                            if parsed_url.netloc == base_domain and absolute_url not in self.visited_urls:
                                self.url_queue.put((absolute_url, depth + 1))
                except Exception as e:
                    print(f"Error crawling {current_url}: {str(e)}")
        
        return discovered_urls
    
    def stop_scan(self):
        """Stop the current scan"""
        self.stop_event.set()

# Keep all existing classes (DefacementMonitor, AIAnalyzer, etc.) as they are
# They remain unchanged from the original code

# Defacement Monitor integration
class DefacementMonitor:
    def __init__(self, config):
        self.config = config
        self.previous_hashes = {}
        self.previous_contents = {}
        self.previous_screenshots = {}
        self.last_checks = {}
        
        # Load last checks
        self.load_last_checks()
    
    def load_last_checks(self):
        if os.path.exists(LAST_CHECKS_FILE):
            with open(LAST_CHECKS_FILE, 'r') as f:
                self.last_checks = json.load(f)
        else:
            self.last_checks = {}
    
    def save_last_checks(self):
        with open(LAST_CHECKS_FILE, 'w') as f:
            json.dump(self.last_checks, f)
    
    def get_page_content(self, url):
        try:
            response = requests.get(url)
            return response.text
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_page_hash(self, content):
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def get_detailed_changes(self, old_content, new_content):
        differ = difflib.Differ()
        diff = list(differ.compare(old_content.splitlines(), new_content.splitlines()))
        return "\n".join(diff)
    
    def take_screenshot(self, url):
        driver = None
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            
            driver = webdriver.Chrome(options=options)
            
            # Set screenshot size from config
            width = self.config.get('screenshot_width', 1920)
            height = self.config.get('screenshot_height', 1080)
            driver.set_window_size(width, height)
            
            # Set page load timeout
            driver.set_page_load_timeout(self.config.get('timeout', 30))
            
            driver.get(url)
            # Wait a bit for dynamic content to load
            time.sleep(2)
            screenshot = driver.get_screenshot_as_png()
            return Image.open(io.BytesIO(screenshot))
        except Exception as e:
            print(f"Error taking screenshot of {url}: {str(e)}")
            # Return a blank image in case of error
            return Image.new('RGB', (800, 600), color=(240, 240, 240))
        finally:
            # Always close the driver
            if driver:
                try:
                    driver.quit()
                except:
                    pass
    
    def compare_screenshots(self, old_screenshot, new_screenshot):
        diff = ImageChops.difference(old_screenshot, new_screenshot)
        return diff.getbbox() is not None
    
    def is_significant_change(self, old_content, new_content):
        for pattern in self.config.get('ignore_patterns', []):
            if pattern in old_content or pattern in new_content:
                return False
        diff_ratio = difflib.SequenceMatcher(None, old_content, new_content).ratio()
        return (1 - diff_ratio) > self.config.get('change_threshold', 0.05)
    
    def check_for_changes(self):
        monitored_urls = self.config.get('monitored_urls', [])
        for url in monitored_urls:
            new_content = self.get_page_content(url)
            new_hash = self.get_page_hash(new_content)
            
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_checks[url] = current_time
            self.save_last_checks()
            
            report_filename = f"report_{url.replace('://', '_').replace('/', '_')}.txt"
            report_path = os.path.join(REPORTS_DIR, report_filename)
            
            # Take screenshot if visual diff is enabled
            if self.config.get('enable_visual_diff', True):
                new_screenshot = self.take_screenshot(url)
                screenshot_filename = f"{url.replace('://', '_').replace('/', '_')}.png"
                screenshot_path = os.path.join(SCREENSHOTS_DIR, screenshot_filename)
                # Always save the new screenshot
                new_screenshot.save(screenshot_path)
            else:
                new_screenshot = None
            
            if url not in self.previous_hashes:
                self.previous_hashes[url] = new_hash
                self.previous_contents[url] = new_content
                if new_screenshot:
                    self.previous_screenshots[url] = new_screenshot
                
                with open(report_path, "w") as f:
                    f.write(f"Initial check for {url} at {current_time}\n")
                    f.write("No previous content to compare.\n\n")
                
                continue
            
            content_changed = new_hash != self.previous_hashes[url] and self.is_significant_change(self.previous_contents[url], new_content)
            visual_changed = False
            
            if new_screenshot and url in self.previous_screenshots:
                visual_changed = self.compare_screenshots(self.previous_screenshots[url], new_screenshot)
            
            with open(report_path, "a") as f:
                f.write(f"\nCheck performed for {url} at {current_time}\n")
                
                if content_changed or (visual_changed and self.config.get('enable_visual_diff', True)):
                    f.write("Changes detected:\n")
                    
                    if content_changed:
                        changes = self.get_detailed_changes(self.previous_contents[url], new_content)
                        f.write("Content changes:\n")
                        f.write(changes)
                        f.write("\n")
                    
                    if visual_changed and self.config.get('enable_visual_diff', True):
                        f.write("Visual changes detected in the screenshot.\n")
                    
                    self.send_notification(f"Changes detected on {url}. Report: {report_filename}, Screenshot: {url}")
                else:
                    f.write("No significant changes detected.\n\n")
            
            self.previous_hashes[url] = new_hash
            self.previous_contents[url] = new_content
            if new_screenshot:
                self.previous_screenshots[url] = new_screenshot
    
    def send_notification(self, message):
        if not self.config.get('pushover_user_key') or not self.config.get('pushover_api_token'):
            return False
        
        custom_message = self.config.get('custom_message', '')
        if custom_message:
            message = f"{custom_message}\n\n{message}"
        
        payload = {
            'token': self.config.get('pushover_api_token'),
            'user': self.config.get('pushover_user_key'),
            'message': message
        }
        
        try:
            response = requests.post('https://api.pushover.net/1/messages.json', data=payload)
            return response.status_code == 200
        except Exception:
            return False

# AI Analysis component
class AIAnalyzer:
    """
    AI-powered vulnerability analysis and remediation advisor
    This is the optional AI feature that uses OpenAI's API to analyze vulnerabilities
    and provide detailed remediation steps
    """
    def __init__(self, config):
        self.config = config
    
    def analyze_vulnerability_remediation(self, vulnerabilities, scan_results):
        """
        Generate detailed remediation steps for vulnerabilities using OpenAI API
        This is the single AI-powered feature that's completely optional
        """
        if not self.config.get('openai_api_key') or not self.config.get('enable_ai_features'):
            return {"error": "OpenAI API key not configured or AI features not enabled"}
        
        if not vulnerabilities and not scan_results:
            return {"status": "success", "analysis": "No vulnerabilities or scan results found to analyze."}
        
        try:
            api_key = self.config.get('openai_api_key')
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            
            # Include relevant scan information for better context
            context = {
                "url": scan_results.get("url", "Unknown"),
                "server_info": scan_results.get("headers", {}).get("Server", "Unknown"),
                "content_type": scan_results.get("content_info", {}).get("content_type", "Unknown"),
                "ssl_info": scan_results.get("ssl_info", {}),
                "vulnerabilities": vulnerabilities
            }
            
            prompt = f"""
            As a security expert, analyze these web security scan results and provide a detailed remediation plan:

            SCAN CONTEXT:
            {json.dumps(context, indent=2)}

            For each issue, please provide:
            1. Risk assessment: Explain the potential impact and severity of each vulnerability
            2. Detailed remediation steps: Specific, actionable instructions to fix each issue
            3. Defensive coding: Where applicable, provide code examples or configuration changes
            4. Security best practices: Additional hardening measures beyond fixing the immediate issues
            5. Priority order: Which issues should be addressed first and why

            Format your response in clear sections with headings and prioritized action items.
            """
            
            model = self.config.get('ai_model', 'gpt-3.5-turbo')
            
            data = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are an expert web security consultant providing detailed vulnerability remediation advice."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,  # Lower temperature for more consistent technical advice
                "max_tokens": 2000
            }
            
            response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)
            
            if response.status_code == 200:
                result = response.json()
                analysis = result["choices"][0]["message"]["content"]
                return {
                    "status": "success",
                    "analysis": analysis
                }
            else:
                return {
                    "status": "error",
                    "error": f"OpenAI API error: {response.status_code} - {response.text}"
                }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Error during AI vulnerability analysis: {str(e)}"
            }

# Initialize components
url_scanner = URLScanner(config)
defacement_monitor = DefacementMonitor(config)
ai_analyzer = AIAnalyzer(config)
report_exporter = ReportExporter()

def check_scan_completion():
    """Check if a scan has completed and update session if needed"""
    # Get current scan URL
    scan_url = session.get('scan_url')
    if not scan_url:
        return
    
    # Check if there's a completed scan report file
    scan_completion_file = os.path.join(REPORTS_DIR, f"scan_completion_{hashlib.md5(scan_url.encode()).hexdigest()}.json")
    
    if os.path.exists(scan_completion_file):
        try:
            with open(scan_completion_file, 'r') as f:
                scan_data = json.load(f)
            
            # Update session with scan completion status and report path
            # DO NOT store the actual results in session (too large)
            session['scan_completed'] = True
            session['report_path'] = scan_data.get('report_path')
            session['active_scan'] = False
            session.modified = True
            
            # Remove the completion file since we've processed it
            os.remove(scan_completion_file)
            
            return True
        except:
            pass
    
    return False

# Robust scan function implementation
def run_scan(url, scan_type, crawl_depth, concurrency, timeout):
    """Run a scan in the background with smooth, incremental progress tracking"""
    try:
        # Create a unique ID for this scan
        scan_id = hashlib.md5(url.encode()).hexdigest()
        progress_file = os.path.join(REPORTS_DIR, f"scan_progress_{scan_id}.json")
        
        # Initialize progress
        progress_data = {
            'progress': 5,
            'stage': 'Starting scan...',
            'completed': False,
            'error': None,
            'url': url,
            'scanned_urls': 0
        }
        
        # Helper function to update progress
        def update_progress(percent, stage, scanned=None):
            nonlocal progress_data
            progress_data['progress'] = percent
            progress_data['stage'] = stage
            if scanned is not None:
                progress_data['scanned_urls'] = scanned
            with open(progress_file, 'w') as f:
                json.dump(progress_data, f)
            # Sleep a tiny bit to ensure progress updates are visible
            time.sleep(0.1)  
        
        # Write initial progress
        update_progress(5, 'Starting scan...')
        
        # Update scanner configuration for this scan
        url_scanner.config.update({
            'scan_depth': crawl_depth,
            'concurrency': concurrency,
            'timeout': timeout
        })
        
        # Update progress: 10%
        update_progress(10, 'Configuration updated')
        
        # NEW: Check if subdomain enumeration is needed
        domain = url_scanner.get_domain_from_url(url)
        if scan_type in ['full', 'advanced'] and domain:
            update_progress(12, 'Enumerating subdomains...')
            try:
                # Run subdomain enumeration
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                subdomains = loop.run_until_complete(url_scanner.enumerate_subdomains(domain))
                loop.close()
                
                if subdomains:
                    update_progress(15, f'Found {len(subdomains)} subdomains')
                    # Add subdomains to target URLs for advanced scan
                    if scan_type == 'advanced':
                        # Note: You might want to limit this or make it configurable
                        pass  # For now, we'll just scan the main domain
            except Exception as e:
                print(f"Error enumerating subdomains: {e}")
        
        # Crawl the site if needed
        target_urls = [url]
        if scan_type == 'full' or scan_type == 'advanced':
            # Progress from 15% to 30% during crawling
            update_progress(15, 'Crawling website...')
            
            # Perform crawl
            try:
                target_urls = url_scanner.crawl_site(url, max_depth=crawl_depth, max_urls=config.get('max_urls_per_scan', 100))
                
                # Progressive updates from 15% to 30% during crawling
                for i in range(16, 30, 3):
                    update_progress(i, f'Analyzing discovered URLs...')
                    time.sleep(0.1)
                
            except Exception as crawl_error:
                print(f"[Scan {scan_id}] Error during crawling: {crawl_error}")
                target_urls = [url]
        
        # Update progress after crawl: 30%
        update_progress(30, f'Found {len(target_urls)} URLs to scan')
        
        # Break down the scanning progress (30% to 95%) into stages
        scan_components = {
            'preparation': {'start': 30, 'end': 35, 'message': 'Preparing scan tools...'},
            'dns': {'start': 35, 'end': 40, 'message': 'Checking DNS records...'},
            'ssl': {'start': 40, 'end': 45, 'message': 'Verifying SSL certificates...'},
            'headers': {'start': 45, 'end': 50, 'message': 'Analyzing HTTP headers...'},
            'content': {'start': 50, 'end': 60, 'message': 'Examining page content...'},
            'vulnerabilities': {'start': 60, 'end': 95, 'message': 'Scanning for vulnerabilities...'}
        }
        
        # Scan each URL
        all_results = {}
        all_vulnerabilities = {}
        
        # Update progress for each component before starting
        update_progress(scan_components['preparation']['start'], scan_components['preparation']['message'])
        time.sleep(0.2)  # Small delay to show progress
        
        # Process URLs
        progress_per_url = (95 - 35) / max(1, len(target_urls))
        
        for i, target_url in enumerate(target_urls):
            try:
                # Update progress for current URL
                current_progress = min(95, 35 + int((i) * progress_per_url))
                update_progress(current_progress, f'Scanning URL {i+1}/{len(target_urls)}: {target_url}', i)
                
                # Perform the scan with all new features
                result = url_scanner.scan_url(target_url)
                all_results[target_url] = result
                if 'vulnerabilities' in result and result['vulnerabilities']:
                    all_vulnerabilities[target_url] = result['vulnerabilities']
                
                # Update progress after completing this URL
                current_progress = min(95, 35 + int((i+1) * progress_per_url))
                update_progress(current_progress, f'Completed URL {i+1}/{len(target_urls)}', i+1)
            except Exception as scan_error:
                print(f"Error scanning {target_url}: {scan_error}")
                all_results[target_url] = {
                    'url': target_url,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'status': 'error',
                    'error_message': str(scan_error)
                }
        
        # Store the results
        scan_results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'url': url,
            'scan_type': scan_type,
            'target_urls': target_urls,
            'results': all_results,
            'vulnerabilities_found': len(all_vulnerabilities) > 0
        }
        
        # Update progress: 95%
        update_progress(95, 'Saving results...', len(target_urls))
        time.sleep(0.2)
        
        # Save the results to a file
        scan_id_str = str(uuid.uuid4())
        report_path = os.path.join(REPORTS_DIR, f"scan_{scan_id_str}.json")
        with open(report_path, 'w') as f:
            json.dump(scan_results, f, indent=4)
        
        # Update progress: 97%
        update_progress(97, 'Generating report...', len(target_urls))
        time.sleep(0.2)
        
        # Write a completion file to signal the main app
        completion_file = os.path.join(REPORTS_DIR, f"scan_completion_{scan_id}.json")
        with open(completion_file, 'w') as f:
            json.dump({
                'results': scan_results,
                'report_path': report_path
            }, f)
        
        # Update progress: 99%
        update_progress(99, 'Finalizing scan...', len(target_urls))
        time.sleep(0.2)
        
        # Update progress: 100%
        update_progress(100, 'Scan completed!', len(target_urls))
        progress_data['completed'] = True
        with open(progress_file, 'w') as f:
            json.dump(progress_data, f)
        
        # Send notification if enabled
        if config.get('notify_on_scan_complete'):
            message = f"Scan completed for {url}. "
            if all_vulnerabilities and config.get('notify_on_vulnerabilities'):
                vuln_count = sum(len(vulns) for vulns in all_vulnerabilities.values())
                message += f"Found {vuln_count} vulnerabilities!"
            defacement_monitor.send_notification(message)
        
    except Exception as e:
        print(f"Critical error during scan: {e}")
        # Update progress with error
        try:
            progress_data['error'] = str(e)
            progress_data['stage'] = 'Error occurred during scan'
            with open(progress_file, 'w') as f:
                json.dump(progress_data, f)
        except:
            pass
        
        # Write error to a file
        error_file = os.path.join(REPORTS_DIR, f"scan_error_{scan_id}.txt")
        with open(error_file, 'w') as f:
            f.write(str(e))

# Cloudflare functions
def get_cloudflare_url():
    """Get the Cloudflare tunnel URL from the file"""
    if os.path.exists(CLOUDFLARE_URL_FILE):
        try:
            with open(CLOUDFLARE_URL_FILE, 'r') as f:
                return f.read().strip()
        except:
            return None
    return None

def is_cloudflare_running():
    """Check if the Cloudflare tunnel is running"""
    if os.path.exists(CLOUDFLARE_PID_FILE):
        try:
            with open(CLOUDFLARE_PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process is running
            if os.name == 'nt':  # Windows
                try:
                    subprocess.check_output(['tasklist', '/FI', f'PID eq {pid}'], stderr=subprocess.DEVNULL)
                    return True
                except:
                    return False
            else:  # Unix/Linux
                try:
                    os.kill(pid, 0)
                    return True
                except:
                    return False
        except:
            return False
    return False

# Flask routes
@app.route('/')
def index():
    return render_template('index.html', config=config)

@app.route('/dashboard')
def dashboard():
    # Check if there are any active scans
    active_scan = session.get('active_scan', False)
    
    # Get the latest scan results if available
    scan_results = {}
    report_path = session.get('report_path')
    if report_path and os.path.exists(report_path):
        try:
            with open(report_path, 'r') as f:
                scan_results = json.load(f)
        except:
            scan_results = {}
    
    # Get defacement monitor status
    monitor_job_status = scheduler.get_job('DefacementMonitorJob') is not None
    
    # Get monitored URLs and last checks
    monitored_urls = config.get('monitored_urls', [])
    
    # Check for Cloudflare tunnel URL and status
    cloudflare_url = get_cloudflare_url()
    cloudflare_running = is_cloudflare_running()
    
    # Clean up stale Cloudflare files if needed
    if not cloudflare_running and os.path.exists(CLOUDFLARE_PID_FILE):
        try:
            os.remove(CLOUDFLARE_PID_FILE)
        except:
            pass
        
    if not cloudflare_running and cloudflare_url and os.path.exists(CLOUDFLARE_URL_FILE):
        try:
            os.remove(CLOUDFLARE_URL_FILE)
            cloudflare_url = None
        except:
            pass
    
    return render_template(
        'dashboard.html',
        active_scan=active_scan,
        scan_results=scan_results,
        monitor_job_status=monitor_job_status,
        monitored_urls=monitored_urls,
        last_checks=defacement_monitor.last_checks,
        config=config,
        cloudflare_url=cloudflare_url,
        cloudflare_running=cloudflare_running,
        ngrok_url=session.get('ngrok_url')
    )

@app.route('/scan', methods=['POST'])
def start_scan():
    url = request.form.get('url')
    scan_type = request.form.get('scan_type', 'basic')
    crawl_depth = int(request.form.get('crawl_depth', config.get('scan_depth', 2)))
    concurrency = int(request.form.get('concurrency', config.get('concurrency', 5)))
    timeout = int(request.form.get('timeout', config.get('timeout', 30)))
    
    if not url:
        flash('Please enter a URL to scan', 'danger')
        return redirect(url_for('index'))
    
    # Clear previous scan completion marker if exists
    old_url = session.get('scan_url')
    if old_url:
        old_completion_file = os.path.join(REPORTS_DIR, f"scan_completion_{hashlib.md5(old_url.encode()).hexdigest()}.json")
        if os.path.exists(old_completion_file):
            os.remove(old_completion_file)
        old_error_file = os.path.join(REPORTS_DIR, f"scan_error_{hashlib.md5(old_url.encode()).hexdigest()}.txt")
        if os.path.exists(old_error_file):
            os.remove(old_error_file)
    
    # Reset scan-related session data
    session.pop('scan_completed', None)
    session.pop('scan_results', None)
    session.pop('report_path', None)
    session.pop('scan_error', None)
    
    # Store scan parameters in session
    session['active_scan'] = True
    session['scan_url'] = url
    session['scan_type'] = scan_type
    session['crawl_depth'] = crawl_depth
    session.modified = True
    
    # Start the scan in a background thread
    scan_thread = threading.Thread(target=run_scan, args=(url, scan_type, crawl_depth, concurrency, timeout))
    scan_thread.daemon = True
    scan_thread.start()
    
    flash('Scan started successfully!', 'success')
    return redirect(url_for('scan_status'))

@app.route('/scan/status')
def scan_status():
    # Check if scan has completed
    check_scan_completion()
    
    active_scan = session.get('active_scan', False)
    scan_completed = session.get('scan_completed', False)
    scan_error = session.get('scan_error', None)
    
    # Check if there's an error file
    scan_url = session.get('scan_url')
    if scan_url and not scan_error:
        error_file = os.path.join(REPORTS_DIR, f"scan_error_{hashlib.md5(scan_url.encode()).hexdigest()}.txt")
        if os.path.exists(error_file):
            with open(error_file, 'r') as f:
                scan_error = f.read()
            session['scan_error'] = scan_error
            session['active_scan'] = False
            session.modified = True
            os.remove(error_file)
    
    if scan_completed:
        return redirect(url_for('scan_result'))
    
    return render_template(
        'scan_status.html',
        active_scan=active_scan,
        scan_url=session.get('scan_url'),
        scan_type=session.get('scan_type'),
        crawl_depth=session.get('crawl_depth'),
        scan_error=scan_error
    )

@app.route('/scan/result')
def scan_result():
    # Load scan results from file
    report_path = session.get('report_path')
    if not report_path or not os.path.exists(report_path):
        flash('No scan results available', 'warning')
        return redirect(url_for('index'))
    
    with open(report_path, 'r') as f:
        scan_results = json.load(f)
    
    return render_template('scan_result.html', scan_results=scan_results, config=config)

@app.route('/scan/stop', methods=['POST'])
def stop_scan():
    url_scanner.stop_scan()
    session['active_scan'] = False
    session.modified = True  # Ensure session changes are saved
    flash('Scan stopped', 'warning')
    return redirect(url_for('index'))

# NEW: Export endpoints
@app.route('/scan/export/<format>')
def export_scan_results(format):
    """Export scan results in various formats"""
    # Try to get scan_id from the report_path in session
    scan_id = None
    report_path = session.get('report_path')
    if report_path:
        # Extract scan_id from report_path (e.g., "reports/scan_UUID.json")
        filename = os.path.basename(report_path)
        if filename.startswith('scan_') and filename.endswith('.json'):
            scan_id = filename[5:-5]  # Remove "scan_" prefix and ".json" suffix
    
    if not scan_id:
        flash('No scan results to export', 'warning')
        return redirect(url_for('dashboard'))
    
    # Load scan results
    report_path = os.path.join(REPORTS_DIR, f"scan_{scan_id}.json")
    if not os.path.exists(report_path):
        flash('Scan results not found', 'danger')
        return redirect(url_for('dashboard'))
    
    with open(report_path, 'r') as f:
        scan_results = json.load(f)
    
    # Generate filename
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"wassp_report_{timestamp}"
    
    try:
        if format == 'pdf':
            filename = os.path.join(REPORTS_DIR, f"{base_filename}.pdf")
            report_exporter.export_pdf(scan_results, filename)
            return send_file(filename, as_attachment=True, download_name=f"{base_filename}.pdf")
        
        elif format == 'json':
            filename = os.path.join(REPORTS_DIR, f"{base_filename}.json")
            report_exporter.export_json(scan_results, filename)
            return send_file(filename, as_attachment=True, download_name=f"{base_filename}.json")
        
        elif format == 'csv':
            filename = os.path.join(REPORTS_DIR, f"{base_filename}.csv")
            report_exporter.export_csv(scan_results, filename)
            return send_file(filename, as_attachment=True, download_name=f"{base_filename}.csv")
        
        elif format == 'html':
            filename = os.path.join(REPORTS_DIR, f"{base_filename}.html")
            report_exporter.export_html(scan_results, filename)
            return send_file(filename, as_attachment=True, download_name=f"{base_filename}.html")
        
        elif format == 'sarif':
            filename = os.path.join(REPORTS_DIR, f"{base_filename}.sarif")
            report_exporter.export_sarif(scan_results, filename)
            return send_file(filename, as_attachment=True, download_name=f"{base_filename}.sarif")
        
        else:
            flash('Invalid export format', 'danger')
            return redirect(url_for('scan_result'))
    
    except Exception as e:
        flash(f'Error exporting report: {str(e)}', 'danger')
        return redirect(url_for('scan_result'))

@app.route('/monitor/start', methods=['POST'])
def start_monitoring():
    interval = int(request.form.get('interval', 10))
    cron_schedule = request.form.get('schedule', '')
    monitor_mode = request.form.get('monitor_mode', 'interval')
    
    # Update defacement monitor config
    defacement_monitor.config = config
    
    if monitor_mode == 'cron' and cron_schedule:
        cron_parts = cron_schedule.split()
        if len(cron_parts) == 5:
            scheduler.add_job(
                id='DefacementMonitorJob',
                func=defacement_monitor.check_for_changes,
                trigger='cron',
                minute=cron_parts[0],
                hour=cron_parts[1],
                day=cron_parts[2],
                month=cron_parts[3],
                day_of_week=cron_parts[4]
            )
        else:
            flash('Invalid cron schedule format', 'danger')
            return redirect(url_for('defacement_settings'))
    else:
        scheduler.add_job(
            id='DefacementMonitorJob',
            func=defacement_monitor.check_for_changes,
            trigger='interval',
            minutes=interval
        )
    
    # Run the job once immediately
    scheduler.add_job(
        id='ImmediateDefacementCheck',
        func=defacement_monitor.check_for_changes,
        trigger='date',
        run_date=datetime.datetime.now()
    )
    
    flash('Defacement monitoring started!', 'success')
    return redirect(url_for('defacement_dashboard'))

@app.route('/monitor/stop', methods=['POST'])
def stop_monitoring():
    try:
        scheduler.remove_job('DefacementMonitorJob')
        flash('Defacement monitoring stopped', 'warning')
    except Exception:
        flash('Defacement monitoring was not running', 'info')
    
    return redirect(url_for('defacement_dashboard'))

@app.route('/config', methods=['GET', 'POST'])
def configure():
    global config
    
    if request.method == 'POST':
        # Update global config
        config.update({
            'pushover_user_key': request.form.get('pushover_user_key', ''),
            'pushover_api_token': request.form.get('pushover_api_token', ''),
            'custom_message': request.form.get('custom_message', ''),
            'change_threshold': float(request.form.get('change_threshold', 5)) / 100,
            'scan_depth': int(request.form.get('scan_depth', 2)),
            'max_urls_per_scan': int(request.form.get('max_urls_per_scan', 100)),
            'timeout': int(request.form.get('timeout', 30)),
            'user_agent': request.form.get('user_agent', 'WASSp Scanner/1.0'),
            'concurrency': int(request.form.get('concurrency', 5)),
            'ipqs_api_key': request.form.get('ipqs_api_key', ''),
            'ai_model': request.form.get('ai_model', 'gpt-3.5-turbo'),
            'notify_on_scan_complete': request.form.get('notify_on_scan_complete') == 'on',
            'notify_on_vulnerabilities': request.form.get('notify_on_vulnerabilities') == 'on',
            'enable_cloudflare': request.form.get('enable_cloudflare') == 'on',
            'enable_ngrok': request.form.get('enable_ngrok') == 'on',
            'enable_ai_features': request.form.get('enable_ai_features') == 'on',
            'cloudflared_path': request.form.get('cloudflared_path', ''),
            'subdomain_wordlist': request.form.get('subdomain_wordlist', ''),
            'api_wordlist': request.form.get('api_wordlist', '')
        })
        
        
        # Only update OpenAI API key if it's not empty (to avoid overwriting with empty string)
        openai_api_key = request.form.get('openai_api_key', '')
        if openai_api_key:
            config['openai_api_key'] = openai_api_key
        
        # Handle multiple select for ignore patterns
        ignore_patterns = request.form.getlist('ignore_patterns')
        config['ignore_patterns'] = ignore_patterns
        
        # Save configuration
        save_config(config)
        
        # Update components with new config
        url_scanner.config = config
        defacement_monitor.config = config
        ai_analyzer.config = config
        
        flash('Configuration saved successfully!', 'success')
        return redirect(url_for('configure'))
    
    return render_template('config.html', config=config)

@app.route('/api/set_openai_key', methods=['POST'])
def set_openai_key():
    """Set the OpenAI API key for the AI vulnerability analysis feature"""
    api_key = request.form.get('openai_api_key', '')
    
    if not api_key:
        return jsonify({'status': 'error', 'message': 'API key is required'}), 400
    
    # Update configuration
    config['openai_api_key'] = api_key
    config['enable_ai_features'] = True
    
    # Save configuration
    save_config(config)
    
    # Update AI analyzer
    ai_analyzer.config = config
    
    # Update session to reflect the change
    session['ai_config_updated'] = True
    session.modified = True
    
    return jsonify({'status': 'success', 'message': 'OpenAI API key configured successfully'})

@app.route('/api/scan_progress')
def api_scan_progress():
    """Return the current progress of a scan with detailed status"""
    # Check for completion before responding
    completion = check_scan_completion()
    
    # Get current scan URL
    scan_url = session.get('scan_url')
    if not scan_url:
        return jsonify({
            'active': False,
            'completed': False,
            'error': 'No active scan',
            'scanned_urls': 0,
            'progress': 0,
            'stage': 'No scan in progress'
        })
    
    # Generate scan ID
    scan_id = hashlib.md5(scan_url.encode()).hexdigest()
    
    # Check if there's a progress file
    progress_file = os.path.join(REPORTS_DIR, f"scan_progress_{scan_id}.json")
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r') as f:
                progress_data = json.load(f)
            
            # If completed, update session and return 100%
            if progress_data.get('completed', False) or completion:
                return jsonify({
                    'active': False,
                    'completed': True,
                    'error': None,
                    'scanned_urls': progress_data.get('scanned_urls', 0),
                    'progress': 100,
                    'stage': 'Scan completed successfully!'
                })
            
            # Return current progress
            return jsonify({
                'active': True,
                'completed': False,
                'error': progress_data.get('error'),
                'scanned_urls': progress_data.get('scanned_urls', 0),
                'progress': progress_data.get('progress', 0),
                'stage': progress_data.get('stage', 'Scanning...')
            })
        except Exception as e:
            print(f"Error reading progress file: {e}")
    
    # Check for error file
    error_file = os.path.join(REPORTS_DIR, f"scan_error_{scan_id}.txt")
    if os.path.exists(error_file):
        try:
            with open(error_file, 'r') as f:
                error_message = f.read()
            
            # Update session with error
            session['scan_error'] = error_message
            session['active_scan'] = False
            session.modified = True
            
            # Remove the error file
            os.remove(error_file)
            
            return jsonify({
                'active': False,
                'completed': False,
                'error': error_message,
                'scanned_urls': 0,
                'progress': 0,
                'stage': 'Error occurred'
            })
        except:
            pass
    
    # Fall back to session data
    active_scan = session.get('active_scan', False)
    completed = session.get('scan_completed', False)
    
    # Get target URLs count from report if available
    target_urls_count = 0
    if completed and session.get('report_path'):
        try:
            with open(session.get('report_path'), 'r') as f:
                scan_data = json.load(f)
                target_urls_count = len(scan_data.get('target_urls', []))
        except:
            pass
    
    return jsonify({
        'active': active_scan and not completed,
        'completed': completed,
        'error': session.get('scan_error'),
        'scanned_urls': target_urls_count,
        'progress': 100 if completed else (10 if active_scan else 0),
        'stage': 'Scanning in progress...' if active_scan else 'No scan active'
    })

@app.route('/api/analyze_vulnerabilities', methods=['POST'])
def api_analyze_vulnerabilities():
    """
    API endpoint for AI-powered vulnerability analysis.
    This is the single optional AI feature that requires an OpenAI API key.
    """
    # Check if AI features are enabled
    if not config.get('enable_ai_features'):
        return jsonify({
            'status': 'error',
            'message': 'AI features are not enabled. Enable them in the configuration.'
        }), 400
    
    # Check if OpenAI API key is configured
    if not config.get('openai_api_key'):
        return jsonify({
            'status': 'error',
            'message': 'OpenAI API key not configured. Add it in the configuration or use the popup.',
            'need_api_key': True
        }), 400
    
    # Get scan results from the request or session
    scan_id = request.form.get('scan_id')
    if not scan_id:
        # Try to get scan_id from the report_path in session
        report_path = session.get('report_path')
        if report_path:
            # Extract scan_id from report_path (e.g., "reports/scan_UUID.json")
            import os.path
            filename = os.path.basename(report_path)
            if filename.startswith('scan_') and filename.endswith('.json'):
                scan_id = filename[5:-5]  # Remove "scan_" prefix and ".json" suffix
    
    if not scan_id:
        return jsonify({
            'status': 'error',
            'message': 'No scan ID provided.'
        }), 400
    
    # Load scan results from file
    report_path = os.path.join(REPORTS_DIR, f"scan_{scan_id}.json")
    if not os.path.exists(report_path):
        return jsonify({
            'status': 'error',
            'message': 'Scan results not found.'
        }), 404
    
    with open(report_path, 'r') as f:
        scan_results = json.load(f)
    
    # Extract vulnerabilities from scan results
    vulnerabilities = []
    for url, result in scan_results.get('results', {}).items():
        if 'vulnerabilities' in result and result['vulnerabilities']:
            for vuln in result['vulnerabilities']:
                vuln['url'] = url
                vulnerabilities.append(vuln)
    
    if not vulnerabilities:
        return jsonify({
            'status': 'success',
            'message': 'No vulnerabilities found to analyze.',
            'analysis': 'No vulnerabilities were detected in the scan. Your site appears to be secure against the basic checks performed.'
        })
    
    # Use the AI analyzer for vulnerability remediation
    main_url = scan_results.get('url')
    main_result = scan_results.get('results', {}).get(main_url, {})
    analysis_result = ai_analyzer.analyze_vulnerability_remediation(vulnerabilities, main_result)
    
    if analysis_result.get('status') == 'success':
        # Save the AI analysis to the scan results
        scan_results['ai_analysis'] = {
            'timestamp': datetime.datetime.now().isoformat(),
            'analysis': analysis_result.get('analysis')
        }
        
        # Update the scan results file
        with open(report_path, 'w') as f:
            json.dump(scan_results, f, indent=4)
        
        # Don't store large scan results in session
        session.modified = True  # Ensure session changes are saved
        
        return jsonify({
            'status': 'success',
            'analysis': analysis_result.get('analysis')
        })
    else:
        return jsonify({
            'status': 'error',
            'message': analysis_result.get('error', 'Unknown error during AI analysis.')
        }), 500

@app.route('/defacement/settings', methods=['GET', 'POST'])
def defacement_settings():
    global config
    
    if request.method == 'POST':
        # Update monitored URLs
        urls = [url.strip() for url in request.form.get('monitored_urls', '').split(',') if url.strip()]
        config['monitored_urls'] = urls
        
        # Update notification settings
        config['pushover_user_key'] = request.form.get('pushover_user_key', '')
        config['pushover_api_token'] = request.form.get('pushover_api_token', '')
        config['custom_message'] = request.form.get('custom_message', '')
        
        # Update ignore patterns
        ignore_patterns = request.form.getlist('ignore_patterns')
        config['ignore_patterns'] = ignore_patterns
        
        # Update change threshold
        config['change_threshold'] = float(request.form.get('change_threshold', 5)) / 100
        
        # Update screenshot settings
        config['enable_visual_diff'] = request.form.get('enable_visual_diff') == 'on'
        config['screenshot_width'] = int(request.form.get('screenshot_width', 1920))
        config['screenshot_height'] = int(request.form.get('screenshot_height', 1080))
        
        # Save configuration
        save_config(config)
        
        # Update defacement monitor
        defacement_monitor.config = config
        
        # Send test notification if requested
        if request.form.get('test_notification') == 'on':
            success = defacement_monitor.send_notification('This is a test notification from WASSp Defacement Monitor')
            if success:
                flash('Test notification sent successfully!', 'success')
            else:
                flash('Failed to send test notification. Check your Pushover configuration.', 'danger')
        
        flash('Defacement monitor settings saved!', 'success')
        return redirect(url_for('defacement_settings'))
    
    return render_template(
        'defacement_settings.html',
        config=config,
        monitored_urls=','.join(config.get('monitored_urls', []))
    )

@app.route('/defacement/dashboard')
def defacement_dashboard():
    # Check if the monitor is running
    monitor_job_status = scheduler.get_job('DefacementMonitorJob') is not None
    
    # Get monitored URLs and last checks
    monitored_urls = config.get('monitored_urls', [])
    
    return render_template(
        'defacement_dashboard.html',
        monitor_job_status=monitor_job_status,
        monitored_urls=monitored_urls,
        last_checks=defacement_monitor.last_checks,
        config=config
    )

@app.route('/defacement/report/<path:url>')
def download_defacement_report(url):
    report_filename = f"report_{url.replace('://', '_').replace('/', '_')}.txt"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    if not os.path.exists(report_path):
        # Create a report file if it doesn't exist
        with open(report_path, 'w') as f:
            f.write(f"No checks have been performed yet for {url}\n")
            f.write(f"Last known check time: {defacement_monitor.last_checks.get(url, 'Never')}\n")
            f.write(f"Current monitoring status: {'Active' if scheduler.get_job('DefacementMonitorJob') else 'Inactive'}\n")
    
    return send_file(report_path, as_attachment=True)

@app.route('/defacement/screenshot/<path:url>')
def get_defacement_screenshot(url):
    screenshot_filename = f"{url.replace('://', '_').replace('/', '_')}.png"
    screenshot_path = os.path.join(SCREENSHOTS_DIR, screenshot_filename)
    
    if not os.path.exists(screenshot_path):
        # Check if we have a placeholder image
        placeholder_path = os.path.join(IMG_DIR, 'no-screenshot.png')
        if not os.path.exists(placeholder_path):
            # Create a simple placeholder image
            placeholder = Image.new('RGB', (800, 600), color=(240, 240, 240))
            placeholder.save(placeholder_path)
        
        return send_file(placeholder_path)
    
    return send_file(screenshot_path)

@app.route('/start_cloudflare_tunnel', methods=['POST'])
def start_cloudflare_tunnel():
    """Start a Cloudflare tunnel for public access using a simpler approach"""
    if not config.get('enable_cloudflare', True):
        flash('Cloudflare tunnels are disabled in the configuration', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get cloudflared executable path from config or use default paths
    cloudflared_path = config.get('cloudflared_path', '')
    if not cloudflared_path:
        # Try common locations
        possible_paths = [
            'cloudflared',  # If in PATH
            os.path.expanduser('~/.cloudflared/cloudflared'),
            os.path.expanduser('~/.cloudflared/cloudflared.exe'),
            'C:\\Users\\{}\\AppData\\Local\\cloudflared\\cloudflared.exe'.format(os.getenv('USERNAME')),
            'C:\\cloudflared\\cloudflared.exe',
            '/usr/local/bin/cloudflared',
            '/usr/bin/cloudflared'
        ]
        
        for path in possible_paths:
            try:
                # Test if executable exists
                if os.path.isfile(path) or (path == 'cloudflared' and shutil.which('cloudflared')):
                    cloudflared_path = path
                    break
            except:
                continue
    
    if not cloudflared_path:
        flash('Cloudflared not found. Please install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Simple approach: run cloudflared and capture its output
        tunnel_process = subprocess.Popen(
            [cloudflared_path, 'tunnel', '--url', f'http://localhost:{app.config.get("PORT", 5000)}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Create a thread to monitor the output
        def monitor_output():
            for line in tunnel_process.stdout:
                print(line.strip())  # Echo to console
                
                # Look for the URL in the output
                if "trycloudflare.com" in line:
                    match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                    if match:
                        tunnel_url = match.group(0)
                        print(f"Found Cloudflare URL: {tunnel_url}")
                        
                        # Save to file for persistence
                        try:
                            with open(CLOUDFLARE_URL_FILE, 'w') as f:
                                f.write(tunnel_url)
                        except Exception as e:
                            print(f"Error saving URL to file: {e}")
        
        # Start the monitor thread
        monitor_thread = threading.Thread(target=monitor_output)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Save PID for stopping later
        with open(CLOUDFLARE_PID_FILE, 'w') as f:
            f.write(str(tunnel_process.pid))
        
        # Save path to cloudflared
        if not config.get('cloudflared_path') and cloudflared_path != 'cloudflared':
            config['cloudflared_path'] = cloudflared_path
            save_config(config)
            
        flash('Cloudflare tunnel started! The URL will appear on the dashboard in a few seconds.', 'success')
        
        # Redirect to dashboard
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Failed to start Cloudflare tunnel: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/stop_cloudflare_tunnel', methods=['POST'])
def stop_cloudflare_tunnel():
    """Stop the running Cloudflare tunnel using a simpler approach"""
    if os.path.exists(CLOUDFLARE_PID_FILE):
        try:
            # Read the PID
            with open(CLOUDFLARE_PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            
            # Kill the process
            if os.name == 'nt':  # Windows
                os.system(f'taskkill /F /PID {pid}')
            else:  # Unix/Linux
                os.kill(pid, signal.SIGTERM)
            
            # Clean up files
            os.remove(CLOUDFLARE_PID_FILE)
            if os.path.exists(CLOUDFLARE_URL_FILE):
                os.remove(CLOUDFLARE_URL_FILE)
            
            flash('Cloudflare tunnel stopped', 'warning')
        except Exception as e:
            flash(f'Error stopping Cloudflare tunnel: {str(e)}', 'danger')
    else:
        flash('No running Cloudflare tunnel found', 'info')
    
    return redirect(url_for('dashboard'))

@app.route('/get_cloudflare_url')
def get_cloudflare_url_api():
    """API endpoint to get the current Cloudflare tunnel URL"""
    return jsonify({
        'url': get_cloudflare_url(),
        'running': is_cloudflare_running()
    })

@app.route('/start_ngrok_tunnel', methods=['POST'])
def start_ngrok_tunnel():
    """Start an ngrok tunnel for public access"""
    if not config.get('enable_ngrok', True):
        flash('Ngrok tunnels are disabled in the configuration', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Open an ngrok tunnel to the app
        public_url = ngrok.connect(app.config.get("PORT", 5000)).public_url
        flash(f'Ngrok tunnel started! Public URL: {public_url}', 'success')
        session['ngrok_url'] = public_url
        session.modified = True  # Ensure session changes are saved
    except Exception as e:
        flash(f'Failed to start ngrok tunnel: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

# API endpoints for AJAX calls
@app.route('/api/test_notification', methods=['POST'])
def api_test_notification():
    """Send a test notification using Pushover"""
    message = request.form.get('message', 'This is a test notification from WASSp.')
    
    success = defacement_monitor.send_notification(message)
    
    if success:
        return jsonify({'status': 'success', 'message': 'Test notification sent successfully!'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to send test notification. Check your Pushover configuration.'})

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

# Jinja filters for templates
@app.template_filter('tojson')
def tojson_filter(obj):
    return json.dumps(obj)

@app.template_filter('date')
def format_date(value, format='%Y-%m-%d %H:%M:%S'):
    if value:
        if isinstance(value, str):
            try:
                dt = datetime.datetime.fromisoformat(value)
                return dt.strftime(format)
            except:
                return value
        elif isinstance(value, datetime.datetime):
            return value.strftime(format)
    return value

# Jinja global functions for templates
@app.context_processor
def utility_processor():
    def now(format='%Y'):
        return datetime.datetime.now().strftime(format)
    
    return dict(now=now)

# Add signal handling for graceful shutdown
def signal_handler(sig, frame):
    print("Shutting down gracefully...")
    # Clean up any running scans
    url_scanner.stop_scan()
    # Stop the scheduler
    scheduler.shutdown()
    # Exit
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Initialize application
if __name__ == '__main__':
    # Create default configuration if it doesn't exist
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config)
    
    # Ensure directories exist
    for directory in [CONFIG_DIR, REPORTS_DIR, SCREENSHOTS_DIR, STATIC_DIR, IMG_DIR, SCAN_STATUS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    # Create default wordlists if they don't exist
    os.makedirs('wordlists', exist_ok=True)
    
    # Create default subdomain wordlist
    if not os.path.exists('wordlists/subdomains.txt'):
        with open('wordlists/subdomains.txt', 'w') as f:
            subdomains = [
                # Development/Testing
                'dev', 'development', 'stage', 'staging', 'test', 'testing', 'uat', 'demo', 'alpha', 'beta', 'preview',
                'sandbox', 'debug', 'qa', 'qa1', 'qa2', 'test1', 'test2', 'test3', 'dev1', 'dev2', 'dev3',
                
                # Common Services
                'www', 'www2', 'www3', 'web', 'web1', 'web2', 'app', 'apps', 'application', 'portal', 'user', 'users',
                'admin', 'administrator', 'panel', 'control', 'controlpanel', 'manager', 'management', 'root',
                
                # API Related
                'api', 'api1', 'api2', 'api3', 'api-v1', 'api-v2', 'api-v3', 'rest', 'restapi', 'ws', 'webservice',
                'service', 'services', 'graphql', 'graph', 'rpc', 'jsonrpc', 'xmlrpc', 'soap', 'wsdl',
                
                # Mail Services
                'mail', 'email', 'smtp', 'pop', 'pop3', 'imap', 'webmail', 'exchange', 'owa', 'outlook', 'mx', 'mx1', 'mx2',
                'relay', 'mailserver', 'newsletter', 'lists', 'subscribe', 'unsubscribe', 'postmaster', 'hostmaster',
                
                # Database/Storage
                'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb', 'redis', 'elastic', 'elasticsearch',
                'sql', 'phpmyadmin', 'pma', 'dbadmin', 'adminer', 'pgadmin', 'data', 'datastore', 'storage',
                
                # CDN/Static Content
                'cdn', 'cdn1', 'cdn2', 'static', 'static1', 'static2', 'assets', 'images', 'img', 'imgs', 'image',
                'media', 'upload', 'uploads', 'download', 'downloads', 'files', 'content', 'resources',
                
                # Security/Auth
                'secure', 'ssl', 'auth', 'authentication', 'oauth', 'oauth2', 'sso', 'login', 'signin', 'signup',
                'register', 'account', 'accounts', 'identity', 'id', 'passport', 'connect', 'gateway',
                
                # Infrastructure
                'vpn', 'remote', 'rdp', 'ssh', 'ftp', 'sftp', 'ftps', 'tftp', 'backup', 'backups', 'bak',
                'monitor', 'monitoring', 'nagios', 'zabbix', 'grafana', 'kibana', 'prometheus', 'logs', 'logging',
                'logstash', 'metrics', 'stats', 'statistics', 'analytics', 'elk', 'apm',
                
                # Communication
                'chat', 'talk', 'im', 'messaging', 'slack', 'teams', 'discord', 'irc', 'jabber', 'xmpp',
                'conference', 'meet', 'meeting', 'zoom', 'webrtc', 'sip', 'voip', 'pbx', 'phone', 'call',
                
                # Documentation/Support
                'docs', 'documentation', 'doc', 'help', 'support', 'kb', 'knowledge', 'knowledgebase', 'faq',
                'wiki', 'confluence', 'jira', 'ticket', 'tickets', 'helpdesk', 'servicedesk', 'desk',
                
                # Development Tools
                'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'repository', 'code', 'source',
                'ci', 'cd', 'jenkins', 'travis', 'circleci', 'pipeline', 'build', 'deploy', 'deployment',
                'docker', 'registry', 'hub', 'k8s', 'kubernetes', 'swarm', 'rancher', 'openshift',
                
                # Business/Commercial
                'shop', 'store', 'ecommerce', 'cart', 'checkout', 'payment', 'pay', 'invoice', 'billing',
                'order', 'orders', 'customer', 'customers', 'crm', 'erp', 'sales', 'marketing', 'campaign',
                'newsletter', 'blog', 'news', 'press', 'about', 'contact', 'partners', 'clients',
                
                # Geographic/Language
                'us', 'uk', 'eu', 'asia', 'africa', 'australia', 'canada', 'india', 'china', 'japan',
                'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'cn', 'jp', 'kr', 'ar', 'nl',
                
                # Mobile
                'm', 'mobile', 'mob', 'ios', 'android', 'app', 'apps', 'smartphone', 'tablet', 'responsive',
                
                # Miscellaneous
                'old', 'new', 'legacy', 'v1', 'v2', 'v3', 'temp', 'temporary', 'bak', 'backup', 'archive',
                'mirror', 'failover', 'disaster', 'recovery', 'dr', 'ha', 'lb', 'loadbalancer', 'proxy',
                'forward', 'reverse', 'gateway', 'firewall', 'waf', 'shield', 'protect', 'security',
                'private', 'public', 'internal', 'external', 'extranet', 'intranet', 'partner', 'b2b',
                'local', 'localhost', 'home', 'office', 'corporate', 'enterprise', 'global', 'world',
                'info', 'information', 'service', 'system', 'systems', 'network', 'net', 'infra'
            ]
            f.write('\n'.join(subdomains))
        
        # Create default API endpoint wordlist
    if not os.path.exists('wordlists/api_endpoints.txt'):
        with open('wordlists/api_endpoints.txt', 'w') as f:
            api_endpoints = [
                # Basic API paths
                '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4', '/api/v5',
                '/v1', '/v2', '/v3', '/rest', '/rest/v1', '/rest/v2',
                '/graphql', '/graphql/v1', '/query', '/api/graphql',
                
                # User Management
                '/api/users', '/api/user', '/api/profile', '/api/profiles', '/api/account', '/api/accounts',
                '/api/users/list', '/api/users/search', '/api/users/create', '/api/users/update', '/api/users/delete',
                '/api/users/{id}', '/api/user/{id}', '/api/profile/{id}', '/api/me', '/api/self',
                '/api/register', '/api/signup', '/api/registration', '/api/create-account',
                
                # Authentication & Authorization
                '/api/auth', '/api/authenticate', '/api/login', '/api/signin', '/api/logout', '/api/signout',
                '/api/auth/login', '/api/auth/logout', '/api/auth/refresh', '/api/auth/token', '/api/auth/verify',
                '/api/token', '/api/tokens', '/api/refresh', '/api/refresh-token', '/api/access-token',
                '/api/oauth', '/api/oauth2', '/api/oauth/token', '/api/oauth/authorize', '/api/oauth/callback',
                '/api/sso', '/api/saml', '/api/oidc', '/api/jwt', '/api/session', '/api/sessions',
                '/api/password', '/api/password/reset', '/api/password/forgot', '/api/password/change',
                '/api/2fa', '/api/mfa', '/api/otp', '/api/verify', '/api/confirm',
                
                # Admin & Management
                '/api/admin', '/api/admin/users', '/api/admin/config', '/api/admin/settings', '/api/admin/system',
                '/api/admin/logs', '/api/admin/audit', '/api/admin/backup', '/api/admin/restore',
                '/api/management', '/api/manager', '/api/control', '/api/panel', '/api/dashboard',
                '/api/config', '/api/configuration', '/api/settings', '/api/preferences', '/api/options',
                
                # Data & CRUD Operations
                '/api/data', '/api/list', '/api/search', '/api/filter', '/api/query', '/api/find',
                '/api/create', '/api/read', '/api/update', '/api/delete', '/api/save', '/api/store',
                '/api/get', '/api/post', '/api/put', '/api/patch', '/api/remove',
                '/api/items', '/api/item', '/api/resources', '/api/resource', '/api/entities', '/api/entity',
                '/api/records', '/api/record', '/api/entries', '/api/entry',
                
                # File & Media
                '/api/upload', '/api/uploads', '/api/download', '/api/downloads', '/api/file', '/api/files',
                '/api/media', '/api/images', '/api/image', '/api/documents', '/api/document',
                '/api/attachment', '/api/attachments', '/api/assets', '/api/asset',
                '/api/export', '/api/import', '/api/backup', '/api/restore',
                
                # Communication & Messaging
                '/api/message', '/api/messages', '/api/email', '/api/emails', '/api/mail', '/api/send',
                '/api/notification', '/api/notifications', '/api/alert', '/api/alerts', '/api/push',
                '/api/sms', '/api/chat', '/api/conversation', '/api/conversations', '/api/thread', '/api/threads',
                '/api/comment', '/api/comments', '/api/reply', '/api/feedback', '/api/contact',
                
                # E-commerce & Payments
                '/api/products', '/api/product', '/api/catalog', '/api/inventory', '/api/stock',
                '/api/cart', '/api/carts', '/api/basket', '/api/checkout', '/api/order', '/api/orders',
                '/api/payment', '/api/payments', '/api/transaction', '/api/transactions', '/api/invoice', '/api/invoices',
                '/api/billing', '/api/subscription', '/api/subscriptions', '/api/pricing', '/api/plans',
                '/api/customer', '/api/customers', '/api/client', '/api/clients',
                
                # Analytics & Monitoring
                '/api/analytics', '/api/stats', '/api/statistics', '/api/metrics', '/api/reports', '/api/report',
                '/api/logs', '/api/log', '/api/events', '/api/event', '/api/tracking', '/api/track',
                '/api/monitor', '/api/monitoring', '/api/health', '/api/healthcheck', '/api/status', '/api/ping',
                '/api/audit', '/api/history', '/api/activity', '/api/usage', '/api/performance',
                
                # Integration & Webhooks
                '/api/webhook', '/api/webhooks', '/api/hook', '/api/hooks', '/api/callback', '/api/callbacks',
                '/api/integration', '/api/integrations', '/api/connect', '/api/sync', '/api/synchronize',
                '/api/third-party', '/api/external', '/api/partner', '/api/partners',
                
                # Search & Discovery
                '/api/search', '/api/find', '/api/lookup', '/api/discover', '/api/explore',
                '/api/autocomplete', '/api/suggest', '/api/suggestions', '/api/typeahead',
                '/api/filter', '/api/filters', '/api/sort', '/api/category', '/api/categories',
                '/api/tag', '/api/tags', '/api/label', '/api/labels',
                
                # API Documentation
                '/api/docs', '/api/documentation', '/api/swagger', '/api/swagger.json', '/api/swagger.yaml',
                '/api/openapi', '/api/openapi.json', '/api/openapi.yaml', '/api/spec', '/api/specification',
                '/api/schema', '/api/schemas', '/api/reference', '/api/help', '/api/info',
                '/api/.well-known', '/.well-known/openapi.json', '/api-docs', '/swagger-ui', '/redoc',
                
                # Versioning Variations
                '/api/latest', '/api/current', '/api/stable', '/api/beta', '/api/alpha', '/api/dev',
                '/api/v1.0', '/api/v1.1', '/api/v2.0', '/api/v2.1', '/api/v3.0',
                '/api/2021', '/api/2022', '/api/2023', '/api/2024', '/api/2025',
                
                # Common Vulnerabilities
                '/api/debug', '/api/test', '/api/testing', '/api/demo', '/api/temp', '/api/tmp',
                '/api/backup', '/api/backups', '/api/old', '/api/new', '/api/legacy',
                '/api/_debug', '/api/_internal', '/api/_private', '/api/_admin',
                '/api/.git', '/api/.svn', '/api/.env', '/api/config.json', '/api/settings.json',
                
                # GraphQL Specific
                '/graphql', '/graphql/console', '/graphql/graphiql', '/graphiql', '/playground',
                '/graphql/schema', '/graphql/introspection', '/altair', '/voyager',
                
                # WebSocket & Real-time
                '/ws', '/websocket', '/socket', '/socket.io', '/hub', '/stream', '/sse',
                '/api/ws', '/api/websocket', '/api/stream', '/api/live', '/api/realtime',
                
                # Mobile API Endpoints
                '/api/mobile', '/api/ios', '/api/android', '/api/app', '/api/device', '/api/devices',
                '/api/push', '/api/push/register', '/api/push/notify', '/api/gcm', '/api/fcm', '/api/apns'
            ]
            f.write('\n'.join(api_endpoints))
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)
#!/usr/bin/env python3
"""
Passive Reconnaissance Module
Performs comprehensive passive reconnaissance including DNS, subdomains, tech stack, and OSINT
"""

import os
import sys
import json
import time
import requests
import dns.resolver
import whois
import socket
import ssl
import hashlib
import subprocess
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style
import xml.etree.ElementTree as ET

class PassiveRecon:
    def __init__(self, target, config, wordlists, api_keys):
        self.target = target
        self.config = config
        self.wordlists = wordlists
        self.api_keys = api_keys
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
        
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Running Passive Reconnaissance...{Style.RESET_ALL}")
        
        # WHOIS information
        self.results['whois'] = self.get_whois_info()
        
        # DNS enumeration
        self.results['dns'] = self.get_dns_records()
        
        # DNSDumpster integration
        self.results['dnsdumpster'] = self.query_dnsdumpster()
        
        # Certificate transparency (crt.sh)
        self.results['crt_sh'] = self.query_crt_sh()
        
        # SSL certificate information
        self.results['certificates'] = self.get_certificate_info()
        
        # Subdomain enumeration
        self.results['subdomains'] = self.enumerate_subdomains()
        
        # Technology stack detection
        self.results['tech_stack'] = self.detect_tech_stack()
        
        # OSINT gathering
        self.results['osint'] = self.gather_osint()
        
        return self.results
    
    def get_whois_info(self):
        """Get WHOIS information"""
        print(f"{Fore.YELLOW}[*] Gathering WHOIS information...{Style.RESET_ALL}")
        try:
            w = whois.whois(self.target)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails
            }
        except Exception as e:
            print(f"{Fore.RED}[-] WHOIS error: {e}{Style.RESET_ALL}")
            return {}
    
    def get_dns_records(self):
        """Get DNS records"""
        print(f"{Fore.YELLOW}[*] Gathering DNS records...{Style.RESET_ALL}")
        records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception:
                continue
        
        return records
    
    def query_dnsdumpster(self):
        """Query DNSDumpster for DNS and subdomain information"""
        print(f"{Fore.YELLOW}[*] Querying DNSDumpster...{Style.RESET_ALL}")
        try:
            session = requests.Session()
            url = "https://dnsdumpster.com/"
            resp = session.get(url, timeout=30)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']
            cookies = session.cookies.get_dict()
            headers = {
                'Referer': url,
                'User-Agent': self.session.headers['User-Agent']
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.target
            }
            resp = session.post(url, data=data, headers=headers, cookies=cookies, timeout=60)
            
            if resp.status_code != 200:
                return {}
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            tables = soup.find_all('table')
            results = {}
            
            if len(tables) >= 4:
                # Host records
                hosts = []
                for row in tables[1].find_all('tr')[1:]:
                    cols = [col.get_text(strip=True) for col in row.find_all('td')]
                    if cols:
                        hosts.append(cols)
                results['hosts'] = hosts
                
                # MX records
                mx = []
                for row in tables[2].find_all('tr')[1:]:
                    cols = [col.get_text(strip=True) for col in row.find_all('td')]
                    if cols:
                        mx.append(cols)
                results['mx'] = mx
                
                # TXT records
                txt = []
                for row in tables[3].find_all('tr')[1:]:
                    cols = [col.get_text(strip=True) for col in row.find_all('td')]
                    if cols:
                        txt.append(cols)
                results['txt'] = txt
            
            return results
        except Exception as e:
            print(f"{Fore.RED}[-] DNSDumpster error: {e}{Style.RESET_ALL}")
            return {}
    
    def get_certificate_info(self):
        """Get SSL certificate information"""
        print(f"{Fore.YELLOW}[*] Gathering certificate information...{Style.RESET_ALL}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', []),
                        'ssl_version': ssock.version()
                    }
        except Exception as e:
            print(f"{Fore.RED}[-] Certificate error: {e}{Style.RESET_ALL}")
            return {}
    
    def enumerate_subdomains(self):
        """Enumerate subdomains using multiple sources"""
        print(f"{Fore.YELLOW}[*] Enumerating subdomains...{Style.RESET_ALL}")
        subdomains = set()
        
        # Certificate transparency logs (crt.sh)
        crt_results = self.query_crt_sh()
        subdomains.update(crt_results['subdomains'])
        
        # DNS bruteforce
        subdomains.update(self.dns_bruteforce())
        
        # DNSDumpster integration
        dnsdumpster_results = self.query_dnsdumpster()
        if 'hosts' in dnsdumpster_results:
            for host in dnsdumpster_results['hosts']:
                if host and len(host) > 0:
                    subdomains.add(host[0].lower())
        
        # VirusTotal (if API key available)
        if self.api_keys.get('virustotal_api_key'):
            try:
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {
                    'apikey': self.api_keys['virustotal_api_key'],
                    'domain': self.target
                }
                resp = self.session.get(url, params=params, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'subdomains' in data:
                        for subdomain in data['subdomains']:
                            subdomains.add(subdomain)
            except Exception:
                pass
        
        # Shodan (if API key available)
        if self.api_keys.get('shodan_api_key'):
            try:
                import shodan
                api = shodan.Shodan(self.api_keys['shodan_api_key'])
                results = api.search(f'hostname:*.{self.target}')
                for result in results['matches']:
                    if 'hostnames' in result:
                        for hostname in result['hostnames']:
                            if hostname.endswith(f'.{self.target}'):
                                subdomains.add(hostname)
            except Exception:
                pass
        
        return list(subdomains)
    
    def query_crt_sh(self):
        """Query crt.sh for certificate transparency logs"""
        print(f"{Fore.YELLOW}[*] Querying crt.sh certificate transparency logs...{Style.RESET_ALL}")
        results = {
            'subdomains': set(),
            'certificates': [],
            'issuers': set(),
            'expiry_dates': [],
            'san_domains': set()
        }
        
        try:
            # Query for wildcard certificates
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    # Extract subdomains
                    name = entry['name_value'].lower()
                    if name.endswith(f'.{self.target}'):
                        results['subdomains'].add(name)
                    
                    # Extract certificate information
                    cert_info = {
                        'id': entry.get('id'),
                        'name_value': entry.get('name_value'),
                        'common_name': entry.get('common_name'),
                        'issuer_name': entry.get('issuer_name'),
                        'not_before': entry.get('not_before'),
                        'not_after': entry.get('not_after'),
                        'serial_number': entry.get('serial_number'),
                        'subject_alt_names': entry.get('subject_alt_names', '')
                    }
                    results['certificates'].append(cert_info)
                    
                    # Extract issuer information
                    if entry.get('issuer_name'):
                        results['issuers'].add(entry['issuer_name'])
                    
                    # Extract expiry dates
                    if entry.get('not_after'):
                        results['expiry_dates'].append(entry['not_after'])
                    
                    # Extract SAN domains
                    if entry.get('subject_alt_names'):
                        san_domains = entry['subject_alt_names'].split('\n')
                        for san in san_domains:
                            san = san.strip().lower()
                            if san.endswith(f'.{self.target}'):
                                results['san_domains'].add(san)
                                results['subdomains'].add(san)
            
            # Query for exact domain match
            url_exact = f"https://crt.sh/?q={self.target}&output=json"
            resp_exact = self.session.get(url_exact, timeout=30)
            if resp_exact.status_code == 200:
                data_exact = resp_exact.json()
                for entry in data_exact:
                    # Extract subdomains
                    name = entry['name_value'].lower()
                    if name.endswith(f'.{self.target}'):
                        results['subdomains'].add(name)
                    
                    # Extract certificate information
                    cert_info = {
                        'id': entry.get('id'),
                        'name_value': entry.get('name_value'),
                        'common_name': entry.get('common_name'),
                        'issuer_name': entry.get('issuer_name'),
                        'not_before': entry.get('not_before'),
                        'not_after': entry.get('not_after'),
                        'serial_number': entry.get('serial_number'),
                        'subject_alt_names': entry.get('subject_alt_names', '')
                    }
                    results['certificates'].append(cert_info)
                    
                    # Extract issuer information
                    if entry.get('issuer_name'):
                        results['issuers'].add(entry['issuer_name'])
                    
                    # Extract expiry dates
                    if entry.get('not_after'):
                        results['expiry_dates'].append(entry['not_after'])
                    
                    # Extract SAN domains
                    if entry.get('subject_alt_names'):
                        san_domains = entry['subject_alt_names'].split('\n')
                        for san in san_domains:
                            san = san.strip().lower()
                            if san.endswith(f'.{self.target}'):
                                results['san_domains'].add(san)
                                results['subdomains'].add(san)
            
            # Convert sets to lists for JSON serialization
            results['subdomains'] = list(results['subdomains'])
            results['issuers'] = list(results['issuers'])
            results['san_domains'] = list(results['san_domains'])
            
            print(f"{Fore.GREEN}[+] Found {len(results['subdomains'])} subdomains via crt.sh{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found {len(results['certificates'])} certificates{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found {len(results['issuers'])} unique issuers{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] crt.sh error: {e}{Style.RESET_ALL}")
        
        return results
    
    def dns_bruteforce(self):
        """DNS bruteforce using wordlists"""
        print(f"{Fore.YELLOW}[*] Performing DNS bruteforce...{Style.RESET_ALL}")
        subdomains = set()
        
        # Get subdomain wordlists
        wordlist_paths = self.wordlists.get('subdomains', [])
        
        for wordlist_path in wordlist_paths:
            if os.path.exists(wordlist_path):
                try:
                    with open(wordlist_path, 'r') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain and not subdomain.startswith('#'):
                                full_domain = f"{subdomain}.{self.target}"
                                try:
                                    answers = dns.resolver.resolve(full_domain, 'A')
                                    if answers:
                                        subdomains.add(full_domain)
                                        print(f"{Fore.GREEN}[+] Found: {full_domain}{Style.RESET_ALL}")
                                except Exception:
                                    continue
                except Exception as e:
                    print(f"{Fore.RED}[-] Error reading wordlist {wordlist_path}: {e}{Style.RESET_ALL}")
        
        return subdomains
    
    def detect_tech_stack(self):
        """Detect technology stack using multiple methods"""
        print(f"{Fore.YELLOW}[*] Detecting technology stack...{Style.RESET_ALL}")
        tech = {}
        
        # Determine target URL
        if self.target.startswith(('http://', 'https://')):
            urls = [self.target]
        else:
            urls = [f"http://{self.target}", f"https://{self.target}"]
        
        # HTTP headers and content analysis
        for url in urls:
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
                headers = resp.headers
                
                # Server information
                if 'Server' in headers:
                    tech['server'] = headers['Server']
                if 'X-Powered-By' in headers:
                    tech['x-powered-by'] = headers['X-Powered-By']
                
                # Security headers
                security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                                  'X-XSS-Protection', 'Strict-Transport-Security', 
                                  'Content-Security-Policy']
                for header in security_headers:
                    if header in headers:
                        tech[header.lower()] = headers[header]
                
                # Favicon hash
                favicon_url = urljoin(url, '/favicon.ico')
                fav_resp = self.session.get(favicon_url, timeout=5, verify=False)
                if fav_resp.status_code == 200:
                    favicon_hash = hashlib.md5(fav_resp.content).hexdigest()
                    tech['favicon_hash'] = favicon_hash
                
                # Content analysis
                page = resp.text.lower()
                if 'wordpress' in page:
                    tech['cms'] = 'WordPress'
                elif 'drupal' in page:
                    tech['cms'] = 'Drupal'
                elif 'joomla' in page:
                    tech['cms'] = 'Joomla'
                
                if 'react' in page:
                    tech['js_framework'] = 'React'
                elif 'angular' in page:
                    tech['js_framework'] = 'Angular'
                elif 'vue' in page:
                    tech['js_framework'] = 'Vue.js'
                
                break
            except Exception:
                continue
        
        # WhatWeb (if available)
        try:
            success, output, _ = subprocess.run(
                f"whatweb --no-errors --log-xml=- {urls[0]}", 
                shell=True, capture_output=True, text=True, timeout=30
            )
            if success and output:
                root = ET.fromstring(output)
                plugins = set()
                for plugin in root.iter('plugin'):
                    plugins.add(plugin.attrib.get('name'))
                if plugins:
                    tech['whatweb_plugins'] = list(plugins)
        except Exception:
            pass
        
        return tech
    
    def gather_osint(self):
        """Gather OSINT information"""
        print(f"{Fore.YELLOW}[*] Gathering OSINT information...{Style.RESET_ALL}")
        osint = {}
        
        # Wayback Machine
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original&collapse=urlkey"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:  # Skip header row
                    osint['wayback_urls'] = [row[0] for row in data[1:]]
        except Exception:
            pass
        
        # GitHub search
        try:
            url = f"https://api.github.com/search/code?q={self.target}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'items' in data:
                    osint['github_repos'] = [item['repository']['full_name'] for item in data['items'][:10]]
        except Exception:
            pass
        
        return osint 
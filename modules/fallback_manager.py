#!/usr/bin/env python3
"""
Fallback Manager Module
Provides alternative methods when API keys are not available
"""

import os
import sys
import json
import time
import requests
import dns.resolver
import socket
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style
import subprocess

class FallbackManager:
    """Manage fallback mechanisms for missing API keys"""
    
    def __init__(self, target, config, api_keys):
        self.target = target
        self.config = config
        self.api_keys = api_keys
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.fallbacks = {}
        
    def setup_fallbacks(self):
        """Setup fallback mechanisms based on available API keys"""
        print(f"{Fore.YELLOW}[*] Setting up fallback mechanisms...{Style.RESET_ALL}")
        
        # Shodan fallback
        if not self.api_keys.get('shodan'):
            self.fallbacks['shodan'] = {
                'type': 'free_search',
                'description': 'Using public search engines and DNS data',
                'enabled': True,
                'method': self.free_internet_search
            }
        
        # Censys fallback
        if not self.api_keys.get('censys'):
            self.fallbacks['censys'] = {
                'type': 'free_search',
                'description': 'Using public search engines and DNS data',
                'enabled': True,
                'method': self.free_internet_search
            }
        
        # VirusTotal fallback
        if not self.api_keys.get('virustotal'):
            self.fallbacks['virustotal'] = {
                'type': 'public_api',
                'description': 'Using public VirusTotal API (limited)',
                'enabled': True,
                'method': self.virustotal_public_search
            }
        
        # SecurityTrails fallback
        if not self.api_keys.get('securitytrails'):
            self.fallbacks['securitytrails'] = {
                'type': 'dns_resolver',
                'description': 'Using DNS resolution and public data',
                'enabled': True,
                'method': self.dns_resolution_search
            }
        
        # Hunter fallback
        if not self.api_keys.get('hunter'):
            self.fallbacks['hunter'] = {
                'type': 'email_guess',
                'description': 'Using email pattern guessing',
                'enabled': True,
                'method': self.email_pattern_guess
            }
        
        # Wappalyzer fallback
        if not self.api_keys.get('wappalyzer'):
            self.fallbacks['wappalyzer'] = {
                'type': 'header_analysis',
                'description': 'Using HTTP header and content analysis',
                'enabled': True,
                'method': self.header_analysis
            }
        
        # Display fallbacks
        if self.fallbacks:
            print(f"{Fore.GREEN}[+] Fallback mechanisms configured:{Style.RESET_ALL}")
            for service, fallback in self.fallbacks.items():
                print(f"  {service}: {fallback['description']}")
        else:
            print(f"{Fore.GREEN}[+] All API keys provided - no fallbacks needed{Style.RESET_ALL}")
        
        return self.fallbacks
    
    def free_internet_search(self, query_type='subdomains'):
        """Free internet search using public search engines"""
        print(f"{Fore.YELLOW}[*] Using free internet search for {query_type}...{Style.RESET_ALL}")
        
        results = []
        
        if query_type == 'subdomains':
            # Use public DNS resolvers
            results.extend(self.public_dns_search())
            
            # Use search engines (basic)
            results.extend(self.search_engine_subdomain_search())
        
        return results
    
    def public_dns_search(self):
        """Search using public DNS resolvers"""
        subdomains = set()
        
        # Common subdomain patterns
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'wiki', 'forum', 'shop', 'store', 'app',
            'mobile', 'm', 'webmail', 'email', 'smtp', 'pop', 'imap'
        ]
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.target}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    subdomains.add(full_domain)
                    print(f"{Fore.GREEN}[+] Found: {full_domain}{Style.RESET_ALL}")
            except:
                continue
        
        return list(subdomains)
    
    def search_engine_subdomain_search(self):
        """Basic search engine subdomain search"""
        subdomains = set()
        
        # Use DuckDuckGo (no API key required)
        try:
            search_query = f"site:{self.target}"
            url = f"https://duckduckgo.com/html/?q={search_query}"
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract domains from search results
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if self.target in href:
                        # Extract subdomain from URL
                        parsed = urlparse(href)
                        if parsed.netloc and self.target in parsed.netloc:
                            subdomains.add(parsed.netloc)
        except Exception as e:
            print(f"{Fore.RED}[-] Search engine search error: {e}{Style.RESET_ALL}")
        
        return list(subdomains)
    
    def virustotal_public_search(self, domain=None):
        """Use VirusTotal public API (limited)"""
        if not domain:
            domain = self.target
        
        print(f"{Fore.YELLOW}[*] Using VirusTotal public search for {domain}...{Style.RESET_ALL}")
        
        results = {}
        
        try:
            # Use VirusTotal public website (limited)
            url = f"https://www.virustotal.com/gui/domain/{domain}/detection"
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                # Basic parsing (limited due to JavaScript rendering)
                results['status'] = 'available'
                results['message'] = 'Domain found in VirusTotal (public data)'
            else:
                results['status'] = 'not_found'
                results['message'] = 'Domain not found in VirusTotal'
                
        except Exception as e:
            results['status'] = 'error'
            results['message'] = f'Error: {e}'
        
        return results
    
    def dns_resolution_search(self):
        """DNS resolution-based search"""
        print(f"{Fore.YELLOW}[*] Using DNS resolution search...{Style.RESET_ALL}")
        
        results = {
            'subdomains': [],
            'dns_records': {},
            'ip_addresses': []
        }
        
        # DNS record types to check
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                results['dns_records'][record_type] = [str(answer) for answer in answers]
                
                # Extract IP addresses
                if record_type in ['A', 'AAAA']:
                    results['ip_addresses'].extend([str(answer) for answer in answers])
                    
            except Exception:
                continue
        
        # Reverse DNS lookup for IP addresses
        for ip in results['ip_addresses']:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if self.target in hostname:
                    results['subdomains'].append(hostname)
            except:
                continue
        
        return results
    
    def email_pattern_guess(self, domain=None):
        """Email pattern guessing"""
        if not domain:
            domain = self.target
        
        print(f"{Fore.YELLOW}[*] Using email pattern guessing for {domain}...{Style.RESET_ALL}")
        
        emails = []
        
        # Common email patterns
        common_patterns = [
            'admin', 'info', 'contact', 'support', 'help', 'sales',
            'marketing', 'hr', 'jobs', 'careers', 'press', 'media',
            'security', 'abuse', 'postmaster', 'webmaster', 'hostmaster',
            'root', 'test', 'demo', 'dev', 'development'
        ]
        
        for pattern in common_patterns:
            email = f"{pattern}@{domain}"
            emails.append({
                'email': email,
                'pattern': pattern,
                'confidence': 'low',
                'source': 'pattern_guess'
            })
        
        return emails
    
    def header_analysis(self, url=None):
        """HTTP header and content analysis"""
        if not url:
            if self.target.startswith(('http://', 'https://')):
                url = self.target
            else:
                url = f"https://{self.target}"
        
        print(f"{Fore.YELLOW}[*] Using HTTP header analysis for {url}...{Style.RESET_ALL}")
        
        results = {
            'technologies': [],
            'headers': {},
            'server_info': {},
            'security_headers': {}
        }
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Extract headers
            headers = response.headers
            results['headers'] = dict(headers)
            
            # Server information
            if 'Server' in headers:
                results['server_info']['server'] = headers['Server']
            if 'X-Powered-By' in headers:
                results['server_info']['powered_by'] = headers['X-Powered-By']
            
            # Security headers
            security_headers = [
                'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                'Strict-Transport-Security', 'Content-Security-Policy',
                'Referrer-Policy', 'Permissions-Policy'
            ]
            
            for header in security_headers:
                if header in headers:
                    results['security_headers'][header] = headers[header]
            
            # Technology detection from headers
            technologies = []
            
            # Server technologies
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
            
            # Framework detection
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            elif 'express' in powered_by:
                technologies.append('Express.js')
            
            # Content analysis
            content_type = headers.get('Content-Type', '').lower()
            if 'wordpress' in content_type or 'wp-content' in response.text.lower():
                technologies.append('WordPress')
            elif 'drupal' in response.text.lower():
                technologies.append('Drupal')
            elif 'joomla' in response.text.lower():
                technologies.append('Joomla')
            
            results['technologies'] = technologies
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def execute_fallback(self, service, query_type='general', **kwargs):
        """Execute fallback method for a specific service"""
        if service not in self.fallbacks:
            return None
        
        fallback = self.fallbacks[service]
        if not fallback['enabled']:
            return None
        
        try:
            print(f"{Fore.YELLOW}[*] Using {service} fallback: {fallback['description']}{Style.RESET_ALL}")
            return fallback['method'](query_type, **kwargs)
        except Exception as e:
            print(f"{Fore.RED}[-] Fallback error for {service}: {e}{Style.RESET_ALL}")
            return None
    
    def get_available_fallbacks(self):
        """Get list of available fallbacks"""
        return list(self.fallbacks.keys())
    
    def is_fallback_available(self, service):
        """Check if fallback is available for a service"""
        return service in self.fallbacks and self.fallbacks[service]['enabled']
    
    def get_fallback_info(self, service):
        """Get fallback information for a service"""
        if service in self.fallbacks:
            return self.fallbacks[service]
        return None 
#!/usr/bin/env python3
"""
Breach Intelligence Module
Comprehensive breach data gathering from multiple sources
"""

import os
import json
import time
import hashlib
import requests
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from colorama import Fore, Style
import re

class BreachIntelligence:
    def __init__(self, target, config, wordlists, api_keys):
        self.target = target
        self.config = config
        self.wordlists = wordlists
        self.api_keys = api_keys
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'UltimateReconTool/1.0'
        })
        self.results = {
            'breach_records': [],
            'email_leaks': [],
            'password_leaks': [],
            'domain_breaches': [],
            'paste_dumps': [],
            'dark_web_mentions': [],
            'intelx_results': [],
            'dehashed_results': [],
            'hibp_results': [],
            'leakcheck_results': [],
            'snusbase_results': [],
            'breach_directory_results': []
        }
        
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Running Breach Intelligence Gathering...{Style.RESET_ALL}")
        
        # HaveIBeenPwned integration
        self.results['hibp_results'] = self.haveibeenpwned_search()
        
        # DeHashed integration
        self.results['dehashed_results'] = self.dehashed_search()
        
        # Intelligence X integration
        self.results['intelx_results'] = self.intelligencex_search()
        
        # LeakCheck integration
        self.results['leakcheck_results'] = self.leakcheck_search()
        
        # Snusbase integration
        self.results['snusbase_results'] = self.snusbase_search()
        
        # Breach Directory integration
        self.results['breach_directory_results'] = self.breach_directory_search()
        
        # Paste sites search
        self.results['paste_dumps'] = self.search_paste_sites()
        
        # Dark web mentions (simulated)
        self.results['dark_web_mentions'] = self.search_dark_web_mentions()
        
        # Aggregate all results
        self.aggregate_breach_data()
        
        return self.results
    
    def haveibeenpwned_search(self):
        """Search HaveIBeenPwned for breaches"""
        print(f"{Fore.YELLOW}[*] Searching HaveIBeenPwned...{Style.RESET_ALL}")
        results = []
        
        if not self.api_keys.get('haveibeenpwned_api_key'):
            print(f"{Fore.YELLOW}[!] HaveIBeenPwned API key not configured{Style.RESET_ALL}")
            return results
        
        try:
            # Generate email patterns for the target
            domain = self.target if '.' in self.target else f"{self.target}.com"
            email_patterns = self.generate_email_patterns(domain)
            
            for email in email_patterns:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {
                    'hibp-api-key': self.api_keys['haveibeenpwned_api_key'],
                    'user-agent': 'UltimateReconTool'
                }
                
                resp = self.session.get(url, headers=headers, timeout=30)
                if resp.status_code == 200:
                    breaches = resp.json()
                    for breach in breaches:
                        results.append({
                            'email': email,
                            'breach_name': breach.get('Name', ''),
                            'breach_date': breach.get('BreachDate', ''),
                            'pwn_count': breach.get('PwnCount', 0),
                            'data_classes': breach.get('DataClasses', []),
                            'description': breach.get('Description', ''),
                            'logo_path': breach.get('LogoPath', ''),
                            'source': 'HaveIBeenPwned',
                            'severity': self.calculate_breach_severity(breach)
                        })
                elif resp.status_code == 404:
                    # Email not found in breaches
                    pass
                else:
                    print(f"{Fore.RED}[-] HIBP API error: {resp.status_code}{Style.RESET_ALL}")
                
                time.sleep(1.6)  # Rate limiting
                
        except Exception as e:
            print(f"{Fore.RED}[-] HaveIBeenPwned error: {e}{Style.RESET_ALL}")
        
        return results
    
    def dehashed_search(self):
        """Search DeHashed for breaches"""
        print(f"{Fore.YELLOW}[*] Searching DeHashed...{Style.RESET_ALL}")
        results = []
        
        if not self.api_keys.get('dehashed_api_key'):
            print(f"{Fore.YELLOW}[!] DeHashed API key not configured{Style.RESET_ALL}")
            return results
        
        try:
            domain = self.target if '.' in self.target else f"{self.target}.com"
            
            url = "https://api.dehashed.com/search"
            params = {
                'query': f"domain:{domain}",
                'size': 100
            }
            headers = {
                'Authorization': f"Bearer {self.api_keys['dehashed_api_key']}",
                'Accept': 'application/json'
            }
            
            resp = self.session.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'entries' in data:
                    for entry in data['entries']:
                        results.append({
                            'email': entry.get('email', ''),
                            'username': entry.get('username', ''),
                            'password': entry.get('password', ''),
                            'hash': entry.get('hash', ''),
                            'database_name': entry.get('database_name', ''),
                            'breach_date': entry.get('date', ''),
                            'source': 'DeHashed',
                            'severity': 'high' if entry.get('password') else 'medium'
                        })
                        
        except Exception as e:
            print(f"{Fore.RED}[-] DeHashed error: {e}{Style.RESET_ALL}")
        
        return results
    
    def intelligencex_search(self):
        """Search Intelligence X for breaches"""
        print(f"{Fore.YELLOW}[*] Searching Intelligence X...{Style.RESET_ALL}")
        results = []
        
        try:
            # Intelligence X API endpoint
            url = "https://intelx.io/api/v1/intel/search"
            
            # Search for domain
            domain = self.target if '.' in self.target else f"{self.target}.com"
            
            payload = {
                "term": domain,
                "maxresults": 100,
                "media": 0,
                "sort": 4,
                "terminate": []
            }
            
            headers = {
                'User-Agent': 'UltimateReconTool/1.0',
                'Content-Type': 'application/json'
            }
            
            resp = self.session.post(url, json=payload, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'records' in data:
                    for record in data['records']:
                        results.append({
                            'title': record.get('name', ''),
                            'url': record.get('mediaurl', ''),
                            'date': record.get('date', ''),
                            'type': record.get('type', ''),
                            'source': 'Intelligence X',
                            'severity': 'medium'
                        })
                        
        except Exception as e:
            print(f"{Fore.RED}[-] Intelligence X error: {e}{Style.RESET_ALL}")
        
        return results
    
    def leakcheck_search(self):
        """Search LeakCheck for breaches"""
        print(f"{Fore.YELLOW}[*] Searching LeakCheck...{Style.RESET_ALL}")
        results = []
        
        if not self.api_keys.get('leakcheck_api_key'):
            print(f"{Fore.YELLOW}[!] LeakCheck API key not configured{Style.RESET_ALL}")
            return results
        
        try:
            domain = self.target if '.' in self.target else f"{self.target}.com"
            email_patterns = self.generate_email_patterns(domain)
            
            for email in email_patterns:
                url = "https://leakcheck.io/api/public"
                params = {
                    'key': self.api_keys['leakcheck_api_key'],
                    'check': email,
                    'type': 'email'
                }
                
                resp = self.session.get(url, params=params, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('success') and data.get('found'):
                        for leak in data.get('leaks', []):
                            results.append({
                                'email': email,
                                'leak_name': leak.get('name', ''),
                                'leak_date': leak.get('date', ''),
                                'lines': leak.get('lines', 0),
                                'source': 'LeakCheck',
                                'severity': 'medium'
                            })
                            
        except Exception as e:
            print(f"{Fore.RED}[-] LeakCheck error: {e}{Style.RESET_ALL}")
        
        return results
    
    def snusbase_search(self):
        """Search Snusbase for breaches"""
        print(f"{Fore.YELLOW}[*] Searching Snusbase...{Style.RESET_ALL}")
        results = []
        
        if not self.api_keys.get('snusbase_api_key'):
            print(f"{Fore.YELLOW}[!] Snusbase API key not configured{Style.RESET_ALL}")
            return results
        
        try:
            domain = self.target if '.' in self.target else f"{self.target}.com"
            
            url = "https://api.snusbase.com/data/search"
            payload = {
                "terms": [domain],
                "types": ["email", "username", "password", "hash"],
                "maxresults": 100
            }
            
            headers = {
                'Auth': self.api_keys['snusbase_api_key'],
                'Content-Type': 'application/json'
            }
            
            resp = self.session.post(url, json=payload, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'results' in data:
                    for result in data['results']:
                        results.append({
                            'email': result.get('email', ''),
                            'username': result.get('username', ''),
                            'password': result.get('password', ''),
                            'hash': result.get('hash', ''),
                            'database': result.get('database', ''),
                            'source': 'Snusbase',
                            'severity': 'high' if result.get('password') else 'medium'
                        })
                        
        except Exception as e:
            print(f"{Fore.RED}[-] Snusbase error: {e}{Style.RESET_ALL}")
        
        return results
    
    def breach_directory_search(self):
        """Search Breach Directory for breaches"""
        print(f"{Fore.YELLOW}[*] Searching Breach Directory...{Style.RESET_ALL}")
        results = []
        
        try:
            # This would integrate with a local breach directory database
            # For now, we'll simulate the search
            domain = self.target if '.' in self.target else f"{self.target}.com"
            
            # Simulate breach directory search
            results.append({
                'domain': domain,
                'note': 'Breach Directory integration requires local database setup',
                'source': 'Breach Directory',
                'severity': 'info'
            })
            
        except Exception as e:
            print(f"{Fore.RED}[-] Breach Directory error: {e}{Style.RESET_ALL}")
        
        return results
    
    def search_paste_sites(self):
        """Search paste sites for target mentions"""
        print(f"{Fore.YELLOW}[*] Searching paste sites...{Style.RESET_ALL}")
        results = []
        
        paste_sites = [
            'pastebin.com',
            'ghostbin.co',
            'rentry.co',
            'paste.ee',
            'paste.gg'
        ]
        
        for site in paste_sites:
            try:
                # Search for target mentions
                search_url = f"https://{site}/search?q={self.target}"
                resp = self.session.get(search_url, timeout=30)
                
                if resp.status_code == 200:
                    # Parse results (simplified)
                    results.append({
                        'site': site,
                        'search_url': search_url,
                        'status': 'searchable',
                        'source': 'Paste Site Search',
                        'severity': 'low'
                    })
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Paste site {site} error: {e}{Style.RESET_ALL}")
        
        return results
    
    def search_dark_web_mentions(self):
        """Search for dark web mentions (simulated)"""
        print(f"{Fore.YELLOW}[*] Searching dark web mentions...{Style.RESET_ALL}")
        results = []
        
        # This would integrate with dark web search engines
        # For now, we'll provide a note about integration
        results.append({
            'note': 'Dark web search requires specialized tools (Tor, OnionScan, etc.)',
            'recommendations': [
                'Use Tor browser for manual dark web searches',
                'Integrate with OnionScan for .onion domain enumeration',
                'Use specialized dark web search engines',
                'Monitor dark web marketplaces and forums'
            ],
            'source': 'Dark Web Intelligence',
            'severity': 'info'
        })
        
        return results
    
    def generate_email_patterns(self, domain):
        """Generate common email patterns for a domain"""
        patterns = [
            'admin', 'info', 'contact', 'support', 'help', 'webmaster',
            'root', 'test', 'mail', 'sales', 'marketing', 'hr', 'jobs',
            'security', 'dev', 'developer', 'admin', 'user', 'guest',
            'service', 'noreply', 'postmaster', 'hostmaster', 'abuse'
        ]
        
        return [f"{pattern}@{domain}" for pattern in patterns]
    
    def calculate_breach_severity(self, breach):
        """Calculate severity of a breach based on data classes"""
        high_severity_classes = ['passwords', 'credit-cards', 'ssn', 'passport-numbers']
        medium_severity_classes = ['email-addresses', 'phone-numbers', 'addresses']
        
        data_classes = breach.get('DataClasses', [])
        
        for class_name in data_classes:
            if any(high in class_name.lower() for high in high_severity_classes):
                return 'high'
            elif any(medium in class_name.lower() for medium in medium_severity_classes):
                return 'medium'
        
        return 'low'
    
    def aggregate_breach_data(self):
        """Aggregate all breach data into summary categories"""
        print(f"{Fore.CYAN}[*] Aggregating breach data...{Style.RESET_ALL}")
        
        # Aggregate email leaks
        all_email_leaks = []
        for source_results in [self.results['hibp_results'], self.results['dehashed_results'], 
                              self.results['leakcheck_results'], self.results['snusbase_results']]:
            for result in source_results:
                if result.get('email'):
                    all_email_leaks.append(result)
        
        self.results['email_leaks'] = all_email_leaks
        
        # Aggregate password leaks
        all_password_leaks = []
        for source_results in [self.results['dehashed_results'], self.results['snusbase_results']]:
            for result in source_results:
                if result.get('password'):
                    all_password_leaks.append(result)
        
        self.results['password_leaks'] = all_password_leaks
        
        # Aggregate domain breaches
        all_domain_breaches = []
        for source_results in [self.results['hibp_results'], self.results['dehashed_results']]:
            for result in source_results:
                if self.target in result.get('email', '') or self.target in result.get('domain', ''):
                    all_domain_breaches.append(result)
        
        self.results['domain_breaches'] = all_domain_breaches
        
        # Aggregate all breach records
        all_breach_records = []
        for key, value in self.results.items():
            if key.endswith('_results') and isinstance(value, list):
                all_breach_records.extend(value)
        
        self.results['breach_records'] = all_breach_records
        
        # Print summary
        print(f"{Fore.GREEN}[+] Breach Intelligence Summary:{Style.RESET_ALL}")
        print(f"  - Total breach records: {len(self.results['breach_records'])}")
        print(f"  - Email leaks: {len(self.results['email_leaks'])}")
        print(f"  - Password leaks: {len(self.results['password_leaks'])}")
        print(f"  - Domain breaches: {len(self.results['domain_breaches'])}")
        print(f"  - Paste dumps: {len(self.results['paste_dumps'])}")
        print(f"  - Dark web mentions: {len(self.results['dark_web_mentions'])}") 
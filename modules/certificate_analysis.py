#!/usr/bin/env python3
"""
Certificate Analysis Module
Comprehensive certificate transparency analysis using crt.sh and other CT logs
"""

import os
import sys
import json
import time
import requests
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from colorama import Fore, Style
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed

class CertificateAnalysis:
    def __init__(self, target, config, wordlists, api_keys):
        self.target = target
        self.config = config
        self.wordlists = wordlists
        self.api_keys = api_keys
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'subdomains': [],
            'certificates': [],
            'issuers': [],
            'expiry_analysis': [],
            'weak_certificates': [],
            'wildcard_certificates': [],
            'san_analysis': [],
            'certificate_chains': [],
            'revoked_certificates': [],
            'duplicate_certificates': [],
            'certificate_authorities': [],
            'certificate_metrics': {}
        }
        
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Running Certificate Analysis...{Style.RESET_ALL}")
        
        # Query crt.sh for comprehensive certificate data
        crt_data = self.query_crt_sh_comprehensive()
        
        # Analyze certificates
        self.analyze_certificates(crt_data)
        
        # Check for weak certificates
        self.detect_weak_certificates()
        
        # Analyze certificate chains
        self.analyze_certificate_chains()
        
        # Check for revoked certificates
        self.check_revoked_certificates()
        
        # Find duplicate certificates
        self.find_duplicate_certificates()
        
        # Generate certificate metrics
        self.generate_certificate_metrics()
        
        return self.results
    
    def query_crt_sh_comprehensive(self):
        """Query crt.sh with comprehensive search patterns"""
        print(f"{Fore.YELLOW}[*] Querying crt.sh with comprehensive patterns...{Style.RESET_ALL}")
        
        search_patterns = [
            f"%.{self.target}",  # Wildcard subdomains
            f"{self.target}",    # Exact domain
            f"*.{self.target}",  # Wildcard pattern
            f"%.%.{self.target}" # Multi-level wildcard
        ]
        
        all_certificates = []
        
        for pattern in search_patterns:
            try:
                url = f"https://crt.sh/?q={pattern}&output=json"
                resp = self.session.get(url, timeout=30)
                
                if resp.status_code == 200:
                    data = resp.json()
                    all_certificates.extend(data)
                    print(f"{Fore.GREEN}[+] Found {len(data)} certificates for pattern: {pattern}{Style.RESET_ALL}")
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error querying pattern {pattern}: {e}{Style.RESET_ALL}")
        
        return all_certificates
    
    def analyze_certificates(self, certificates):
        """Analyze certificate data"""
        print(f"{Fore.YELLOW}[*] Analyzing {len(certificates)} certificates...{Style.RESET_ALL}")
        
        subdomains = set()
        issuers = set()
        expiry_dates = []
        wildcard_certs = []
        san_domains = set()
        
        for cert in certificates:
            # Extract subdomains
            name_value = cert.get('name_value', '').lower()
            if name_value.endswith(f'.{self.target}'):
                subdomains.add(name_value)
            
            # Extract issuers
            issuer = cert.get('issuer_name', '')
            if issuer:
                issuers.add(issuer)
            
            # Extract expiry dates
            not_after = cert.get('not_after', '')
            if not_after:
                expiry_dates.append(not_after)
            
            # Check for wildcard certificates
            if '*' in name_value:
                wildcard_certs.append({
                    'name_value': name_value,
                    'issuer': cert.get('issuer_name', ''),
                    'not_after': cert.get('not_after', ''),
                    'serial_number': cert.get('serial_number', '')
                })
            
            # Extract SAN domains
            san_data = cert.get('subject_alt_names', '')
            if san_data:
                san_list = san_data.split('\n')
                for san in san_list:
                    san = san.strip().lower()
                    if san.endswith(f'.{self.target}'):
                        san_domains.add(san)
                        subdomains.add(san)
        
        # Store results
        self.results['subdomains'] = list(subdomains)
        self.results['issuers'] = list(issuers)
        self.results['expiry_analysis'] = self.analyze_expiry_dates(expiry_dates)
        self.results['wildcard_certificates'] = wildcard_certs
        self.results['san_analysis'] = list(san_domains)
        self.results['certificates'] = certificates
        
        print(f"{Fore.GREEN}[+] Analysis complete:{Style.RESET_ALL}")
        print(f"  - Subdomains found: {len(self.results['subdomains'])}")
        print(f"  - Unique issuers: {len(self.results['issuers'])}")
        print(f"  - Wildcard certificates: {len(self.results['wildcard_certificates'])}")
        print(f"  - SAN domains: {len(self.results['san_analysis'])}")
    
    def analyze_expiry_dates(self, expiry_dates):
        """Analyze certificate expiry dates"""
        analysis = {
            'total_certificates': len(expiry_dates),
            'expired_certificates': 0,
            'expiring_soon': 0,
            'expiring_30_days': 0,
            'expiring_90_days': 0,
            'expiring_1_year': 0,
            'expiry_distribution': {}
        }
        
        current_time = datetime.now()
        thirty_days = current_time + timedelta(days=30)
        ninety_days = current_time + timedelta(days=90)
        one_year = current_time + timedelta(days=365)
        
        for expiry_str in expiry_dates:
            try:
                # Parse expiry date (format: YYYY-MM-DD HH:MM:SS)
                expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
                
                if expiry_date < current_time:
                    analysis['expired_certificates'] += 1
                elif expiry_date <= thirty_days:
                    analysis['expiring_30_days'] += 1
                    analysis['expiring_soon'] += 1
                elif expiry_date <= ninety_days:
                    analysis['expiring_90_days'] += 1
                elif expiry_date <= one_year:
                    analysis['expiring_1_year'] += 1
                
                # Group by year
                year = expiry_date.year
                analysis['expiry_distribution'][year] = analysis['expiry_distribution'].get(year, 0) + 1
                
            except Exception:
                continue
        
        return analysis
    
    def detect_weak_certificates(self):
        """Detect weak or problematic certificates"""
        print(f"{Fore.YELLOW}[*] Detecting weak certificates...{Style.RESET_ALL}")
        
        weak_certs = []
        
        for cert in self.results['certificates']:
            issues = []
            
            # Check for short validity periods
            try:
                not_before = datetime.strptime(cert.get('not_before', ''), '%Y-%m-%d %H:%M:%S')
                not_after = datetime.strptime(cert.get('not_after', ''), '%Y-%m-%d %H:%M:%S')
                validity_days = (not_after - not_before).days
                
                if validity_days < 30:
                    issues.append(f"Short validity period: {validity_days} days")
                elif validity_days > 825:  # More than 2 years
                    issues.append(f"Long validity period: {validity_days} days")
                    
            except Exception:
                pass
            
            # Check for wildcard certificates
            if '*' in cert.get('name_value', ''):
                issues.append("Wildcard certificate")
            
            # Check for specific weak issuers
            weak_issuers = [
                'Let\'s Encrypt',  # Often used for testing
                'DigiCert Inc',
                'Comodo CA Limited'
            ]
            
            issuer = cert.get('issuer_name', '')
            if any(weak_issuer in issuer for weak_issuer in weak_issuers):
                issues.append(f"Weak issuer: {issuer}")
            
            # Check for expired certificates
            try:
                not_after = datetime.strptime(cert.get('not_after', ''), '%Y-%m-%d %H:%M:%S')
                if not_after < datetime.now():
                    issues.append("Expired certificate")
            except Exception:
                pass
            
            if issues:
                weak_certs.append({
                    'name_value': cert.get('name_value', ''),
                    'issuer': cert.get('issuer_name', ''),
                    'serial_number': cert.get('serial_number', ''),
                    'not_after': cert.get('not_after', ''),
                    'issues': issues
                })
        
        self.results['weak_certificates'] = weak_certs
        print(f"{Fore.GREEN}[+] Found {len(weak_certs)} weak certificates{Style.RESET_ALL}")
    
    def analyze_certificate_chains(self):
        """Analyze certificate chains and trust relationships"""
        print(f"{Fore.YELLOW}[*] Analyzing certificate chains...{Style.RESET_ALL}")
        
        chains = []
        issuer_map = {}
        
        # Group certificates by issuer
        for cert in self.results['certificates']:
            issuer = cert.get('issuer_name', '')
            if issuer not in issuer_map:
                issuer_map[issuer] = []
            issuer_map[issuer].append(cert)
        
        # Analyze chains
        for issuer, certs in issuer_map.items():
            if len(certs) > 1:
                chains.append({
                    'issuer': issuer,
                    'certificate_count': len(certs),
                    'domains': [cert.get('name_value', '') for cert in certs],
                    'expiry_dates': [cert.get('not_after', '') for cert in certs]
                })
        
        self.results['certificate_chains'] = chains
        print(f"{Fore.GREEN}[+] Analyzed {len(chains)} certificate chains{Style.RESET_ALL}")
    
    def check_revoked_certificates(self):
        """Check for revoked certificates (placeholder for future implementation)"""
        print(f"{Fore.YELLOW}[*] Checking for revoked certificates...{Style.RESET_ALL}")
        
        # This would integrate with OCSP or CRL checking
        # For now, we'll provide a framework
        revoked_certs = []
        
        # Placeholder for OCSP checking
        for cert in self.results['certificates']:
            # In a real implementation, you would:
            # 1. Extract OCSP responder URL from certificate
            # 2. Make OCSP request to check revocation status
            # 3. Parse response to determine if revoked
            pass
        
        self.results['revoked_certificates'] = revoked_certs
        print(f"{Fore.GREEN}[+] Revocation check complete{Style.RESET_ALL}")
    
    def find_duplicate_certificates(self):
        """Find duplicate certificates based on various criteria"""
        print(f"{Fore.YELLOW}[*] Finding duplicate certificates...{Style.RESET_ALL}")
        
        duplicates = []
        
        # Group by serial number
        serial_map = {}
        for cert in self.results['certificates']:
            serial = cert.get('serial_number', '')
            if serial not in serial_map:
                serial_map[serial] = []
            serial_map[serial].append(cert)
        
        # Find duplicates
        for serial, certs in serial_map.items():
            if len(certs) > 1:
                duplicates.append({
                    'type': 'serial_number',
                    'serial': serial,
                    'certificates': certs,
                    'count': len(certs)
                })
        
        # Group by name_value
        name_map = {}
        for cert in self.results['certificates']:
            name = cert.get('name_value', '')
            if name not in name_map:
                name_map[name] = []
            name_map[name].append(cert)
        
        # Find duplicates
        for name, certs in name_map.items():
            if len(certs) > 1:
                duplicates.append({
                    'type': 'name_value',
                    'name': name,
                    'certificates': certs,
                    'count': len(certs)
                })
        
        self.results['duplicate_certificates'] = duplicates
        print(f"{Fore.GREEN}[+] Found {len(duplicates)} duplicate certificate groups{Style.RESET_ALL}")
    
    def generate_certificate_metrics(self):
        """Generate comprehensive certificate metrics"""
        print(f"{Fore.YELLOW}[*] Generating certificate metrics...{Style.RESET_ALL}")
        
        metrics = {
            'total_certificates': len(self.results['certificates']),
            'unique_subdomains': len(self.results['subdomains']),
            'unique_issuers': len(self.results['issuers']),
            'wildcard_certificates': len(self.results['wildcard_certificates']),
            'weak_certificates': len(self.results['weak_certificates']),
            'duplicate_groups': len(self.results['duplicate_certificates']),
            'certificate_chains': len(self.results['certificate_chains']),
            'san_domains': len(self.results['san_analysis']),
            'expiry_analysis': self.results['expiry_analysis']
        }
        
        # Calculate additional metrics
        if metrics['total_certificates'] > 0:
            metrics['avg_certificates_per_issuer'] = metrics['total_certificates'] / metrics['unique_issuers']
            metrics['weak_certificate_percentage'] = (metrics['weak_certificates'] / metrics['total_certificates']) * 100
            metrics['wildcard_percentage'] = (metrics['wildcard_certificates'] / metrics['total_certificates']) * 100
        
        self.results['certificate_metrics'] = metrics
        
        print(f"{Fore.GREEN}[+] Certificate Metrics:{Style.RESET_ALL}")
        print(f"  - Total Certificates: {metrics['total_certificates']}")
        print(f"  - Unique Subdomains: {metrics['unique_subdomains']}")
        print(f"  - Unique Issuers: {metrics['unique_issuers']}")
        print(f"  - Wildcard Certificates: {metrics['wildcard_certificates']}")
        print(f"  - Weak Certificates: {metrics['weak_certificates']} ({metrics.get('weak_certificate_percentage', 0):.1f}%)")
        print(f"  - Duplicate Groups: {metrics['duplicate_groups']}")
        print(f"  - Certificate Chains: {metrics['certificate_chains']}")
        print(f"  - SAN Domains: {metrics['san_domains']}")
    
    def export_certificate_data(self, output_file: str = None):
        """Export certificate data to various formats"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"certificate_analysis_{self.target}_{timestamp}"
        
        # Export to JSON
        json_file = f"{output_file}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Export subdomains to text file
        subdomain_file = f"{output_file}_subdomains.txt"
        with open(subdomain_file, 'w') as f:
            for subdomain in self.results['subdomains']:
                f.write(f"{subdomain}\n")
        
        # Export weak certificates to CSV
        weak_cert_file = f"{output_file}_weak_certificates.csv"
        with open(weak_cert_file, 'w') as f:
            f.write("Domain,Issuer,Serial Number,Expiry Date,Issues\n")
            for cert in self.results['weak_certificates']:
                issues_str = "; ".join(cert['issues'])
                f.write(f"{cert['name_value']},{cert['issuer']},{cert['serial_number']},{cert['not_after']},{issues_str}\n")
        
        print(f"{Fore.GREEN}[+] Certificate data exported to:{Style.RESET_ALL}")
        print(f"  - JSON: {json_file}")
        print(f"  - Subdomains: {subdomain_file}")
        print(f"  - Weak Certificates: {weak_cert_file}")
        
        return {
            'json_file': json_file,
            'subdomain_file': subdomain_file,
            'weak_cert_file': weak_cert_file
        } 
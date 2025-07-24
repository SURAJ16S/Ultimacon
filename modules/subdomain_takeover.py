#!/usr/bin/env python3
"""
Subdomain Takeover & Misconfiguration Detection Module
Detects potential subdomain takeover opportunities and cloud bucket misconfigurations
"""

import os
import sys
import json
import time
import requests
import dns.resolver
import socket
import ssl
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional, Tuple
from colorama import Fore, Style
import asyncio
import aiohttp
import aiofiles
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from pathlib import Path

class SubdomainTakeover:
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
            'takeover_candidates': [],
            'cloud_buckets': [],
            'misconfigurations': [],
            'cname_checks': [],
            'dns_checks': [],
            'http_checks': [],
            'ssl_checks': [],
            'aws_buckets': [],
            'azure_blobs': [],
            'gcp_buckets': [],
            'github_pages': [],
            'heroku_apps': [],
            'vercel_deployments': [],
            'netlify_sites': [],
            'cloudflare_pages': [],
            'firebase_hosting': [],
            'shopify_stores': [],
            'wordpress_sites': [],
            'squarespace_sites': [],
            'wix_sites': []
        }
        
        # Known takeover patterns
        self.takeover_patterns = {
            'aws_s3': {
                'patterns': [
                    r's3\.amazonaws\.com',
                    r'\.s3-.*\.amazonaws\.com',
                    r'\.s3\.*\.amazonaws\.com'
                ],
                'indicators': ['NoSuchBucket', 'AccessDenied', 'PermanentRedirect'],
                'test_bucket': True
            },
            'azure_blob': {
                'patterns': [
                    r'\.blob\.core\.windows\.net',
                    r'\.azurewebsites\.net'
                ],
                'indicators': ['The specified blob does not exist', 'ContainerNotFound'],
                'test_bucket': True
            },
            'gcp_storage': {
                'patterns': [
                    r'storage\.googleapis\.com',
                    r'\.appspot\.com'
                ],
                'indicators': ['NoSuchBucket', 'AccessDenied'],
                'test_bucket': True
            },
            'github_pages': {
                'patterns': [
                    r'\.github\.io',
                    r'\.githubusercontent\.com'
                ],
                'indicators': ['404', 'There isn\'t a GitHub Pages site here'],
                'test_bucket': False
            },
            'heroku': {
                'patterns': [
                    r'\.herokuapp\.com',
                    r'\.herokussl\.com'
                ],
                'indicators': ['No such app', 'Heroku | No such app'],
                'test_bucket': False
            },
            'vercel': {
                'patterns': [
                    r'\.vercel\.app',
                    r'\.now\.sh'
                ],
                'indicators': ['404', 'This deployment could not be found'],
                'test_bucket': False
            },
            'netlify': {
                'patterns': [
                    r'\.netlify\.app',
                    r'\.netlify\.com'
                ],
                'indicators': ['404', 'Not Found', 'This site is not published'],
                'test_bucket': False
            },
            'cloudflare_pages': {
                'patterns': [
                    r'\.pages\.dev'
                ],
                'indicators': ['404', 'Not Found'],
                'test_bucket': False
            },
            'firebase': {
                'patterns': [
                    r'\.firebaseapp\.com',
                    r'\.web\.app'
                ],
                'indicators': ['404', 'Not Found'],
                'test_bucket': False
            },
            'shopify': {
                'patterns': [
                    r'\.myshopify\.com'
                ],
                'indicators': ['404', 'Not Found'],
                'test_bucket': False
            },
            'wordpress': {
                'patterns': [
                    r'\.wordpress\.com'
                ],
                'indicators': ['404', 'Not Found'],
                'test_bucket': False
            },
            'squarespace': {
                'patterns': [
                    r'\.squarespace\.com'
                ],
                'indicators': ['404', 'Not Found'],
                'test_bucket': False
            },
            'wix': {
                'patterns': [
                    r'\.wixsite\.com'
                ],
                'indicators': ['404', 'Not Found'],
                'test_bucket': False
            }
        }
        
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Running Subdomain Takeover Detection...{Style.RESET_ALL}")
        
        # Get subdomains from previous modules or enumerate
        subdomains = self.get_subdomains()
        
        if not subdomains:
            print(f"{Fore.YELLOW}[!] No subdomains found for takeover testing{Style.RESET_ALL}")
            return self.results
        
        print(f"{Fore.CYAN}[*] Testing {len(subdomains)} subdomains for takeover opportunities{Style.RESET_ALL}")
        
        # DNS-based takeover detection
        self.results['dns_checks'] = self.check_dns_takeovers(subdomains)
        
        # HTTP-based takeover detection
        self.results['http_checks'] = self.check_http_takeovers(subdomains)
        
        # CNAME-based takeover detection
        self.results['cname_checks'] = self.check_cname_takeovers(subdomains)
        
        # Cloud bucket misconfiguration checks
        self.results['cloud_buckets'] = self.check_cloud_buckets(subdomains)
        
        # AWS S3 bucket checks
        self.results['aws_buckets'] = self.check_aws_buckets(subdomains)
        
        # Azure Blob checks
        self.results['azure_blobs'] = self.check_azure_blobs(subdomains)
        
        # GCP Storage checks
        self.results['gcp_buckets'] = self.check_gcp_buckets(subdomains)
        
        # Platform-specific checks
        self.results['github_pages'] = self.check_github_pages(subdomains)
        self.results['heroku_apps'] = self.check_heroku_apps(subdomains)
        self.results['vercel_deployments'] = self.check_vercel_deployments(subdomains)
        self.results['netlify_sites'] = self.check_netlify_sites(subdomains)
        self.results['cloudflare_pages'] = self.check_cloudflare_pages(subdomains)
        self.results['firebase_hosting'] = self.check_firebase_hosting(subdomains)
        self.results['shopify_stores'] = self.check_shopify_stores(subdomains)
        self.results['wordpress_sites'] = self.check_wordpress_sites(subdomains)
        self.results['squarespace_sites'] = self.check_squarespace_sites(subdomains)
        self.results['wix_sites'] = self.check_wix_sites(subdomains)
        
        # Aggregate takeover candidates
        self.aggregate_takeover_candidates()
        
        return self.results
    
    def get_subdomains(self):
        """Get subdomains from previous modules or enumerate"""
        subdomains = []
        
        # Try to load from previous results
        results_dir = Path("results")
        if results_dir.exists():
            for json_file in results_dir.glob("*.json"):
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        if 'modules' in data and 'passive_recon' in data['modules']:
                            passive_results = data['modules']['passive_recon']
                            if 'subdomains' in passive_results:
                                subdomains.extend(passive_results['subdomains'])
                except Exception:
                    continue
        
        # If no subdomains found, generate common ones
        if not subdomains:
            domain = self.target if '.' in self.target else f"{self.target}.com"
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
                'api', 'cdn', 'static', 'assets', 'img', 'images', 'media',
                'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store',
                'app', 'web', 'portal', 'dashboard', 'panel', 'cpanel', 'webmail'
            ]
            subdomains = [f"{sub}.{domain}" for sub in common_subdomains]
        
        return list(set(subdomains))  # Remove duplicates
    
    def check_dns_takeovers(self, subdomains):
        """Check for DNS-based takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking DNS-based takeovers...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                # Check CNAME records
                cname_records = self.get_cname_records(subdomain)
                for cname in cname_records:
                    for service, pattern_info in self.takeover_patterns.items():
                        for pattern in pattern_info['patterns']:
                            if re.search(pattern, cname, re.IGNORECASE):
                                results.append({
                                    'subdomain': subdomain,
                                    'cname': cname,
                                    'service': service,
                                    'type': 'cname_takeover',
                                    'severity': 'high',
                                    'description': f'CNAME points to {service} service',
                                    'exploitation': self.get_exploitation_guide(service)
                                })
                
                # Check for dangling CNAMEs
                dangling_cname = self.check_dangling_cname(subdomain)
                if dangling_cname:
                    results.append(dangling_cname)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_http_takeovers(self, subdomains):
        """Check for HTTP-based takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking HTTP-based takeovers...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                # Check HTTP responses
                http_result = self.check_http_response(subdomain)
                if http_result:
                    results.append(http_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking HTTP for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_cname_takeovers(self, subdomains):
        """Check for CNAME-based takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking CNAME-based takeovers...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                cname_records = self.get_cname_records(subdomain)
                for cname in cname_records:
                    # Check if CNAME points to a service that can be taken over
                    takeover_info = self.analyze_cname_takeover(subdomain, cname)
                    if takeover_info:
                        results.append(takeover_info)
                        
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking CNAME for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_cloud_buckets(self, subdomains):
        """Check for cloud bucket misconfigurations"""
        print(f"{Fore.YELLOW}[*] Checking cloud bucket misconfigurations...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                # Check for bucket-like subdomains
                if any(keyword in subdomain.lower() for keyword in ['bucket', 's3', 'blob', 'storage']):
                    bucket_result = self.check_bucket_misconfiguration(subdomain)
                    if bucket_result:
                        results.append(bucket_result)
                        
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking bucket for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_aws_buckets(self, subdomains):
        """Check AWS S3 buckets for misconfigurations"""
        print(f"{Fore.YELLOW}[*] Checking AWS S3 buckets...{Style.RESET_ALL}")
        results = []
        
        # Extract potential bucket names
        bucket_names = self.extract_bucket_names(subdomains)
        
        for bucket_name in bucket_names:
            try:
                bucket_result = self.test_aws_bucket(bucket_name)
                if bucket_result:
                    results.append(bucket_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking AWS bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_azure_blobs(self, subdomains):
        """Check Azure Blob Storage for misconfigurations"""
        print(f"{Fore.YELLOW}[*] Checking Azure Blob Storage...{Style.RESET_ALL}")
        results = []
        
        # Extract potential blob names
        blob_names = self.extract_blob_names(subdomains)
        
        for blob_name in blob_names:
            try:
                blob_result = self.test_azure_blob(blob_name)
                if blob_result:
                    results.append(blob_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Azure blob {blob_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_gcp_buckets(self, subdomains):
        """Check GCP Storage buckets for misconfigurations"""
        print(f"{Fore.YELLOW}[*] Checking GCP Storage buckets...{Style.RESET_ALL}")
        results = []
        
        # Extract potential bucket names
        bucket_names = self.extract_gcp_bucket_names(subdomains)
        
        for bucket_name in bucket_names:
            try:
                bucket_result = self.test_gcp_bucket(bucket_name)
                if bucket_result:
                    results.append(bucket_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking GCP bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_github_pages(self, subdomains):
        """Check GitHub Pages for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking GitHub Pages...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                github_result = self.test_github_pages(subdomain)
                if github_result:
                    results.append(github_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking GitHub Pages for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_heroku_apps(self, subdomains):
        """Check Heroku apps for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Heroku apps...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                heroku_result = self.test_heroku_app(subdomain)
                if heroku_result:
                    results.append(heroku_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Heroku for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_vercel_deployments(self, subdomains):
        """Check Vercel deployments for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Vercel deployments...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                vercel_result = self.test_vercel_deployment(subdomain)
                if vercel_result:
                    results.append(vercel_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Vercel for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_netlify_sites(self, subdomains):
        """Check Netlify sites for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Netlify sites...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                netlify_result = self.test_netlify_site(subdomain)
                if netlify_result:
                    results.append(netlify_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Netlify for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_cloudflare_pages(self, subdomains):
        """Check Cloudflare Pages for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Cloudflare Pages...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                cf_result = self.test_cloudflare_pages(subdomain)
                if cf_result:
                    results.append(cf_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Cloudflare Pages for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_firebase_hosting(self, subdomains):
        """Check Firebase Hosting for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Firebase Hosting...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                firebase_result = self.test_firebase_hosting(subdomain)
                if firebase_result:
                    results.append(firebase_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Firebase for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_shopify_stores(self, subdomains):
        """Check Shopify stores for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Shopify stores...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                shopify_result = self.test_shopify_store(subdomain)
                if shopify_result:
                    results.append(shopify_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Shopify for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_wordpress_sites(self, subdomains):
        """Check WordPress sites for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking WordPress sites...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                wp_result = self.test_wordpress_site(subdomain)
                if wp_result:
                    results.append(wp_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking WordPress for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_squarespace_sites(self, subdomains):
        """Check Squarespace sites for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Squarespace sites...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                ss_result = self.test_squarespace_site(subdomain)
                if ss_result:
                    results.append(ss_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Squarespace for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def check_wix_sites(self, subdomains):
        """Check Wix sites for takeover opportunities"""
        print(f"{Fore.YELLOW}[*] Checking Wix sites...{Style.RESET_ALL}")
        results = []
        
        for subdomain in subdomains:
            try:
                wix_result = self.test_wix_site(subdomain)
                if wix_result:
                    results.append(wix_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking Wix for {subdomain}: {e}{Style.RESET_ALL}")
        
        return results
    
    def get_cname_records(self, subdomain):
        """Get CNAME records for a subdomain"""
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            return [str(answer) for answer in answers]
        except Exception:
            return []
    
    def check_dangling_cname(self, subdomain):
        """Check for dangling CNAME records"""
        try:
            cname_records = self.get_cname_records(subdomain)
            for cname in cname_records:
                # Check if the CNAME target resolves
                try:
                    dns.resolver.resolve(cname, 'A')
                except Exception:
                    # CNAME target doesn't resolve - potential takeover
                    return {
                        'subdomain': subdomain,
                        'cname': cname,
                        'type': 'dangling_cname',
                        'severity': 'high',
                        'description': 'CNAME points to non-existent domain',
                        'exploitation': 'Register the target domain to take over the subdomain'
                    }
        except Exception:
            pass
        return None
    
    def check_http_response(self, subdomain):
        """Check HTTP response for takeover indicators"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Check for takeover indicators
            for service, pattern_info in self.takeover_patterns.items():
                for indicator in pattern_info['indicators']:
                    if indicator.lower() in resp.text.lower():
                        return {
                            'subdomain': subdomain,
                            'service': service,
                            'type': 'http_takeover',
                            'severity': 'high',
                            'description': f'HTTP response contains {service} takeover indicator',
                            'response_code': resp.status_code,
                            'exploitation': self.get_exploitation_guide(service)
                        }
        except Exception:
            pass
        return None
    
    def analyze_cname_takeover(self, subdomain, cname):
        """Analyze CNAME for takeover potential"""
        for service, pattern_info in self.takeover_patterns.items():
            for pattern in pattern_info['patterns']:
                if re.search(pattern, cname, re.IGNORECASE):
                    return {
                        'subdomain': subdomain,
                        'cname': cname,
                        'service': service,
                        'type': 'cname_takeover',
                        'severity': 'high',
                        'description': f'CNAME points to {service} service',
                        'exploitation': self.get_exploitation_guide(service)
                    }
        return None
    
    def check_bucket_misconfiguration(self, subdomain):
        """Check for bucket misconfiguration"""
        try:
            # Test for open bucket listing
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                # Check for bucket listing indicators
                bucket_indicators = [
                    'ListBucketResult',
                    'Contents',
                    'Key',
                    'Size',
                    'LastModified'
                ]
                
                if any(indicator in resp.text for indicator in bucket_indicators):
                    return {
                        'subdomain': subdomain,
                        'type': 'bucket_listing',
                        'severity': 'high',
                        'description': 'Bucket allows public listing',
                        'exploitation': 'Bucket contents are publicly accessible'
                    }
        except Exception:
            pass
        return None
    
    def extract_bucket_names(self, subdomains):
        """Extract potential AWS S3 bucket names"""
        bucket_names = []
        for subdomain in subdomains:
            # Remove domain suffix
            name = subdomain.split('.')[0]
            if name and len(name) > 2:
                bucket_names.append(name)
        return list(set(bucket_names))
    
    def test_aws_bucket(self, bucket_name):
        """Test AWS S3 bucket for misconfigurations"""
        try:
            # Test for bucket listing
            url = f"http://{bucket_name}.s3.amazonaws.com"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                return {
                    'bucket_name': bucket_name,
                    'type': 'aws_s3_open',
                    'severity': 'high',
                    'description': 'AWS S3 bucket allows public access',
                    'url': url,
                    'exploitation': 'Bucket contents are publicly accessible'
                }
            elif resp.status_code == 403:
                return {
                    'bucket_name': bucket_name,
                    'type': 'aws_s3_exists',
                    'severity': 'medium',
                    'description': 'AWS S3 bucket exists but access denied',
                    'url': url,
                    'exploitation': 'Bucket exists but requires authentication'
                }
        except Exception:
            pass
        return None
    
    def extract_blob_names(self, subdomains):
        """Extract potential Azure Blob names"""
        blob_names = []
        for subdomain in subdomains:
            name = subdomain.split('.')[0]
            if name and len(name) > 2:
                blob_names.append(name)
        return list(set(blob_names))
    
    def test_azure_blob(self, blob_name):
        """Test Azure Blob Storage for misconfigurations"""
        try:
            # Test for blob access
            url = f"https://{blob_name}.blob.core.windows.net"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                return {
                    'blob_name': blob_name,
                    'type': 'azure_blob_open',
                    'severity': 'high',
                    'description': 'Azure Blob allows public access',
                    'url': url,
                    'exploitation': 'Blob contents are publicly accessible'
                }
        except Exception:
            pass
        return None
    
    def extract_gcp_bucket_names(self, subdomains):
        """Extract potential GCP Storage bucket names"""
        bucket_names = []
        for subdomain in subdomains:
            name = subdomain.split('.')[0]
            if name and len(name) > 2:
                bucket_names.append(name)
        return list(set(bucket_names))
    
    def test_gcp_bucket(self, bucket_name):
        """Test GCP Storage bucket for misconfigurations"""
        try:
            # Test for bucket access
            url = f"https://storage.googleapis.com/{bucket_name}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                return {
                    'bucket_name': bucket_name,
                    'type': 'gcp_storage_open',
                    'severity': 'high',
                    'description': 'GCP Storage bucket allows public access',
                    'url': url,
                    'exploitation': 'Bucket contents are publicly accessible'
                }
        except Exception:
            pass
        return None
    
    def test_github_pages(self, subdomain):
        """Test GitHub Pages for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404 and 'github' in resp.text.lower():
                return {
                    'subdomain': subdomain,
                    'type': 'github_pages_takeover',
                    'severity': 'high',
                    'description': 'GitHub Pages site not found',
                    'exploitation': 'Create a GitHub repository with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_heroku_app(self, subdomain):
        """Test Heroku app for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if 'no such app' in resp.text.lower():
                return {
                    'subdomain': subdomain,
                    'type': 'heroku_takeover',
                    'severity': 'high',
                    'description': 'Heroku app not found',
                    'exploitation': 'Create a Heroku app with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_vercel_deployment(self, subdomain):
        """Test Vercel deployment for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404 and 'vercel' in resp.text.lower():
                return {
                    'subdomain': subdomain,
                    'type': 'vercel_takeover',
                    'severity': 'high',
                    'description': 'Vercel deployment not found',
                    'exploitation': 'Create a Vercel deployment with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_netlify_site(self, subdomain):
        """Test Netlify site for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404 and 'netlify' in resp.text.lower():
                return {
                    'subdomain': subdomain,
                    'type': 'netlify_takeover',
                    'severity': 'high',
                    'description': 'Netlify site not found',
                    'exploitation': 'Create a Netlify site with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_cloudflare_pages(self, subdomain):
        """Test Cloudflare Pages for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404:
                return {
                    'subdomain': subdomain,
                    'type': 'cloudflare_pages_takeover',
                    'severity': 'high',
                    'description': 'Cloudflare Pages site not found',
                    'exploitation': 'Create a Cloudflare Pages site with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_firebase_hosting(self, subdomain):
        """Test Firebase Hosting for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404:
                return {
                    'subdomain': subdomain,
                    'type': 'firebase_takeover',
                    'severity': 'high',
                    'description': 'Firebase Hosting site not found',
                    'exploitation': 'Create a Firebase Hosting site with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_shopify_store(self, subdomain):
        """Test Shopify store for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404:
                return {
                    'subdomain': subdomain,
                    'type': 'shopify_takeover',
                    'severity': 'high',
                    'description': 'Shopify store not found',
                    'exploitation': 'Create a Shopify store with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_wordpress_site(self, subdomain):
        """Test WordPress site for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404:
                return {
                    'subdomain': subdomain,
                    'type': 'wordpress_takeover',
                    'severity': 'high',
                    'description': 'WordPress site not found',
                    'exploitation': 'Create a WordPress site with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_squarespace_site(self, subdomain):
        """Test Squarespace site for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404:
                return {
                    'subdomain': subdomain,
                    'type': 'squarespace_takeover',
                    'severity': 'high',
                    'description': 'Squarespace site not found',
                    'exploitation': 'Create a Squarespace site with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def test_wix_site(self, subdomain):
        """Test Wix site for takeover"""
        try:
            url = f"http://{subdomain}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 404:
                return {
                    'subdomain': subdomain,
                    'type': 'wix_takeover',
                    'severity': 'high',
                    'description': 'Wix site not found',
                    'exploitation': 'Create a Wix site with the same name to take over'
                }
        except Exception:
            pass
        return None
    
    def get_exploitation_guide(self, service):
        """Get exploitation guide for a service"""
        guides = {
            'aws_s3': 'Register the S3 bucket name to take over the subdomain',
            'azure_blob': 'Register the Azure Blob Storage account to take over the subdomain',
            'gcp_storage': 'Register the GCP Storage bucket to take over the subdomain',
            'github_pages': 'Create a GitHub repository with the same name to take over',
            'heroku': 'Create a Heroku app with the same name to take over',
            'vercel': 'Create a Vercel deployment with the same name to take over',
            'netlify': 'Create a Netlify site with the same name to take over',
            'cloudflare_pages': 'Create a Cloudflare Pages site with the same name to take over',
            'firebase': 'Create a Firebase Hosting site with the same name to take over',
            'shopify': 'Create a Shopify store with the same name to take over',
            'wordpress': 'Create a WordPress site with the same name to take over',
            'squarespace': 'Create a Squarespace site with the same name to take over',
            'wix': 'Create a Wix site with the same name to take over'
        }
        return guides.get(service, 'Research the specific service for takeover methods')
    
    def aggregate_takeover_candidates(self):
        """Aggregate all takeover candidates"""
        print(f"{Fore.CYAN}[*] Aggregating takeover candidates...{Style.RESET_ALL}")
        
        all_candidates = []
        
        # Collect all takeover candidates from different checks
        for key, value in self.results.items():
            if key.endswith('_checks') or key.endswith('_buckets') or key.endswith('_blobs') or key.endswith('_sites') or key.endswith('_apps') or key.endswith('_deployments') or key.endswith('_pages') or key.endswith('_hosting') or key.endswith('_stores'):
                if isinstance(value, list):
                    all_candidates.extend(value)
        
        self.results['takeover_candidates'] = all_candidates
        
        # Print summary
        print(f"{Fore.GREEN}[+] Subdomain Takeover Summary:{Style.RESET_ALL}")
        print(f"  - Total takeover candidates: {len(self.results['takeover_candidates'])}")
        print(f"  - DNS checks: {len(self.results['dns_checks'])}")
        print(f"  - HTTP checks: {len(self.results['http_checks'])}")
        print(f"  - CNAME checks: {len(self.results['cname_checks'])}")
        print(f"  - Cloud buckets: {len(self.results['cloud_buckets'])}")
        print(f"  - AWS S3 buckets: {len(self.results['aws_buckets'])}")
        print(f"  - Azure Blobs: {len(self.results['azure_blobs'])}")
        print(f"  - GCP buckets: {len(self.results['gcp_buckets'])}")
        
        # Print high-severity findings
        high_severity = [c for c in all_candidates if c.get('severity') == 'high']
        if high_severity:
            print(f"\n{Fore.RED}[!] High-severity takeover candidates found:{Style.RESET_ALL}")
            for candidate in high_severity:
                print(f"  - {candidate['subdomain']}: {candidate['type']} - {candidate['description']}") 
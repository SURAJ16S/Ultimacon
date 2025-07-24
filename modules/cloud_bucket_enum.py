#!/usr/bin/env python3
"""
Cloud Bucket Enumeration Module
Comprehensive cloud bucket misconfiguration detection and enumeration
"""

import os
import sys
import json
import time
import requests
import boto3
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional, Tuple
from colorama import Fore, Style
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import azure.storage.blob
from azure.storage.blob import BlobServiceClient
from google.cloud import storage
from google.cloud.exceptions import NotFound

class CloudBucketEnum:
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
            'aws_buckets': [],
            'azure_blobs': [],
            'gcp_buckets': [],
            'digitalocean_spaces': [],
            'cloudflare_r2': [],
            'backblaze_b2': [],
            'wasabi_buckets': [],
            'minio_buckets': [],
            'openstack_containers': [],
            'bucket_misconfigurations': [],
            'public_buckets': [],
            'directory_listings': [],
            'sensitive_files': [],
            'bucket_policies': [],
            'cors_misconfigurations': [],
            'versioning_issues': [],
            'encryption_issues': [],
            'access_logs': [],
            'bucket_analytics': []
        }
        
        # Common bucket name patterns
        self.bucket_patterns = {
            'aws_s3': [
                r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$',
                r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.s3\.amazonaws\.com$'
            ],
            'azure_blob': [
                r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.blob\.core\.windows\.net$'
            ],
            'gcp_storage': [
                r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'
            ]
        }
        
        # Sensitive file patterns
        self.sensitive_files = [
            '.env', '.git/config', '.gitignore', 'config.php', 'wp-config.php',
            'database.yml', 'secrets.json', 'credentials.json', 'id_rsa',
            'private.key', 'cert.pem', 'backup.sql', 'dump.sql', '*.log',
            'admin/', 'admin.php', 'login.php', 'config.ini', 'settings.py',
            'requirements.txt', 'package.json', 'composer.json', 'Dockerfile'
        ]
        
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Running Cloud Bucket Enumeration...{Style.RESET_ALL}")
        
        # Generate bucket names
        bucket_names = self.generate_bucket_names()
        
        print(f"{Fore.CYAN}[*] Testing {len(bucket_names)} potential bucket names{Style.RESET_ALL}")
        
        # AWS S3 bucket enumeration
        self.results['aws_buckets'] = self.enumerate_aws_buckets(bucket_names)
        
        # Azure Blob Storage enumeration
        self.results['azure_blobs'] = self.enumerate_azure_blobs(bucket_names)
        
        # GCP Storage bucket enumeration
        self.results['gcp_buckets'] = self.enumerate_gcp_buckets(bucket_names)
        
        # DigitalOcean Spaces enumeration
        self.results['digitalocean_spaces'] = self.enumerate_digitalocean_spaces(bucket_names)
        
        # Cloudflare R2 enumeration
        self.results['cloudflare_r2'] = self.enumerate_cloudflare_r2(bucket_names)
        
        # Backblaze B2 enumeration
        self.results['backblaze_b2'] = self.enumerate_backblaze_b2(bucket_names)
        
        # Wasabi bucket enumeration
        self.results['wasabi_buckets'] = self.enumerate_wasabi_buckets(bucket_names)
        
        # MinIO bucket enumeration
        self.results['minio_buckets'] = self.enumerate_minio_buckets(bucket_names)
        
        # OpenStack containers enumeration
        self.results['openstack_containers'] = self.enumerate_openstack_containers(bucket_names)
        
        # Analyze bucket misconfigurations
        self.analyze_bucket_misconfigurations()
        
        return self.results
    
    def generate_bucket_names(self):
        """Generate potential bucket names based on target"""
        bucket_names = []
        
        # Extract domain name
        domain = self.target if '.' in self.target else f"{self.target}.com"
        domain_parts = domain.split('.')
        
        # Common bucket name patterns
        patterns = [
            domain,
            domain.replace('.', '-'),
            domain.replace('.', ''),
            domain_parts[0],
            f"{domain_parts[0]}-backup",
            f"{domain_parts[0]}-dev",
            f"{domain_parts[0]}-staging",
            f"{domain_parts[0]}-prod",
            f"{domain_parts[0]}-test",
            f"{domain_parts[0]}-assets",
            f"{domain_parts[0]}-static",
            f"{domain_parts[0]}-media",
            f"{domain_parts[0]}-uploads",
            f"{domain_parts[0]}-files",
            f"{domain_parts[0]}-data",
            f"{domain_parts[0]}-logs",
            f"{domain_parts[0]}-temp",
            f"{domain_parts[0]}-cache",
            f"{domain_parts[0]}-public",
            f"{domain_parts[0]}-private",
            f"{domain_parts[0]}-config",
            f"{domain_parts[0]}-secrets",
            f"{domain_parts[0]}-backups",
            f"{domain_parts[0]}-archive",
            f"{domain_parts[0]}-storage",
            f"{domain_parts[0]}-bucket",
            f"{domain_parts[0]}-s3",
            f"{domain_parts[0]}-blob",
            f"{domain_parts[0]}-cloud",
            f"{domain_parts[0]}-cdn",
            f"{domain_parts[0]}-images",
            f"{domain_parts[0]}-videos",
            f"{domain_parts[0]}-documents",
            f"{domain_parts[0]}-downloads",
            f"{domain_parts[0]}-exports",
            f"{domain_parts[0]}-imports",
            f"{domain_parts[0]}-sync",
            f"{domain_parts[0]}-mirror",
            f"{domain_parts[0]}-replica",
            f"{domain_parts[0]}-snapshot",
            f"{domain_parts[0]}-backup-{int(time.time())}",
            f"{domain_parts[0]}-{int(time.time())}",
            f"{domain_parts[0]}-{time.strftime('%Y%m%d')}",
            f"{domain_parts[0]}-{time.strftime('%Y%m')}",
            f"{domain_parts[0]}-{time.strftime('%Y')}",
        ]
        
        # Add common variations
        for pattern in patterns:
            bucket_names.extend([
                pattern,
                pattern.lower(),
                pattern.replace('-', ''),
                pattern.replace('-', '_'),
                pattern.replace('_', '-'),
                f"{pattern}1",
                f"{pattern}2",
                f"{pattern}01",
                f"{pattern}02",
                f"{pattern}-old",
                f"{pattern}-new",
                f"{pattern}-current",
                f"{pattern}-latest"
            ])
        
        # Remove duplicates and invalid names
        bucket_names = list(set(bucket_names))
        bucket_names = [name for name in bucket_names if self.is_valid_bucket_name(name)]
        
        return bucket_names
    
    def is_valid_bucket_name(self, name):
        """Check if bucket name is valid"""
        if not name or len(name) < 3 or len(name) > 63:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', name):
            return False
        
        # Check for consecutive dots or hyphens
        if '..' in name or '--' in name:
            return False
        
        # Check for IP address format
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
            return False
        
        return True
    
    def enumerate_aws_buckets(self, bucket_names):
        """Enumerate AWS S3 buckets"""
        print(f"{Fore.YELLOW}[*] Enumerating AWS S3 buckets...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                bucket_result = self.test_aws_bucket(bucket_name)
                if bucket_result:
                    results.append(bucket_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing AWS bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_aws_bucket(self, bucket_name):
        """Test AWS S3 bucket for access and misconfigurations"""
        try:
            # Test different S3 endpoints
            endpoints = [
                f"http://{bucket_name}.s3.amazonaws.com",
                f"https://{bucket_name}.s3.amazonaws.com",
                f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com",
                f"https://{bucket_name}.s3-website-us-east-1.amazonaws.com",
                f"http://{bucket_name}.s3-website-us-west-1.amazonaws.com",
                f"https://{bucket_name}.s3-website-us-west-1.amazonaws.com",
                f"http://{bucket_name}.s3-website-us-west-2.amazonaws.com",
                f"https://{bucket_name}.s3-website-us-west-2.amazonaws.com",
                f"http://{bucket_name}.s3-website-eu-west-1.amazonaws.com",
                f"https://{bucket_name}.s3-website-eu-west-1.amazonaws.com"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        # Check for bucket listing
                        if self.is_bucket_listing(resp.text):
                            return {
                                'bucket_name': bucket_name,
                                'endpoint': endpoint,
                                'type': 'aws_s3_public_listing',
                                'severity': 'high',
                                'description': 'AWS S3 bucket allows public listing',
                                'files_found': self.extract_files_from_listing(resp.text),
                                'exploitation': 'Bucket contents are publicly accessible'
                            }
                        else:
                            return {
                                'bucket_name': bucket_name,
                                'endpoint': endpoint,
                                'type': 'aws_s3_public_access',
                                'severity': 'medium',
                                'description': 'AWS S3 bucket allows public access',
                                'exploitation': 'Bucket is accessible but may not list contents'
                            }
                    
                    elif resp.status_code == 403:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'aws_s3_exists',
                            'severity': 'low',
                            'description': 'AWS S3 bucket exists but access denied',
                            'exploitation': 'Bucket exists but requires authentication'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing AWS bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_azure_blobs(self, bucket_names):
        """Enumerate Azure Blob Storage containers"""
        print(f"{Fore.YELLOW}[*] Enumerating Azure Blob Storage...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                blob_result = self.test_azure_blob(bucket_name)
                if blob_result:
                    results.append(blob_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing Azure blob {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_azure_blob(self, bucket_name):
        """Test Azure Blob Storage container for access"""
        try:
            endpoints = [
                f"https://{bucket_name}.blob.core.windows.net",
                f"https://{bucket_name}.blob.core.windows.net/?restype=container&comp=list"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        # Check for container listing
                        if self.is_azure_listing(resp.text):
                            return {
                                'bucket_name': bucket_name,
                                'endpoint': endpoint,
                                'type': 'azure_blob_public_listing',
                                'severity': 'high',
                                'description': 'Azure Blob container allows public listing',
                                'files_found': self.extract_azure_files(resp.text),
                                'exploitation': 'Container contents are publicly accessible'
                            }
                        else:
                            return {
                                'bucket_name': bucket_name,
                                'endpoint': endpoint,
                                'type': 'azure_blob_public_access',
                                'severity': 'medium',
                                'description': 'Azure Blob container allows public access',
                                'exploitation': 'Container is accessible but may not list contents'
                            }
                    
                    elif resp.status_code == 403:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'azure_blob_exists',
                            'severity': 'low',
                            'description': 'Azure Blob container exists but access denied',
                            'exploitation': 'Container exists but requires authentication'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing Azure blob {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_gcp_buckets(self, bucket_names):
        """Enumerate GCP Storage buckets"""
        print(f"{Fore.YELLOW}[*] Enumerating GCP Storage buckets...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                bucket_result = self.test_gcp_bucket(bucket_name)
                if bucket_result:
                    results.append(bucket_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing GCP bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_gcp_bucket(self, bucket_name):
        """Test GCP Storage bucket for access"""
        try:
            endpoints = [
                f"https://storage.googleapis.com/{bucket_name}",
                f"https://storage.googleapis.com/{bucket_name}/",
                f"https://{bucket_name}.storage.googleapis.com"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        # Check for bucket listing
                        if self.is_gcp_listing(resp.text):
                            return {
                                'bucket_name': bucket_name,
                                'endpoint': endpoint,
                                'type': 'gcp_storage_public_listing',
                                'severity': 'high',
                                'description': 'GCP Storage bucket allows public listing',
                                'files_found': self.extract_gcp_files(resp.text),
                                'exploitation': 'Bucket contents are publicly accessible'
                            }
                        else:
                            return {
                                'bucket_name': bucket_name,
                                'endpoint': endpoint,
                                'type': 'gcp_storage_public_access',
                                'severity': 'medium',
                                'description': 'GCP Storage bucket allows public access',
                                'exploitation': 'Bucket is accessible but may not list contents'
                            }
                    
                    elif resp.status_code == 403:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'gcp_storage_exists',
                            'severity': 'low',
                            'description': 'GCP Storage bucket exists but access denied',
                            'exploitation': 'Bucket exists but requires authentication'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing GCP bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_digitalocean_spaces(self, bucket_names):
        """Enumerate DigitalOcean Spaces"""
        print(f"{Fore.YELLOW}[*] Enumerating DigitalOcean Spaces...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                space_result = self.test_digitalocean_space(bucket_name)
                if space_result:
                    results.append(space_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing DigitalOcean space {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_digitalocean_space(self, bucket_name):
        """Test DigitalOcean Space for access"""
        try:
            endpoints = [
                f"https://{bucket_name}.nyc3.digitaloceanspaces.com",
                f"https://{bucket_name}.ams3.digitaloceanspaces.com",
                f"https://{bucket_name}.sgp1.digitaloceanspaces.com",
                f"https://{bucket_name}.fra1.digitaloceanspaces.com"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'digitalocean_space_public',
                            'severity': 'medium',
                            'description': 'DigitalOcean Space allows public access',
                            'exploitation': 'Space contents may be publicly accessible'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing DigitalOcean space {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_cloudflare_r2(self, bucket_names):
        """Enumerate Cloudflare R2 buckets"""
        print(f"{Fore.YELLOW}[*] Enumerating Cloudflare R2 buckets...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                r2_result = self.test_cloudflare_r2(bucket_name)
                if r2_result:
                    results.append(r2_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing Cloudflare R2 bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_cloudflare_r2(self, bucket_name):
        """Test Cloudflare R2 bucket for access"""
        try:
            endpoints = [
                f"https://{bucket_name}.r2.cloudflarestorage.com",
                f"https://{bucket_name}.r2.dev"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'cloudflare_r2_public',
                            'severity': 'medium',
                            'description': 'Cloudflare R2 bucket allows public access',
                            'exploitation': 'R2 bucket contents may be publicly accessible'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing Cloudflare R2 bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_backblaze_b2(self, bucket_names):
        """Enumerate Backblaze B2 buckets"""
        print(f"{Fore.YELLOW}[*] Enumerating Backblaze B2 buckets...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                b2_result = self.test_backblaze_b2(bucket_name)
                if b2_result:
                    results.append(b2_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing Backblaze B2 bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_backblaze_b2(self, bucket_name):
        """Test Backblaze B2 bucket for access"""
        try:
            endpoints = [
                f"https://f004.backblazeb2.com/file/{bucket_name}",
                f"https://f004.backblazeb2.com/b2api/v1/b2_list_file_names"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'backblaze_b2_public',
                            'severity': 'medium',
                            'description': 'Backblaze B2 bucket allows public access',
                            'exploitation': 'B2 bucket contents may be publicly accessible'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing Backblaze B2 bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_wasabi_buckets(self, bucket_names):
        """Enumerate Wasabi buckets"""
        print(f"{Fore.YELLOW}[*] Enumerating Wasabi buckets...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                wasabi_result = self.test_wasabi_bucket(bucket_name)
                if wasabi_result:
                    results.append(wasabi_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing Wasabi bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_wasabi_bucket(self, bucket_name):
        """Test Wasabi bucket for access"""
        try:
            endpoints = [
                f"https://s3.wasabisys.com/{bucket_name}",
                f"https://s3.us-east-1.wasabisys.com/{bucket_name}",
                f"https://s3.us-west-1.wasabisys.com/{bucket_name}"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'wasabi_public',
                            'severity': 'medium',
                            'description': 'Wasabi bucket allows public access',
                            'exploitation': 'Wasabi bucket contents may be publicly accessible'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing Wasabi bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_minio_buckets(self, bucket_names):
        """Enumerate MinIO buckets"""
        print(f"{Fore.YELLOW}[*] Enumerating MinIO buckets...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                minio_result = self.test_minio_bucket(bucket_name)
                if minio_result:
                    results.append(minio_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing MinIO bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_minio_bucket(self, bucket_name):
        """Test MinIO bucket for access"""
        try:
            # Common MinIO endpoints
            endpoints = [
                f"http://localhost:9000/{bucket_name}",
                f"https://localhost:9000/{bucket_name}",
                f"http://minio:9000/{bucket_name}",
                f"https://minio:9000/{bucket_name}"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'minio_public',
                            'severity': 'medium',
                            'description': 'MinIO bucket allows public access',
                            'exploitation': 'MinIO bucket contents may be publicly accessible'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing MinIO bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def enumerate_openstack_containers(self, bucket_names):
        """Enumerate OpenStack containers"""
        print(f"{Fore.YELLOW}[*] Enumerating OpenStack containers...{Style.RESET_ALL}")
        results = []
        
        for bucket_name in bucket_names:
            try:
                openstack_result = self.test_openstack_container(bucket_name)
                if openstack_result:
                    results.append(openstack_result)
                    
            except Exception as e:
                print(f"{Fore.RED}[-] Error testing OpenStack container {bucket_name}: {e}{Style.RESET_ALL}")
        
        return results
    
    def test_openstack_container(self, bucket_name):
        """Test OpenStack container for access"""
        try:
            # Common OpenStack endpoints
            endpoints = [
                f"https://swift.example.com/{bucket_name}",
                f"https://object-storage.example.com/{bucket_name}"
            ]
            
            for endpoint in endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=10)
                    
                    if resp.status_code == 200:
                        return {
                            'bucket_name': bucket_name,
                            'endpoint': endpoint,
                            'type': 'openstack_public',
                            'severity': 'medium',
                            'description': 'OpenStack container allows public access',
                            'exploitation': 'OpenStack container contents may be publicly accessible'
                        }
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error testing OpenStack container {bucket_name}: {e}{Style.RESET_ALL}")
        
        return None
    
    def is_bucket_listing(self, content):
        """Check if content is a bucket listing"""
        indicators = [
            'ListBucketResult',
            'Contents',
            'Key',
            'Size',
            'LastModified',
            'Owner',
            'ID',
            'DisplayName'
        ]
        return any(indicator in content for indicator in indicators)
    
    def is_azure_listing(self, content):
        """Check if content is an Azure container listing"""
        indicators = [
            'EnumerationResults',
            'Blobs',
            'Blob',
            'Name',
            'Url',
            'Properties'
        ]
        return any(indicator in content for indicator in indicators)
    
    def is_gcp_listing(self, content):
        """Check if content is a GCP bucket listing"""
        indicators = [
            'ListBucketResult',
            'Contents',
            'Key',
            'Size',
            'LastModified'
        ]
        return any(indicator in content for indicator in indicators)
    
    def extract_files_from_listing(self, content):
        """Extract file names from bucket listing"""
        files = []
        try:
            # Parse XML listing
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            for elem in root.iter():
                if elem.tag.endswith('Key'):
                    files.append(elem.text)
                    
        except Exception:
            # Fallback to regex
            file_pattern = r'<Key>([^<]+)</Key>'
            files = re.findall(file_pattern, content)
        
        return files[:10]  # Limit to first 10 files
    
    def extract_azure_files(self, content):
        """Extract file names from Azure listing"""
        files = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            for elem in root.iter():
                if elem.tag.endswith('Name'):
                    files.append(elem.text)
                    
        except Exception:
            file_pattern = r'<Name>([^<]+)</Name>'
            files = re.findall(file_pattern, content)
        
        return files[:10]
    
    def extract_gcp_files(self, content):
        """Extract file names from GCP listing"""
        files = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            for elem in root.iter():
                if elem.tag.endswith('Key'):
                    files.append(elem.text)
                    
        except Exception:
            file_pattern = r'<Key>([^<]+)</Key>'
            files = re.findall(file_pattern, content)
        
        return files[:10]
    
    def analyze_bucket_misconfigurations(self):
        """Analyze bucket misconfigurations"""
        print(f"{Fore.CYAN}[*] Analyzing bucket misconfigurations...{Style.RESET_ALL}")
        
        # Aggregate all bucket results
        all_buckets = []
        for key, value in self.results.items():
            if key.endswith('_buckets') or key.endswith('_blobs') or key.endswith('_spaces') or key.endswith('_r2') or key.endswith('_b2') or key.endswith('_containers'):
                if isinstance(value, list):
                    all_buckets.extend(value)
        
        # Categorize misconfigurations
        public_buckets = [b for b in all_buckets if 'public' in b.get('type', '').lower()]
        listing_buckets = [b for b in all_buckets if 'listing' in b.get('type', '').lower()]
        
        self.results['public_buckets'] = public_buckets
        self.results['directory_listings'] = listing_buckets
        self.results['bucket_misconfigurations'] = all_buckets
        
        # Print summary
        print(f"{Fore.GREEN}[+] Cloud Bucket Enumeration Summary:{Style.RESET_ALL}")
        print(f"  - Total buckets found: {len(all_buckets)}")
        print(f"  - Public buckets: {len(public_buckets)}")
        print(f"  - Directory listings: {len(listing_buckets)}")
        print(f"  - AWS S3 buckets: {len(self.results['aws_buckets'])}")
        print(f"  - Azure Blobs: {len(self.results['azure_blobs'])}")
        print(f"  - GCP buckets: {len(self.results['gcp_buckets'])}")
        print(f"  - DigitalOcean Spaces: {len(self.results['digitalocean_spaces'])}")
        print(f"  - Cloudflare R2: {len(self.results['cloudflare_r2'])}")
        print(f"  - Backblaze B2: {len(self.results['backblaze_b2'])}")
        print(f"  - Wasabi buckets: {len(self.results['wasabi_buckets'])}")
        print(f"  - MinIO buckets: {len(self.results['minio_buckets'])}")
        print(f"  - OpenStack containers: {len(self.results['openstack_containers'])}")
        
        # Print high-severity findings
        high_severity = [b for b in all_buckets if b.get('severity') == 'high']
        if high_severity:
            print(f"\n{Fore.RED}[!] High-severity bucket misconfigurations found:{Style.RESET_ALL}")
            for bucket in high_severity:
                print(f"  - {bucket['bucket_name']}: {bucket['type']} - {bucket['description']}") 
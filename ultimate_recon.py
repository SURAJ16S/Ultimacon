#!/usr/bin/env python3
"""
ULTIMATE RECONNAISSANCE TOOL - The Most Comprehensive Reconnaissance Framework
Author: Security Researcher
Version: 2.0
Description: All-in-one reconnaissance tool covering every possible aspect of information gathering
"""

import os
import sys
import json
import time
import signal
import threading
import subprocess
import requests
import dns.resolver
import whois
import socket
import ssl
import re
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import ipaddress
import nmap
import shodan
import censys
from pathlib import Path
import yaml
import xml.etree.ElementTree as ET
from colorama import init, Fore, Back, Style
import tqdm
import asyncio
import aiohttp
import aiodns
import aiofiles
import hashlib
from bs4 import BeautifulSoup

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class UltimateRecon:
    def __init__(self, target, output_dir="results", auto_setup=True):
        self.target = target
        self.output_dir = output_dir
        self.results = {}
        
        # Auto-setup if enabled
        if auto_setup:
            self.run_auto_setup()
        
        self.config = self.load_config()
        self.tools_config = self.load_tools_config()
        self.wordlists = self.load_wordlists()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Initialize progress tracking
        self.total_tasks = 0
        self.completed_tasks = 0
        self.start_time = None
        self.estimated_time = 0
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize API keys
        self.api_keys = self.load_api_keys()
        
        # Initialize fallback manager
        self.fallback_manager = self.initialize_fallback_manager()
        
        # Target analysis
        self.target_type = self.analyze_target_type()
        self.target_info = {}
        
    def load_config(self):
        """Load main configuration"""
        config = {
            'threads': 15,  # More realistic default
            'timeout': 30,
            'retries': 3,
            'rate_limit': 1,
            'stealth_mode': False,
            'aggressive_mode': False,
            'output_formats': ['txt', 'json', 'html'],
            'enable_apis': True,
            'enable_bruteforce': True,
            'enable_vuln_scan': True,
            'enable_osint': True
        }
        return config
    
    def load_tools_config(self):
        """Load tools configuration"""
        return {
            'nmap': {
                'path': 'nmap',
                'args': '-sS -sV -O --script=vuln,auth,default',
                'stealth_args': '-sS -sV -O --script=vuln,auth,default --max-retries 2'
            },
            'gobuster': {
                'path': 'gobuster',
                'args': 'dir -t 50 -w {wordlist} -u {target}',
                'stealth_args': 'dir -t 20 -w {wordlist} -u {target} --delay 2s'
            },
            'subfinder': {
                'path': 'subfinder',
                'args': '-d {target} -silent',
                'stealth_args': '-d {target} -silent -timeout 30'
            },
            'amass': {
                'path': 'amass',
                'args': 'enum -d {target} -passive',
                'stealth_args': 'enum -d {target} -passive -timeout 30'
            },
            'ffuf': {
                'path': 'ffuf',
                'args': '-u {target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403',
                'stealth_args': '-u {target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -rate 100'
            },
            'whatweb': {
                'path': 'whatweb',
                'args': '--no-errors --log-xml=- {target}'
            },
            'wappalyzer': {
                'api_key': os.getenv('WAPPALYZER_API_KEY', '')
            }
        }
    
    def load_wordlists(self):
        """Load wordlist configurations"""
        return {
            'subdomains': [
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt',
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt'
            ],
            'directories': [
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt'
            ],
            'files': [
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt'
            ],
            'usernames': [
                '/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt',
                '/usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt'
            ],
            'passwords': [
                '/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
                '/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt'
            ]
        }
    
    def load_api_keys(self):
        """Load API keys from environment or config file"""
        api_keys = {}
        
        # Try to load from environment variables
        api_keys['shodan'] = os.getenv('SHODAN_API_KEY', '')
        api_keys['censys_id'] = os.getenv('CENSYS_API_ID', '')
        api_keys['censys_secret'] = os.getenv('CENSYS_API_SECRET', '')
        api_keys['virustotal'] = os.getenv('VIRUSTOTAL_API_KEY', '')
        api_keys['securitytrails'] = os.getenv('SECURITYTRAILS_API_KEY', '')
        api_keys['hunter'] = os.getenv('HUNTER_API_KEY', '')
        api_keys['wappalyzer'] = os.getenv('WAPPALYZER_API_KEY', '')
        
        # Try to load from config file
        config_file = 'api_keys.json'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_keys = json.load(f)
                    api_keys.update(file_keys)
            except:
                pass
        
        return api_keys
    
    def run_auto_setup(self):
        """Run automatic setup and system check"""
        print(f"{Fore.CYAN}[*] Running automatic setup...{Style.RESET_ALL}")
        
        # Check if setup has already been run
        if os.path.exists('config.yaml') and os.path.exists('api_keys.json'):
            print(f"{Fore.GREEN}[+] Configuration files found, skipping setup{Style.RESET_ALL}")
            return
        
        # Run system check
        try:
            from system_check import SystemChecker
            checker = SystemChecker()
            results, recommendations = checker.run_full_check()
            
            # Auto-configure based on system specs
            self.auto_configure_system(results)
            
        except ImportError:
            print(f"{Fore.YELLOW}[!] System check module not found, using default configuration{Style.RESET_ALL}")
    
    def auto_configure_system(self, system_results):
        """Auto-configure based on system specifications"""
        performance = system_results.get('performance', 'medium')
        
        # Default configurations based on performance category (realistic)
        configs = {
            'low': {
                'threads': 5,
                'timeout': 30,
                'retries': 2,
                'rate_limit': 2,
                'stealth_mode': True,
                'aggressive_mode': False,
                'enable_apis': True,
                'enable_bruteforce': False,
                'enable_vuln_scan': False,
                'enable_osint': True
            },
            'medium': {
                'threads': 15,
                'timeout': 30,
                'retries': 3,
                'rate_limit': 1,
                'stealth_mode': False,
                'aggressive_mode': False,
                'enable_apis': True,
                'enable_bruteforce': True,
                'enable_vuln_scan': True,
                'enable_osint': True
            },
            'high': {
                'threads': 30,
                'timeout': 30,
                'retries': 3,
                'rate_limit': 1,
                'stealth_mode': False,
                'aggressive_mode': False,
                'enable_apis': True,
                'enable_bruteforce': True,
                'enable_vuln_scan': True,
                'enable_osint': True
            },
            'enterprise': {
                'threads': 50,
                'timeout': 30,
                'retries': 3,
                'rate_limit': 0.5,
                'stealth_mode': False,
                'aggressive_mode': True,
                'enable_apis': True,
                'enable_bruteforce': True,
                'enable_vuln_scan': True,
                'enable_osint': True
            }
        }
        
        # Save auto-configuration
        config = configs[performance]
        with open('config.yaml', 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        # Create default API keys file
        default_api_keys = {
            'shodan': '',
            'censys_id': '',
            'censys_secret': '',
            'virustotal': '',
            'securitytrails': '',
            'hunter': '',
            'wappalyzer': '',
            'haveibeenpwned': '',
            'dehashed': ''
        }
        
        with open('api_keys.json', 'w') as f:
            json.dump(default_api_keys, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Auto-configured for {performance.upper()} performance category{Style.RESET_ALL}")
    
    def initialize_fallback_manager(self):
        """Initialize fallback manager"""
        try:
            sys.path.append('modules')
            from fallback_manager import FallbackManager
            
            fallback_manager = FallbackManager(self.target, self.config, self.api_keys)
            fallback_manager.setup_fallbacks()
            return fallback_manager
            
        except ImportError:
            print(f"{Fore.YELLOW}[!] Fallback manager not found, continuing without fallbacks{Style.RESET_ALL}")
            return None
    
    def analyze_target_type(self):
        """Analyze target type (domain, IP, URL, network)"""
        target = self.target.lower()
        
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            return 'url'
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass
        
        # Check if it's a network range
        try:
            ipaddress.ip_network(target, strict=False)
            return 'network'
        except ValueError:
            pass
        
        # Check if it's a domain
        if '.' in target and not target.startswith('.') and not target.endswith('.'):
            return 'domain'
        
        return 'unknown'
    
    def print_banner(self):
        """Print the tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                    ULTIMATE RECONNAISSANCE TOOL v2.0                              ║
║                        The Most Comprehensive Reconnaissance Framework            ║
║                              All-in-One Information Gathering                     ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}[*] Target: {self.target}
[*] Type: {self.target_type.upper()}
[*] Output Directory: {self.output_dir}
[*] Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[*] Configuration: {self.config['threads']} threads, {self.config['timeout']}s timeout
{Style.RESET_ALL}
"""
        print(banner)
    
    def show_progress(self, task_name, current, total, eta=None):
        """Show progress bar with ETA"""
        percentage = (current / total) * 100
        bar_length = 50
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        eta_str = f"ETA: {eta}" if eta else ""
        print(f"\r{Fore.GREEN}[{task_name}] {bar} {percentage:.1f}% ({current}/{total}) {eta_str}", end='', flush=True)
    
    def estimate_time(self, task_count):
        """Estimate time based on task count and target type"""
        base_time = 60  # Base time in seconds
        
        if self.target_type == 'domain':
            base_time *= 2
        elif self.target_type == 'network':
            base_time *= 5
        elif self.target_type == 'ip':
            base_time *= 1.5
        
        if self.config['aggressive_mode']:
            base_time *= 0.5
        elif self.config['stealth_mode']:
            base_time *= 2
        
        return base_time * (task_count / 100)  # Scale with task count
    
    def run_command(self, command, timeout=300):
        """Run shell command with timeout and error handling"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def check_tool_availability(self):
        """Check if required tools are available"""
        tools = ['nmap', 'gobuster', 'subfinder', 'amass', 'ffuf', 'whatweb']
        available_tools = []
        
        print(f"{Fore.BLUE}[*] Checking tool availability...{Style.RESET_ALL}")
        
        for tool in tools:
            success, _, _ = self.run_command(f"which {tool}", timeout=10)
            if success:
                available_tools.append(tool)
                print(f"{Fore.GREEN}[+] {tool}: Available{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] {tool}: Not found{Style.RESET_ALL}")
        
        return available_tools
    
    def save_results(self, module_name, data):
        """Save results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.target}_{module_name}_{timestamp}"
        
        # Save as JSON
        json_file = os.path.join(self.output_dir, f"{filename}.json")
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        # Save as TXT
        txt_file = os.path.join(self.output_dir, f"{filename}.txt")
        with open(txt_file, 'w') as f:
            f.write(f"=== {module_name.upper()} RESULTS ===\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"{key}:\n")
                    if isinstance(value, list):
                        for item in value:
                            f.write(f"  - {item}\n")
                    else:
                        f.write(f"  {value}\n")
                    f.write("\n")
            elif isinstance(data, list):
                for item in data:
                    f.write(f"- {item}\n")
        
        return json_file, txt_file

    def run(self):
        """Main execution method"""
        self.print_banner()
        
        # Safety check - MUST be first
        if not self.run_safety_check():
            print(f"{Fore.RED}[!] Safety check failed - aborting reconnaissance{Style.RESET_ALL}")
            return False
        
        # Check tool availability
        available_tools = self.check_tool_availability()
        
        # Initialize results
        self.results = {
            'target_info': {},
            'passive_recon': {},
            'active_recon': {},
            'certificate_analysis': {},
            'vulnerability_scan': {},
            'osint': {},
            'summary': {}
        }
        
        # Start time tracking
        self.start_time = time.time()
        
        try:
            # Phase 1: Target Analysis and Passive Reconnaissance
            print(f"\n{Fore.CYAN}[PHASE 1] TARGET ANALYSIS AND PASSIVE RECONNAISSANCE{Style.RESET_ALL}")
            self.target_analysis()
            self.passive_reconnaissance()
            
            # Phase 2: Certificate Analysis (crt.sh)
            print(f"\n{Fore.CYAN}[PHASE 2] CERTIFICATE ANALYSIS{Style.RESET_ALL}")
            self.certificate_analysis()
            
            # Phase 3: Active Reconnaissance
            print(f"\n{Fore.CYAN}[PHASE 3] ACTIVE RECONNAISSANCE{Style.RESET_ALL}")
            self.active_reconnaissance()
            
            # Phase 4: Service Enumeration
            print(f"\n{Fore.CYAN}[PHASE 4] SERVICE ENUMERATION{Style.RESET_ALL}")
            self.service_enumeration()
            
            # Phase 5: Vulnerability Assessment
            print(f"\n{Fore.CYAN}[PHASE 5] VULNERABILITY ASSESSMENT{Style.RESET_ALL}")
            self.vulnerability_assessment()
            
            # Phase 6: OSINT and Intelligence Gathering
            print(f"\n{Fore.CYAN}[PHASE 6] OSINT AND INTELLIGENCE GATHERING{Style.RESET_ALL}")
            self.osint_gathering()
            
            # Phase 7: Report Generation
            print(f"\n{Fore.CYAN}[PHASE 7] REPORT GENERATION{Style.RESET_ALL}")
            self.generate_final_report()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Reconnaissance interrupted by user{Style.RESET_ALL}")
            self.generate_final_report()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during reconnaissance: {e}{Style.RESET_ALL}")
            self.generate_final_report()
        
        # Calculate total time
        total_time = time.time() - self.start_time
        print(f"\n{Fore.GREEN}[+] Reconnaissance completed in {total_time:.2f} seconds{Style.RESET_ALL}")
        return True

    def run_safety_check(self):
        """Run comprehensive safety check before reconnaissance"""
        print(f"\n{Fore.CYAN}🔒 RUNNING SAFETY CHECK{Style.RESET_ALL}")
        print("=" * 50)
        
        # Check if safety checker is available
        if not hasattr(self, 'safety_checker') or self.safety_checker is None:
            try:
                from safety_check import SafetyChecker
                self.safety_checker = SafetyChecker()
            except ImportError:
                print(f"{Fore.YELLOW}[!] Safety checker not available - using basic safety checks{Style.RESET_ALL}")
                return self.basic_safety_check()
        
        # Run comprehensive safety check
        return self.safety_checker.run_safety_check(self.target)
    
    def basic_safety_check(self):
        """Basic safety check when full safety checker is not available"""
        print(f"{Fore.YELLOW}[!] Running basic safety check for: {self.target}{Style.RESET_ALL}")
        
        # Display safety warnings
        print(f"\n{Fore.RED}⚠️  SAFETY WARNING ⚠️{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This tool is for authorized security testing only.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}You MUST have explicit permission before scanning.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}You are responsible for compliance with all applicable laws.{Style.RESET_ALL}")
        
        # Check for obvious safety issues
        safety_issues = []
        
        # Check for localhost
        if self.target.lower() in ['localhost', '127.0.0.1', '::1']:
            safety_issues.append("Localhost detected")
        
        # Check for private IPs
        try:
            ip = ipaddress.ip_address(self.target)
            if ip.is_private:
                safety_issues.append("Private IP address detected")
        except:
            pass
        
        # Check for government domains
        gov_domains = ['.gov', '.mil', '.gov.uk', '.gouv.fr', '.gov.au']
        if any(domain in self.target.lower() for domain in gov_domains):
            safety_issues.append("Government domain detected")
        
        # Check for financial domains
        financial_keywords = ['bank', 'credit', 'finance', 'insurance', 'paypal', 'stripe']
        if any(keyword in self.target.lower() for keyword in financial_keywords):
            safety_issues.append("Financial institution detected")
        
        if safety_issues:
            print(f"\n{Fore.RED}⚠️  SAFETY ISSUES DETECTED:{Style.RESET_ALL}")
            for issue in safety_issues:
                print(f"  • {issue}")
            
            print(f"\n{Fore.YELLOW}Do you have explicit permission to scan this target? (yes/no): {Style.RESET_ALL}", end="")
            response = input().strip().lower()
            
            if response != 'yes':
                print(f"{Fore.RED}[!] Scan cancelled for safety{Style.RESET_ALL}")
                return False
        
        print(f"{Fore.GREEN}[+] Basic safety check passed{Style.RESET_ALL}")
        return True

    def passive_reconnaissance(self):
        """Perform passive reconnaissance including DNSDumpster and tech stack detection"""
        print(f"{Fore.MAGENTA}[*] Running Passive Reconnaissance...{Style.RESET_ALL}")
        results = {}
        # DNSDumpster integration
        dnsdumpster_data = self.query_dnsdumpster()
        results['dnsdumpster'] = dnsdumpster_data
        # Tech stack detection
        tech_stack = self.detect_tech_stack()
        results['tech_stack'] = tech_stack
        # Save results
        self.save_results('passive_recon', results)
        self.results['passive_recon'] = results
        print(f"{Fore.GREEN}[+] Passive Reconnaissance Complete{Style.RESET_ALL}")
    
    def certificate_analysis(self):
        """Perform comprehensive certificate analysis using crt.sh"""
        print(f"{Fore.MAGENTA}[*] Running Certificate Analysis...{Style.RESET_ALL}")
        
        try:
            # Import and run certificate analysis module
            sys.path.append('modules')
            from certificate_analysis import CertificateAnalysis
            
            cert_analyzer = CertificateAnalysis(self.target, self.config, self.wordlists, self.api_keys)
            results = cert_analyzer.run()
            
            # Export certificate data
            export_files = cert_analyzer.export_certificate_data()
            
            # Save results
            self.save_results('certificate_analysis', results)
            self.results['certificate_analysis'] = results
            
            print(f"{Fore.GREEN}[+] Certificate Analysis Complete{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Certificate data exported to:{Style.RESET_ALL}")
            for file_type, file_path in export_files.items():
                print(f"  - {file_type}: {file_path}")
                
        except ImportError as e:
            print(f"{Fore.RED}[-] Certificate analysis module not found: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Skipping certificate analysis{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Certificate analysis error: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Skipping certificate analysis{Style.RESET_ALL}")

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
                print(f"{Fore.RED}[-] DNSDumpster request failed: {resp.status_code}{Style.RESET_ALL}")
                return {}
            # Parse DNSDumpster results
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
            print(f"{Fore.GREEN}[+] DNSDumpster data collected{Style.RESET_ALL}")
            return results
        except Exception as e:
            print(f"{Fore.RED}[-] DNSDumpster error: {e}{Style.RESET_ALL}")
            return {}

    def detect_tech_stack(self):
        """Detect technology stack using HTTP headers, favicon hash, WhatWeb, Wappalyzer, and Nmap NSE scripts"""
        print(f"{Fore.YELLOW}[*] Detecting technology stack...{Style.RESET_ALL}")
        tech = {}
        urls = []
        if self.target_type == 'domain':
            urls = [f"http://{self.target}", f"https://{self.target}"]
        elif self.target_type == 'url':
            urls = [self.target]
        else:
            return tech
        # 1. HTTP Headers, favicon, and page content
        for url in urls:
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
                headers = resp.headers
                if 'Server' in headers:
                    tech['server'] = headers['Server']
                if 'X-Powered-By' in headers:
                    tech['x-powered-by'] = headers['X-Powered-By']
                if 'Set-Cookie' in headers:
                    tech['cookies'] = headers['Set-Cookie']
                for h in ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security', 'Content-Security-Policy']:
                    if h in headers:
                        tech[h.lower()] = headers[h]
                favicon_url = urljoin(url, '/favicon.ico')
                fav_resp = self.session.get(favicon_url, timeout=5, verify=False)
                if fav_resp.status_code == 200:
                    favicon_hash = hashlib.md5(fav_resp.content).hexdigest()
                    tech['favicon_hash'] = favicon_hash
                # Page content analysis
                page = resp.text.lower()
                if 'wordpress' in page:
                    tech['cms'] = 'WordPress'
                elif 'drupal' in page:
                    tech['cms'] = 'Drupal'
                elif 'joomla' in page:
                    tech['cms'] = 'Joomla'
                elif 'shopify' in page:
                    tech['cms'] = 'Shopify'
                if 'react' in page:
                    tech['js_framework'] = 'React'
                elif 'angular' in page:
                    tech['js_framework'] = 'Angular'
                elif 'vue' in page:
                    tech['js_framework'] = 'Vue.js'
                if 'php' in page:
                    tech['language'] = 'PHP'
                elif 'python' in page:
                    tech['language'] = 'Python'
                elif 'node.js' in page or 'express' in page:
                    tech['language'] = 'Node.js'
                elif 'java' in page:
                    tech['language'] = 'Java'
                break
            except Exception:
                continue
        # 2. WhatWeb CLI (if available)
        whatweb_path = self.tools_config.get('whatweb', {}).get('path', 'whatweb')
        success, output, _ = self.run_command(f"{whatweb_path} --no-errors --log-xml=- {urls[0]}", timeout=30)
        if success and output:
            try:
                root = ET.fromstring(output)
                plugins = set()
                for plugin in root.iter('plugin'):
                    plugins.add(plugin.attrib.get('name'))
                if plugins:
                    tech['whatweb_plugins'] = list(plugins)
            except Exception:
                pass
        # 3. Wappalyzer API (if API key is set)
        wappalyzer_key = self.api_keys.get('wappalyzer', '')
        if wappalyzer_key:
            try:
                resp = self.session.post(
                    'https://api.wappalyzer.com/lookup/v2/',
                    headers={
                        'x-api-key': wappalyzer_key,
                        'Content-Type': 'application/json'
                    },
                    json={"urls": urls}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data and isinstance(data, list) and 'technologies' in data[0]:
                        tech['wappalyzer'] = [t['name'] for t in data[0]['technologies']]
            except Exception:
                pass
        # 4. Nmap HTTP NSE scripts (if nmap is available)
        if 'nmap' in self.check_tool_availability():
            nmap_cmd = f"nmap -p 80,443 --script=http-enum,http-title,http-headers {self.target} -oX -"
            success, output, _ = self.run_command(nmap_cmd, timeout=60)
            if success and output:
                try:
                    root = ET.fromstring(output)
                    nmap_tech = set()
                    for elem in root.iter('script'):
                        if 'output' in elem.attrib:
                            nmap_tech.add(elem.attrib['output'])
                    if nmap_tech:
                        tech['nmap_http'] = list(nmap_tech)
                except Exception:
                    pass
        print(f"{Fore.GREEN}[+] Technology stack detection complete{Style.RESET_ALL}")
        return tech

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ultimate Reconnaissance Tool")
    parser.add_argument("target", help="Target (domain, IP, URL, or network)")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive mode")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    
    args = parser.parse_args()
    
    # Create and run reconnaissance
    recon = UltimateRecon(args.target, args.output)
    recon.config['threads'] = args.threads
    recon.config['stealth_mode'] = args.stealth
    recon.config['aggressive_mode'] = args.aggressive
    recon.config['timeout'] = args.timeout
    
    recon.run() 
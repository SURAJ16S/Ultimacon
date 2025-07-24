#!/usr/bin/env python3
"""
Active Reconnaissance Module
Performs active reconnaissance including port scanning, directory bruteforcing, and web crawling
"""

import os
import sys
import json
import time
import requests
import subprocess
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import nmap

class ActiveRecon:
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
        print(f"{Fore.MAGENTA}[*] Running Active Reconnaissance...{Style.RESET_ALL}")
        
        # Port scanning
        self.results['port_scan'] = self.port_scan()
        
        # Directory and file bruteforcing
        self.results['directory_scan'] = self.directory_bruteforce()
        
        # Web crawling
        self.results['web_crawl'] = self.web_crawl()
        
        # API endpoint discovery
        self.results['api_discovery'] = self.api_discovery()
        
        return self.results
    
    def port_scan(self):
        """Perform comprehensive port scanning"""
        print(f"{Fore.YELLOW}[*] Performing port scan...{Style.RESET_ALL}")
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3000, 5000, 3306, 5432, 27017, 6379, 11211]
        
        open_ports = []
        
        # Quick TCP scan
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                sock.close()
            except Exception:
                continue
        
        # Nmap scan (if available)
        nmap_results = self.nmap_scan()
        if nmap_results:
            open_ports.extend(nmap_results)
        
        return open_ports
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            3000: 'Node.js', 5000: 'Python', 3306: 'MySQL', 5432: 'PostgreSQL',
            27017: 'MongoDB', 6379: 'Redis', 11211: 'Memcached'
        }
        return services.get(port, 'Unknown')
    
    def nmap_scan(self):
        """Perform Nmap scan"""
        try:
            nm = nmap.PortScanner()
            
            # Determine scan arguments based on configuration
            if self.config.get('stealth_mode'):
                scan_args = '-sS -sV -O --max-retries 2'
            elif self.config.get('aggressive_mode'):
                scan_args = '-sS -sV -O -A --script=vuln'
            else:
                scan_args = '-sS -sV -O --script=vuln,auth,default'
            
            print(f"{Fore.YELLOW}[*] Running Nmap scan with args: {scan_args}{Style.RESET_ALL}")
            nm.scan(self.target, arguments=scan_args)
            
            results = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service_info = nm[host][proto][port]
                        results.append({
                            'port': port,
                            'service': service_info.get('name', 'Unknown'),
                            'version': service_info.get('version', ''),
                            'state': service_info.get('state', 'unknown'),
                            'product': service_info.get('product', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        })
            
            return results
        except Exception as e:
            print(f"{Fore.RED}[-] Nmap scan error: {e}{Style.RESET_ALL}")
            return []
    
    def directory_bruteforce(self):
        """Perform directory and file bruteforcing"""
        print(f"{Fore.YELLOW}[*] Performing directory bruteforce...{Style.RESET_ALL}")
        
        results = {
            'directories': [],
            'files': [],
            'sensitive_files': []
        }
        
        # Get target URL
        if self.target.startswith(('http://', 'https://')):
            base_url = self.target
        else:
            base_url = f"http://{self.target}"
        
        # Directory wordlists
        dir_wordlists = self.wordlists.get('directories', [])
        if not dir_wordlists:
            # Use default common directories
            dir_wordlists = ['/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt']
        
        # File wordlists
        file_wordlists = self.wordlists.get('files', [])
        if not file_wordlists:
            # Use default common files
            file_wordlists = ['/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt']
        
        # Sensitive files to check
        sensitive_files = [
            '/robots.txt', '/sitemap.xml', '/.env', '/config.php', '/web.config',
            '/.git/config', '/.svn/entries', '/.DS_Store', '/Thumbs.db',
            '/security.txt', '/.well-known/security.txt', '/admin', '/login',
            '/wp-config.php', '/phpinfo.php', '/info.php', '/test.php'
        ]
        
        # Check sensitive files first
        for file_path in sensitive_files:
            url = urljoin(base_url, file_path)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 403, 401]:
                    results['sensitive_files'].append({
                        'url': url,
                        'status': resp.status_code,
                        'size': len(resp.content)
                    })
            except Exception:
                continue
        
        # Use gobuster for directory bruteforcing (if available)
        gobuster_results = self.gobuster_scan(base_url, dir_wordlists[0] if dir_wordlists else None)
        if gobuster_results:
            results['directories'].extend(gobuster_results)
        
        # Use ffuf for file bruteforcing (if available)
        ffuf_results = self.ffuf_scan(base_url, file_wordlists[0] if file_wordlists else None)
        if ffuf_results:
            results['files'].extend(ffuf_results)
        
        return results
    
    def gobuster_scan(self, base_url, wordlist):
        """Run gobuster directory scan"""
        if not wordlist or not os.path.exists(wordlist):
            return []
        
        try:
            cmd = f"gobuster dir -u {base_url} -w {wordlist} -t {self.config.get('threads', 50)} --no-error"
            if self.config.get('stealth_mode'):
                cmd += " --delay 2s"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                results = []
                for line in lines:
                    if line and not line.startswith('Gobuster'):
                        parts = line.split()
                        if len(parts) >= 3:
                            path = parts[0]
                            status = parts[1]
                            size = parts[2]
                            results.append({
                                'path': path,
                                'status': status,
                                'size': size
                            })
                return results
        except Exception as e:
            print(f"{Fore.RED}[-] Gobuster error: {e}{Style.RESET_ALL}")
        
        return []
    
    def ffuf_scan(self, base_url, wordlist):
        """Run ffuf file scan"""
        if not wordlist or not os.path.exists(wordlist):
            return []
        
        try:
            cmd = f"ffuf -u {base_url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -t {self.config.get('threads', 50)}"
            if self.config.get('stealth_mode'):
                cmd += " -rate 100"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                results = []
                for line in lines:
                    if line and not line.startswith('ffuf'):
                        parts = line.split()
                        if len(parts) >= 3:
                            path = parts[0]
                            status = parts[1]
                            size = parts[2]
                            results.append({
                                'path': path,
                                'status': status,
                                'size': size
                            })
                return results
        except Exception as e:
            print(f"{Fore.RED}[-] FFUF error: {e}{Style.RESET_ALL}")
        
        return []
    
    def web_crawl(self):
        """Perform web crawling to discover additional endpoints"""
        print(f"{Fore.YELLOW}[*] Performing web crawl...{Style.RESET_ALL}")
        
        discovered_urls = set()
        crawled_urls = set()
        
        # Get target URL
        if self.target.startswith(('http://', 'https://')):
            base_url = self.target
        else:
            base_url = f"http://{self.target}"
        
        # Start with the main page
        urls_to_crawl = [base_url]
        
        while urls_to_crawl and len(crawled_urls) < 100:  # Limit crawling
            url = urls_to_crawl.pop(0)
            
            if url in crawled_urls:
                continue
            
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                crawled_urls.add(url)
                
                if resp.status_code == 200:
                    # Extract links from HTML
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(url, href)
                        
                        # Only follow links within the same domain
                        if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                            discovered_urls.add(absolute_url)
                            if absolute_url not in crawled_urls and len(urls_to_crawl) < 50:
                                urls_to_crawl.append(absolute_url)
                
                time.sleep(0.1)  # Rate limiting
                
            except Exception:
                continue
        
        return list(discovered_urls)
    
    def api_discovery(self):
        """Discover API endpoints"""
        print(f"{Fore.YELLOW}[*] Discovering API endpoints...{Style.RESET_ALL}")
        
        api_endpoints = []
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/graphiql',
            '/swagger', '/swagger-ui', '/docs', '/documentation', '/openapi.json',
            '/api-docs', '/redoc', '/postman', '/insomnia'
        ]
        
        # Get target URL
        if self.target.startswith(('http://', 'https://')):
            base_url = self.target
        else:
            base_url = f"http://{self.target}"
        
        for path in common_api_paths:
            url = urljoin(base_url, path)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 401, 403]:
                    api_endpoints.append({
                        'url': url,
                        'status': resp.status_code,
                        'content_type': resp.headers.get('Content-Type', ''),
                        'size': len(resp.content)
                    })
            except Exception:
                continue
        
        return api_endpoints 
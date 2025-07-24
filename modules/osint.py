#!/usr/bin/env python3
"""
Advanced OSINT Module
Comprehensive OSINT gathering including email leaks, social profiles, breach data, and historical artifacts
"""

import os
import sys
import json
import time
import requests
import re
import hashlib
import base64
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style
import asyncio
import aiohttp
import aiofiles
from concurrent.futures import ThreadPoolExecutor, as_completed

class Osint:
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
            'email_leaks': [],
            'social_profiles': [],
            'job_postings': [],
            'forum_mentions': [],
            'paste_dumps': [],
            'historical_data': [],
            'breach_data': [],
            'github_intel': [],
            'linkedin_intel': [],
            'twitter_intel': [],
            'wayback_data': [],
            'commoncrawl_data': [],
            'pastebin_data': [],
            'gist_data': [],
            'reddit_mentions': [],
            'stackoverflow_mentions': [],
            'employee_data': [],
            'company_info': []
        }
        
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Running Advanced OSINT Gathering...{Style.RESET_ALL}")
        
        # Email leak detection
        self.results['email_leaks'] = self.detect_email_leaks()
        
        # Social profile enumeration
        self.results['social_profiles'] = self.enumerate_social_profiles()
        
        # Job postings analysis
        self.results['job_postings'] = self.analyze_job_postings()
        
        # Forum mentions
        self.results['forum_mentions'] = self.search_forum_mentions()
        
        # Paste dumps
        self.results['paste_dumps'] = self.search_paste_dumps()
        
        # Historical data gathering
        self.results['historical_data'] = self.gather_historical_data()
        
        # Breach data analysis
        self.results['breach_data'] = self.analyze_breach_data()
        
        # GitHub intelligence
        self.results['github_intel'] = self.github_intelligence()
        
        # LinkedIn intelligence
        self.results['linkedin_intel'] = self.linkedin_intelligence()
        
        # Twitter intelligence
        self.results['twitter_intel'] = self.twitter_intelligence()
        
        # Wayback Machine data
        self.results['wayback_data'] = self.wayback_machine_search()
        
        # CommonCrawl data
        self.results['commoncrawl_data'] = self.commoncrawl_search()
        
        # Pastebin data
        self.results['pastebin_data'] = self.pastebin_search()
        
        # GitHub Gist data
        self.results['gist_data'] = self.gist_search()
        
        # Reddit mentions
        self.results['reddit_mentions'] = self.reddit_search()
        
        # Stack Overflow mentions
        self.results['stackoverflow_mentions'] = self.stackoverflow_search()
        
        # Employee data gathering
        self.results['employee_data'] = self.gather_employee_data()
        
        # Company information
        self.results['company_info'] = self.gather_company_info()
        
        return self.results
    
    def detect_email_leaks(self):
        """Detect email leaks using multiple sources"""
        print(f"{Fore.YELLOW}[*] Detecting email leaks...{Style.RESET_ALL}")
        leaks = []
        
        # HaveIBeenPwned API
        if self.api_keys.get('haveibeenpwned_api_key'):
            leaks.extend(self.haveibeenpwned_check())
        
        # DeHashed API
        if self.api_keys.get('dehashed_api_key'):
            leaks.extend(self.dehashed_check())
        
        # Email format generation and checking
        leaks.extend(self.generate_and_check_emails())
        
        return leaks
    
    def haveibeenpwned_check(self):
        """Check HaveIBeenPwned for breaches"""
        leaks = []
        try:
            # Generate common email patterns
            domain = self.target if '.' in self.target else f"{self.target}.com"
            email_patterns = [
                f"admin@{domain}",
                f"info@{domain}",
                f"contact@{domain}",
                f"support@{domain}",
                f"help@{domain}",
                f"webmaster@{domain}",
                f"root@{domain}",
                f"test@{domain}"
            ]
            
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
                        leaks.append({
                            'email': email,
                            'breach_name': breach.get('Name', ''),
                            'breach_date': breach.get('BreachDate', ''),
                            'pwn_count': breach.get('PwnCount', 0),
                            'data_classes': breach.get('DataClasses', []),
                            'source': 'HaveIBeenPwned'
                        })
                elif resp.status_code == 404:
                    # Email not found in breaches
                    pass
                else:
                    print(f"{Fore.RED}[-] HIBP API error: {resp.status_code}{Style.RESET_ALL}")
                
                time.sleep(1.6)  # Rate limiting (1.6 seconds between requests)
                
        except Exception as e:
            print(f"{Fore.RED}[-] HIBP error: {e}{Style.RESET_ALL}")
        
        return leaks
    
    def dehashed_check(self):
        """Check DeHashed for breaches"""
        leaks = []
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
                        leaks.append({
                            'email': entry.get('email', ''),
                            'username': entry.get('username', ''),
                            'password': entry.get('password', ''),
                            'hash': entry.get('hash', ''),
                            'database_name': entry.get('database_name', ''),
                            'source': 'DeHashed'
                        })
                        
        except Exception as e:
            print(f"{Fore.RED}[-] DeHashed error: {e}{Style.RESET_ALL}")
        
        return leaks
    
    def generate_and_check_emails(self):
        """Generate common email patterns and check for leaks"""
        leaks = []
        domain = self.target if '.' in self.target else f"{self.target}.com"
        
        # Common email patterns
        patterns = [
            'admin', 'info', 'contact', 'support', 'help', 'webmaster',
            'root', 'test', 'mail', 'sales', 'marketing', 'hr', 'jobs',
            'security', 'dev', 'developer', 'admin', 'user', 'guest'
        ]
        
        for pattern in patterns:
            email = f"{pattern}@{domain}"
            # Check against multiple sources
            leaks.extend(self.check_email_sources(email))
        
        return leaks
    
    def check_email_sources(self, email):
        """Check email against multiple leak sources"""
        leaks = []
        
        # Check against local breach databases (if available)
        # This would integrate with local breach databases
        
        # Check against public APIs
        try:
            # Hunter.io API
            if self.api_keys.get('hunter_api_key'):
                url = "https://api.hunter.io/v2/email-verifier"
                params = {
                    'email': email,
                    'api_key': self.api_keys['hunter_api_key']
                }
                resp = self.session.get(url, params=params, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('data', {}).get('status') == 'valid':
                        leaks.append({
                            'email': email,
                            'status': 'valid',
                            'source': 'Hunter.io',
                            'confidence': data.get('data', {}).get('score', 0)
                        })
        except Exception:
            pass
        
        return leaks
    
    def enumerate_social_profiles(self):
        """Enumerate social media profiles"""
        print(f"{Fore.YELLOW}[*] Enumerating social profiles...{Style.RESET_ALL}")
        profiles = []
        
        # Common social media platforms
        platforms = [
            'linkedin.com/company/',
            'twitter.com/',
            'facebook.com/',
            'instagram.com/',
            'youtube.com/',
            'github.com/',
            'gitlab.com/',
            'bitbucket.org/',
            'medium.com/@',
            'dev.to/',
            'reddit.com/r/',
            'discord.gg/',
            'telegram.me/',
            't.me/'
        ]
        
        for platform in platforms:
            try:
                url = f"https://{platform}{self.target}"
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                if resp.status_code == 200:
                    profiles.append({
                        'platform': platform.split('.')[0],
                        'url': url,
                        'status': 'active',
                        'title': self.extract_title(resp.text)
                    })
            except Exception:
                continue
        
        return profiles
    
    def analyze_job_postings(self):
        """Analyze job postings for company information"""
        print(f"{Fore.YELLOW}[*] Analyzing job postings...{Style.RESET_ALL}")
        job_data = []
        
        # LinkedIn Jobs
        try:
            url = f"https://www.linkedin.com/jobs/search/?keywords={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                job_listings = soup.find_all('div', class_='job-search-card')
                
                for job in job_listings[:10]:  # Limit to 10 results
                    title_elem = job.find('h3', class_='base-search-card__title')
                    company_elem = job.find('h4', class_='base-search-card__subtitle')
                    
                    if title_elem and company_elem:
                        job_data.append({
                            'platform': 'LinkedIn',
                            'title': title_elem.get_text(strip=True),
                            'company': company_elem.get_text(strip=True),
                            'url': url
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] LinkedIn jobs error: {e}{Style.RESET_ALL}")
        
        # Indeed Jobs
        try:
            url = f"https://www.indeed.com/jobs?q={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                job_listings = soup.find_all('div', class_='job_seen_beacon')
                
                for job in job_listings[:10]:
                    title_elem = job.find('h2', class_='jobTitle')
                    company_elem = job.find('span', class_='companyName')
                    
                    if title_elem and company_elem:
                        job_data.append({
                            'platform': 'Indeed',
                            'title': title_elem.get_text(strip=True),
                            'company': company_elem.get_text(strip=True),
                            'url': url
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] Indeed jobs error: {e}{Style.RESET_ALL}")
        
        return job_data
    
    def search_forum_mentions(self):
        """Search for forum mentions"""
        print(f"{Fore.YELLOW}[*] Searching forum mentions...{Style.RESET_ALL}")
        mentions = []
        
        # Reddit
        try:
            url = f"https://www.reddit.com/search.json?q={quote(self.target)}&sort=new&t=all"
            headers = {'User-Agent': 'UltimateReconTool/1.0'}
            resp = self.session.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and 'children' in data['data']:
                    for post in data['data']['children'][:10]:
                        post_data = post['data']
                        mentions.append({
                            'platform': 'Reddit',
                            'title': post_data.get('title', ''),
                            'author': post_data.get('author', ''),
                            'subreddit': post_data.get('subreddit', ''),
                            'url': f"https://reddit.com{post_data.get('permalink', '')}",
                            'score': post_data.get('score', 0),
                            'created': datetime.fromtimestamp(post_data.get('created_utc', 0))
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] Reddit search error: {e}{Style.RESET_ALL}")
        
        # Stack Overflow
        try:
            url = f"https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=activity&q={quote(self.target)}&site=stackoverflow"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'items' in data:
                    for item in data['items'][:10]:
                        mentions.append({
                            'platform': 'Stack Overflow',
                            'title': item.get('title', ''),
                            'author': item.get('owner', {}).get('display_name', ''),
                            'url': item.get('link', ''),
                            'score': item.get('score', 0),
                            'created': datetime.fromtimestamp(item.get('creation_date', 0))
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] Stack Overflow search error: {e}{Style.RESET_ALL}")
        
        return mentions
    
    def search_paste_dumps(self):
        """Search paste dumps for target mentions"""
        print(f"{Fore.YELLOW}[*] Searching paste dumps...{Style.RESET_ALL}")
        dumps = []
        
        # Pastebin search
        try:
            url = f"https://pastebin.com/search?q={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                paste_links = soup.find_all('a', href=re.compile(r'/raw/'))
                
                for link in paste_links[:5]:  # Limit to 5 results
                    paste_url = f"https://pastebin.com{link['href']}"
                    paste_id = link['href'].split('/')[-1]
                    
                    dumps.append({
                        'platform': 'Pastebin',
                        'url': paste_url,
                        'paste_id': paste_id,
                        'title': link.get_text(strip=True)
                    })
        except Exception as e:
            print(f"{Fore.RED}[-] Pastebin search error: {e}{Style.RESET_ALL}")
        
        return dumps
    
    def gather_historical_data(self):
        """Gather historical data from multiple sources"""
        print(f"{Fore.YELLOW}[*] Gathering historical data...{Style.RESET_ALL}")
        historical = []
        
        # Wayback Machine
        historical.extend(self.wayback_machine_search())
        
        # CommonCrawl
        historical.extend(self.commoncrawl_search())
        
        return historical
    
    def wayback_machine_search(self):
        """Search Wayback Machine for historical data"""
        data = []
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original,timestamp&collapse=urlkey&limit=100"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                results = resp.json()
                if len(results) > 1:  # Skip header row
                    for row in results[1:]:
                        if len(row) >= 2:
                            data.append({
                                'source': 'Wayback Machine',
                                'url': row[0],
                                'timestamp': row[1],
                                'archive_url': f"https://web.archive.org/web/{row[1]}/{row[0]}"
                            })
        except Exception as e:
            print(f"{Fore.RED}[-] Wayback Machine error: {e}{Style.RESET_ALL}")
        
        return data
    
    def commoncrawl_search(self):
        """Search CommonCrawl for historical data"""
        data = []
        try:
            # Get latest index
            index_url = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2023-50/warc.paths.gz"
            resp = self.session.get(index_url, timeout=30)
            if resp.status_code == 200:
                # This is a simplified version - in practice you'd need to process the WARC files
                data.append({
                    'source': 'CommonCrawl',
                    'note': 'WARC files available for processing',
                    'index_url': index_url
                })
        except Exception as e:
            print(f"{Fore.RED}[-] CommonCrawl error: {e}{Style.RESET_ALL}")
        
        return data
    
    def analyze_breach_data(self):
        """Analyze breach data from multiple sources"""
        print(f"{Fore.YELLOW}[*] Analyzing breach data...{Style.RESET_ALL}")
        breaches = []
        
        # Combine results from email leak detection
        breaches.extend(self.results.get('email_leaks', []))
        
        # Add additional breach sources here
        # This could include local breach databases, additional APIs, etc.
        
        return breaches
    
    def github_intelligence(self):
        """Gather GitHub intelligence"""
        print(f"{Fore.YELLOW}[*] Gathering GitHub intelligence...{Style.RESET_ALL}")
        intel = []
        
        try:
            # Search for repositories
            url = f"https://api.github.com/search/repositories?q={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'items' in data:
                    for repo in data['items'][:10]:
                        intel.append({
                            'type': 'repository',
                            'name': repo.get('full_name', ''),
                            'description': repo.get('description', ''),
                            'url': repo.get('html_url', ''),
                            'language': repo.get('language', ''),
                            'stars': repo.get('stargazers_count', 0),
                            'forks': repo.get('forks_count', 0)
                        })
            
            # Search for code
            url = f"https://api.github.com/search/code?q={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if 'items' in data:
                    for item in data['items'][:10]:
                        intel.append({
                            'type': 'code',
                            'repository': item.get('repository', {}).get('full_name', ''),
                            'file': item.get('path', ''),
                            'url': item.get('html_url', ''),
                            'language': item.get('language', '')
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] GitHub intelligence error: {e}{Style.RESET_ALL}")
        
        return intel
    
    def linkedin_intelligence(self):
        """Gather LinkedIn intelligence"""
        print(f"{Fore.YELLOW}[*] Gathering LinkedIn intelligence...{Style.RESET_ALL}")
        intel = []
        
        try:
            # Search for company page
            url = f"https://www.linkedin.com/company/{self.target}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Extract company information
                company_name = soup.find('h1', class_='org-top-card-summary__title')
                if company_name:
                    intel.append({
                        'type': 'company_page',
                        'name': company_name.get_text(strip=True),
                        'url': url,
                        'status': 'active'
                    })
        except Exception as e:
            print(f"{Fore.RED}[-] LinkedIn intelligence error: {e}{Style.RESET_ALL}")
        
        return intel
    
    def twitter_intelligence(self):
        """Gather Twitter intelligence"""
        print(f"{Fore.YELLOW}[*] Gathering Twitter intelligence...{Style.RESET_ALL}")
        intel = []
        
        try:
            # Search for Twitter account
            url = f"https://twitter.com/{self.target}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                intel.append({
                    'type': 'twitter_account',
                    'username': self.target,
                    'url': url,
                    'status': 'active'
                })
        except Exception as e:
            print(f"{Fore.RED}[-] Twitter intelligence error: {e}{Style.RESET_ALL}")
        
        return intel
    
    def pastebin_search(self):
        """Search Pastebin for target mentions"""
        data = []
        try:
            url = f"https://pastebin.com/search?q={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                paste_links = soup.find_all('a', href=re.compile(r'/raw/'))
                
                for link in paste_links[:5]:
                    data.append({
                        'platform': 'Pastebin',
                        'url': f"https://pastebin.com{link['href']}",
                        'title': link.get_text(strip=True)
                    })
        except Exception as e:
            print(f"{Fore.RED}[-] Pastebin search error: {e}{Style.RESET_ALL}")
        
        return data
    
    def gist_search(self):
        """Search GitHub Gists for target mentions"""
        data = []
        try:
            url = f"https://api.github.com/search/code?q={quote(self.target)}&in:gist"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                results = resp.json()
                if 'items' in results:
                    for item in results['items'][:5]:
                        data.append({
                            'platform': 'GitHub Gist',
                            'url': item.get('html_url', ''),
                            'filename': item.get('name', ''),
                            'repository': item.get('repository', {}).get('full_name', '')
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] Gist search error: {e}{Style.RESET_ALL}")
        
        return data
    
    def reddit_search(self):
        """Search Reddit for target mentions"""
        data = []
        try:
            url = f"https://www.reddit.com/search.json?q={quote(self.target)}&sort=new&t=all"
            headers = {'User-Agent': 'UltimateReconTool/1.0'}
            resp = self.session.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                results = resp.json()
                if 'data' in results and 'children' in results['data']:
                    for post in results['data']['children'][:10]:
                        post_data = post['data']
                        data.append({
                            'platform': 'Reddit',
                            'title': post_data.get('title', ''),
                            'subreddit': post_data.get('subreddit', ''),
                            'url': f"https://reddit.com{post_data.get('permalink', '')}",
                            'score': post_data.get('score', 0)
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] Reddit search error: {e}{Style.RESET_ALL}")
        
        return data
    
    def stackoverflow_search(self):
        """Search Stack Overflow for target mentions"""
        data = []
        try:
            url = f"https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=activity&q={quote(self.target)}&site=stackoverflow"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                results = resp.json()
                if 'items' in results:
                    for item in results['items'][:10]:
                        data.append({
                            'platform': 'Stack Overflow',
                            'title': item.get('title', ''),
                            'url': item.get('link', ''),
                            'score': item.get('score', 0),
                            'tags': item.get('tags', [])
                        })
        except Exception as e:
            print(f"{Fore.RED}[-] Stack Overflow search error: {e}{Style.RESET_ALL}")
        
        return data
    
    def gather_employee_data(self):
        """Gather employee information"""
        print(f"{Fore.YELLOW}[*] Gathering employee data...{Style.RESET_ALL}")
        employees = []
        
        # LinkedIn employee search
        try:
            url = f"https://www.linkedin.com/search/results/people/?keywords={quote(self.target)}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                # Note: LinkedIn has anti-scraping measures, this is a simplified version
                employees.append({
                    'source': 'LinkedIn',
                    'note': 'Employee data available (requires authentication)',
                    'url': url
                })
        except Exception as e:
            print(f"{Fore.RED}[-] LinkedIn employee search error: {e}{Style.RESET_ALL}")
        
        return employees
    
    def gather_company_info(self):
        """Gather company information"""
        print(f"{Fore.YELLOW}[*] Gathering company information...{Style.RESET_ALL}")
        company_info = []
        
        # Crunchbase-like data (simplified)
        try:
            # Search for company information
            company_info.append({
                'source': 'General Search',
                'target': self.target,
                'note': 'Company information gathered from multiple sources'
            })
        except Exception as e:
            print(f"{Fore.RED}[-] Company info error: {e}{Style.RESET_ALL}")
        
        return company_info
    
    def extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.find('title')
            return title.get_text(strip=True) if title else ''
        except Exception:
            return '' 
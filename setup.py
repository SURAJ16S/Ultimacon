#!/usr/bin/env python3
"""
Ultimate Reconnaissance Tool - Setup and Configuration Script
Automated system detection, configuration, and fallback mechanisms
"""

import os
import sys
import json
import platform
import psutil
import shutil
import subprocess
import requests
import getpass
from pathlib import Path
from colorama import init, Fore, Style
import yaml
import socket
import time

# Initialize colorama
init(autoreset=True)

class SystemAnalyzer:
    """Analyze system specifications and capabilities"""
    
    def __init__(self):
        self.specs = {}
        
    def analyze_system(self):
        """Analyze system specifications"""
        print(f"{Fore.CYAN}[*] Analyzing system specifications...{Style.RESET_ALL}")
        
        # CPU Information
        self.specs['cpu'] = {
            'cores': psutil.cpu_count(),
            'physical_cores': psutil.cpu_count(logical=False),
            'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            'architecture': platform.machine(),
            'processor': platform.processor()
        }
        
        # Memory Information
        memory = psutil.virtual_memory()
        self.specs['memory'] = {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_gb': round(memory.used / (1024**3), 2),
            'percent_used': memory.percent
        }
        
        # Disk Information
        disk = psutil.disk_usage('/')
        self.specs['disk'] = {
            'total_gb': round(disk.total / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'used_gb': round(disk.used / (1024**3), 2),
            'percent_used': round((disk.used / disk.total) * 100, 2)
        }
        
        # Network Information
        self.specs['network'] = self.analyze_network()
        
        # Operating System
        self.specs['os'] = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'python_version': platform.python_version()
        }
        
        # Performance Category
        self.specs['performance_category'] = self.categorize_performance()
        
        return self.specs
    
    def analyze_network(self):
        """Analyze network capabilities"""
        network_info = {
            'speed_test': False,
            'download_speed': 0,
            'upload_speed': 0,
            'latency': 0
        }
        
        try:
            # Test network connectivity
            response = requests.get('https://www.google.com', timeout=5)
            if response.status_code == 200:
                network_info['connected'] = True
                
                # Simple speed test
                start_time = time.time()
                response = requests.get('https://httpbin.org/bytes/1024', timeout=10)
                if response.status_code == 200:
                    download_time = time.time() - start_time
                    network_info['download_speed'] = round(1024 / download_time / 1024, 2)  # MB/s
                    network_info['speed_test'] = True
        except:
            network_info['connected'] = False
        
        return network_info
    
    def categorize_performance(self):
        """Categorize system performance"""
        cpu_score = self.specs['cpu']['cores'] * (self.specs['cpu']['frequency'] / 1000)
        memory_score = self.specs['memory']['total_gb']
        
        total_score = cpu_score + memory_score
        
        if total_score < 10:
            return 'low'
        elif total_score < 25:
            return 'medium'
        elif total_score < 50:
            return 'high'
        else:
            return 'enterprise'
    
    def display_specs(self):
        """Display system specifications"""
        print(f"\n{Fore.GREEN}📊 System Specifications:{Style.RESET_ALL}")
        print("=" * 50)
        
        # CPU
        print(f"{Fore.YELLOW}🖥️  CPU:{Style.RESET_ALL}")
        print(f"  Cores: {self.specs['cpu']['cores']} (Physical: {self.specs['cpu']['physical_cores']})")
        print(f"  Frequency: {self.specs['cpu']['frequency']:.1f} MHz")
        print(f"  Architecture: {self.specs['cpu']['architecture']}")
        
        # Memory
        print(f"\n{Fore.YELLOW}💾 Memory:{Style.RESET_ALL}")
        print(f"  Total: {self.specs['memory']['total_gb']} GB")
        print(f"  Available: {self.specs['memory']['available_gb']} GB")
        print(f"  Used: {self.specs['memory']['percent_used']:.1f}%")
        
        # Disk
        print(f"\n{Fore.YELLOW}💿 Disk:{Style.RESET_ALL}")
        print(f"  Total: {self.specs['disk']['total_gb']} GB")
        print(f"  Free: {self.specs['disk']['free_gb']} GB")
        print(f"  Used: {self.specs['disk']['percent_used']:.1f}%")
        
        # Network
        print(f"\n{Fore.YELLOW}🌐 Network:{Style.RESET_ALL}")
        if self.specs['network']['connected']:
            print(f"  Status: Connected")
            if self.specs['network']['speed_test']:
                print(f"  Download Speed: ~{self.specs['network']['download_speed']} MB/s")
        else:
            print(f"  Status: Not connected")
        
        # OS
        print(f"\n{Fore.YELLOW}🖥️  Operating System:{Style.RESET_ALL}")
        print(f"  System: {self.specs['os']['system']} {self.specs['os']['release']}")
        print(f"  Python: {self.specs['os']['python_version']}")
        
        # Performance Category
        category = self.specs['performance_category']
        category_colors = {
            'low': Fore.RED,
            'medium': Fore.YELLOW,
            'high': Fore.GREEN,
            'enterprise': Fore.CYAN
        }
        print(f"\n{Fore.YELLOW}⚡ Performance Category:{Style.RESET_ALL}")
        print(f"  {category_colors[category]}{category.upper()}{Style.RESET_ALL}")

class ConfigurationManager:
    """Manage tool configuration and setup"""
    
    def __init__(self, system_specs):
        self.system_specs = system_specs
        self.config = {}
        self.api_keys = {}
        self.wordlists = {}
        
    def setup_configuration(self):
        """Interactive configuration setup"""
        print(f"\n{Fore.CYAN}[*] Setting up configuration...{Style.RESET_ALL}")
        
        # Auto-configure based on system specs
        self.auto_configure()
        
        # Interactive configuration
        self.interactive_config()
        
        # Setup wordlists
        self.setup_wordlists()
        
        # Setup API keys
        self.setup_api_keys()
        
        # Save configuration
        self.save_configuration()
        
        return self.config, self.api_keys, self.wordlists
    
    def auto_configure(self):
        """Auto-configure based on system specifications"""
        category = self.system_specs['performance_category']
        
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
        
        self.config = configs[category]
        print(f"{Fore.GREEN}[+] Auto-configured for {category.upper()} performance category{Style.RESET_ALL}")
    
    def interactive_config(self):
        """Interactive configuration customization"""
        print(f"\n{Fore.YELLOW}[?] Customize configuration? (y/N): {Style.RESET_ALL}", end="")
        if input().lower() != 'y':
            return
        
        print(f"\n{Fore.CYAN}Customizing configuration...{Style.RESET_ALL}")
        
        # Threads
        print(f"Current threads: {self.config['threads']}")
        print(f"Recommended for your system: {min(self.system_specs['cpu']['cores'] * 10, 100)}")
        print(f"Enter new thread count (or press Enter to keep current): ", end="")
        new_threads = input().strip()
        if new_threads.isdigit():
            self.config['threads'] = int(new_threads)
        
        # Timeout
        print(f"Current timeout: {self.config['timeout']} seconds")
        print(f"Enter new timeout (or press Enter to keep current): ", end="")
        new_timeout = input().strip()
        if new_timeout.isdigit():
            self.config['timeout'] = int(new_timeout)
        
        # Modes
        print(f"\nCurrent modes:")
        print(f"  Stealth mode: {self.config['stealth_mode']}")
        print(f"  Aggressive mode: {self.config['aggressive_mode']}")
        
        print(f"Enable stealth mode? (y/N): ", end="")
        if input().lower() == 'y':
            self.config['stealth_mode'] = True
            self.config['aggressive_mode'] = False
        
        print(f"Enable aggressive mode? (y/N): ", end="")
        if input().lower() == 'y':
            self.config['aggressive_mode'] = True
            self.config['stealth_mode'] = False
    
    def setup_wordlists(self):
        """Setup wordlist locations"""
        print(f"\n{Fore.CYAN}[*] Setting up wordlists...{Style.RESET_ALL}")
        
        # Default wordlist locations
        default_locations = {
            'linux': {
                'subdomains': [
                    '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
                    '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt'
                ],
                'directories': [
                    '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                    '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt'
                ],
                'files': [
                    '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt'
                ]
            },
            'windows': {
                'subdomains': [
                    'C:\\wordlists\\subdomains-top1million-5000.txt',
                    'C:\\wordlists\\subdomains-top1million-20000.txt'
                ],
                'directories': [
                    'C:\\wordlists\\common.txt',
                    'C:\\wordlists\\big.txt'
                ],
                'files': [
                    'C:\\wordlists\\common.txt'
                ]
            }
        }
        
        system = self.system_specs['os']['system'].lower()
        default_paths = default_locations.get(system, default_locations['linux'])
        
        self.wordlists = {}
        
        for wordlist_type, paths in default_paths.items():
            print(f"\n{Fore.YELLOW}📁 {wordlist_type.title()} wordlists:{Style.RESET_ALL}")
            
            valid_paths = []
            for path in paths:
                if os.path.exists(path):
                    print(f"  ✅ {path}")
                    valid_paths.append(path)
                else:
                    print(f"  ❌ {path} (not found)")
            
            if not valid_paths:
                print(f"  {Fore.RED}No valid {wordlist_type} wordlists found{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}Enter custom path (or press Enter to skip): {Style.RESET_ALL}", end="")
                custom_path = input().strip()
                if custom_path and os.path.exists(custom_path):
                    valid_paths.append(custom_path)
            
            self.wordlists[wordlist_type] = valid_paths
        
        # Download wordlists if none found
        if not any(self.wordlists.values()):
            print(f"\n{Fore.YELLOW}[!] No wordlists found. Would you like to download some? (y/N): {Style.RESET_ALL}", end="")
            if input().lower() == 'y':
                self.download_wordlists()
    
    def download_wordlists(self):
        """Download common wordlists"""
        print(f"\n{Fore.CYAN}[*] Downloading wordlists...{Style.RESET_ALL}")
        
        wordlist_urls = {
            'subdomains': [
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt'
            ],
            'directories': [
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt'
            ]
        }
        
        wordlist_dir = Path('wordlists')
        wordlist_dir.mkdir(exist_ok=True)
        
        for wordlist_type, urls in wordlist_urls.items():
            print(f"\n{Fore.YELLOW}Downloading {wordlist_type} wordlists...{Style.RESET_ALL}")
            
            for url in urls:
                try:
                    filename = url.split('/')[-1]
                    filepath = wordlist_dir / filename
                    
                    print(f"  Downloading {filename}...")
                    response = requests.get(url, timeout=30)
                    response.raise_for_status()
                    
                    with open(filepath, 'w') as f:
                        f.write(response.text)
                    
                    print(f"  ✅ Downloaded {filename}")
                    
                    if wordlist_type not in self.wordlists:
                        self.wordlists[wordlist_type] = []
                    self.wordlists[wordlist_type].append(str(filepath))
                    
                except Exception as e:
                    print(f"  ❌ Failed to download {filename}: {e}")
    
    def setup_api_keys(self):
        """Setup API keys with fallback mechanisms"""
        print(f"\n{Fore.CYAN}[*] Setting up API keys...{Style.RESET_ALL}")
        
        api_services = {
            'shodan': {
                'name': 'Shodan',
                'description': 'Internet-wide scanning and device search',
                'fallback': 'free_search',
                'url': 'https://account.shodan.io/register'
            },
            'censys': {
                'name': 'Censys',
                'description': 'Internet-wide scanning and device search',
                'fallback': 'free_search',
                'url': 'https://censys.io/register'
            },
            'virustotal': {
                'name': 'VirusTotal',
                'description': 'Malware and domain reputation',
                'fallback': 'public_api',
                'url': 'https://www.virustotal.com/gui/join-us'
            },
            'securitytrails': {
                'name': 'SecurityTrails',
                'description': 'DNS and subdomain intelligence',
                'fallback': 'dns_resolver',
                'url': 'https://securitytrails.com/app/account/signup'
            },
            'hunter': {
                'name': 'Hunter.io',
                'description': 'Email finding and verification',
                'fallback': 'email_guess',
                'url': 'https://hunter.io/users/sign_up'
            },
            'wappalyzer': {
                'name': 'Wappalyzer',
                'description': 'Technology stack detection',
                'fallback': 'header_analysis',
                'url': 'https://www.wappalyzer.com/'
            }
        }
        
        self.api_keys = {}
        
        for service, info in api_services.items():
            print(f"\n{Fore.YELLOW}🔑 {info['name']} - {info['description']}{Style.RESET_ALL}")
            print(f"  Fallback: {info['fallback']}")
            print(f"  Register: {info['url']}")
            
            # Check if API key exists in environment
            env_key = f"{service.upper()}_API_KEY"
            if os.getenv(env_key):
                print(f"  ✅ Found in environment variable: {env_key}")
                self.api_keys[service] = os.getenv(env_key)
                continue
            
            # Check if API key exists in existing config
            if os.path.exists('api_keys.json'):
                try:
                    with open('api_keys.json', 'r') as f:
                        existing_keys = json.load(f)
                        if service in existing_keys and existing_keys[service]:
                            print(f"  ✅ Found in existing configuration")
                            self.api_keys[service] = existing_keys[service]
                            continue
                except:
                    pass
            
            # Ask for API key
            print(f"  Enter API key (or press Enter to use fallback): ", end="")
            api_key = getpass.getpass().strip()
            
            if api_key:
                self.api_keys[service] = api_key
                print(f"  ✅ API key saved")
            else:
                print(f"  ⚠️  Using fallback: {info['fallback']}")
                self.api_keys[service] = None
    
    def save_configuration(self):
        """Save configuration to files"""
        print(f"\n{Fore.CYAN}[*] Saving configuration...{Style.RESET_ALL}")
        
        # Save main configuration
        config_file = 'config.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        print(f"  ✅ Configuration saved to {config_file}")
        
        # Save API keys
        api_keys_file = 'api_keys.json'
        with open(api_keys_file, 'w') as f:
            json.dump(self.api_keys, f, indent=2)
        print(f"  ✅ API keys saved to {api_keys_file}")
        
        # Save wordlists configuration
        wordlists_file = 'wordlists_config.json'
        with open(wordlists_file, 'w') as f:
            json.dump(self.wordlists, f, indent=2)
        print(f"  ✅ Wordlists configuration saved to {wordlists_file}")

class FallbackManager:
    """Manage fallback mechanisms for missing API keys"""
    
    def __init__(self, api_keys):
        self.api_keys = api_keys
        self.fallbacks = {}
    
    def setup_fallbacks(self):
        """Setup fallback mechanisms"""
        print(f"\n{Fore.CYAN}[*] Setting up fallback mechanisms...{Style.RESET_ALL}")
        
        # Shodan fallback
        if not self.api_keys.get('shodan'):
            self.fallbacks['shodan'] = {
                'type': 'free_search',
                'description': 'Using public search engines and DNS data',
                'enabled': True
            }
        
        # Censys fallback
        if not self.api_keys.get('censys'):
            self.fallbacks['censys'] = {
                'type': 'free_search',
                'description': 'Using public search engines and DNS data',
                'enabled': True
            }
        
        # VirusTotal fallback
        if not self.api_keys.get('virustotal'):
            self.fallbacks['virustotal'] = {
                'type': 'public_api',
                'description': 'Using public VirusTotal API (limited)',
                'enabled': True
            }
        
        # SecurityTrails fallback
        if not self.api_keys.get('securitytrails'):
            self.fallbacks['securitytrails'] = {
                'type': 'dns_resolver',
                'description': 'Using DNS resolution and public data',
                'enabled': True
            }
        
        # Hunter fallback
        if not self.api_keys.get('hunter'):
            self.fallbacks['hunter'] = {
                'type': 'email_guess',
                'description': 'Using email pattern guessing',
                'enabled': True
            }
        
        # Wappalyzer fallback
        if not self.api_keys.get('wappalyzer'):
            self.fallbacks['wappalyzer'] = {
                'type': 'header_analysis',
                'description': 'Using HTTP header and content analysis',
                'enabled': True
            }
        
        # Display fallbacks
        if self.fallbacks:
            print(f"{Fore.YELLOW}Fallback mechanisms configured:{Style.RESET_ALL}")
            for service, fallback in self.fallbacks.items():
                print(f"  {service}: {fallback['description']}")
        else:
            print(f"{Fore.GREEN}All API keys provided - no fallbacks needed{Style.RESET_ALL}")
        
        return self.fallbacks

def main():
    """Main setup function"""
    print(f"{Fore.CYAN}🚀 Ultimate Reconnaissance Tool - Setup{Style.RESET_ALL}")
    print("=" * 60)
    
    try:
        # Analyze system
        analyzer = SystemAnalyzer()
        specs = analyzer.analyze_system()
        analyzer.display_specs()
        
        # Setup configuration
        config_manager = ConfigurationManager(specs)
        config, api_keys, wordlists = config_manager.setup_configuration()
        
        # Setup fallbacks
        fallback_manager = FallbackManager(api_keys)
        fallbacks = fallback_manager.setup_fallbacks()
        
        # Final summary
        print(f"\n{Fore.GREEN}✅ Setup completed successfully!{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}📋 Summary:{Style.RESET_ALL}")
        print(f"  Performance Category: {specs['performance_category'].upper()}")
        print(f"  Configuration: config.yaml")
        print(f"  API Keys: api_keys.json")
        print(f"  Wordlists: {len([w for w in wordlists.values() if w])} types configured")
        print(f"  Fallbacks: {len(fallbacks)} services using fallbacks")
        
        print(f"\n{Fore.CYAN}🎯 Ready to run reconnaissance!{Style.RESET_ALL}")
        print(f"  python ultimate_recon.py example.com")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Setup interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Setup error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 
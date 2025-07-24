#!/usr/bin/env python3
"""
System Check Script for Ultimate Reconnaissance Tool
Analyzes system specifications and provides configuration recommendations
"""

import os
import sys
import platform
import psutil
import subprocess
import requests
import time
from pathlib import Path
from colorama import init, Fore, Style
import json

# Initialize colorama
init(autoreset=True)

class SystemChecker:
    """Check system specifications and capabilities"""
    
    def __init__(self):
        self.results = {}
        self.recommendations = []
        
    def run_full_check(self):
        """Run complete system check"""
        print(f"{Fore.CYAN}🔍 Ultimate Reconnaissance Tool - System Check{Style.RESET_ALL}")
        print("=" * 60)
        
        self.check_system_specs()
        self.check_network()
        self.check_dependencies()
        self.check_tools()
        self.check_wordlists()
        self.check_api_keys()
        self.generate_recommendations()
        self.display_results()
        
        return self.results, self.recommendations
    
    def check_system_specs(self):
        """Check system specifications"""
        print(f"{Fore.YELLOW}[*] Checking system specifications...{Style.RESET_ALL}")
        
        # CPU
        cpu_info = {
            'cores': psutil.cpu_count(),
            'physical_cores': psutil.cpu_count(logical=False),
            'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            'architecture': platform.machine(),
            'processor': platform.processor()
        }
        
        # Memory
        memory = psutil.virtual_memory()
        memory_info = {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_gb': round(memory.used / (1024**3), 2),
            'percent_used': memory.percent
        }
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_info = {
            'total_gb': round(disk.total / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'used_gb': round(disk.used / (1024**3), 2),
            'percent_used': round((disk.used / disk.total) * 100, 2)
        }
        
        # OS
        os_info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'python_version': platform.python_version()
        }
        
        self.results['system'] = {
            'cpu': cpu_info,
            'memory': memory_info,
            'disk': disk_info,
            'os': os_info
        }
        
        # Performance assessment (more realistic)
        cpu_score = cpu_info['cores'] * (cpu_info['frequency'] / 1000)
        memory_score = memory_info['total_gb']
        total_score = cpu_score + memory_score
        
        if total_score < 6:
            performance = 'low'
        elif total_score < 15:
            performance = 'medium'
        elif total_score < 30:
            performance = 'high'
        else:
            performance = 'enterprise'
        
        self.results['performance'] = performance
        
        print(f"  ✅ CPU: {cpu_info['cores']} cores @ {cpu_info['frequency']:.1f} MHz")
        print(f"  ✅ Memory: {memory_info['total_gb']} GB")
        print(f"  ✅ Disk: {disk_info['free_gb']} GB free")
        print(f"  ✅ Performance: {performance.upper()}")
    
    def check_network(self):
        """Check network connectivity and speed"""
        print(f"{Fore.YELLOW}[*] Checking network connectivity...{Style.RESET_ALL}")
        
        network_info = {
            'connected': False,
            'speed_test': False,
            'download_speed': 0,
            'latency': 0
        }
        
        try:
            # Test connectivity
            response = requests.get('https://www.google.com', timeout=5)
            if response.status_code == 200:
                network_info['connected'] = True
                print(f"  ✅ Internet connection: OK")
                
                # Simple speed test
                start_time = time.time()
                response = requests.get('https://httpbin.org/bytes/1024', timeout=10)
                if response.status_code == 200:
                    download_time = time.time() - start_time
                    network_info['download_speed'] = round(1024 / download_time / 1024, 2)
                    network_info['speed_test'] = True
                    print(f"  ✅ Download speed: ~{network_info['download_speed']} MB/s")
            else:
                print(f"  ❌ Internet connection: Failed")
        except Exception as e:
            print(f"  ❌ Internet connection: {e}")
        
        self.results['network'] = network_info
    
    def check_dependencies(self):
        """Check Python dependencies"""
        print(f"{Fore.YELLOW}[*] Checking Python dependencies...{Style.RESET_ALL}")
        
        required_packages = [
            'requests', 'dnspython', 'python-whois', 'beautifulsoup4',
            'colorama', 'pyyaml', 'psutil', 'aiohttp', 'aiodns'
        ]
        
        missing_packages = []
        installed_packages = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                installed_packages.append(package)
                print(f"  ✅ {package}")
            except ImportError:
                missing_packages.append(package)
                print(f"  ❌ {package}")
        
        self.results['dependencies'] = {
            'installed': installed_packages,
            'missing': missing_packages
        }
        
        if missing_packages:
            print(f"  {Fore.YELLOW}Missing packages: {', '.join(missing_packages)}{Style.RESET_ALL}")
    
    def check_tools(self):
        """Check external tools availability"""
        print(f"{Fore.YELLOW}[*] Checking external tools...{Style.RESET_ALL}")
        
        tools = {
            'nmap': 'Network scanning',
            'gobuster': 'Directory bruteforcing',
            'ffuf': 'Web fuzzing',
            'subfinder': 'Subdomain enumeration',
            'amass': 'Subdomain enumeration',
            'whatweb': 'Technology detection',
            'nuclei': 'Vulnerability scanning'
        }
        
        available_tools = []
        missing_tools = []
        
        for tool, description in tools.items():
            if shutil.which(tool):
                available_tools.append(tool)
                print(f"  ✅ {tool} - {description}")
            else:
                missing_tools.append(tool)
                print(f"  ❌ {tool} - {description}")
        
        self.results['tools'] = {
            'available': available_tools,
            'missing': missing_tools
        }
    
    def check_wordlists(self):
        """Check wordlist availability"""
        print(f"{Fore.YELLOW}[*] Checking wordlists...{Style.RESET_ALL}")
        
        wordlist_paths = {
            'subdomains': [
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt',
                'wordlists/subdomains-top1million-5000.txt',
                'wordlists/subdomains-top1million-20000.txt'
            ],
            'directories': [
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt',
                'wordlists/common.txt',
                'wordlists/big.txt'
            ]
        }
        
        found_wordlists = {}
        missing_wordlists = {}
        
        for wordlist_type, paths in wordlist_paths.items():
            found = []
            missing = []
            
            for path in paths:
                if os.path.exists(path):
                    found.append(path)
                else:
                    missing.append(path)
            
            found_wordlists[wordlist_type] = found
            missing_wordlists[wordlist_type] = missing
            
            if found:
                print(f"  ✅ {wordlist_type}: {len(found)} found")
            else:
                print(f"  ❌ {wordlist_type}: None found")
        
        self.results['wordlists'] = {
            'found': found_wordlists,
            'missing': missing_wordlists
        }
    
    def check_api_keys(self):
        """Check API key availability"""
        print(f"{Fore.YELLOW}[*] Checking API keys...{Style.RESET_ALL}")
        
        api_services = [
            'shodan', 'censys', 'virustotal', 'securitytrails',
            'hunter', 'wappalyzer', 'haveibeenpwned', 'dehashed'
        ]
        
        found_keys = []
        missing_keys = []
        
        # Check environment variables
        for service in api_services:
            env_key = f"{service.upper()}_API_KEY"
            if os.getenv(env_key):
                found_keys.append(service)
                print(f"  ✅ {service} (environment)")
            else:
                missing_keys.append(service)
        
        # Check config file
        if os.path.exists('api_keys.json'):
            try:
                with open('api_keys.json', 'r') as f:
                    config_keys = json.load(f)
                    for service in api_services:
                        if service in config_keys and config_keys[service]:
                            if service not in found_keys:
                                found_keys.append(service)
                                print(f"  ✅ {service} (config)")
                            if service in missing_keys:
                                missing_keys.remove(service)
            except:
                pass
        
        for service in missing_keys:
            print(f"  ❌ {service}")
        
        self.results['api_keys'] = {
            'found': found_keys,
            'missing': missing_keys
        }
    
    def generate_recommendations(self):
        """Generate recommendations based on system check"""
        print(f"{Fore.YELLOW}[*] Generating recommendations...{Style.RESET_ALL}")
        
        # Performance-based recommendations
        performance = self.results['performance']
        if performance == 'low':
            self.recommendations.append({
                'type': 'performance',
                'priority': 'high',
                'message': 'System has limited resources. Use stealth mode and limit concurrent operations.',
                'action': 'Run with --stealth flag and -t 10 threads'
            })
        elif performance == 'enterprise':
            self.recommendations.append({
                'type': 'performance',
                'priority': 'info',
                'message': 'High-performance system detected. Can handle aggressive scanning.',
                'action': 'Run with --aggressive flag and -t 100 threads'
            })
        
        # Network recommendations
        if not self.results['network']['connected']:
            self.recommendations.append({
                'type': 'network',
                'priority': 'critical',
                'message': 'No internet connection detected. Some features will be limited.',
                'action': 'Check internet connection before running reconnaissance'
            })
        
        # Dependency recommendations
        missing_deps = self.results['dependencies']['missing']
        if missing_deps:
            self.recommendations.append({
                'type': 'dependencies',
                'priority': 'high',
                'message': f'Missing Python packages: {", ".join(missing_deps)}',
                'action': 'Run: pip install -r requirements.txt'
            })
        
        # Tool recommendations
        missing_tools = self.results['tools']['missing']
        if missing_tools:
            self.recommendations.append({
                'type': 'tools',
                'priority': 'medium',
                'message': f'Missing external tools: {", ".join(missing_tools)}',
                'action': 'Install missing tools for enhanced functionality'
            })
        
        # Wordlist recommendations
        missing_wordlists = []
        for wordlist_type, paths in self.results['wordlists']['missing'].items():
            if paths:  # If all paths for this type are missing
                missing_wordlists.append(wordlist_type)
        
        if missing_wordlists:
            self.recommendations.append({
                'type': 'wordlists',
                'priority': 'medium',
                'message': f'Missing wordlists: {", ".join(missing_wordlists)}',
                'action': 'Run setup.py to download wordlists or install SecLists'
            })
        
        # API key recommendations
        missing_apis = self.results['api_keys']['missing']
        if missing_apis:
            self.recommendations.append({
                'type': 'api_keys',
                'priority': 'low',
                'message': f'Missing API keys: {", ".join(missing_apis)}',
                'action': 'Configure API keys for enhanced OSINT capabilities'
            })
    
    def display_results(self):
        """Display comprehensive results"""
        print(f"\n{Fore.GREEN}📊 System Check Results{Style.RESET_ALL}")
        print("=" * 60)
        
        # System specs
        system = self.results['system']
        print(f"\n{Fore.YELLOW}🖥️  System Specifications:{Style.RESET_ALL}")
        print(f"  CPU: {system['cpu']['cores']} cores @ {system['cpu']['frequency']:.1f} MHz")
        print(f"  Memory: {system['memory']['total_gb']} GB")
        print(f"  Disk: {system['disk']['free_gb']} GB free")
        print(f"  OS: {system['os']['system']} {system['os']['release']}")
        print(f"  Python: {system['os']['python_version']}")
        print(f"  Performance: {self.results['performance'].upper()}")
        
        # Network
        network = self.results['network']
        print(f"\n{Fore.YELLOW}🌐 Network:{Style.RESET_ALL}")
        if network['connected']:
            print(f"  Status: Connected")
            if network['speed_test']:
                print(f"  Speed: ~{network['download_speed']} MB/s")
        else:
            print(f"  Status: Not connected")
        
        # Dependencies
        deps = self.results['dependencies']
        print(f"\n{Fore.YELLOW}📦 Dependencies:{Style.RESET_ALL}")
        print(f"  Installed: {len(deps['installed'])}/{len(deps['installed']) + len(deps['missing'])}")
        if deps['missing']:
            print(f"  Missing: {', '.join(deps['missing'])}")
        
        # Tools
        tools = self.results['tools']
        print(f"\n{Fore.YELLOW}🛠️  External Tools:{Style.RESET_ALL}")
        print(f"  Available: {len(tools['available'])}/{len(tools['available']) + len(tools['missing'])}")
        if tools['missing']:
            print(f"  Missing: {', '.join(tools['missing'])}")
        
        # Wordlists
        wordlists = self.results['wordlists']
        print(f"\n{Fore.YELLOW}📁 Wordlists:{Style.RESET_ALL}")
        for wordlist_type, found in wordlists['found'].items():
            print(f"  {wordlist_type}: {len(found)} found")
        
        # API Keys
        apis = self.results['api_keys']
        print(f"\n{Fore.YELLOW}🔑 API Keys:{Style.RESET_ALL}")
        print(f"  Configured: {len(apis['found'])}/{len(apis['found']) + len(apis['missing'])}")
        if apis['missing']:
            print(f"  Missing: {', '.join(apis['missing'])}")
        
        # Recommendations
        if self.recommendations:
            print(f"\n{Fore.YELLOW}💡 Recommendations:{Style.RESET_ALL}")
            for i, rec in enumerate(self.recommendations, 1):
                priority_colors = {
                    'critical': Fore.RED,
                    'high': Fore.YELLOW,
                    'medium': Fore.CYAN,
                    'low': Fore.GREEN,
                    'info': Fore.BLUE
                }
                color = priority_colors.get(rec['priority'], Fore.WHITE)
                print(f"  {i}. {color}[{rec['priority'].upper()}] {rec['message']}{Style.RESET_ALL}")
                print(f"     Action: {rec['action']}")
        
        # Overall status
        critical_issues = len([r for r in self.recommendations if r['priority'] == 'critical'])
        high_issues = len([r for r in self.recommendations if r['priority'] == 'high'])
        
        if critical_issues > 0:
            status = f"{Fore.RED}CRITICAL ISSUES DETECTED{Style.RESET_ALL}"
        elif high_issues > 0:
            status = f"{Fore.YELLOW}ISSUES DETECTED{Style.RESET_ALL}"
        else:
            status = f"{Fore.GREEN}SYSTEM READY{Style.RESET_ALL}"
        
        print(f"\n{Fore.CYAN}🎯 Overall Status: {status}{Style.RESET_ALL}")

def main():
    """Main function"""
    checker = SystemChecker()
    results, recommendations = checker.run_full_check()
    
    # Save results
    with open('system_check_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{Fore.GREEN}✅ System check completed!{Style.RESET_ALL}")
    print(f"Results saved to: system_check_results.json")

if __name__ == "__main__":
    main() 
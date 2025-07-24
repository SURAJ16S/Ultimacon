#!/usr/bin/env python3
"""
Tool Manager for Ultimate Reconnaissance Tool
Automatically checks and installs required external tools
"""

import os
import sys
import subprocess
import platform
import shutil
import requests
import zipfile
import tarfile
from pathlib import Path
from colorama import init, Fore, Style
import yaml
import json

# Initialize colorama
init(autoreset=True)

class ToolManager:
    """Manages external tool dependencies"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.tools_config = self.load_tools_config()
        self.install_path = self.get_install_path()
        
    def load_tools_config(self):
        """Load tools configuration"""
        return {
            'nmap': {
                'name': 'Nmap',
                'description': 'Network mapper for port scanning',
                'urls': {
                    'windows': 'https://nmap.org/dist/nmap-7.94-setup.exe',
                    'linux': 'https://nmap.org/dist/nmap-7.94.tar.bz2',
                    'macos': 'https://nmap.org/dist/nmap-7.94.tar.bz2'
                },
                'package_names': {
                    'ubuntu': 'nmap',
                    'debian': 'nmap',
                    'centos': 'nmap',
                    'fedora': 'nmap',
                    'macos': 'nmap'
                },
                'check_command': 'nmap --version',
                'required': True
            },
            'gobuster': {
                'name': 'Gobuster',
                'description': 'Directory/file bruteforcing tool',
                'urls': {
                    'windows': 'https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster-windows-amd64.exe',
                    'linux': 'https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster-linux-amd64',
                    'macos': 'https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster-darwin-amd64'
                },
                'package_names': {
                    'ubuntu': 'gobuster',
                    'debian': 'gobuster',
                    'centos': 'gobuster',
                    'fedora': 'gobuster',
                    'macos': 'gobuster'
                },
                'check_command': 'gobuster version',
                'required': True
            },
            'ffuf': {
                'name': 'FFUF',
                'description': 'Fast web fuzzer',
                'urls': {
                    'windows': 'https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_windows_amd64.zip',
                    'linux': 'https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_linux_amd64.tar.gz',
                    'macos': 'https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_macos_amd64.tar.gz'
                },
                'package_names': {
                    'ubuntu': 'ffuf',
                    'debian': 'ffuf',
                    'centos': 'ffuf',
                    'fedora': 'ffuf',
                    'macos': 'ffuf'
                },
                'check_command': 'ffuf -version',
                'required': True
            },
            'subfinder': {
                'name': 'Subfinder',
                'description': 'Subdomain discovery tool',
                'urls': {
                    'windows': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_windows_amd64.zip',
                    'linux': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.tar.gz',
                    'macos': 'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_macos_amd64.tar.gz'
                },
                'package_names': {
                    'ubuntu': 'subfinder',
                    'debian': 'subfinder',
                    'centos': 'subfinder',
                    'fedora': 'subfinder',
                    'macos': 'subfinder'
                },
                'check_command': 'subfinder -version',
                'required': True
            },
            'amass': {
                'name': 'Amass',
                'description': 'Network mapping and attack surface discovery',
                'urls': {
                    'windows': 'https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_windows_amd64.zip',
                    'linux': 'https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip',
                    'macos': 'https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_macos_amd64.zip'
                },
                'package_names': {
                    'ubuntu': 'amass',
                    'debian': 'amass',
                    'centos': 'amass',
                    'fedora': 'amass',
                    'macos': 'amass'
                },
                'check_command': 'amass version',
                'required': False
            },
            'whatweb': {
                'name': 'WhatWeb',
                'description': 'Web application fingerprinting',
                'urls': {
                    'windows': 'https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.zip',
                    'linux': 'https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.zip',
                    'macos': 'https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.zip'
                },
                'package_names': {
                    'ubuntu': 'whatweb',
                    'debian': 'whatweb',
                    'centos': 'whatweb',
                    'fedora': 'whatweb',
                    'macos': 'whatweb'
                },
                'check_command': 'whatweb --version',
                'required': False
            },
            'nuclei': {
                'name': 'Nuclei',
                'description': 'Vulnerability scanner',
                'urls': {
                    'windows': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.0.4/nuclei_3.0.4_windows_amd64.zip',
                    'linux': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.0.4/nuclei_3.0.4_linux_amd64.tar.gz',
                    'macos': 'https://github.com/projectdiscovery/nuclei/releases/download/v3.0.4/nuclei_3.0.4_macos_amd64.tar.gz'
                },
                'package_names': {
                    'ubuntu': 'nuclei',
                    'debian': 'nuclei',
                    'centos': 'nuclei',
                    'fedora': 'nuclei',
                    'macos': 'nuclei'
                },
                'check_command': 'nuclei -version',
                'required': False
            },
            'nikto': {
                'name': 'Nikto',
                'description': 'Web server scanner',
                'urls': {
                    'windows': 'https://github.com/sullo/nikto/archive/refs/heads/master.zip',
                    'linux': 'https://github.com/sullo/nikto/archive/refs/heads/master.zip',
                    'macos': 'https://github.com/sullo/nikto/archive/refs/heads/master.zip'
                },
                'package_names': {
                    'ubuntu': 'nikto',
                    'debian': 'nikto',
                    'centos': 'nikto',
                    'fedora': 'nikto',
                    'macos': 'nikto'
                },
                'check_command': 'nikto -Version',
                'required': False
            }
        }
    
    def get_install_path(self):
        """Get the installation path for tools"""
        if self.system == 'windows':
            return Path.home() / 'ultimate_recon_tools'
        else:
            return Path.home() / '.ultimate_recon_tools'
    
    def check_tool_availability(self, tool_name):
        """Check if a tool is available in PATH"""
        tool_config = self.tools_config.get(tool_name)
        if not tool_config:
            return False, f"Unknown tool: {tool_name}"
        
        # Check if tool is in PATH
        if shutil.which(tool_name):
            try:
                result = subprocess.run(
                    tool_config['check_command'].split(),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return True, f"{tool_config['name']} is available"
                else:
                    return False, f"{tool_config['name']} found but not working properly"
            except subprocess.TimeoutExpired:
                return False, f"{tool_config['name']} command timed out"
            except Exception as e:
                return False, f"Error checking {tool_config['name']}: {e}"
        
        return False, f"{tool_config['name']} not found in PATH"
    
    def get_package_manager(self):
        """Get the appropriate package manager for the system"""
        if self.system == 'windows':
            return 'chocolatey'
        elif self.system == 'linux':
            # Detect Linux distribution
            try:
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'ubuntu' in content or 'debian' in content:
                        return 'apt'
                    elif 'centos' in content or 'rhel' in content or 'fedora' in content:
                        return 'yum'
                    elif 'arch' in content:
                        return 'pacman'
                    else:
                        return 'apt'  # Default to apt
            except:
                return 'apt'
        elif self.system == 'darwin':  # macOS
            return 'brew'
        else:
            return None
    
    def install_via_package_manager(self, tool_name):
        """Install tool via package manager"""
        tool_config = self.tools_config.get(tool_name)
        if not tool_config:
            return False, f"Unknown tool: {tool_name}"
        
        package_manager = self.get_package_manager()
        if not package_manager:
            return False, "No package manager available"
        
        package_name = tool_config['package_names'].get(package_manager)
        if not package_name:
            return False, f"No package name for {tool_name} on {package_manager}"
        
        try:
            if package_manager == 'apt':
                cmd = ['sudo', 'apt', 'update', '-y']
                subprocess.run(cmd, check=True, capture_output=True)
                cmd = ['sudo', 'apt', 'install', '-y', package_name]
            elif package_manager == 'yum':
                cmd = ['sudo', 'yum', 'install', '-y', package_name]
            elif package_manager == 'pacman':
                cmd = ['sudo', 'pacman', '-S', '--noconfirm', package_name]
            elif package_manager == 'brew':
                cmd = ['brew', 'install', package_name]
            elif package_manager == 'chocolatey':
                cmd = ['choco', 'install', package_name, '-y']
            else:
                return False, f"Unsupported package manager: {package_manager}"
            
            print(f"{Fore.YELLOW}[*] Installing {tool_config['name']} via {package_manager}...{Style.RESET_ALL}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, f"{tool_config['name']} installed successfully via {package_manager}"
            else:
                return False, f"Failed to install {tool_config['name']} via {package_manager}: {result.stderr}"
                
        except subprocess.CalledProcessError as e:
            return False, f"Package manager error: {e}"
        except Exception as e:
            return False, f"Installation error: {e}"
    
    def download_and_install_tool(self, tool_name):
        """Download and install tool manually"""
        tool_config = self.tools_config.get(tool_name)
        if not tool_config:
            return False, f"Unknown tool: {tool_name}"
        
        # Create installation directory
        self.install_path.mkdir(parents=True, exist_ok=True)
        
        # Get download URL
        url = tool_config['urls'].get(self.system)
        if not url:
            return False, f"No download URL for {tool_name} on {self.system}"
        
        try:
            print(f"{Fore.YELLOW}[*] Downloading {tool_config['name']}...{Style.RESET_ALL}")
            
            # Download the file
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            # Determine filename from URL
            filename = url.split('/')[-1]
            file_path = self.install_path / filename
            
            # Save the file
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract and install
            return self.extract_and_install_tool(file_path, tool_name, tool_config)
            
        except Exception as e:
            return False, f"Download failed: {e}"
    
    def extract_and_install_tool(self, file_path, tool_name, tool_config):
        """Extract and install downloaded tool"""
        try:
            extract_path = self.install_path / tool_name
            extract_path.mkdir(exist_ok=True)
            
            # Extract based on file type
            if file_path.suffix == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            elif file_path.suffix in ['.tar.gz', '.tgz']:
                with tarfile.open(file_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_path)
            elif file_path.suffix == '.tar.bz2':
                with tarfile.open(file_path, 'r:bz2') as tar_ref:
                    tar_ref.extractall(extract_path)
            else:
                # Assume it's a binary file
                binary_path = self.install_path / tool_name
                shutil.copy2(file_path, binary_path)
                binary_path.chmod(0o755)  # Make executable
                
                # Add to PATH
                self.add_to_path(binary_path.parent)
                return True, f"{tool_config['name']} installed successfully"
            
            # Find the binary in extracted files
            binary_file = self.find_binary_in_directory(extract_path, tool_name)
            if binary_file:
                # Move to tools directory
                final_path = self.install_path / tool_name
                shutil.copy2(binary_file, final_path)
                final_path.chmod(0o755)  # Make executable
                
                # Add to PATH
                self.add_to_path(self.install_path)
                
                # Clean up
                shutil.rmtree(extract_path)
                file_path.unlink()
                
                return True, f"{tool_config['name']} installed successfully"
            else:
                return False, f"Could not find binary for {tool_config['name']}"
                
        except Exception as e:
            return False, f"Extraction failed: {e}"
    
    def find_binary_in_directory(self, directory, tool_name):
        """Find binary file in extracted directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower() == tool_name.lower() or file.lower().startswith(tool_name.lower()):
                    return Path(root) / file
        return None
    
    def add_to_path(self, path):
        """Add directory to PATH"""
        path_str = str(path)
        
        if self.system == 'windows':
            # Add to Windows PATH
            try:
                current_path = os.environ.get('PATH', '')
                if path_str not in current_path:
                    new_path = f"{current_path};{path_str}"
                    subprocess.run(['setx', 'PATH', new_path], check=True)
            except:
                print(f"{Fore.YELLOW}[!] Please manually add {path_str} to your PATH{Style.RESET_ALL}")
        else:
            # Add to shell profile
            shell_profile = self.get_shell_profile()
            if shell_profile:
                path_line = f'export PATH="$PATH:{path_str}"'
                try:
                    with open(shell_profile, 'r') as f:
                        content = f.read()
                    
                    if path_str not in content:
                        with open(shell_profile, 'a') as f:
                            f.write(f'\n# Ultimate Reconnaissance Tools\n{path_line}\n')
                        print(f"{Fore.GREEN}[+] Added {path_str} to {shell_profile}{Style.RESET_ALL}")
                except:
                    print(f"{Fore.YELLOW}[!] Please manually add {path_str} to your PATH{Style.RESET_ALL}")
    
    def get_shell_profile(self):
        """Get the appropriate shell profile file"""
        home = Path.home()
        
        if os.path.exists(home / '.bashrc'):
            return home / '.bashrc'
        elif os.path.exists(home / '.zshrc'):
            return home / '.zshrc'
        elif os.path.exists(home / '.profile'):
            return home / '.profile'
        else:
            return None
    
    def check_all_tools(self):
        """Check all required tools and install missing ones"""
        print(f"{Fore.CYAN}[*] Checking required tools...{Style.RESET_ALL}")
        
        missing_tools = []
        available_tools = []
        
        for tool_name, tool_config in self.tools_config.items():
            is_available, message = self.check_tool_availability(tool_name)
            
            if is_available:
                print(f"{Fore.GREEN}[+] {tool_config['name']}: {message}{Style.RESET_ALL}")
                available_tools.append(tool_name)
            else:
                print(f"{Fore.RED}[-] {tool_config['name']}: {message}{Style.RESET_ALL}")
                missing_tools.append(tool_name)
        
        return available_tools, missing_tools
    
    def install_missing_tools(self, missing_tools, auto_install=True):
        """Install missing tools"""
        if not missing_tools:
            print(f"{Fore.GREEN}[+] All required tools are available{Style.RESET_ALL}")
            return True
        
        print(f"\n{Fore.YELLOW}[!] Missing tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
        
        if not auto_install:
            response = input(f"{Fore.YELLOW}Do you want to install missing tools? (y/n): {Style.RESET_ALL}")
            if response.lower() != 'y':
                return False
        
        success_count = 0
        failed_tools = []
        
        for tool_name in missing_tools:
            tool_config = self.tools_config.get(tool_name)
            if not tool_config:
                continue
            
            print(f"\n{Fore.CYAN}[*] Installing {tool_config['name']}...{Style.RESET_ALL}")
            
            # Try package manager first
            success, message = self.install_via_package_manager(tool_name)
            
            if not success:
                # Try manual download
                success, message = self.download_and_install_tool(tool_name)
            
            if success:
                print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
                success_count += 1
            else:
                print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
                failed_tools.append(tool_name)
        
        print(f"\n{Fore.CYAN}[*] Installation Summary:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Successfully installed: {success_count}{Style.RESET_ALL}")
        if failed_tools:
            print(f"{Fore.RED}[-] Failed to install: {', '.join(failed_tools)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please install these tools manually{Style.RESET_ALL}")
        
        return len(failed_tools) == 0
    
    def verify_installation(self):
        """Verify that all tools are working"""
        print(f"\n{Fore.CYAN}[*] Verifying tool installations...{Style.RESET_ALL}")
        
        all_working = True
        for tool_name, tool_config in self.tools_config.items():
            is_available, message = self.check_tool_availability(tool_name)
            
            if is_available:
                print(f"{Fore.GREEN}[+] {tool_config['name']}: Working{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] {tool_config['name']}: {message}{Style.RESET_ALL}")
                all_working = False
        
        return all_working

def main():
    """Main function"""
    print(f"{Fore.CYAN}🔧 Ultimate Reconnaissance Tool Manager{Style.RESET_ALL}")
    print("=" * 50)
    
    manager = ToolManager()
    
    # Check all tools
    available_tools, missing_tools = manager.check_all_tools()
    
    if missing_tools:
        print(f"\n{Fore.YELLOW}[!] Found {len(missing_tools)} missing tools{Style.RESET_ALL}")
        
        # Install missing tools
        success = manager.install_missing_tools(missing_tools, auto_install=False)
        
        if success:
            # Verify installation
            manager.verify_installation()
        else:
            print(f"\n{Fore.RED}[!] Some tools could not be installed automatically{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Please install them manually and run this script again{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}[+] All tools are available and working{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 
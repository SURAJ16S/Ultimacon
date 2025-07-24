#!/usr/bin/env python3
"""
Installation Script for Ultimate Reconnaissance Tool
Demonstrates setup and configuration functionality
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def run_system_check():
    """Run system check"""
    print("\n🔍 Running system check...")
    
    try:
        from system_check import SystemChecker
        checker = SystemChecker()
        results, recommendations = checker.run_full_check()
        return results, recommendations
    except ImportError as e:
        print(f"❌ System check module not found: {e}")
        return None, None

def run_setup():
    """Run interactive setup"""
    print("\n⚙️  Running interactive setup...")
    
    try:
        from setup import SystemAnalyzer, ConfigurationManager, FallbackManager
        
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
        
        return True
    except ImportError as e:
        print(f"❌ Setup module not found: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        'results',
        'wordlists',
        'modules',
        'logs',
        'reports'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"  ✅ Created: {directory}/")

def main():
    """Main installation function"""
    print("🚀 Ultimate Reconnaissance Tool - Installation")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Run system check
    results, recommendations = run_system_check()
    
    # Run setup
    if run_setup():
        print("\n✅ Installation completed successfully!")
        print("\n🎯 Next steps:")
        print("  1. Configure API keys in api_keys.json")
        print("  2. Customize configuration in config.yaml")
        print("  3. Run: python ultimate_recon.py example.com")
    else:
        print("\n⚠️  Installation completed with warnings")
        print("   Some features may not be available")
    
    print("\n📚 Documentation:")
    print("  - README.md: Complete usage guide")
    print("  - python system_check.py: Check system status")
    print("  - python setup.py: Interactive setup")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Test script for crt.sh integration and certificate analysis
"""

import sys
import os
import json
from datetime import datetime

# Add modules directory to path
sys.path.append('modules')

def test_crt_integration():
    """Test the crt.sh integration"""
    print("🔍 Testing crt.sh Integration")
    print("=" * 50)
    
    try:
        from certificate_analysis import CertificateAnalysis
        
        # Test configuration
        config = {
            'threads': 10,
            'timeout': 30,
            'retries': 3,
            'rate_limit': 1
        }
        
        wordlists = {
            'subdomains': [],
            'directories': [],
            'files': [],
            'usernames': [],
            'passwords': []
        }
        
        api_keys = {}
        
        # Test with a known domain
        test_domain = "example.com"
        print(f"Testing with domain: {test_domain}")
        
        # Initialize certificate analyzer
        analyzer = CertificateAnalysis(test_domain, config, wordlists, api_keys)
        
        # Run analysis
        print("\n[*] Running certificate analysis...")
        results = analyzer.run()
        
        # Display results
        print("\n📊 Certificate Analysis Results:")
        print("-" * 30)
        
        metrics = results.get('certificate_metrics', {})
        print(f"Total Certificates: {metrics.get('total_certificates', 0)}")
        print(f"Unique Subdomains: {metrics.get('unique_subdomains', 0)}")
        print(f"Unique Issuers: {metrics.get('unique_issuers', 0)}")
        print(f"Wildcard Certificates: {metrics.get('wildcard_certificates', 0)}")
        print(f"Weak Certificates: {metrics.get('weak_certificates', 0)}")
        print(f"Duplicate Groups: {metrics.get('duplicate_groups', 0)}")
        print(f"Certificate Chains: {metrics.get('certificate_chains', 0)}")
        print(f"SAN Domains: {metrics.get('san_domains', 0)}")
        
        # Display subdomains found
        subdomains = results.get('subdomains', [])
        if subdomains:
            print(f"\n🌐 Subdomains Found ({len(subdomains)}):")
            for subdomain in subdomains[:10]:  # Show first 10
                print(f"  - {subdomain}")
            if len(subdomains) > 10:
                print(f"  ... and {len(subdomains) - 10} more")
        
        # Display weak certificates
        weak_certs = results.get('weak_certificates', [])
        if weak_certs:
            print(f"\n⚠️  Weak Certificates Found ({len(weak_certs)}):")
            for cert in weak_certs[:5]:  # Show first 5
                print(f"  - {cert.get('name_value', 'Unknown')}")
                print(f"    Issues: {', '.join(cert.get('issues', []))}")
        
        # Display wildcard certificates
        wildcard_certs = results.get('wildcard_certificates', [])
        if wildcard_certs:
            print(f"\n🔗 Wildcard Certificates Found ({len(wildcard_certs)}):")
            for cert in wildcard_certs[:5]:  # Show first 5
                print(f"  - {cert.get('name_value', 'Unknown')}")
                print(f"    Issuer: {cert.get('issuer', 'Unknown')}")
        
        # Export results
        print(f"\n💾 Exporting results...")
        export_files = analyzer.export_certificate_data()
        
        print(f"\n✅ Certificate analysis completed successfully!")
        print(f"📁 Export files:")
        for file_type, file_path in export_files.items():
            print(f"  - {file_type}: {file_path}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Error: Certificate analysis module not found: {e}")
        print("Make sure the certificate_analysis.py module is in the modules/ directory")
        return False
    except Exception as e:
        print(f"❌ Error during certificate analysis: {e}")
        return False

def test_passive_recon_crt():
    """Test crt.sh integration in passive reconnaissance"""
    print("\n🔍 Testing crt.sh in Passive Reconnaissance")
    print("=" * 50)
    
    try:
        from passive_recon import PassiveRecon
        
        # Test configuration
        config = {
            'threads': 10,
            'timeout': 30,
            'retries': 3,
            'rate_limit': 1
        }
        
        wordlists = {
            'subdomains': [],
            'directories': [],
            'files': [],
            'usernames': [],
            'passwords': []
        }
        
        api_keys = {}
        
        # Test with a known domain
        test_domain = "example.com"
        print(f"Testing with domain: {test_domain}")
        
        # Initialize passive recon
        recon = PassiveRecon(test_domain, config, wordlists, api_keys)
        
        # Run passive reconnaissance
        print("\n[*] Running passive reconnaissance...")
        results = recon.run()
        
        # Display crt.sh results
        crt_results = results.get('crt_sh', {})
        if crt_results:
            print(f"\n📊 crt.sh Results:")
            print("-" * 20)
            print(f"Subdomains: {len(crt_results.get('subdomains', []))}")
            print(f"Certificates: {len(crt_results.get('certificates', []))}")
            print(f"Issuers: {len(crt_results.get('issuers', []))}")
            print(f"SAN Domains: {len(crt_results.get('san_domains', []))}")
            
            # Show some subdomains
            subdomains = crt_results.get('subdomains', [])
            if subdomains:
                print(f"\n🌐 Sample Subdomains:")
                for subdomain in subdomains[:5]:
                    print(f"  - {subdomain}")
        
        print(f"\n✅ Passive reconnaissance with crt.sh completed successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Error: Passive reconnaissance module not found: {e}")
        return False
    except Exception as e:
        print(f"❌ Error during passive reconnaissance: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Ultimate Reconnaissance Tool - crt.sh Integration Test")
    print("=" * 60)
    
    # Test certificate analysis module
    cert_test = test_crt_integration()
    
    # Test passive reconnaissance with crt.sh
    passive_test = test_passive_recon_crt()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 Test Summary:")
    print(f"Certificate Analysis Module: {'✅ PASS' if cert_test else '❌ FAIL'}")
    print(f"Passive Recon with crt.sh: {'✅ PASS' if passive_test else '❌ FAIL'}")
    
    if cert_test and passive_test:
        print("\n🎉 All tests passed! crt.sh integration is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Please check the error messages above.")

if __name__ == "__main__":
    main() 
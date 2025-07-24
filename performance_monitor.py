#!/usr/bin/env python3
"""
Performance Monitor for Ultimate Reconnaissance Tool
Tracks CPU, RAM, network, and power usage during operations
"""

import os
import sys
import time
import psutil
import threading
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse
from colorama import Fore, Style
import matplotlib.pyplot as plt
import numpy as np

class PerformanceMonitor:
    def __init__(self, output_file: str = "performance_log.json"):
        self.output_file = output_file
        self.monitoring = False
        self.metrics = []
        self.start_time = None
        self.end_time = None
        
        # Network monitoring
        self.network_start = psutil.net_io_counters()
        self.network_metrics = []
        
        # CPU monitoring
        self.cpu_metrics = []
        
        # Memory monitoring
        self.memory_metrics = []
        
        # Disk monitoring
        self.disk_metrics = []
        
    def start_monitoring(self):
        """Start performance monitoring"""
        self.monitoring = True
        self.start_time = datetime.now()
        self.network_start = psutil.net_io_counters()
        
        print(f"{Fore.GREEN}[+] Performance monitoring started{Style.RESET_ALL}")
        
        # Start monitoring threads
        self.cpu_thread = threading.Thread(target=self.monitor_cpu, daemon=True)
        self.memory_thread = threading.Thread(target=self.monitor_memory, daemon=True)
        self.network_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.disk_thread = threading.Thread(target=self.monitor_disk, daemon=True)
        
        self.cpu_thread.start()
        self.memory_thread.start()
        self.network_thread.start()
        self.disk_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        self.end_time = datetime.now()
        
        print(f"{Fore.YELLOW}[*] Performance monitoring stopped{Style.RESET_ALL}")
        
        # Wait for threads to finish
        time.sleep(2)
        
        # Generate report
        self.generate_report()
    
    def monitor_cpu(self):
        """Monitor CPU usage"""
        while self.monitoring:
            try:
                cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
                cpu_avg = psutil.cpu_percent(interval=1)
                
                self.cpu_metrics.append({
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': cpu_avg,
                    'cpu_per_core': cpu_percent,
                    'cpu_count': psutil.cpu_count(),
                    'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
                })
                
            except Exception as e:
                print(f"{Fore.RED}[-] CPU monitoring error: {e}{Style.RESET_ALL}")
    
    def monitor_memory(self):
        """Monitor memory usage"""
        while self.monitoring:
            try:
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                self.memory_metrics.append({
                    'timestamp': datetime.now().isoformat(),
                    'memory_total': memory.total,
                    'memory_available': memory.available,
                    'memory_percent': memory.percent,
                    'memory_used': memory.used,
                    'memory_free': memory.free,
                    'swap_total': swap.total,
                    'swap_used': swap.used,
                    'swap_percent': swap.percent
                })
                
            except Exception as e:
                print(f"{Fore.RED}[-] Memory monitoring error: {e}{Style.RESET_ALL}")
            
            time.sleep(2)
    
    def monitor_network(self):
        """Monitor network usage"""
        while self.monitoring:
            try:
                network = psutil.net_io_counters()
                
                # Calculate network usage since start
                bytes_sent = network.bytes_sent - self.network_start.bytes_sent
                bytes_recv = network.bytes_recv - self.network_start.bytes_recv
                
                self.network_metrics.append({
                    'timestamp': datetime.now().isoformat(),
                    'bytes_sent': bytes_sent,
                    'bytes_recv': bytes_recv,
                    'packets_sent': network.packets_sent - self.network_start.packets_sent,
                    'packets_recv': network.packets_recv - self.network_start.packets_recv,
                    'errin': network.errin - self.network_start.errin,
                    'errout': network.errout - self.network_start.errout,
                    'dropin': network.dropin - self.network_start.dropin,
                    'dropout': network.dropout - self.network_start.dropout
                })
                
            except Exception as e:
                print(f"{Fore.RED}[-] Network monitoring error: {e}{Style.RESET_ALL}")
            
            time.sleep(5)
    
    def monitor_disk(self):
        """Monitor disk usage"""
        while self.monitoring:
            try:
                disk_usage = psutil.disk_usage('/')
                disk_io = psutil.disk_io_counters()
                
                self.disk_metrics.append({
                    'timestamp': datetime.now().isoformat(),
                    'disk_total': disk_usage.total,
                    'disk_used': disk_usage.used,
                    'disk_free': disk_usage.free,
                    'disk_percent': disk_usage.percent,
                    'disk_read_bytes': disk_io.read_bytes if disk_io else 0,
                    'disk_write_bytes': disk_io.write_bytes if disk_io else 0,
                    'disk_read_count': disk_io.read_count if disk_io else 0,
                    'disk_write_count': disk_io.write_count if disk_io else 0
                })
                
            except Exception as e:
                print(f"{Fore.RED}[-] Disk monitoring error: {e}{Style.RESET_ALL}")
            
            time.sleep(10)
    
    def get_current_stats(self):
        """Get current system statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            network = psutil.net_io_counters()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': memory.used / (1024**3),
                'memory_available_gb': memory.available / (1024**3),
                'network_bytes_sent_mb': network.bytes_sent / (1024**2),
                'network_bytes_recv_mb': network.bytes_recv / (1024**2)
            }
        except Exception as e:
            print(f"{Fore.RED}[-] Error getting current stats: {e}{Style.RESET_ALL}")
            return None
    
    def generate_report(self):
        """Generate performance report"""
        if not self.cpu_metrics or not self.memory_metrics:
            print(f"{Fore.YELLOW}[!] No metrics collected{Style.RESET_ALL}")
            return
        
        # Calculate averages and peaks
        cpu_percentages = [m['cpu_percent'] for m in self.cpu_metrics]
        memory_percentages = [m['memory_percent'] for m in self.memory_metrics]
        
        # Network totals
        if self.network_metrics:
            total_bytes_sent = self.network_metrics[-1]['bytes_sent']
            total_bytes_recv = self.network_metrics[-1]['bytes_recv']
        else:
            total_bytes_sent = 0
            total_bytes_recv = 0
        
        # Duration
        duration = self.end_time - self.start_time
        
        # Generate report
        report = {
            'scan_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'duration_hours': duration.total_seconds() / 3600
            },
            'cpu_analysis': {
                'average_cpu_percent': np.mean(cpu_percentages),
                'peak_cpu_percent': np.max(cpu_percentages),
                'min_cpu_percent': np.min(cpu_percentages),
                'cpu_samples': len(cpu_percentages)
            },
            'memory_analysis': {
                'average_memory_percent': np.mean(memory_percentages),
                'peak_memory_percent': np.max(memory_percentages),
                'min_memory_percent': np.min(memory_percentages),
                'memory_samples': len(memory_percentages)
            },
            'network_analysis': {
                'total_bytes_sent_mb': total_bytes_sent / (1024**2),
                'total_bytes_recv_mb': total_bytes_recv / (1024**2),
                'total_data_transferred_mb': (total_bytes_sent + total_bytes_recv) / (1024**2),
                'average_bandwidth_mbps': ((total_bytes_sent + total_bytes_recv) / (1024**2)) / (duration.total_seconds() / 3600)
            },
            'system_info': {
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': psutil.virtual_memory().total / (1024**3),
                'platform': sys.platform,
                'python_version': sys.version
            },
            'raw_metrics': {
                'cpu_metrics': self.cpu_metrics,
                'memory_metrics': self.memory_metrics,
                'network_metrics': self.network_metrics,
                'disk_metrics': self.disk_metrics
            }
        }
        
        # Save report
        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        self.print_summary(report)
        
        # Generate charts
        self.generate_charts(report)
    
    def print_summary(self, report):
        """Print performance summary"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                    PERFORMANCE MONITORING SUMMARY                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        scan_info = report['scan_info']
        cpu_analysis = report['cpu_analysis']
        memory_analysis = report['memory_analysis']
        network_analysis = report['network_analysis']
        system_info = report['system_info']
        
        print(f"\n{Fore.YELLOW}📊 Scan Information:{Style.RESET_ALL}")
        print(f"  Duration: {scan_info['duration_hours']:.2f} hours ({scan_info['duration_seconds']:.0f} seconds)")
        print(f"  Start Time: {scan_info['start_time']}")
        print(f"  End Time: {scan_info['end_time']}")
        
        print(f"\n{Fore.YELLOW}🖥️  CPU Analysis:{Style.RESET_ALL}")
        print(f"  Average CPU Usage: {cpu_analysis['average_cpu_percent']:.1f}%")
        print(f"  Peak CPU Usage: {cpu_analysis['peak_cpu_percent']:.1f}%")
        print(f"  Minimum CPU Usage: {cpu_analysis['min_cpu_percent']:.1f}%")
        print(f"  CPU Cores: {system_info['cpu_count']}")
        
        print(f"\n{Fore.YELLOW}💾 Memory Analysis:{Style.RESET_ALL}")
        print(f"  Average Memory Usage: {memory_analysis['average_memory_percent']:.1f}%")
        print(f"  Peak Memory Usage: {memory_analysis['peak_memory_percent']:.1f}%")
        print(f"  Total System Memory: {system_info['memory_total_gb']:.1f} GB")
        
        print(f"\n{Fore.YELLOW}🌐 Network Analysis:{Style.RESET_ALL}")
        print(f"  Total Data Sent: {network_analysis['total_bytes_sent_mb']:.2f} MB")
        print(f"  Total Data Received: {network_analysis['total_bytes_recv_mb']:.2f} MB")
        print(f"  Total Data Transferred: {network_analysis['total_data_transferred_mb']:.2f} MB")
        print(f"  Average Bandwidth: {network_analysis['average_bandwidth_mbps']:.2f} Mbps")
        
        print(f"\n{Fore.YELLOW}💡 System Information:{Style.RESET_ALL}")
        print(f"  Platform: {system_info['platform']}")
        print(f"  Python Version: {system_info['python_version']}")
        
        # Performance recommendations
        self.print_recommendations(report)
    
    def print_recommendations(self, report):
        """Print performance recommendations"""
        print(f"\n{Fore.GREEN}💡 Performance Recommendations:{Style.RESET_ALL}")
        
        cpu_avg = report['cpu_analysis']['average_cpu_percent']
        memory_avg = report['memory_analysis']['average_memory_percent']
        bandwidth = report['network_analysis']['average_bandwidth_mbps']
        
        if cpu_avg > 80:
            print(f"  ⚠️  High CPU usage detected ({cpu_avg:.1f}%). Consider:")
            print(f"     - Reducing thread count with -t parameter")
            print(f"     - Using --stealth mode for slower scanning")
            print(f"     - Upgrading to a more powerful CPU")
        
        if memory_avg > 80:
            print(f"  ⚠️  High memory usage detected ({memory_avg:.1f}%). Consider:")
            print(f"     - Closing unnecessary applications")
            print(f"     - Reducing concurrent operations")
            print(f"     - Upgrading RAM")
        
        if bandwidth < 5:
            print(f"  ⚠️  Low bandwidth detected ({bandwidth:.2f} Mbps). Consider:")
            print(f"     - Upgrading internet connection")
            print(f"     - Using wired connection instead of WiFi")
            print(f"     - Scheduling scans during off-peak hours")
        
        if cpu_avg < 30 and memory_avg < 50:
            print(f"  ✅ Good performance! You can:")
            print(f"     - Increase thread count for faster scanning")
            print(f"     - Enable more modules for comprehensive results")
            print(f"     - Use --aggressive mode for maximum coverage")
    
    def generate_charts(self, report):
        """Generate performance charts"""
        try:
            # CPU usage over time
            timestamps = [m['timestamp'] for m in report['raw_metrics']['cpu_metrics']]
            cpu_values = [m['cpu_percent'] for m in report['raw_metrics']['cpu_metrics']]
            
            plt.figure(figsize=(12, 8))
            
            # CPU chart
            plt.subplot(2, 2, 1)
            plt.plot(range(len(cpu_values)), cpu_values, 'b-', linewidth=1)
            plt.title('CPU Usage Over Time')
            plt.ylabel('CPU Usage (%)')
            plt.grid(True, alpha=0.3)
            
            # Memory chart
            memory_values = [m['memory_percent'] for m in report['raw_metrics']['memory_metrics']]
            plt.subplot(2, 2, 2)
            plt.plot(range(len(memory_values)), memory_values, 'r-', linewidth=1)
            plt.title('Memory Usage Over Time')
            plt.ylabel('Memory Usage (%)')
            plt.grid(True, alpha=0.3)
            
            # Network chart
            if report['raw_metrics']['network_metrics']:
                network_sent = [m['bytes_sent'] / (1024**2) for m in report['raw_metrics']['network_metrics']]
                network_recv = [m['bytes_recv'] / (1024**2) for m in report['raw_metrics']['network_metrics']]
                
                plt.subplot(2, 2, 3)
                plt.plot(range(len(network_sent)), network_sent, 'g-', label='Sent', linewidth=1)
                plt.plot(range(len(network_recv)), network_recv, 'orange', label='Received', linewidth=1)
                plt.title('Network Usage Over Time')
                plt.ylabel('Data (MB)')
                plt.legend()
                plt.grid(True, alpha=0.3)
            
            # System overview
            plt.subplot(2, 2, 4)
            labels = ['CPU', 'Memory', 'Network']
            values = [
                report['cpu_analysis']['average_cpu_percent'],
                report['memory_analysis']['average_memory_percent'],
                min(100, report['network_analysis']['average_bandwidth_mbps'] * 2)  # Scale for visualization
            ]
            colors = ['#ff9999', '#66b3ff', '#99ff99']
            plt.pie(values, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            plt.title('System Resource Usage')
            
            plt.tight_layout()
            plt.savefig('performance_charts.png', dpi=300, bbox_inches='tight')
            print(f"{Fore.GREEN}[+] Performance charts saved to: performance_charts.png{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating charts: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Performance Monitor for Ultimate Reconnaissance Tool")
    parser.add_argument("--output", default="performance_log.json", help="Output file for performance data")
    parser.add_argument("--duration", type=int, default=0, help="Monitoring duration in seconds (0 for manual stop)")
    
    args = parser.parse_args()
    
    monitor = PerformanceMonitor(args.output)
    
    print(f"{Fore.CYAN}[*] Starting performance monitoring...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop monitoring{Style.RESET_ALL}")
    
    try:
        monitor.start_monitoring()
        
        if args.duration > 0:
            time.sleep(args.duration)
            monitor.stop_monitoring()
        else:
            # Keep running until interrupted
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Stopping performance monitoring...{Style.RESET_ALL}")
        monitor.stop_monitoring()

if __name__ == "__main__":
    main() 
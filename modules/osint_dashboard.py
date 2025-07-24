#!/usr/bin/env python3
"""
OSINT Dashboard Module
Provides a web-based dashboard for viewing and analyzing OSINT results
"""

import os
import json
import time
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO, emit
import webbrowser
from colorama import Fore, Style

class OsintDashboard:
    def __init__(self, target, config, wordlists, api_keys):
        self.target = target
        self.config = config
        self.wordlists = wordlists
        self.api_keys = api_keys
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.results = {}
        self.live_data = {}
        self.setup_routes()
        
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            return render_template('dashboard.html', target=self.target)
        
        @self.app.route('/api/results')
        def get_results():
            return jsonify(self.results)
        
        @self.app.route('/api/live')
        def get_live_data():
            return jsonify(self.live_data)
        
        @self.app.route('/api/email-leaks')
        def get_email_leaks():
            return jsonify(self.results.get('email_leaks', []))
        
        @self.app.route('/api/social-profiles')
        def get_social_profiles():
            return jsonify(self.results.get('social_profiles', []))
        
        @self.app.route('/api/breach-data')
        def get_breach_data():
            return jsonify(self.results.get('breach_data', []))
        
        @self.app.route('/api/github-intel')
        def get_github_intel():
            return jsonify(self.results.get('github_intel', []))
        
        @self.app.route('/api/historical-data')
        def get_historical_data():
            return jsonify(self.results.get('historical_data', []))
        
        @self.app.route('/api/forum-mentions')
        def get_forum_mentions():
            return jsonify(self.results.get('forum_mentions', []))
        
        @self.app.route('/api/job-postings')
        def get_job_postings():
            return jsonify(self.results.get('job_postings', []))
        
        @self.app.route('/api/paste-dumps')
        def get_paste_dumps():
            return jsonify(self.results.get('paste_dumps', []))
        
        @self.socketio.on('connect')
        def handle_connect():
            print(f"{Fore.GREEN}[+] Dashboard client connected{Style.RESET_ALL}")
            emit('status', {'message': 'Connected to OSINT Dashboard'})
        
        @self.socketio.on('request_update')
        def handle_update_request():
            emit('data_update', self.results)
    
    def update_results(self, new_results):
        """Update results and notify dashboard"""
        self.results.update(new_results)
        self.socketio.emit('data_update', self.results)
    
    def update_live_data(self, data_type, data):
        """Update live data and notify dashboard"""
        self.live_data[data_type] = data
        self.socketio.emit('live_update', {data_type: data})
    
    def run_dashboard(self, port=5000):
        """Run the dashboard server"""
        print(f"{Fore.CYAN}[*] Starting OSINT Dashboard on http://localhost:{port}{Style.RESET_ALL}")
        
        # Open browser automatically
        def open_browser():
            time.sleep(2)
            webbrowser.open(f'http://localhost:{port}')
        
        threading.Thread(target=open_browser, daemon=True).start()
        
        # Run the Flask app
        self.socketio.run(self.app, host='0.0.0.0', port=port, debug=False)
    
    def create_templates(self):
        """Create HTML templates for the dashboard"""
        templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        os.makedirs(templates_dir, exist_ok=True)
        
        # Main dashboard template
        dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Dashboard - {{ target }}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .header .target {
            font-size: 1.2em;
            color: #e74c3c;
            font-weight: bold;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
        }
        
        .stat-label {
            color: #7f8c8d;
            margin-top: 5px;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .panel {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .panel h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
        }
        
        .data-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .data-item {
            background: #f8f9fa;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        
        .data-item h4 {
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .data-item p {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .data-item a {
            color: #3498db;
            text-decoration: none;
        }
        
        .data-item a:hover {
            text-decoration: underline;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }
        
        .status-active {
            background: #27ae60;
        }
        
        .status-inactive {
            background: #e74c3c;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 20px;
        }
        
        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ OSINT Dashboard</h1>
            <div class="target">Target: {{ target }}</div>
            <div id="status">Status: <span id="status-text">Connecting...</span></div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="email-leaks-count">0</div>
                <div class="stat-label">Email Leaks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="social-profiles-count">0</div>
                <div class="stat-label">Social Profiles</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="breach-count">0</div>
                <div class="stat-label">Breach Records</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="github-repos-count">0</div>
                <div class="stat-label">GitHub Repos</div>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <h3>📧 Email Leaks & Breaches</h3>
                <div class="data-list" id="email-leaks-list">
                    <div class="loading">Loading email leak data...</div>
                </div>
            </div>
            
            <div class="panel">
                <h3>👥 Social Profiles</h3>
                <div class="data-list" id="social-profiles-list">
                    <div class="loading">Loading social profiles...</div>
                </div>
            </div>
            
            <div class="panel">
                <h3>💼 Job Postings</h3>
                <div class="data-list" id="job-postings-list">
                    <div class="loading">Loading job postings...</div>
                </div>
            </div>
            
            <div class="panel">
                <h3>💬 Forum Mentions</h3>
                <div class="data-list" id="forum-mentions-list">
                    <div class="loading">Loading forum mentions...</div>
                </div>
            </div>
            
            <div class="panel">
                <h3>📋 Paste Dumps</h3>
                <div class="data-list" id="paste-dumps-list">
                    <div class="loading">Loading paste dumps...</div>
                </div>
            </div>
            
            <div class="panel">
                <h3>📊 GitHub Intelligence</h3>
                <div class="data-list" id="github-intel-list">
                    <div class="loading">Loading GitHub intelligence...</div>
                </div>
            </div>
        </div>
        
        <div class="panel" style="margin-top: 20px;">
            <h3>📈 Data Visualization</h3>
            <div class="chart-container">
                <canvas id="breachChart"></canvas>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let breachChart;
        
        socket.on('connect', function() {
            document.getElementById('status-text').textContent = 'Connected';
            document.getElementById('status-text').style.color = '#27ae60';
        });
        
        socket.on('disconnect', function() {
            document.getElementById('status-text').textContent = 'Disconnected';
            document.getElementById('status-text').style.color = '#e74c3c';
        });
        
        socket.on('data_update', function(data) {
            updateDashboard(data);
        });
        
        socket.on('live_update', function(data) {
            updateLiveData(data);
        });
        
        function updateDashboard(data) {
            // Update statistics
            document.getElementById('email-leaks-count').textContent = data.email_leaks ? data.email_leaks.length : 0;
            document.getElementById('social-profiles-count').textContent = data.social_profiles ? data.social_profiles.length : 0;
            document.getElementById('breach-count').textContent = data.breach_data ? data.breach_data.length : 0;
            document.getElementById('github-repos-count').textContent = data.github_intel ? data.github_intel.length : 0;
            
            // Update email leaks
            updateList('email-leaks-list', data.email_leaks, function(item) {
                return `
                    <div class="data-item">
                        <h4>${item.email || 'Unknown'}</h4>
                        <p><strong>Breach:</strong> ${item.breach_name || 'Unknown'}</p>
                        <p><strong>Date:</strong> ${item.breach_date || 'Unknown'}</p>
                        <p><strong>Source:</strong> ${item.source || 'Unknown'}</p>
                    </div>
                `;
            });
            
            // Update social profiles
            updateList('social-profiles-list', data.social_profiles, function(item) {
                return `
                    <div class="data-item">
                        <h4>${item.platform}</h4>
                        <p><strong>URL:</strong> <a href="${item.url}" target="_blank">${item.url}</a></p>
                        <p><strong>Status:</strong> <span class="status-indicator status-${item.status}"></span>${item.status}</p>
                    </div>
                `;
            });
            
            // Update job postings
            updateList('job-postings-list', data.job_postings, function(item) {
                return `
                    <div class="data-item">
                        <h4>${item.title}</h4>
                        <p><strong>Company:</strong> ${item.company}</p>
                        <p><strong>Platform:</strong> ${item.platform}</p>
                    </div>
                `;
            });
            
            // Update forum mentions
            updateList('forum-mentions-list', data.forum_mentions, function(item) {
                return `
                    <div class="data-item">
                        <h4>${item.title}</h4>
                        <p><strong>Platform:</strong> ${item.platform}</p>
                        <p><strong>URL:</strong> <a href="${item.url}" target="_blank">View Post</a></p>
                        <p><strong>Score:</strong> ${item.score}</p>
                    </div>
                `;
            });
            
            // Update paste dumps
            updateList('paste-dumps-list', data.paste_dumps, function(item) {
                return `
                    <div class="data-item">
                        <h4>${item.platform}</h4>
                        <p><strong>URL:</strong> <a href="${item.url}" target="_blank">View Paste</a></p>
                        <p><strong>Title:</strong> ${item.title}</p>
                    </div>
                `;
            });
            
            // Update GitHub intelligence
            updateList('github-intel-list', data.github_intel, function(item) {
                return `
                    <div class="data-item">
                        <h4>${item.name || item.repository}</h4>
                        <p><strong>Type:</strong> ${item.type}</p>
                        <p><strong>URL:</strong> <a href="${item.url}" target="_blank">View Repository</a></p>
                        <p><strong>Language:</strong> ${item.language || 'Unknown'}</p>
                    </div>
                `;
            });
            
            // Update breach chart
            updateBreachChart(data);
        }
        
        function updateList(elementId, data, itemRenderer) {
            const element = document.getElementById(elementId);
            if (!data || data.length === 0) {
                element.innerHTML = '<div class="loading">No data available</div>';
                return;
            }
            
            element.innerHTML = data.map(itemRenderer).join('');
        }
        
        function updateBreachChart(data) {
            const ctx = document.getElementById('breachChart').getContext('2d');
            
            if (breachChart) {
                breachChart.destroy();
            }
            
            const breachSources = {};
            if (data.breach_data) {
                data.breach_data.forEach(breach => {
                    const source = breach.source || 'Unknown';
                    breachSources[source] = (breachSources[source] || 0) + 1;
                });
            }
            
            breachChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(breachSources),
                    datasets: [{
                        data: Object.values(breachSources),
                        backgroundColor: [
                            '#FF6384',
                            '#36A2EB',
                            '#FFCE56',
                            '#4BC0C0',
                            '#9966FF',
                            '#FF9F40'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        },
                        title: {
                            display: true,
                            text: 'Breach Sources Distribution'
                        }
                    }
                }
            });
        }
        
        function updateLiveData(data) {
            // Handle live data updates
            console.log('Live data update:', data);
        }
        
        // Request initial data
        socket.emit('request_update');
        
        // Auto-refresh every 30 seconds
        setInterval(function() {
            socket.emit('request_update');
        }, 30000);
    </script>
</body>
</html>
        '''
        
        with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
            f.write(dashboard_html)
    
    def run(self):
        """Main execution method"""
        print(f"{Fore.MAGENTA}[*] Starting OSINT Dashboard...{Style.RESET_ALL}")
        
        # Create templates
        self.create_templates()
        
        # Start dashboard server
        self.run_dashboard()
        
        return self.results 
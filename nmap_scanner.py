#!/usr/bin/env python3
"""
Multithreaded Nmap Scanner with Dynamic Display
Scans a list of IPs for open ports with real-time progress updates
"""

import subprocess
import threading
import argparse
import sys
import os
import re
from collections import defaultdict
from queue import Queue
import time
from datetime import datetime
import html


class NmapScanner:
    def __init__(self, ip_list, threads, output_prefix="nmap_scan", no_pn=False):
        self.ip_list = ip_list
        self.threads = threads if threads != "all" else len(ip_list)
        self.output_prefix = output_prefix
        self.no_pn = no_pn
        
        # Thread-safe data structures
        self.lock = threading.Lock()
        
        # Create output directory
        self.output_dir = f"{self.output_prefix}_results"
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.results = {}  # {ip: [ports]}
        self.ip_status = {}  # {ip: status_message}
        self.ip_progress = {}  # {ip: progress_percentage}
        self.detailed_results = {}  # {ip: nmap_output}
        self.completed = 0
        self.in_progress = 0
        self.total = len(ip_list)
        
        # Initialize all IPs as not started
        for ip in ip_list:
            self.results[ip] = None
            self.ip_status[ip] = 'Pending...'
            self.ip_progress[ip] = 0.0
        
        # Detailed scan tracking
        self.detailed_completed = 0
        self.detailed_in_progress = 0
        self.detailed_total = 0
        self.detailed_queue = Queue()  # Separate queue for detailed scans
        self.detailed_workers_started = False
        
        # Display throttling
        self.last_display_time = 0
        self.display_interval = 0.2  # Update display max every 0.2 seconds
        self.display_lines = 0  # Track number of lines in last display
        
        # Queue for IPs to scan
        self.queue = Queue()
        for ip in ip_list:
            self.queue.put(ip)
            
        # Background thread for real-time HTML updates
        self.html_thread = threading.Thread(target=self.html_report_loop, daemon=True)
        self.html_thread.start()
        
    def html_report_loop(self):
        """Periodically generate HTML report in real-time"""
        while True:
            time.sleep(2.0)
            try:
                # Use lock to safely access shared dictionaries
                with self.lock:
                    self.generate_html_report()
            except Exception:
                pass
    
    def clear_screen_area(self):
        """Clear the display area and move cursor to top"""
        # Move cursor to top-left and clear screen
        sys.stdout.write('\033[H\033[2J')
        sys.stdout.flush()
    
    def display_results(self, force=False):
        """Display current results in dynamic format"""
        # Throttle display updates to prevent flickering
        current_time = time.time()
        if not force and (current_time - self.last_display_time) < self.display_interval:
            return
        
        self.last_display_time = current_time
        
        with self.lock:
            # Move cursor to beginning and clear previous output
            if self.display_lines > 0:
                # Move cursor up to beginning of previous display
                sys.stdout.write(f'\033[{self.display_lines}A')
                sys.stdout.flush()
            
            lines = []
            
            # Calculate overall percentage
            overall_percentage = (self.completed / self.total * 100) if self.total > 0 else 0
            
            # Phase 1 Header
            lines.append("=" * 80)
            lines.append(f"PHASE 1 - PORT DISCOVERY")
            lines.append(f"PROGRESS: {self.completed} completed | {self.in_progress} in progress | {self.total} total ({overall_percentage:.0f}%)")
            lines.append("=" * 80)
            
            # Show all IPs with their individual progress
            for ip in sorted(self.ip_list):
                progress = self.ip_progress[ip]
                status_msg = self.ip_status[ip]
                ports = self.results[ip]
                
                if ports is not None and len(ports) > 0:
                    # Complete with ports
                    ports_str = ','.join(map(str, sorted(ports)))
                    lines.append(f"({progress:04.1f}%) {ip:15s} | {ports_str}")
                elif ports is not None and len(ports) == 0:
                    # Complete but no ports
                    lines.append(f"({progress:04.1f}%) {ip:15s} | No open ports")
                else:
                    # Show actual nmap status instead of generic "Scanning..."
                    lines.append(f"({progress:04.1f}%) {ip:15s} | {status_msg}")
            
            lines.append("=" * 80)
            
            # Phase 2 section (if any detailed scans are running)
            if self.detailed_total > 0:
                detailed_percentage = (self.detailed_completed / self.detailed_total * 100) if self.detailed_total > 0 else 0
                lines.append("")
                lines.append("=" * 80)
                lines.append(f"PHASE 2 - DETAILED SCANNING (Services, Versions, Vulnerabilities)")
                lines.append(f"PROGRESS: {self.detailed_completed} completed | {self.detailed_in_progress} in progress | {self.detailed_total} total ({detailed_percentage:.0f}%)")
                lines.append("=" * 80)
                
                # Show detailed scan status
                for ip in sorted(self.ip_list):
                    if ip in self.detailed_results:
                        lines.append(f"  {ip:15s} - Detailed scan complete")
                    elif self.results.get(ip) and len(self.results[ip]) > 0:
                        # Has ports but not yet scanned
                        if ip in [item[0] for item in list(self.detailed_queue.queue)]:
                            lines.append(f"  {ip:15s} - Queued for detailed scan")
                
                lines.append("=" * 80)
            
            # Print all lines with line clearing
            for line in lines:
                # Clear line and print
                sys.stdout.write('\033[K' + line + '\n')
            
            self.display_lines = len(lines)
            sys.stdout.flush()
    
    def parse_nmap_output(self, output):
        """Parse nmap output to extract open ports"""
        ports = []
        for line in output.split('\n'):
            # Match lines like: "22/tcp   open  ssh"
            match = re.match(r'^(\d+)/tcp\s+open', line)
            if match:
                ports.append(int(match.group(1)))
        return ports
    
    def needs_pn_flag(self, output):
        """Check if nmap suggests using -Pn flag"""
        if self.no_pn:
            return False  # Don't retry with -Pn if disabled
        
        markers = [
            "host seems down",
            "Note: Host seems down",
            "try -Pn",
            "skipping host"
        ]
        output_lower = output.lower()
        return any(marker.lower() in output_lower for marker in markers)
    
    def scan_ip(self, ip):
        """Scan a single IP address with real-time progress tracking"""
        try:
            # First attempt - normal scan with verbose output
            cmd = ['nmap', '-v', '-T4', '-p-', ip]
            
            # Use Popen for real-time output parsing
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            output_lines = []
            ports_found = []
            
            # Read output line by line in real-time
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                output_lines.append(line)
                
                # Update status based on nmap's verbose output
                with self.lock:
                    # Parse discovered ports
                    if 'Discovered open port' in line:
                        match = re.search(r'(\d+)/tcp', line)
                        if match:
                            port = int(match.group(1))
                            if port not in ports_found:
                                ports_found.append(port)
                    
                    # Update status messages and progress from nmap output
                    if 'Initiating Ping Scan' in line:
                        self.ip_status[ip] = "Ping Scan"
                        self.ip_progress[ip] = 5.0
                    elif 'Initiating Connect Scan' in line or 'Initiating SYN Stealth Scan' in line:
                        self.ip_status[ip] = "Port Scan"
                        self.ip_progress[ip] = 20.0
                    elif 'Discovered open port' in line:
                        self.ip_progress[ip] = min(self.ip_progress[ip] + 5.0, 80.0)
                        ports_str = ','.join(map(str, sorted(ports_found)))
                        self.ip_status[ip] = f"Found {len(ports_found)} port(s) | {ports_str}"
                    elif 'Completed Connect Scan' in line or 'Completed SYN Stealth Scan' in line:
                        self.ip_progress[ip] = 90.0
                        if ports_found:
                            ports_str = ','.join(map(str, sorted(ports_found)))
                            self.ip_status[ip] = f"Finalizing... | {ports_str}"
                        else:
                            self.ip_status[ip] = "Finalizing..."
                    elif 'Nmap done' in line:
                        self.ip_progress[ip] = 95.0
                        self.ip_status[ip] = "Complete"
                
                self.display_results()
            
            process.wait(timeout=600)
            output = ''.join(output_lines)
            
            # Check if we need to retry with -Pn
            if self.needs_pn_flag(output) and not self.no_pn:
                with self.lock:
                    self.ip_status[ip] = "Retrying with -Pn..."
                    self.ip_progress[ip] = 0.0
                self.display_results()
                
                # Retry with -Pn flag
                cmd = ['nmap', '-v', '-T4', '-Pn', '-p-', ip]
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                output_lines = []
                ports_found = []
                
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    output_lines.append(line)
                    
                    with self.lock:
                        if 'Discovered open port' in line:
                            match = re.search(r'(\d+)/tcp', line)
                            if match:
                                port = int(match.group(1))
                                if port not in ports_found:
                                    ports_found.append(port)
                        
                        if 'Initiating Ping Scan' in line:
                            self.ip_status[ip] = "Ping Scan (-Pn)"
                            self.ip_progress[ip] = 5.0
                        elif 'Initiating Connect Scan' in line or 'Initiating SYN Stealth Scan' in line:
                            self.ip_status[ip] = "Port Scan (-Pn)"
                            self.ip_progress[ip] = 20.0
                        elif 'Discovered open port' in line:
                            self.ip_progress[ip] = min(self.ip_progress[ip] + 5.0, 80.0)
                            ports_str = ','.join(map(str, sorted(ports_found)))
                            self.ip_status[ip] = f"Found {len(ports_found)} port(s) | {ports_str}"
                        elif 'Completed Connect Scan' in line or 'Completed SYN Stealth Scan' in line:
                            self.ip_progress[ip] = 90.0
                            if ports_found:
                                ports_str = ','.join(map(str, sorted(ports_found)))
                                self.ip_status[ip] = f"Finalizing... | {ports_str}"
                            else:
                                self.ip_status[ip] = "Finalizing..."
                        elif 'Nmap done' in line:
                            self.ip_progress[ip] = 95.0
                            self.ip_status[ip] = "Complete"
                    
                    self.display_results()
                
                process.wait(timeout=600)
                output = ''.join(output_lines)
            
            # Parse final results
            ports = self.parse_nmap_output(output)
            
            # Save Phase 1 output
            phase1_file = os.path.join(self.output_dir, f"{self.output_prefix}_{ip}_phase1.txt")
            with self.lock:
                with open(phase1_file, 'w', encoding='utf-8') as f:
                    f.write(output)
            
            return ports
            
        except subprocess.TimeoutExpired:
            return []  # Timeout - no ports found
        except Exception as e:
            with self.lock:
                self.ip_status[ip] = f"Error: {str(e)[:30]}"
            return []
    
    def worker(self):
        """Worker thread function"""
        while True:
            try:
                ip = self.queue.get(timeout=1)
            except:
                break
            
            # Update in_progress count
            with self.lock:
                self.in_progress += 1
                self.ip_status[ip] = 'Starting scan...'
                self.ip_progress[ip] = 0.0
            
            self.display_results(force=True)
            
            # Perform scan (status updates happen inside scan_ip)
            ports = self.scan_ip(ip)
            
            # Update results
            with self.lock:
                self.results[ip] = ports
                self.ip_status[ip] = 'Complete'
                self.ip_progress[ip] = 100.0
                self.in_progress -= 1
                self.completed += 1
                
                # If this IP has open ports, queue it for detailed scan immediately
                if ports and len(ports) > 0:
                    self.detailed_queue.put((ip, ports))
                    self.detailed_total += 1
                    # Start detailed workers if not already started
                    if not self.detailed_workers_started:
                        self.detailed_workers_started = True
                        self.start_detailed_workers()
            
            self.display_results()
            self.queue.task_done()
    
    def save_port_specific_results(self, port, script_name, ip, output):
        """Thread-safe append of port-specific script results to a common file"""
        clean_script = script_name.replace('*', '_all').replace(' ', '_')
        filename = os.path.join(self.output_dir, f"{self.output_prefix}_port_{port}_{clean_script}.txt")
        with self.lock:
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(f"\n{'=' * 60}\n")
                f.write(f"RESULTS FOR IP: {ip} | PORT: {port} | SCRIPT: {script_name}\n")
                f.write(f"{'=' * 60}\n")
                f.write(output)
                f.write("\n")

    def detailed_scan(self, ip, ports):
        """Perform detailed scan with service detection and vulnerability scanning per port"""
        combined_output = ""
        
        for port in sorted(ports):
            port_str = str(port)
            try:
                # 1. Run vuln script for this specific port
                cmd_vuln = [
                    'nmap', '-Pn', '-n', '-v', '-sV', '-sC', '-sT',
                    '--script', 'vuln',
                    '-p', port_str,
                    '-oN', '-',  # Normal output to stdout
                    ip
                ]
                
                result_vuln = subprocess.run(
                    cmd_vuln, capture_output=True, text=True, timeout=1800
                )
                
                out_vuln = f"\n--- VULN SCAN (Port {port}) ---\n" + result_vuln.stdout
                if result_vuln.stderr:
                    out_vuln += "\n=== STDERR ===\n" + result_vuln.stderr
                combined_output += out_vuln + "\n"
                
                # Save just the vuln result for this port to a file
                self.save_port_specific_results(port, "vuln", ip, out_vuln)
                
                # 2. Run protocol-specific scripts if applicable
                if port == 22:
                    cmd_ssh = [
                        'nmap', '-Pn', '-n', '-v', '-sV', '-sC', '-sT',
                        '--script', 'ssh*',
                        '-p', port_str,
                        '-oN', '-',
                        ip
                    ]
                    result_ssh = subprocess.run(
                        cmd_ssh, capture_output=True, text=True, timeout=1800
                    )
                    out_ssh = f"\n--- SSH SCAN (Port 22) ---\n" + result_ssh.stdout
                    if result_ssh.stderr:
                        out_ssh += "\n=== STDERR ===\n" + result_ssh.stderr
                    combined_output += out_ssh + "\n"
                    
                    self.save_port_specific_results(port, "ssh*", ip, out_ssh)
                    
                elif port == 443:
                    cmd_ssl = [
                        'nmap', '-Pn', '-n', '-v', '-sV', '-sC', '-sT',
                        '--script', 'ssl*',
                        '-p', port_str,
                        '-oN', '-',
                        ip
                    ]
                    result_ssl = subprocess.run(
                        cmd_ssl, capture_output=True, text=True, timeout=1800
                    )
                    out_ssl = f"\n--- SSL SCAN (Port 443) ---\n" + result_ssl.stdout
                    if result_ssl.stderr:
                        out_ssl += "\n=== STDERR ===\n" + result_ssl.stderr
                    combined_output += out_ssl + "\n"
                    
                    self.save_port_specific_results(port, "ssl*", ip, out_ssl)
                    
            except subprocess.TimeoutExpired:
                timeout_msg = f"\nDetailed scan timed out for {ip} on port {port}\n"
                combined_output += timeout_msg
                self.save_port_specific_results(port, "timeout", ip, timeout_msg)
            except Exception as e:
                err_msg = f"\nError during detailed scan of {ip} on port {port}: {e}\n"
                combined_output += err_msg
                self.save_port_specific_results(port, "error", ip, err_msg)
                
        return combined_output
    
    def detailed_scan_worker(self):
        """Worker for detailed scanning phase"""
        while True:
            try:
                item = self.detailed_queue.get(timeout=1)
            except:
                break
            
            ip, ports = item
            
            # Update in_progress count
            with self.lock:
                self.detailed_in_progress += 1
            
            self.display_results()
            
            # Perform detailed scan
            detailed_output = self.detailed_scan(ip, ports)
            
            # Print detailed results to terminal
            print("\n" + "=" * 80)
            print(f"DETAILED SCAN RESULTS FOR {ip}")
            print("=" * 80)
            print(detailed_output)
            print("=" * 80 + "\n")
            
            # Update results
            with self.lock:
                self.detailed_results[ip] = detailed_output
                self.detailed_in_progress -= 1
                self.detailed_completed += 1
            
            self.display_results()
            self.detailed_queue.task_done()
    
    def save_text_report(self):
        """Save IP and ports to text file"""
        filename = os.path.join(self.output_dir, f"{self.output_prefix}_ports.txt")
        with open(filename, 'w') as f:
            f.write(f"Nmap Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for ip in sorted(self.results.keys()):
                ports = self.results[ip]
                if ports:
                    ports_str = ','.join(map(str, sorted(ports)))
                    f.write(f"{ip} : {ports_str}\n")
                else:
                    f.write(f"{ip} : No open ports found\n")
        
        return filename
    
    def start_detailed_workers(self):
        """Start detailed scan worker threads"""
        num_threads = min(self.threads, 3)  # Limit detailed scans to 3 concurrent
        
        for _ in range(num_threads):
            t = threading.Thread(target=self.detailed_scan_worker, daemon=True)
            t.start()
    
    def generate_html_report(self):
        """Generate HTML report with collapsible sections"""
        filename = os.path.join(self.output_dir, f"{self.output_prefix}_report.html")
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .results {{
            padding: 30px;
        }}
        
        .ip-section {{
            margin-bottom: 20px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
            transition: box-shadow 0.3s ease;
        }}
        
        .ip-section:hover {{
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .ip-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }}
        
        .ip-header:hover {{
            opacity: 0.95;
        }}
        
        .ip-title {{
            font-size: 1.3em;
            font-weight: 600;
        }}
        
        .ports-badge {{
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .toggle-icon {{
            font-size: 1.2em;
            transition: transform 0.3s ease;
        }}
        
        .toggle-icon.open {{
            transform: rotate(180deg);
        }}
        
        .ip-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
            background: #f8f9fa;
        }}
        
        .ip-content.open {{
            max-height: 5000px;
        }}
        
        .ports-summary {{
            padding: 20px;
            background: white;
            margin: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .ports-summary h3 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .port-list {{
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
            color: #495057;
        }}
        
        .raw-output {{
            margin: 15px;
        }}
        
        .raw-toggle {{
            background: #6c757d;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            transition: background 0.3s ease;
        }}
        
        .raw-toggle:hover {{
            background: #5a6268;
        }}
        
        .raw-content {{
            display: none;
            margin-top: 15px;
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
        }}
        
        .raw-content.show {{
            display: block;
        }}
        
        .raw-content pre {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .no-ports {{
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Nmap Scan Report</h1>
            <p>{datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-number">{len(self.results)}</div>
                <div class="stat-label">Total IPs Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{sum(1 for ports in self.results.values() if ports)}</div>
                <div class="stat-label">IPs with Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{sum(len(ports) for ports in self.results.values() if ports)}</div>
                <div class="stat-label">Total Open Ports</div>
            </div>
        </div>
        
        <div class="results">
'''
        
        # Add each IP section
        for ip in sorted(self.results.keys()):
            ports = self.results[ip]
            status = self.ip_status.get(ip, 'Unknown')
            
            if ports is None:
                # Scanning not complete
                badge_text = "Running"
                if "Found" in status:
                    badge_text = "Port Discovery Running"
                elif "Pending" in status:
                    badge_text = "Not Started"
                    
                html_content += f'''
            <div class="ip-section">
                <div class="ip-header" onclick="toggleSection('{ip}')">
                    <div class="ip-title">{html.escape(ip)}</div>
                    <div>
                        <span class="ports-badge">{html.escape(badge_text)}</span>
                        <span class="toggle-icon" id="icon-{ip}">▼</span>
                    </div>
                </div>
                <div class="ip-content" id="content-{ip}">
                    <div class="raw-output">
                        <button class="raw-toggle" onclick="toggleRaw('{ip}')">Show/Hide Raw Nmap Output</button>
                        <div class="raw-content" id="raw-{ip}">
                            <pre>Status: {html.escape(status)}</pre>
                        </div>
                    </div>
                </div>
            </div>
'''
            elif len(ports) > 0:
                ports_str = ','.join(map(str, sorted(ports)))
                
                if ip in self.detailed_results:
                    detailed = self.detailed_results[ip]
                else:
                    detailed = "Detailed scan is running / pending..."
                
                html_content += f'''
            <div class="ip-section">
                <div class="ip-header" onclick="toggleSection('{ip}')">
                    <div class="ip-title">{html.escape(ip)}</div>
                    <div>
                        <span class="ports-badge">{len(ports)} port(s)</span>
                        <span class="toggle-icon" id="icon-{ip}">▼</span>
                    </div>
                </div>
                <div class="ip-content" id="content-{ip}">
                    <div class="ports-summary">
                        <h3>Open Ports</h3>
                        <div class="port-list">{html.escape(ports_str)}</div>
                    </div>
                    <div class="raw-output">
                        <button class="raw-toggle" onclick="toggleRaw('{ip}')">Show/Hide Raw Nmap Output</button>
                        <div class="raw-content" id="raw-{ip}">
                            <pre>{html.escape(detailed)}</pre>
                        </div>
                    </div>
                </div>
            </div>
'''
            else:
                html_content += f'''
            <div class="ip-section">
                <div class="ip-header">
                    <div class="ip-title">{html.escape(ip)}</div>
                    <span class="ports-badge">No open ports</span>
                </div>
            </div>
'''
        
        html_content += '''        </div>
    </div>
    
    <script>
        function toggleSection(ip) {
            const content = document.getElementById('content-' + ip);
            const icon = document.getElementById('icon-' + ip);
            
            content.classList.toggle('open');
            icon.classList.toggle('open');
        }
        
        function toggleRaw(ip) {
            const raw = document.getElementById('raw-' + ip);
            raw.classList.toggle('show');
        }
    </script>
</body>
</html>
'''
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
    
    def run(self):
        """Run the scanner with multiple threads"""
        # Clear screen and prepare display
        self.clear_screen_area()
        
        # Initial display
        self.display_results()
        
        # Create and start worker threads for phase 1
        threads = []
        num_threads = min(self.threads, self.total)
        
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for all phase 1 scans to complete
        self.queue.join()
        
        # Wait for all phase 1 threads to finish
        for t in threads:
            t.join()
        
        # Final display for phase 1
        self.display_results()
        
        # Save text report
        text_file = self.save_text_report()
        print(f"\n\n✓ Port scan results saved to: {text_file}\n")
        
        # Wait for all detailed scans to complete (if any were started)
        if self.detailed_total > 0:
            print(f"\nWaiting for {self.detailed_total} detailed scan(s) to complete...\n")
            self.detailed_queue.join()
        
        # Final display
        self.display_results()
        
        # Generate final HTML report
        with self.lock:
            html_file = self.generate_html_report()
        print(f"\n✓ Final HTML report generated: {html_file}\n")
        
        return self.results


def read_ip_list(filename):
    """Read IPs and hostnames from file"""
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Accept both IP addresses and standard hostnames
                ips.append(line)
    
    return ips


def main():
    parser = argparse.ArgumentParser(
        description='Multithreaded Nmap Scanner with Dynamic Display',
        epilog='Example: %(prog)s -f ips.txt -t 10'
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Text file containing list of IP addresses or hostnames (one per line)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        default='5',
        help='Number of threads (default: 5, use "all" for concurrent scanning of all IPs)'
    )
    
    parser.add_argument(
        '--no-pn',
        action='store_true',
        help='Disable automatic retry with -Pn flag when host appears down'
    )
    
    args = parser.parse_args()
    
    # Read IP list
    ip_list = read_ip_list(args.file)
    
    if not ip_list:
        print(f"Error: No valid IP addresses found in '{args.file}'", file=sys.stderr)
        sys.exit(1)
    
    # Parse thread count
    if args.threads.lower() == 'all':
        threads = 'all'
    else:
        try:
            threads = int(args.threads)
            if threads < 1:
                print("Error: Thread count must be at least 1", file=sys.stderr)
                sys.exit(1)
        except ValueError:
            print(f"Error: Invalid thread count '{args.threads}'", file=sys.stderr)
            sys.exit(1)
    
    print(f"Starting scan of {len(ip_list)} target(s) with {threads if threads == 'all' else str(threads)} thread(s)...")
    print("Using nmap with -T4 timing and full port range (-p-)")
    if not args.no_pn:
        print("Auto-retry with -Pn if host appears down")
    else:
        print("-Pn auto-retry DISABLED")
    print()
    time.sleep(2)
    
    # Run scanner
    scanner = NmapScanner(ip_list, threads, no_pn=args.no_pn)
    results = scanner.run()
    
    print("\n\nScan Complete!")
    print(f"\nTotal IPs scanned: {len(results)}")
    print(f"IPs with open ports: {sum(1 for ports in results.values() if ports)}")


if __name__ == '__main__':
    main()

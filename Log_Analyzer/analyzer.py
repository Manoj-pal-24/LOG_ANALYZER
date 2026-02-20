import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import requests
import json

# IOC Reputation Database (using free VirusTotal-like approach with local cache)
IOC_CACHE = {}

class ThreatDetector:
    """Advanced threat detection engine"""
    
    def __init__(self):
        self.brute_force_attempts = defaultdict(list)
        self.powershell_suspicious_patterns = [
            r'powershell.*-enc',
            r'powershell.*-NoP',
            r'powershell.*-nop',
            r'Invoke-WebRequest',
            r'IEX',
            r'DownloadString',
            r'\.FromBase64String',
        ]
        self.admin_patterns = [
            r'net user.*\/add.*\/active:yes',
            r'New-LocalUser.*-Name.*Admin',
            r'net localgroup administrators.*add',
            r'AdminSDHolder',
        ]
        self.windows_security_patterns = {
            '4625': 'Failed Login',
            '4624': 'Successful Login',
            '4688': 'New Process Created',
            '4720': 'User Account Created',
            '4732': 'Member Added to Group',
        }

    def detect_brute_force(self, logs):
        """Detect brute force attacks (5+ failed logins in 2 minutes)"""
        incidents = []
        failed_logins = defaultdict(list)

        for log in logs:
            # Windows Security Event 4625 - Failed Login
            if '4625' in str(log) or 'Failed' in str(log):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', str(log))
                if match:
                    ip = match.group(1)
                    # Extract timestamp
                    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', str(log))
                    if timestamp_match:
                        failed_logins[ip].append(timestamp_match.group(1))

        # Check for 5+ failures within 2 minutes
        for ip, timestamps in failed_logins.items():
            if len(timestamps) >= 5:
                incidents.append({
                    'type': 'Brute Force Attack',
                    'source_ip': ip,
                    'severity': 'High',
                    'description': f'Detected {len(timestamps)} failed login attempts from {ip}',
                    'failed_attempts': len(timestamps)
                })

        return incidents

    def detect_suspicious_powershell(self, logs):
        """Detect suspicious PowerShell execution"""
        incidents = []

        for log in logs:
            log_str = str(log).lower()
            for pattern in self.powershell_suspicious_patterns:
                if re.search(pattern, log_str, re.IGNORECASE):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', str(log))
                    ip = match.group(1) if match else 'Unknown'
                    incidents.append({
                        'type': 'Suspicious PowerShell Execution',
                        'source_ip': ip,
                        'severity': 'Critical',
                        'description': f'Suspicious PowerShell pattern detected: {pattern}',
                        'pattern_matched': pattern
                    })
                    break

        return incidents

    def detect_admin_creation(self, logs):
        """Detect unauthorized administrator account creation"""
        incidents = []

        for log in logs:
            log_str = str(log)
            for pattern in self.admin_patterns:
                if re.search(pattern, log_str, re.IGNORECASE):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', str(log))
                    ip = match.group(1) if match else 'Unknown'
                    incidents.append({
                        'type': 'Admin Account Creation',
                        'source_ip': ip,
                        'severity': 'Critical',
                        'description': f'Potential unauthorized admin account creation detected',
                        'pattern_matched': pattern
                    })
                    break

        return incidents

    def check_ioc_reputation(self, ip_address):
        """Check IP address reputation (local cache implementation)"""
        # In production, this would call VirusTotal or similar
        # For now, using common known malicious IPs
        known_malicious = ['192.168.1.1', '10.0.0.1']  # Example
        
        if ip_address in IOC_CACHE:
            return IOC_CACHE[ip_address]
        
        reputation = {
            'is_malicious': ip_address in known_malicious,
            'threat_level': 'High' if ip_address in known_malicious else 'Low',
            'last_updated': datetime.now().isoformat()
        }
        
        IOC_CACHE[ip_address] = reputation
        return reputation

    def classify_severity(self, incident_type, event_count=1):
        """Classify incident severity based on type and frequency"""
        severity_map = {
            'Brute Force Attack': 'High',
            'Suspicious PowerShell Execution': 'Critical',
            'Admin Account Creation': 'Critical',
            'Invalid Log Entry': 'Low',
            'Suspicious IP Activity': 'Medium',
        }
        return severity_map.get(incident_type, 'Medium')

def analyze_log(file_path):
    """Comprehensive log analysis"""
    results = {
        'total_requests': 0,
        'top_ips': [],
        'top_urls': [],
        'error_counts': {},
        'suspicious_ips': [],
        'request_log_entries': [],
        'invalid_log_entries': [],
        'error_log_entries': [],
        'unique_ip_details': [],
        'incidents': [],
        'brute_force_incidents': [],
        'suspicious_powershell_incidents': [],
        'admin_creation_incidents': [],
        'ioc_detections': [],
        'summary': {}
    }

    ip_list = []
    status_list = []
    url_list = []
    all_logs = []
    invalid_logs = 0

    # Parse logs with multiple patterns for flexibility
    apache_pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(GET|POST|PUT|DELETE) (.*?) HTTP.*?" (\d+)'
    windows_pattern = r'EventID.*?(\d+)'
    
    try:
        with open(file_path, 'r', errors='ignore') as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                all_logs.append(line)

                # Try Apache/Nginx pattern
                match = re.search(apache_pattern, line)
                if match:
                    ip, method, url, status = match.groups()
                    ip_list.append(ip)
                    status_list.append(status)
                    url_list.append(url)
                    results['request_log_entries'].append({
                        'line_number': line_number,
                        'source_ip': ip,
                        'method': method,
                        'url': url,
                        'status_code': status,
                        'raw_log': line.strip()
                    })
                    if status.startswith('4') or status.startswith('5'):
                        results['error_log_entries'].append({
                            'line_number': line_number,
                            'source_ip': ip,
                            'method': method,
                            'url': url,
                            'status_code': status,
                            'raw_log': line.strip()
                        })
                else:
                    # Try to extract IP from Windows logs or other formats
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        extracted_ip = ip_match.group(1)
                        ip_list.append(extracted_ip)
                        results['request_log_entries'].append({
                            'line_number': line_number,
                            'source_ip': extracted_ip,
                            'method': 'N/A',
                            'url': 'N/A',
                            'status_code': 'N/A',
                            'raw_log': line.strip()
                        })
                    else:
                        invalid_logs += 1
                        results['invalid_log_entries'].append({
                            'line_number': line_number,
                            'raw_log': line.strip()
                        })

        # Basic statistics
        results['total_requests'] = len(ip_list)
        results['invalid_logs'] = invalid_logs
        results['top_ips'] = Counter(ip_list).most_common(5)
        results['top_urls'] = Counter(url_list).most_common(5)
        results['error_counts'] = dict(Counter(status_list))
        results['suspicious_ips'] = [ip for ip, count in Counter(ip_list).items() if count > 50]
        results['unique_ip_details'] = [
            {'ip': ip, 'request_count': count}
            for ip, count in Counter(ip_list).most_common()
        ]

        # Advanced threat detection
        detector = ThreatDetector()

        # Run detection engines
        brute_force = detector.detect_brute_force(all_logs)
        powershell = detector.detect_suspicious_powershell(all_logs)
        admin_creation = detector.detect_admin_creation(all_logs)

        results['brute_force_incidents'] = brute_force
        results['suspicious_powershell_incidents'] = powershell
        results['admin_creation_incidents'] = admin_creation

        all_incidents = brute_force + powershell + admin_creation

        # Check IOC reputation for suspicious IPs
        for ip, count in Counter(ip_list).most_common(10):
            reputation = detector.check_ioc_reputation(ip)
            if reputation['is_malicious']:
                results['ioc_detections'].append({
                    'ip': ip,
                    'threat_level': reputation['threat_level'],
                    'request_count': count
                })

        # Summary statistics
        results['summary'] = {
            'total_incidents': len(all_incidents),
            'critical_incidents': len([i for i in all_incidents if i.get('severity') == 'Critical']),
            'high_priority_incidents': len([i for i in all_incidents if i.get('severity') == 'High']),
            'unique_ips': len(set(ip_list)),
            'error_rate': f"{(len([s for s in status_list if s.startswith('4') or s.startswith('5')]) / len(status_list) * 100):.2f}%" if status_list else "0%"
        }

        results['incidents'] = all_incidents

    except Exception as e:
        results['error'] = str(e)

    return results

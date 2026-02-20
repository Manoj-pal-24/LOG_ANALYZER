import json
import csv
from datetime import datetime
from io import StringIO, BytesIO

def export_to_json(analysis_results, incidents=None):
    """Export analysis results to JSON format"""
    export_data = {
        'export_timestamp': datetime.now().isoformat(),
        'summary': analysis_results.get('summary', {}),
        'statistics': {
            'total_requests': analysis_results.get('total_requests', 0),
            'invalid_logs': analysis_results.get('invalid_logs', 0),
            'top_ips': analysis_results.get('top_ips', []),
            'top_urls': analysis_results.get('top_urls', []),
            'error_counts': analysis_results.get('error_counts', {}),
        },
        'threats_detected': {
            'brute_force': analysis_results.get('brute_force_incidents', []),
            'suspicious_powershell': analysis_results.get('suspicious_powershell_incidents', []),
            'admin_creation': analysis_results.get('admin_creation_incidents', []),
            'ioc_detections': analysis_results.get('ioc_detections', []),
        },
        'incidents': incidents if incidents else analysis_results.get('incidents', [])
    }
    return json.dumps(export_data, indent=2, default=str)

def export_to_csv(analysis_results):
    """Export analysis results to CSV format"""
    output = StringIO()
    
    # Summary section
    summary_writer = csv.writer(output)
    summary_writer.writerow(['Log Analysis Report'])
    summary_writer.writerow(['Generated', datetime.now().isoformat()])
    summary_writer.writerow([])
    
    # Summary statistics
    summary_writer.writerow(['Summary Statistics'])
    summary = analysis_results.get('summary', {})
    for key, value in summary.items():
        summary_writer.writerow([key, value])
    
    summary_writer.writerow([])
    summary_writer.writerow(['Top IPs'])
    summary_writer.writerow(['IP Address', 'Request Count'])
    for ip, count in analysis_results.get('top_ips', []):
        summary_writer.writerow([ip, count])
    
    summary_writer.writerow([])
    summary_writer.writerow(['Top URLs'])
    summary_writer.writerow(['URL', 'Request Count'])
    for url, count in analysis_results.get('top_urls', []):
        summary_writer.writerow([url, count])
    
    summary_writer.writerow([])
    summary_writer.writerow(['Error Status Codes'])
    summary_writer.writerow(['Status Code', 'Count'])
    for status, count in analysis_results.get('error_counts', {}).items():
        summary_writer.writerow([status, count])
    
    summary_writer.writerow([])
    summary_writer.writerow(['Detected Incidents'])
    summary_writer.writerow(['Type', 'Source IP', 'Severity', 'Description'])
    
    for incident in analysis_results.get('incidents', []):
        summary_writer.writerow([
            incident.get('type', ''),
            incident.get('source_ip', ''),
            incident.get('severity', ''),
            incident.get('description', '')
        ])
    
    return output.getvalue()

def classify_severity_level(event_type, characteristics=None):
    """Classify severity based on event type and characteristics"""
    severity_rules = {
        'Brute Force Attack': 'High',
        'Suspicious PowerShell Execution': 'Critical',
        'Admin Account Creation': 'Critical',
        'Unauthorized Access': 'High',
        'Data Exfiltration': 'Critical',
        'Privilege Escalation': 'High',
        'Suspicious Process': 'Medium',
        'Access Denied': 'Low',
    }
    
    return severity_rules.get(event_type, 'Medium')

def generate_alert_message(incident_type, details):
    """Generate alert message for incidents"""
    messages = {
        'Brute Force Attack': f"ALERT: Brute force attack detected from {details.get('source_ip', 'Unknown')}. {details.get('failed_attempts', 0)} failed attempts detected.",
        'Suspicious PowerShell Execution': f"ALERT: Suspicious PowerShell execution detected. Pattern: {details.get('pattern_matched', 'Unknown')}",
        'Admin Account Creation': f"ALERT: Unauthorized admin account creation detected. Pattern matched: {details.get('pattern_matched', 'Unknown')}",
    }
    
    return messages.get(incident_type, f"ALERT: {incident_type} detected")

def parse_windows_event_log(log_line):
    """Parse Windows Event Log format"""
    import re
    event_pattern = {
        'event_id': r'EventID[=>\s]*(\d+)',
        'timestamp': r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
        'source': r'Source\s*=\s*(\w+)',
        'user': r'User[=>\s]*([^\s]+)',
    }
    
    parsed = {}
    for key, pattern in event_pattern.items():
        match = re.search(pattern, log_line)
        if match:
            parsed[key] = match.group(1)
    
    return parsed

def parse_apache_log(log_line):
    """Parse Apache/Nginx log format"""
    import re
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[([^\]]+)\].*?"(GET|POST|PUT|DELETE) ([^\s]+) HTTP/[\d.]+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    
    match = re.search(pattern, log_line)
    if match:
        return {
            'ip': match.group(1),
            'timestamp': match.group(2),
            'method': match.group(3),
            'url': match.group(4),
            'status_code': match.group(5),
            'bytes': match.group(6),
            'referrer': match.group(7),
            'user_agent': match.group(8),
        }
    return None

def calculate_risk_score(incidents):
    """Calculate overall risk score based on incidents"""
    risk_score = 0
    severity_weights = {
        'Critical': 30,
        'High': 15,
        'Medium': 8,
        'Low': 2,
    }
    
    for incident in incidents:
        severity = incident.get('severity', 'Medium')
        risk_score += severity_weights.get(severity, 5)
    
    # Normalize to 0-100 scale
    risk_score = min(risk_score, 100)
    
    return risk_score

def format_report_summary(analysis_results):
    """Format comprehensive report summary"""
    summary = analysis_results.get('summary', {})
    
    report = f"""
    ========================================
    LOG ANALYSIS REPORT
    ========================================
    
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    SUMMARY STATISTICS:
    - Total Requests Analyzed: {summary.get('total_incidents', 0)}
    - Critical Incidents: {summary.get('critical_incidents', 0)}
    - High Priority Incidents: {summary.get('high_priority_incidents', 0)}
    - Unique Source IPs: {summary.get('unique_ips', 0)}
    - Error Rate: {summary.get('error_rate', '0%')}
    
    THREATS DETECTED:
    - Brute Force Attacks: {len(analysis_results.get('brute_force_incidents', []))}
    - Suspicious PowerShell: {len(analysis_results.get('suspicious_powershell_incidents', []))}
    - Admin Creation Attempts: {len(analysis_results.get('admin_creation_incidents', []))}
    - IOC Detections: {len(analysis_results.get('ioc_detections', []))}
    
    RISK SCORE: {calculate_risk_score(analysis_results.get('incidents', []))}/100
    
    ========================================
    """
    
    return report

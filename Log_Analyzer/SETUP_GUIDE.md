# AutoSOC SIEM - Setup and Usage Guide

## 🎯 Overview

AutoSOC SIEM is a mini Security Operations Center platform that provides real-time threat detection, analysis, and response capabilities. It's designed for organizations and educational purposes to detect and analyze security threats in log files.

## 📋 Pre-Setup Checklist

Before starting, ensure you have:
- [ ] Python 3.8+ installed
- [ ] pip package manager available
- [ ] Virtual environment created (recommended)
- [ ] All dependencies installed from requirements.txt
- [ ] 200+ MB free disk space for database and logs

## 🚀 Quick Start (5 minutes)

### Step 1: Activate Virtual Environment
```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# If you see permission denied, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
python app.py
```

Expected output:
```
 * Running on http://127.0.0.1:5000
 * Press CTRL+C to quit
```

### Step 4: Access the Application
Open your browser and navigate to:
```
http://localhost:5000
```

## 📝 First Time Setup

### Step 1: Register Account
1. On the login page, click "Register here"
2. Create a new account:
   - Username: `analyst`
   - Password: `SecurePassword123`
   - Confirm Password: `SecurePassword123`
3. Click "Register"
4. You'll be redirected to the login page

### Step 2: Login
1. Enter your username and password
2. Click "Login"
3. You'll be taken to the dashboard

### Step 3: Upload Your First Log File
1. Click on "Analyze" in the navigation menu
2. Click on the file upload area
3. Select `uploads/sample_logs.txt` or your own log file
4. Click "Analyze Log File"
5. Wait for the analysis to complete (usually 2-3 seconds)

## 🔍 Understanding the Dashboard

### Dashboard Widgets

**Total Incidents**: Shows the total number of detected security incidents
- Click to view all incidents

**Critical Incidents**: Shows threats requiring immediate action
- Review these first for incident response

**High Priority**: Threats requiring investigation
- Plan response actions

**Open Incidents**: Currently unresolved incidents
- Track progress on investigation

**Unread Alerts**: New alerts awaiting review
- Real-time notification center

**Risk Score**: Overall system risk (0-100)
- Green (0-30): Low risk
- Yellow (30-70): Medium risk
- Red (70-100): High risk

### Recent Incidents Table
- Shows the 10 most recent incidents
- Click "View Details" to investigate further
- Shows incident type, source IP, severity, and status

## 🔐 User Account Management

### Creating Multiple Users
For organizational use, create multiple analyst accounts:

```powershell
# Access the registration page
http://localhost:5000/register
```

### User Roles
- **Analyst**: Can analyze logs and view incidents (default)
- **Admin**: Full system access (configurable in database)

## 📤 Uploading Log Files

### Supported Formats

1. **Apache/Nginx Logs**
   ```
   192.168.1.100 - - [01/Feb/2024 10:15:30] "GET /api HTTP/1.1" 200 1234
   ```

2. **Windows Event Logs**
   ```
   EventID=4625: Failed login attempt
   EventID=4688: New process creation
   EventID=4720: User account created
   ```

3. **Linux Syslog**
   ```
   Feb  1 10:15:30 hostname process[pid]: Log message
   ```

4. **JSON/CSV Formats**
   - Custom structured log formats
   - Must contain IP addresses or event details

### File Upload Guidelines
- **Maximum File Size**: 16MB
- **Supported Extensions**: .txt, .log, .csv, .json
- **Processing Time**: <2 seconds for 10,000 entries
- **Character Encoding**: UTF-8 (with error handling for other encodings)

## 🚨 Threat Detection Explained

### Brute Force Attack Detection
**What it detects**: 5+ failed login attempts from same IP within 2 minutes
**Severity**: HIGH
**Sample Log Entry**:
```
EventID=4625: Failed login from 192.168.1.101 at 10:15:40
EventID=4625: Failed login from 192.168.1.101 at 10:15:45
EventID=4625: Failed login from 192.168.1.101 at 10:15:50
EventID=4625: Failed login from 192.168.1.101 at 10:15:55
EventID=4625: Failed login from 192.168.1.101 at 10:16:00
```

### Suspicious PowerShell Detection
**What it detects**: Encoded or obfuscated PowerShell commands
**Severity**: CRITICAL
**Suspicious Patterns**:
- `-enc` (encoded commands)
- `-nop` (no profile)
- `Invoke-WebRequest` (network downloads)
- `FromBase64String` (credential theft)
- `IEX` (code execution)

**Sample Log Entry**:
```
EventID=4688: powershell.exe -enc QwBvAHAAeQAtAEkAdGVt
```

### Admin Account Creation
**What it detects**: Unauthorized admin account creation
**Severity**: CRITICAL
**Suspicious Patterns**:
- `net user` with `/add` and admin flags
- `New-LocalUser` with admin rights
- `net localgroup administrators /add`

**Sample Log Entry**:
```
EventID=4720: New user account created: SuspiciousAdmin
```

### IOC (Indicator of Compromise) Checking
**What it detects**: Known malicious IP addresses
**Severity**: Based on threat intelligence
**Action**: Flags IPs making repeated connections

## 📊 Analyzing Results

### Understanding the Analysis Report

1. **Summary Statistics**
   - Total Requests: Number of log entries analyzed
   - Critical/High Incidents: Number of threats found
   - Unique IPs: Number of distinct source addresses
   - Error Rate: Percentage of HTTP 4xx/5xx errors

2. **Threat Detection Section**
   - Lists all detected threats with details
   - Shows severity level and action required

3. **Top Source IPs**
   - Shows IPs making most requests
   - Helps identify suspicious activity patterns

4. **Top Requested URLs**
   - Most accessed endpoints
   - Can identify targeted resources

5. **HTTP Status Codes**
   - Distribution of response codes
   - 200s: Successful responses
   - 4xx: Client errors (potential attacks)
   - 5xx: Server errors

## 📥 Exporting Reports

### Export Formats

**JSON Export**
- Complete structured data
- Suitable for programmatic processing
- Includes all incidents, statistics, and details
- Use case: Integration with SIEM platforms, automated alerting

**CSV Export**
- Tabular format for spreadsheet analysis
- Suitable for reporting and presentations
- Use case: Management reports, detailed investigation

### How to Export

1. Go to "Reports" section
2. Click "Export as JSON" or "Export as CSV"
3. File downloads automatically
4. Open in preferred application

## 🚨 Incident Management

### Viewing Incidents

1. Click "Incidents" in navigation menu
2. Browse list of all detected incidents
3. Filter by severity, status, or type (if available)
4. Click "View Details" for specific incident

### Investigating an Incident

1. Click "View Details" on an incident
2. Review the incident information:
   - Type of attack detected
   - Source IP address
   - Associated username
   - Severity level
   - Description of threat

3. Review associated logs and alerts
4. Determine response action
5. Close incident when resolved

### Closing an Incident

1. View incident details
2. Click "✓ Close Incident" button
3. Incident status changes to "CLOSED"
4. Archived for historical review

## 🔔 Alerts System

### Understanding Alerts

Alerts are generated automatically when threats are detected:
- **CRITICAL**: Immediate action required
- **HIGH**: Investigate within hours
- **MEDIUM**: Monitor and continue investigation
- **LOW**: Log and review later

### Reviewing Alerts

1. Click "Alerts" in navigation
2. View all unread alerts with newest first
3. Click on alert details to investigate
4. Alerts are marked as read when viewed in incident details

## 💡 Tips and Best Practices

### Security Monitoring Best Practices

1. **Regular Log Review**: Analyze logs at least daily
2. **Set Baselines**: Understand normal network activity
3. **Alert Prioritization**: Focus on CRITICAL incidents first
4. **Documentation**: Keep notes on investigated incidents
5. **Pattern Recognition**: Look for repeated patterns/IPs

### Performance Optimization

1. **Batch Processing**: Analyze logs in regular intervals
2. **Archive Old Logs**: Keep database size manageable
3. **Regular Backups**: Backup logs_analyzer.db periodically
4. **User Management**: Remove inactive accounts

### Troubleshooting Tips

- **Slow Performance**: Check database size with `dir logs_analyzer.db`
- **Login Issues**: Clear browser cookies and cache
- **File Upload Errors**: Verify file encoding is UTF-8
- **Missing Data**: Check that uploads folder has write permissions

## 🔧 Configuration & Customization

### Changing the Port

Edit `app.py` and change:
```python
if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Change 5001 to desired port
```

### Adjusting Detection Sensitivity

Edit `analyzer.py` to modify detection thresholds:
```python
# Current thresholds:
- Brute Force: 5 attempts in 2 minutes
- IOC Check: IPs with >50 requests
```

### Adding Custom Detection Rules

Add new patterns to `analyzer.py` in the `ThreatDetector` class:
```python
self.custom_patterns = [
    r'your_pattern_here',
]
```

## 📚 Sample Use Cases

### Use Case 1: Detecting Brute Force Attacks
**Scenario**: Your web server receives multiple failed login attempts
**Process**:
1. Export logs from web server
2. Upload to AutoSOC
3. System detects brute force pattern
4. Creates HIGH severity incident
5. Review attacker IP and block if needed

### Use Case 2: Detecting PowerShell Malware
**Scenario**: Suspicious PowerShell activity detected
**Process**:
1. Collect Windows security event logs
2. Upload Event Viewer logs to AutoSOC
3. System detects encoded PowerShell command
4. Creates CRITICAL incident
5. Investigate and contain affected system

### Use Case 3: Identifying Compromised Accounts
**Scenario**: Unusual access patterns from internal network
**Process**:
1. Extract logs from access control system
2. Upload to AutoSOC
3. System analyzes IP patterns and user behavior
4. Flags anomalies as MEDIUM/HIGH severity
5. Investigate and reset credentials if needed

## 🆘 Troubleshooting Guide

### Application Won't Start

**Problem**: "Address already in use"
**Solution**: 
- Change port in app.py to 5001 or higher
- Or: `netstat -ano | findstr :5000` (Windows) to find process using port

**Problem**: "ModuleNotFoundError: No module named 'flask'"
**Solution**: 
- Activate virtual environment: `.\.venv\Scripts\Activate.ps1`
- Install dependencies: `pip install -r requirements.txt`

### Database Issues

**Problem**: "Database is locked"
**Solution**:
- Close all open connections
- Restart the application
- Delete `logs_analyzer.db` to reset (WARNING: Loses all data)

**Problem**: "No such table"
**Solution**:
- Application will auto-create tables on first run
- If not working: Delete `logs_analyzer.db` and restart

### Login Problems

**Problem**: "Invalid credentials" but password is correct
**Solution**:
- Ensure you registered the account first
- Password is case-sensitive
- Check for extra spaces in username/password

### File Upload Issues

**Problem**: "Unsupported file type"
**Solution**:
- Only .txt, .log, .csv, .json are supported
- Save file with correct extension
- Ensure file exists and is readable

## 📞 Getting Help

### Common Questions

**Q: How do I backup my incidents?**
A: The database is stored in `logs_analyzer.db`. Copy this file for backup.

**Q: Can I use this in production?**
A: Currently designed for educational/small organization use. For production, enhance security features and deploy on secured server.

**Q: How many users can the system handle?**
A: Flask debug server handles ~10-20 concurrent users. For larger deployments, use production WSGI server like Gunicorn.

**Q: Can I sync with other tools?**
A: Yes! Export JSON reports and integrate with your existing tools via custom scripts.

## 🔐 Security Recommendations

1. **Change Secret Key**: In production, set a unique `app.secret_key`
2. **Use HTTPS**: Deploy with SSL/TLS certificates
3. **Strong Passwords**: Enforce strong password policies
4. **Regular Updates**: Keep dependencies updated
5. **Log Rotation**: Implement log rotation to manage storage
6. **Database Backup**: Regular backups of logs_analyzer.db

## 📚 Additional Resources

- Flask Documentation: https://flask.palletsprojects.com/
- Python Security: https://docs.python.org/3/library/security_warnings.html
- OWASP Security: https://owasp.org/

---

**Version**: 1.0.0  
**Last Updated**: February 2024  
**Support**: For issues or feature requests, contact development team

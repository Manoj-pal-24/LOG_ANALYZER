# 🛡️ AutoSOC SIEM - Mini Security Operations Center

A lightweight, Feature-rich Security Information and Event Management (SIEM) platform designed for organizations and educational purposes. This tool provides real-time threat detection, analysis, and reporting capabilities similar to Splunk but tailored for smaller deployments.

## 📋 Features

### Core Security Analysis Features
- ✅ **Brute Force Attack Detection** - Detects 5+ failed login attempts within 2 minutes
- ✅ **Suspicious PowerShell Execution Detection** - Monitors for suspicious PowerShell patterns and commands
- ✅ **Administrator Account Creation Monitoring** - Detects unauthorized admin account creation events
- ✅ **IOC (Indicator of Compromise) Checking** - Validates IP addresses against reputation databases
- ✅ **Severity Classification** - Automatically classifies incidents as Low, Medium, High, or Critical

### User Management & Authentication
- ✅ User registration and login system
- ✅ Role-based access control (Analyst, Admin)
- ✅ Secure password handling with hashing

### Dashboard & Monitoring
- ✅ Real-time security dashboard with incident overview
- ✅ Risk score calculation and visualization
- ✅ Incident tracking and management
- ✅ Alert generation and notification system
- ✅ Visual incident status monitoring (Open/Closed)
- ✅ Searchable analyzed-file history with direct download

### Log Analysis & Processing
- ✅ Multi-format log support (Apache, Nginx, Windows Event Logs, Linux Syslog, JSON, CSV)
- ✅ Advanced log parsing and pattern matching
- ✅ Error rate analysis and HTTP status code tracking
- ✅ Top source IP and URL identification
- ✅ Suspicious activity detection

### Reporting & Export
- ✅ Export analysis reports in **JSON** format
- ✅ Export analysis reports in **CSV** format
- ✅ Comprehensive incident reporting
- ✅ Detailed threat summaries

### Database Storage
- ✅ SQLite database for persistent storage
- ✅ User management database
- ✅ Incident and alert history
- ✅ Log correlation and storage

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Windows/Linux/macOS

### Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd c:\Users\Lenovo\Log_Analyzer
   ```

2. **Create a virtual environment (optional but recommended):**
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database (automatic on first run):**
   The database will be created automatically when you first run the application.

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Access the web interface:**
   Open your browser and navigate to: `http://localhost:5000`

## 📝 Usage Guide

### Quick Start Workflow
1. Open the app at `http://localhost:5000`
2. Register a new user account and sign in
3. Go to **Analyze** and upload a log file (`.txt`, `.log`, `.csv`, `.json`)
4. Click **Analyze Log File** and wait for processing to complete
5. Review the analysis summary cards and detected threat sections

### Drill-Down Analysis (Block-Level)
1. On the **Analysis Results** page, click any summary block (Total Requests, Critical Incidents, High Priority, Unique IPs, Error Rate, Invalid Logs)
2. Open the dedicated detail page for that block
3. Review record-level data (raw lines, HTTP error entries, IP breakdown, etc.)
4. Download only that block's details using **Download JSON** or **Download CSV**

### Reports Page Actions
1. Go to **Reports**
2. Use **Export as JSON** or **Export as CSV** for full report export
3. In **Block-Level Analysis Actions**, choose any block to:
   - Open detailed view
   - Download block-specific JSON
   - Download block-specific CSV

### Incident Investigation Flow
1. Open **Incidents** to view all detected incidents
2. Click **View Details** for full context, logs, and alert records
3. Close incidents after investigation when required

### Supported Log Formats

#### Apache/Nginx Access Logs
```
192.168.1.100 - - [01/Feb/2024 10:15:30] "GET /api/users HTTP/1.1" 200 1234
```

#### Windows Event Logs
```
EventID=4625: Failed login attempt
EventID=4688: New process created
EventID=4720: User account created
```

#### Linux Syslog
```
Feb  1 10:15:30 server sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/apt update
```

### Main Navigation Overview
- **Dashboard**: SOC overview, risk score, recent incidents, and analyzed-file search/download history
- **Analyze**: Upload logs and run detection
- **Incidents**: Investigate and manage security events
- **Alerts**: View current alert activity
- **Reports**: Export full reports and block-level reports

## 🔍 Detection Rules

### Brute Force Attack
- **Condition**: 5 or more failed login attempts from the same IP within 2 minutes
- **Severity**: HIGH
- **Action**: Incident created and alert generated

### Suspicious PowerShell Execution
- **Patterns Detected**:
  - Encoded commands (`-enc`, `-nop`)
  - Invoke-WebRequest
  - Credential theft attempts (FromBase64String)
- **Severity**: CRITICAL
- **Action**: Immediate alert and incident creation

### Admin Account Creation
- **Patterns Detected**:
  - `net user` with admin flags
  - `New-LocalUser` PowerShell commands
  - Administrator group additions
- **Severity**: CRITICAL
- **Action**: Incident created with high priority

### IOC Detection
- Checks source IPs against known malicious databases
- Flags suspicious activity patterns
- **Severity**: Based on threat intelligence

## 📊 Database Schema

### Users Table
- `user_id` - Primary Key
- `username` - Unique username
- `password` - Hashed password
- `role` - User role (analyst/admin)
- `created_at` - Account creation timestamp

### Incidents Table
- `incident_id` - Primary Key
- `event_type` - Type of security event
- `source_ip` - Source IP address
- `username` - Associated username
- `severity` - Incident severity level
- `timestamp` - Event timestamp
- `status` - Open/Closed status
- `user_id` - User who created incident
- `description` - Detailed description

### Logs Table
- `log_id` - Primary Key
- `log_type` - Type of log (Apache, Windows, etc.)
- `log_source` - Log source/origin
- `log_data` - Raw log data
- `incident_id` - Associated incident
- `timestamp` - Log timestamp

### Alerts Table
- `alert_id` - Primary Key
- `incident_id` - Associated incident
- `alert_type` - Type of alert
- `message` - Alert message
- `severity` - Alert severity
- `is_read` - Read status
- `timestamp` - Alert timestamp

### Analyzed Files Table
- `file_id` - Primary Key
- `user_id` - Owner of analyzed file record
- `original_filename` - Filename uploaded by user
- `stored_filename` - Sanitized filename saved on server
- `file_path` - Server path for stored file
- `analyzed_at` - When file was analyzed
- `last_accessed_at` - Last time file was downloaded
- `access_count` - Number of downloads/accesses

## 🔒 Security Features

- **Password Hashing**: Secure password storage using Werkzeug
- **Session Management**: Secure user session handling
- **File Upload Validation**: Restricted file types and size limits (16MB max)
- **SQL Injection Protection**: Parameterized database queries
- **CSRF Protection**: Secure form handling

## 📈 Performance

- **Log Processing Speed**: <2 seconds for 10,000 log entries
- **Incident Detection**: Real-time threat classification
- **Database Queries**: Optimized for quick incident retrieval
- **Concurrent Users**: Supports multiple simultaneous analysts

## 🛠️ Technical Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, JavaScript
- **Authentication**: Werkzeug Security
- **APIs**: RESTful endpoints for data retrieval

## 📦 Project Structure

```
Log_Analyzer/
├── app.py                 # Main Flask application
├── analyzer.py            # Log analysis and threat detection engine
├── models.py              # Database models and operations
├── auth.py                # Authentication management
├── report_generator.py     # Report generation and export
├── requirements.txt        # Python dependencies
├── logs_analyzer.db       # SQLite database (auto-created)
├── static/
│   └── style.css          # Styling
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── analyze.html
│   ├── result.html
│   ├── incidents.html
│   ├── incident_detail.html
│   ├── alerts.html
│   ├── reports.html
│   └── error.html
└── uploads/               # Uploaded log files directory
```

## 🔧 Configuration

### Flask Configuration
- Debug mode enabled (change in production)
- Secret key: Change in `app.py` before deployment
- Upload folder: `uploads/` directory
- Max file size: 16MB

## 🚨 Severity Levels

| Level | Color | Description | Action |
|-------|-------|-------------|--------|
| **Critical** | Red | Immediate security threat | Investigate immediately |
| **High** | Orange | Significant security concern | Investigate within hours |
| **Medium** | Yellow | Suspicious but not immediate | Monitor and investigate |
| **Low** | Green | Minor security event | Log and review periodically |

## 📚 Sample Incident Scenarios

### Scenario 1: Brute Force Attack
- Source IP makes 7 failed login attempts in 90 seconds
- System automatically detects and creates HIGH severity incident
- Alert is generated and stored
- Analyst can view details and take action

### Scenario 2: Suspicious PowerShell
- Log contains: `powershell -enc UwB0YXJ0LVByb2Nlc3M=`
- Detected as suspicious encoded command
- CRITICAL incident created immediately
- Analyst receives alert for urgent investigation

### Scenario 3: Admin Account Creation
- Log entry: `net user admin /add /active:yes`
- Pattern matched as unauthorized admin creation
- CRITICAL incident generated
- Added to incident queue for investigation

## 🤝 Contributing

Contributions are welcome! To contribute:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is provided for educational and organizational purposes.

## 🆘 Troubleshooting

### Database Errors
- Delete `logs_analyzer.db` and restart application to reinitialize

### Login Issues
- Ensure you have registered an account first
- Check that cookies are enabled in your browser

### File Upload Issues
- Verify file format is supported (.txt, .log, .csv, .json)
- Check file size is under 16MB
- Ensure `uploads/` folder has write permissions

### Port Already in Use
- Change the port in `app.py`: `app.run(debug=True, port=5001)`

## 📧 Support & Feedback

For issues, suggestions, or feature requests, please create an issue or contact the development team.

## 🔮 Future Enhancements

- Machine learning-based anomaly detection
- Real-time log streaming capabilities
- Email/SMS alert notifications
- Automatic response and containment actions
- Integration with threat intelligence feeds
- Multi-tenant support
- Advanced visualization dashboards
- API rate limiting and throttling

---

**Version**: 1.0.0  
**Last Updated**: February 2024  
**Developed for**: AutoSOC Project - Educational & Organizational Security Monitoring
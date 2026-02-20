from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import os
import json
import csv
from analyzer import analyze_log
from werkzeug.utils import secure_filename
from models import (
    init_db,
    create_incident,
    create_alert,
    get_all_incidents,
    get_incident_details,
    get_unread_alerts,
    close_incident,
    create_analyzed_file_record,
    get_recent_analyzed_files,
    search_analyzed_files,
    get_analyzed_file,
    mark_file_accessed
)
from auth import AuthManager
from report_generator import export_to_json, export_to_csv, generate_alert_message, calculate_risk_score, format_report_summary
from functools import wraps
from datetime import datetime
from io import BytesIO, StringIO

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'log', 'csv', 'json'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
LATEST_ANALYSIS_CACHE = {}

# Initialize database
init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_latest_analysis(user_id):
    return LATEST_ANALYSIS_CACHE.get(user_id)

def build_block_details(analysis_result, block_key):
    summary = analysis_result.get('summary', {})
    incidents = analysis_result.get('incidents', [])

    block_map = {
        'total_requests': {
            'title': 'Total Requests',
            'description': 'Detailed request logs parsed from the uploaded file.',
            'count': analysis_result.get('total_requests', 0),
            'columns': ['line_number', 'source_ip', 'method', 'url', 'status_code', 'raw_log'],
            'records': analysis_result.get('request_log_entries', [])
        },
        'critical_incidents': {
            'title': 'Critical Incidents',
            'description': 'Incidents classified as Critical severity.',
            'count': summary.get('critical_incidents', 0),
            'columns': ['type', 'source_ip', 'severity', 'description'],
            'records': [item for item in incidents if item.get('severity') == 'Critical']
        },
        'high_priority_incidents': {
            'title': 'High Priority Incidents',
            'description': 'Incidents classified as High severity.',
            'count': summary.get('high_priority_incidents', 0),
            'columns': ['type', 'source_ip', 'severity', 'description'],
            'records': [item for item in incidents if item.get('severity') == 'High']
        },
        'unique_ips': {
            'title': 'Unique IPs',
            'description': 'Unique source IP addresses and their request counts.',
            'count': summary.get('unique_ips', 0),
            'columns': ['ip', 'request_count'],
            'records': analysis_result.get('unique_ip_details', [])
        },
        'error_rate': {
            'title': 'HTTP Error Rate',
            'description': 'Requests with 4xx/5xx HTTP status codes.',
            'count': summary.get('error_rate', '0%'),
            'columns': ['line_number', 'source_ip', 'method', 'url', 'status_code', 'raw_log'],
            'records': analysis_result.get('error_log_entries', [])
        },
        'invalid_logs': {
            'title': 'Invalid Logs',
            'description': 'Unparseable log lines found during analysis.',
            'count': analysis_result.get('invalid_logs', 0),
            'columns': ['line_number', 'raw_log'],
            'records': analysis_result.get('invalid_log_entries', [])
        }
    }

    return block_map.get(block_key)

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password:
            return render_template('register.html', error="Username and password required")

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")

        success, message = AuthManager.register_user(username, password)

        if success:
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error=message)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        success, user = AuthManager.verify_credentials(username, password)

        if success:
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with overview"""
    incidents = get_all_incidents()
    user_id = session.get('user_id')
    search_query = request.args.get('file_search', '').strip()

    if search_query:
        analyzed_files = search_analyzed_files(user_id, search_query, limit=20)
    else:
        analyzed_files = get_recent_analyzed_files(user_id, limit=10)
    
    # Calculate statistics
    total_incidents = len(incidents)
    critical_incidents = len([i for i in incidents if i['severity'] == 'Critical'])
    high_incidents = len([i for i in incidents if i['severity'] == 'High'])
    open_incidents = len([i for i in incidents if i['status'] == 'open'])
    unread_alerts = get_unread_alerts()
    
    # Get recent incidents
    recent_incidents = incidents[:10]
    
    stats = {
        'total_incidents': total_incidents,
        'critical_incidents': critical_incidents,
        'high_incidents': high_incidents,
        'open_incidents': open_incidents,
        'unread_alerts': unread_alerts,
        'risk_score': calculate_risk_score(incidents)
    }
    
    return render_template(
        'dashboard.html',
        stats=stats,
        recent_incidents=recent_incidents,
        analyzed_files=analyzed_files,
        file_search=search_query
    )

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    """Upload and analyze log files"""
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return render_template('analyze.html', error="No file part in the request.")

        file = request.files['logfile']
        if not file or file.filename == '':
            return render_template('analyze.html', error="Please select a log file to analyze.")

        if not allowed_file(file.filename):
            return render_template('analyze.html', error="Unsupported file type. Allowed: txt, log, csv, json")

        original_filename = file.filename
        safe_filename = secure_filename(original_filename)
        unique_prefix = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        filename = f"{unique_prefix}_{safe_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Analyze the log file
        analysis_result = analyze_log(filepath)
        user_id = session.get('user_id')

        create_analyzed_file_record(
            user_id=user_id,
            original_filename=original_filename,
            stored_filename=filename,
            file_path=filepath
        )

        LATEST_ANALYSIS_CACHE[user_id] = {
            'filename': original_filename,
            'analyzed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'result': analysis_result
        }

        # Store incidents in database
        for incident in analysis_result.get('incidents', []):
            incident_id = create_incident(
                event_type=incident.get('type', 'Unknown'),
                source_ip=incident.get('source_ip', 'Unknown'),
                username=session.get('username'),
                severity=incident.get('severity', 'Medium'),
                description=incident.get('description', ''),
                user_id=user_id
            )
            
            # Create alert
            alert_message = generate_alert_message(incident.get('type', ''), incident)
            create_alert(incident_id, incident.get('type', 'Security Alert'), alert_message, incident.get('severity', 'Medium'))

        return render_template('result.html', 
                             result=analysis_result,
                             report_summary=format_report_summary(analysis_result),
                             filename=original_filename,
                             now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    return render_template('analyze.html')

@app.route('/download/analyzed-file/<int:file_id>')
@login_required
def download_analyzed_file(file_id):
    """Download an analyzed file from user's history and record access."""
    user_id = session.get('user_id')
    analyzed_file = get_analyzed_file(file_id, user_id)

    if not analyzed_file:
        return render_template('error.html', error="File not found in your history"), 404

    file_path = analyzed_file['file_path']
    if not os.path.exists(file_path):
        return render_template('error.html', error="File is no longer available on server"), 404

    mark_file_accessed(file_id, user_id)

    return send_file(
        file_path,
        as_attachment=True,
        download_name=analyzed_file['original_filename']
    )

@app.route('/incidents')
@login_required
def view_incidents():
    """View all incidents"""
    incidents = get_all_incidents()
    return render_template('incidents.html', incidents=incidents)

@app.route('/incident/<int:incident_id>')
@login_required
def incident_details(incident_id):
    """View incident details"""
    incident, logs, alerts = get_incident_details(incident_id)
    
    if not incident:
        return render_template('error.html', error="Incident not found"), 404
    
    return render_template('incident_detail.html', 
                         incident=incident, 
                         logs=logs, 
                         alerts=alerts)

@app.route('/incident/<int:incident_id>/close', methods=['POST'])
@login_required
def close_incident_route(incident_id):
    """Close an incident"""
    close_incident(incident_id)
    return redirect(url_for('incident_details', incident_id=incident_id))

@app.route('/alerts')
@login_required
def view_alerts():
    """View all alerts"""
    incidents = get_all_incidents()
    return render_template('alerts.html', incidents=incidents)

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    incidents = get_all_incidents()
    stats = {
        'total_incidents': len(incidents),
        'critical_incidents': len([i for i in incidents if i['severity'] == 'Critical']),
        'high_incidents': len([i for i in incidents if i['severity'] == 'High']),
        'open_incidents': len([i for i in incidents if i['status'] == 'open']),
    }

    user_id = session.get('user_id')
    latest_analysis = get_user_latest_analysis(user_id)
    analysis_blocks = []

    if latest_analysis:
        analysis_result = latest_analysis.get('result', {})
        block_keys = [
            'total_requests',
            'critical_incidents',
            'high_priority_incidents',
            'unique_ips',
            'error_rate',
            'invalid_logs'
        ]

        for block_key in block_keys:
            block_data = build_block_details(analysis_result, block_key)
            if block_data:
                analysis_blocks.append({
                    'key': block_key,
                    'title': block_data.get('title'),
                    'description': block_data.get('description'),
                    'count': block_data.get('count')
                })

    return render_template(
        'reports.html',
        stats=stats,
        analysis_blocks=analysis_blocks,
        has_latest_analysis=latest_analysis is not None,
        latest_analysis_filename=latest_analysis.get('filename') if latest_analysis else None,
        latest_analysis_time=latest_analysis.get('analyzed_at') if latest_analysis else None
    )

@app.route('/export/<format>')
@login_required
def export_report(format):
    """Export analysis report in JSON or CSV format"""
    incidents = get_all_incidents()
    
    # Recreate analysis summary
    analysis_results = {
        'summary': {
            'total_incidents': len(incidents),
            'critical_incidents': len([i for i in incidents if i['severity'] == 'Critical']),
            'high_priority_incidents': len([i for i in incidents if i['severity'] == 'High']),
        },
        'incidents': [dict(i) for i in incidents]
    }
    
    if format == 'json':
        content = export_to_json(analysis_results, incidents=[dict(i) for i in incidents])
        return send_file(
            BytesIO(content.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
    elif format == 'csv':
        content = export_to_csv(analysis_results)
        return send_file(
            BytesIO(content.encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    return render_template('error.html', error="Invalid format"), 400

@app.route('/analysis/details/<block_key>')
@login_required
def analysis_block_details(block_key):
    """Detailed drill-down view for specific analysis summary blocks"""
    user_id = session.get('user_id')
    latest_analysis = get_user_latest_analysis(user_id)

    if not latest_analysis:
        return render_template('error.html', error="No analysis data found. Please analyze a log file first."), 404

    block_data = build_block_details(latest_analysis['result'], block_key)
    if not block_data:
        return render_template('error.html', error="Invalid analysis block requested."), 400

    return render_template(
        'analysis_detail.html',
        block_key=block_key,
        block_data=block_data,
        filename=latest_analysis.get('filename', 'Unknown'),
        analyzed_at=latest_analysis.get('analyzed_at', 'Unknown')
    )

@app.route('/analysis/export/<block_key>/<format>')
@login_required
def export_analysis_block(block_key, format):
    """Export specific analysis block details in JSON or CSV"""
    user_id = session.get('user_id')
    latest_analysis = get_user_latest_analysis(user_id)

    if not latest_analysis:
        return render_template('error.html', error="No analysis data found. Please analyze a log file first."), 404

    block_data = build_block_details(latest_analysis['result'], block_key)
    if not block_data:
        return render_template('error.html', error="Invalid analysis block requested."), 400

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if format == 'json':
        export_payload = {
            'export_timestamp': datetime.now().isoformat(),
            'source_file': latest_analysis.get('filename', 'Unknown'),
            'analyzed_at': latest_analysis.get('analyzed_at', 'Unknown'),
            'block_key': block_key,
            'block_title': block_data.get('title'),
            'block_count': block_data.get('count'),
            'records': block_data.get('records', [])
        }
        content = json.dumps(export_payload, indent=2, default=str)
        return send_file(
            BytesIO(content.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'{block_key}_{timestamp}.json'
        )

    if format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([block_data.get('title', 'Analysis Block Report')])
        writer.writerow(['Source File', latest_analysis.get('filename', 'Unknown')])
        writer.writerow(['Analyzed At', latest_analysis.get('analyzed_at', 'Unknown')])
        writer.writerow(['Exported At', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Block Count', block_data.get('count')])
        writer.writerow([])

        columns = block_data.get('columns', [])
        writer.writerow(columns)
        for record in block_data.get('records', []):
            writer.writerow([record.get(column, '') for column in columns])

        return send_file(
            BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'{block_key}_{timestamp}.csv'
        )

    return render_template('error.html', error="Invalid format"), 400

# ==================== API ROUTES ====================

@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    """API endpoint for dashboard statistics"""
    incidents = get_all_incidents()
    
    stats = {
        'total_incidents': len(incidents),
        'critical_incidents': len([i for i in incidents if i['severity'] == 'Critical']),
        'high_incidents': len([i for i in incidents if i['severity'] == 'High']),
        'open_incidents': len([i for i in incidents if i['status'] == 'open']),
        'risk_score': calculate_risk_score(incidents),
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(stats)

@app.route('/api/incidents-by-severity')
@login_required
def api_incidents_by_severity():
    """API endpoint for incidents grouped by severity"""
    incidents = get_all_incidents()
    
    severity_counts = {
        'Critical': len([i for i in incidents if i['severity'] == 'Critical']),
        'High': len([i for i in incidents if i['severity'] == 'High']),
        'Medium': len([i for i in incidents if i['severity'] == 'Medium']),
        'Low': len([i for i in incidents if i['severity'] == 'Low']),
    }
    
    return jsonify(severity_counts)

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=True)

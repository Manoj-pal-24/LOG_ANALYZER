import sqlite3
from datetime import datetime
import os

DATABASE = 'logs_analyzer.db'

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # User table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Incident table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            username TEXT,
            severity TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'open',
            user_id INTEGER,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')

    # Log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT,
            log_source TEXT,
            log_data TEXT,
            incident_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )
    ''')

    # Alert table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT,
            severity TEXT,
            is_read INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )
    ''')

    # Analyzed file history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyzed_files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed_at TIMESTAMP,
            access_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')

    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_user(username, password, role='analyst'):
    """Create a new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, password, role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user(username):
    """Get user by username"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_incident(event_type, source_ip, username, severity, description, user_id):
    """Create a new incident"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO incidents (event_type, source_ip, username, severity, description, user_id)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (event_type, source_ip, username, severity, description, user_id)
    )
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()
    return incident_id

def create_alert(incident_id, alert_type, message, severity):
    """Create a new alert"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO alerts (incident_id, alert_type, message, severity)
           VALUES (?, ?, ?, ?)''',
        (incident_id, alert_type, message, severity)
    )
    conn.commit()
    conn.close()

def get_all_incidents():
    """Get all incidents"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents ORDER BY timestamp DESC')
    incidents = cursor.fetchall()
    conn.close()
    return incidents

def get_incident_details(incident_id):
    """Get incident details"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents WHERE incident_id = ?', (incident_id,))
    incident = cursor.fetchone()
    cursor.execute('SELECT * FROM logs WHERE incident_id = ?', (incident_id,))
    logs = cursor.fetchall()
    cursor.execute('SELECT * FROM alerts WHERE incident_id = ?', (incident_id,))
    alerts = cursor.fetchall()
    conn.close()
    return incident, logs, alerts

def get_unread_alerts():
    """Get unread alerts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE is_read = 0')
    count = cursor.fetchone()[0]
    conn.close()
    return count

def mark_alert_as_read(alert_id):
    """Mark alert as read"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE alerts SET is_read = 1 WHERE alert_id = ?', (alert_id,))
    conn.commit()
    conn.close()

def close_incident(incident_id):
    """Close an incident"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE incidents SET status = ? WHERE incident_id = ?', ('closed', incident_id))
    conn.commit()
    conn.close()

def create_analyzed_file_record(user_id, original_filename, stored_filename, file_path):
    """Store analyzed file details for history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO analyzed_files (user_id, original_filename, stored_filename, file_path)
           VALUES (?, ?, ?, ?)''',
        (user_id, original_filename, stored_filename, file_path)
    )
    conn.commit()
    file_id = cursor.lastrowid
    conn.close()
    return file_id

def get_recent_analyzed_files(user_id, limit=10):
    """Get recently analyzed/accessed files for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT * FROM analyzed_files
           WHERE user_id = ?
           ORDER BY COALESCE(last_accessed_at, analyzed_at) DESC
           LIMIT ?''',
        (user_id, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows

def search_analyzed_files(user_id, query, limit=20):
    """Search analyzed files by filename for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    like_query = f'%{query.strip()}%'
    cursor.execute(
        '''SELECT * FROM analyzed_files
           WHERE user_id = ? AND original_filename LIKE ?
           ORDER BY COALESCE(last_accessed_at, analyzed_at) DESC
           LIMIT ?''',
        (user_id, like_query, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_analyzed_file(file_id, user_id):
    """Get a specific analyzed file for the current user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM analyzed_files WHERE file_id = ? AND user_id = ?',
        (file_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()
    return row

def mark_file_accessed(file_id, user_id):
    """Update access timestamp and count for analyzed files"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''UPDATE analyzed_files
           SET last_accessed_at = CURRENT_TIMESTAMP,
               access_count = access_count + 1
           WHERE file_id = ? AND user_id = ?''',
        (file_id, user_id)
    )
    conn.commit()
    conn.close()

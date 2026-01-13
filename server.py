#!/usr/bin/env python3
"""
Privara HIDS - Backend Server with OS-Compatible Framework
Supports: Manjaro Linux (primary), Windows 11 (secondary), Fake modeling (fallback)

Features:
- Real system readings (CPU, RAM, Disk I/O)
- Configuration file management with validation
- GDPR-compliant logging with automatic cleanup
- Khepri-ML AI agent for process risk scoring
"""

from flask import Flask, send_from_directory, jsonify, request
import psutil
import platform
import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
import sys

app = Flask(__name__, static_folder='.')

# --- OS DETECTION & INITIALIZATION ---

SYSTEM_OS = platform.system()  # 'Linux' or 'Windows'
IS_MANJARO = SYSTEM_OS == 'Linux' and Path('/etc/manjaro-release').exists()
IS_WINDOWS = SYSTEM_OS == 'Windows'

DB_PATH = Path(__file__).parent / "privara.db"
CONFIG_PATH = Path(__file__).parent / "config.json"
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Detect actual operating system
if IS_MANJARO:
    DETECTED_OS = "Manjaro Linux"
elif IS_WINDOWS:
    DETECTED_OS = "Windows 11"
else:
    DETECTED_OS = f"Linux ({platform.release()})"

print(f"[*] Privara HIDS Backend initialized on: {DETECTED_OS}")
print(f"[*] Database: {DB_PATH}")
print(f"[*] Logs directory: {LOG_DIR}")

# --- DATABASE INITIALIZATION ---

def init_db():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS process_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL DEFAULT current_timestamp,
            pid INTEGER NOT NULL,
            name TEXT NOT NULL,
            cpu REAL,
            mem REAL
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL DEFAULT current_timestamp,
            threat_id TEXT NOT NULL,
            threat_name TEXT NOT NULL,
            risk_level TEXT,
            status TEXT
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL DEFAULT current_timestamp,
            user TEXT,
            action TEXT,
            details TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    write_log("INFO", f"Database initialized on {DETECTED_OS}")

# --- CONFIGURATION MANAGEMENT ---

DEFAULT_CONFIG = {
    "monitoring": {
        "enabled": True,
        "interval_seconds": 10
    },
    "thresholds": {
        "cpu_alert": 80,
        "memory_alert": 85,
        "disk_alert": 90
    },
    "logging": {
        "enabled": True,
        "retention_days": 90,
        "level": "INFO"
    },
    "ui": {
        "theme": "Tech Noir",
        "timezone": "GMT"
    }
}

def load_config():
    """Load configuration from file or return defaults"""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
                return validate_config(config)
        except Exception as e:
            write_log("ERROR", f"Config load error: {e}")
    return DEFAULT_CONFIG.copy()

def validate_config(config):
    """Validate and sanitize configuration to prevent injection attacks"""
    validated = DEFAULT_CONFIG.copy()
    
    if "monitoring" in config and isinstance(config["monitoring"], dict):
        validated["monitoring"]["enabled"] = config["monitoring"].get("enabled", True)
        interval = config["monitoring"].get("interval_seconds", 10)
        validated["monitoring"]["interval_seconds"] = max(1, min(3600, interval))
    
    if "thresholds" in config and isinstance(config["thresholds"], dict):
        for key in ["cpu_alert", "memory_alert", "disk_alert"]:
            if key in config["thresholds"]:
                value = config["thresholds"][key]
                validated["thresholds"][key] = max(0, min(100, int(value)))
    
    if "logging" in config and isinstance(config["logging"], dict):
        validated["logging"]["enabled"] = config["logging"].get("enabled", True)
        retention = config["logging"].get("retention_days", 90)
        validated["logging"]["retention_days"] = max(1, min(365, int(retention)))
        validated["logging"]["level"] = config["logging"].get("level", "INFO")
    
    if "ui" in config and isinstance(config["ui"], dict):
        validated["ui"].update(config["ui"])
    
    return validated

def save_config(config):
    """Save configuration to file"""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        write_log("INFO", "Configuration saved")
        return True
    except Exception as e:
        write_log("ERROR", f"Config save failed: {e}")
        return False

CONFIG = load_config()

# --- GDPR-COMPLIANT LOGGING ---

def write_log(level, message):
    """Write to GDPR-compliant log file"""
    if not CONFIG["logging"]["enabled"]:
        return
    
    timestamp = datetime.now().isoformat()
    log_file = LOG_DIR / f"privara_{datetime.now().strftime('%Y%m%d')}.log"
    
    try:
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
        
        cleanup_old_logs()
    except Exception as e:
        print(f"Log write error: {e}")

def cleanup_old_logs():
    """Automatically delete logs older than retention period (GDPR compliance)"""
    retention_days = CONFIG["logging"]["retention_days"]
    cutoff = datetime.now().timestamp() - (retention_days * 86400)
    
    for log_file in LOG_DIR.glob("privara_*.log"):
        try:
            if log_file.stat().st_mtime < cutoff:
                log_file.unlink()
        except Exception as e:
            print(f"Log cleanup error: {e}")

# --- OS-COMPATIBLE SYSTEM READINGS ---

def get_system_info():
    """Get system metrics with OS-specific fallbacks: Manjaro → Windows → Fake"""
    try:
        if IS_MANJARO:
            return get_manjaro_info()
        elif IS_WINDOWS:
            return get_windows_info()
        else:
            return get_linux_generic_info()
    except Exception as e:
        write_log("ERROR", f"System reading failed: {e}")
        return get_fake_info()

def get_manjaro_info():
    """Read metrics from Manjaro Linux using psutil"""
    try:
        vm = psutil.virtual_memory()
        disk = psutil.disk_io_counters()
        return {
            "os": "Manjaro Linux",
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": vm.percent,
            "memory_available_mb": vm.available / (1024**2),
            "disk_io": (disk.read_bytes / (1024**2)) if disk else 0,
            "disk_io_write": (disk.write_bytes / (1024**2)) if disk else 0
        }
    except Exception as e:
        write_log("ERROR", f"Manjaro info read failed: {e}")
        return get_fake_info()

def get_windows_info():
    """Read metrics from Windows 11 using psutil and WMI"""
    try:
        vm = psutil.virtual_memory()
        disk = psutil.disk_io_counters()
        return {
            "os": "Windows 11",
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": vm.percent,
            "memory_available_mb": vm.available / (1024**2),
            "disk_io": (disk.read_bytes / (1024**2)) if disk else 0,
            "disk_io_write": (disk.write_bytes / (1024**2)) if disk else 0
        }
    except Exception as e:
        write_log("ERROR", f"Windows info read failed: {e}")
        return get_fake_info()

def get_linux_generic_info():
    """Fallback for generic Linux systems"""
    try:
        vm = psutil.virtual_memory()
        disk = psutil.disk_io_counters()
        return {
            "os": f"Linux ({platform.release()})",
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": vm.percent,
            "memory_available_mb": vm.available / (1024**2),
            "disk_io": (disk.read_bytes / (1024**2)) if disk else 0,
            "disk_io_write": (disk.write_bytes / (1024**2)) if disk else 0
        }
    except Exception as e:
        write_log("ERROR", f"Linux info read failed: {e}")
        return get_fake_info()

def get_fake_info():
    """Fallback simulated metrics"""
    import random
    return {
        "os": "Simulated (Fallback)",
        "cpu_percent": random.uniform(5, 35),
        "memory_percent": random.uniform(40, 70),
        "memory_available_mb": random.uniform(2000, 8000),
        "disk_io": random.uniform(10, 100),
        "disk_io_write": random.uniform(5, 50)
    }

# --- KHEPRI-ML RISK SCORING ---

def compute_risk_and_verdict(name, cpu, mem):
    """Khepri-ML v0.2 - Risk scoring based on process characteristics"""
    suspicious_keywords = ["miner", "crypt", "rat", "remote", "shell", "powershell", "cmd.exe", "nc.exe", "keylog", "exploit"]
    score = 0
    lower_name = (name or "").lower()
    
    # Name-based scoring
    if any(k in lower_name for k in suspicious_keywords):
        score += 40
    
    # CPU-based scoring
    if cpu:
        if cpu > 80:
            score += 40
        elif cpu > 40:
            score += 20
    
    # Memory-based scoring
    if mem:
        if mem > 20:
            score += 20
    
    score = min(score, 100)
    
    if score >= 70:
        verdict = "Critical"
    elif score >= 40:
        verdict = "Suspicious"
    elif score >= 10:
        verdict = "Elevated"
    else:
        verdict = "Benign"
    
    return score, verdict, "Khepri-ML v0.2"

# --- API ROUTES ---

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/system-info')
def api_system_info():
    """Get real-time system information"""
    info = get_system_info()
    return jsonify(info)

@app.route('/api/processes')
def api_processes():
    """Get list of running processes with risk scores"""
    procs = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            info = p.info
            if info['name']:
                risk_score, verdict, agent = compute_risk_and_verdict(
                    info.get('name'),
                    info.get('cpu_percent'),
                    info.get('memory_percent')
                )
                procs.append({
                    'pid': info.get('pid'),
                    'name': info.get('name'),
                    'cpu': info.get('cpu_percent') or 0,
                    'mem': info.get('memory_percent') or 0,
                    'risk_score': risk_score,
                    'verdict': verdict,
                    'agent': agent
                })
    except Exception as e:
        write_log("ERROR", f"Process enumeration failed: {e}")
    
    return jsonify(procs)

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update configuration"""
    global CONFIG
    
    if request.method == 'POST':
        try:
            new_config = request.json
            CONFIG = validate_config(new_config)
            if save_config(CONFIG):
                write_log("INFO", "Configuration updated via API")
                return jsonify({"status": "ok", "config": CONFIG})
            else:
                return jsonify({"status": "error", "message": "Failed to save config"}), 500
        except Exception as e:
            write_log("ERROR", f"Config update failed: {e}")
            return jsonify({"status": "error", "message": str(e)}), 400
    
    return jsonify(CONFIG)

@app.route('/api/logs')
def api_logs():
    """Get recent log entries"""
    try:
        today_log = LOG_DIR / f"privara_{datetime.now().strftime('%Y%m%d')}.log"
        if today_log.exists():
            with open(today_log, 'r') as f:
                lines = f.readlines()[-100:]  # Last 100 entries
            return jsonify({"logs": lines, "count": len(lines)})
        return jsonify({"logs": [], "count": 0})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs/delete', methods=['POST'])
def api_delete_logs():
    """Delete all logs (GDPR Right to be Forgotten)"""
    try:
        deleted_count = 0
        for log_file in LOG_DIR.glob("privara_*.log"):
            log_file.unlink()
            deleted_count += 1
        
        write_log("WARNING", f"All {deleted_count} logs deleted via user request (GDPR Right to be Forgotten)")
        return jsonify({"status": "ok", "message": f"Deleted {deleted_count} log files"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/log-snapshot', methods=['POST', 'GET'])
def api_log_snapshot():
    """Take a snapshot of current processes and store in database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            info = p.info
            cur.execute(
                "INSERT INTO process_snapshots (pid, name, cpu, mem) VALUES (?, ?, ?, ?)",
                (info.get('pid'), info.get('name'), info.get('cpu_percent'), info.get('memory_percent'))
            )
        
        conn.commit()
        conn.close()
        write_log("INFO", "Process snapshot logged to database")
        return jsonify({"status": "ok", "message": "Snapshot recorded"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(error):
    write_log("ERROR", f"Server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# --- JAVAFX SYSTEM MONITOR INTEGRATION ---

# Store latest metrics from JavaFX monitor
javafx_metrics = {}

@app.route('/api/system-update', methods=['POST'])
def api_system_update():
    """Receive system metrics from JavaFX monitor"""
    global javafx_metrics
    
    try:
        metrics = request.json
        if not metrics:
            return jsonify({"status": "error", "message": "No metrics provided"}), 400
        
        # Validate required fields
        required_fields = ['cpu_percent', 'memory_percent', 'timestamp']
        if not all(field in metrics for field in required_fields):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400
        
        # Store metrics in memory
        javafx_metrics = metrics
        
        # Log to database
        write_log("INFO", f"JavaFX metrics received: CPU={metrics.get('cpu_percent')}%, MEM={metrics.get('memory_percent')}%")
        
        # Optionally store in SQLite for historical analysis
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT current_timestamp,
                cpu_percent REAL,
                memory_percent REAL,
                disk_io_mbps REAL,
                process_count INTEGER
            )
        """)
        cur.execute(
            "INSERT INTO system_metrics (cpu_percent, memory_percent, disk_io_mbps, process_count) VALUES (?, ?, ?, ?)",
            (metrics.get('cpu_percent'), metrics.get('memory_percent'), 
             metrics.get('disk_io_total_mbps', 0), metrics.get('process_count', 0))
        )
        conn.commit()
        conn.close()
        
        return jsonify({"status": "ok", "message": "Metrics received"}), 200
    
    except Exception as e:
        write_log("ERROR", f"Failed to process JavaFX metrics: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/system-info-enhanced')
def api_system_info_enhanced():
    """Get enhanced system information from JavaFX monitor (if available)"""
    
    if javafx_metrics:
        # Return JavaFX metrics (more detailed)
        return jsonify({
            "source": "JavaFX Monitor (OSHI)",
            "os": javafx_metrics.get('os_name', 'Unknown'),
            "cpu_percent": javafx_metrics.get('cpu_percent', 0),
            "cpu_model": javafx_metrics.get('cpu_model', 'Unknown'),
            "cpu_cores": {
                "physical": javafx_metrics.get('cpu_cores_physical', 0),
                "logical": javafx_metrics.get('cpu_cores_logical', 0)
            },
            "memory_percent": javafx_metrics.get('memory_percent', 0),
            "memory_total_gb": javafx_metrics.get('memory_total_gb', 0),
            "memory_used_gb": javafx_metrics.get('memory_used_gb', 0),
            "disk_io_mbps": javafx_metrics.get('disk_io_total_mbps', 0),
            "disk_read_mbps": javafx_metrics.get('disk_read_mbps', 0),
            "disk_write_mbps": javafx_metrics.get('disk_write_mbps', 0),
            "process_count": javafx_metrics.get('process_count', 0),
            "thread_count": javafx_metrics.get('thread_count', 0),
            "top_processes": javafx_metrics.get('top_processes', []),
            "network_interfaces": javafx_metrics.get('network_interfaces', []),
            "timestamp": javafx_metrics.get('timestamp', 0)
        })
    else:
        # Fallback to psutil metrics
        return jsonify(get_system_info())


@app.route('/api/metrics-history')
def api_metrics_history():
    """Get historical system metrics from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Get last 100 data points
        cur.execute("""
            SELECT ts, cpu_percent, memory_percent, disk_io_mbps, process_count
            FROM system_metrics
            ORDER BY id DESC
            LIMIT 100
        """)
        
        rows = cur.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                "timestamp": row[0],
                "cpu_percent": row[1],
                "memory_percent": row[2],
                "disk_io_mbps": row[3],
                "process_count": row[4]
            })
        
        return jsonify({"history": history, "count": len(history)})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    init_db()
    write_log("INFO", f"Privara HIDS v3.0 started on {DETECTED_OS}")
    write_log("INFO", f"Available at http://localhost:8000")
    app.run(host='0.0.0.0', port=8000, debug=False)


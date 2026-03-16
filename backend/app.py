# ---------------------------------------------------------
# IMPORT REQUIRED LIBRARIES
# ---------------------------------------------------------
from flask import Flask, jsonify
from flask_cors import CORS
import threading
import time
import random

# Internal Modules
from config import Config
from device_simulator import DeviceManager
from fdi_detector import FDIDetector
from auth_manager import AuthManager
from attack_simulator import AttackSimulator
from crypto_utils import generate_signature
from database import init_db, get_connection

# Initialize Database Architecture automatically
init_db()


# ---------------------------------------------------------
# FLASK APP INITIALIZATION
# ---------------------------------------------------------
app = Flask(__name__)
# Enable CORS so the separate HTML frontend can talk to this local API
CORS(app)

# Initialize Core System Components
devices = DeviceManager()
detector = FDIDetector()
auth = AuthManager()
attack_sim = AttackSimulator(devices)


# ---------------------------------------------------------
# BACKGROUND SIMULATION ENGINE
# ---------------------------------------------------------
def simulate():
    """
    This function runs continuously in the background.
    It simulates devices issuing regular consumption readings
    to the Smart Energy Grid.
    """
    while True:
        # Loop through all 7 devices
        for d in devices.get_all_devices():
            # If the device isn't authenticated, give it a token
            if not d.token:
                d.token = auth.authenticate(d.device_id)

            # 2% chance of a random background attack occurring natively
            attack = random.random() < 0.02
            
            # Generate the simulated energy reading
            r = d.get_reading(attack)
            
            # Sign the reading cryptographically
            r["signature"] = generate_signature(r)
            
            # Record reading to our FDI detector (which writes to the database)
            detector.record(r)

        # Wait before broadcasting the next set of readings
        time.sleep(Config.READING_INTERVAL)


# Start the background simulator in a separate Thread so it doesn't block the API
threading.Thread(target=simulate, daemon=True).start()


# ---------------------------------------------------------
# API ENDPOINTS (The "Controllers")
# ---------------------------------------------------------

@app.route("/api/health")
def health():
    """
    Health Check Endpoint: Used by the UI to verify if the Python backend
    and MySQL database are online.
    """
    db_status = "disconnected"
    try:
        conn = get_connection()
        if conn.is_connected():
            db_status = "connected"
        conn.close()
    except:
        pass
    
    return jsonify({
        "status": "running",
        "database": db_status
    })

@app.route("/api/trigger-fdi-attack")
def trigger():
    reading = attack_sim.trigger_fdi_attack()
    detector.record(reading)
    return jsonify(reading)


@app.route("/api/tamper-signature")
def tamper():
    reading = attack_sim.tamper_signature()
    detector.record(reading)
    return jsonify(reading)


@app.route("/api/devices")
def get_devices():
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True) if hasattr(conn.cursor(), 'dictionary') else conn.cursor()
        cursor.execute("SELECT device_id, device_name, device_type FROM devices")
        db_devices = cursor.fetchall()
        
        results = []
        for d in db_devices:
            if isinstance(d, dict):
                results.append(d)
            else:
                results.append({
                    "device_id": d[0],
                    "device_name": d[1],
                    "device_type": d[2]
                })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()


@app.route("/api/fdi-alerts")
def get_fdi_alerts():
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True) if hasattr(conn.cursor(), 'dictionary') else conn.cursor()
        
        # We need a unified timeline of events for the dashboard
        # 1. Normal/Attack energy readings
        # 2. FDI Alerts (handled by the energy_readings is_attack flag conceptually, or specifically from fdi_attacks)
        # 3. Crypto attacks
        
        query = """
            SELECT id, device_id, 'NORMAL_READING' as type, CONCAT('Read: ', consumption_kwh, ' kWh') as detail, timestamp
            FROM energy_readings
            WHERE is_attack = 0
            
            UNION ALL
            
            SELECT id, device_id, 'FDI_ATTACK' as type, detection_reason as detail, timestamp
            FROM fdi_attacks
            
            UNION ALL
            
            SELECT id, device_id, 'CRYPTO_ATTACK' as type, verification_status as detail, timestamp
            FROM crypto_attacks
            
            ORDER BY timestamp DESC
            LIMIT 50
        """
        
        cursor.execute(query)
        events = cursor.fetchall()
        
        results = []
        for e in events:
            if isinstance(e, dict):
                results.append({
                    "id": e['id'],
                    "device_id": e['device_id'],
                    "type": e['type'],
                    "detail": e['detail'],
                    "timestamp": e['timestamp']
                })
            else:
                results.append({
                    "id": e[0],
                    "device_id": e[1],
                    "type": e[2],
                    "detail": e[3],
                    "timestamp": e[4]
                })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()


@app.route("/api/security-dashboard")
def get_security_dashboard():
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True) if hasattr(conn.cursor(), 'dictionary') else conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()
        total_devices = total_devices['COUNT(*)'] if isinstance(total_devices, dict) else total_devices[0]

        cursor.execute("SELECT COUNT(*) FROM fdi_attacks")
        fdi_count_total = cursor.fetchone()
        fdi_count_total = fdi_count_total['COUNT(*)'] if isinstance(fdi_count_total, dict) else fdi_count_total[0]

        cursor.execute("SELECT COUNT(*) FROM crypto_attacks")
        crypto_count_total = cursor.fetchone()
        crypto_count_total = crypto_count_total['COUNT(*)'] if isinstance(crypto_count_total, dict) else crypto_count_total[0]
        
        # Check if an attack has occurred in the last 15 seconds to trigger "Under Attack"
        cursor.execute("SELECT COUNT(*) FROM fdi_attacks WHERE timestamp >= NOW() - INTERVAL 15 SECOND")
        recent_fdi = cursor.fetchone()
        recent_fdi = recent_fdi['COUNT(*)'] if isinstance(recent_fdi, dict) else recent_fdi[0]
        
        cursor.execute("SELECT COUNT(*) FROM crypto_attacks WHERE timestamp >= NOW() - INTERVAL 15 SECOND")
        recent_crypto = cursor.fetchone()
        recent_crypto = recent_crypto['COUNT(*)'] if isinstance(recent_crypto, dict) else recent_crypto[0]
        
        is_under_attack = (recent_fdi > 0 or recent_crypto > 0)
        
        return jsonify({
            "total_devices": total_devices,
            "fdi_attacks_detected": fdi_count_total,
            "crypto_failures": crypto_count_total,
            "status": "Under Attack" if is_under_attack else "Secure",
            "recent_fdi": recent_fdi
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()


if __name__ == "__main__":

    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=True
    )
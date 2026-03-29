# ---------------------------------------------------------
# IMPORT REQUIRED LIBRARIES
# ---------------------------------------------------------
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import random
from datetime import datetime

# Internal Modules
from config import Config
from device_simulator import DeviceManager
from fdi_detector import FDIDetector
from auth_manager import AuthManager
from attack_simulator import AttackSimulator
from crypto_utils import generate_signature, get_failure_count
from database import init_db, get_connection
from jwt_manager import JWTManager

# Initialize Database Architecture automatically
init_db()


# ---------------------------------------------------------
# FLASK APP INITIALIZATION
# ---------------------------------------------------------
app = Flask(__name__)
CORS(app)

# Initialize Core System Components
devices = DeviceManager()
detector = FDIDetector()
auth = AuthManager()
attack_sim = AttackSimulator(devices)
jwt_mgr = JWTManager()


# ---------------------------------------------------------
# BACKGROUND SIMULATION ENGINE
# ---------------------------------------------------------
def simulate():
    while True:
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


# Start the background simulator in a separate Thread 
threading.Thread(target=simulate, daemon=True).start()


# ---------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------

@app.route("/api/health")
def health():
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
        "database": db_status,
        "defense_active": detector.defense_active
    })


# ---------------------------------------------------------
# ATTACK TRIGGER ENDPOINTS
# ---------------------------------------------------------

@app.route("/api/trigger-fdi-attack")
def trigger_fdi():
    reading = attack_sim.trigger_fdi_attack()
    result = detector.record(reading)
    return jsonify({
        **reading,
        "defense_result": result,
        "timestamp": str(reading["timestamp"])
    })


@app.route("/api/tamper-signature")
def tamper_sig():
    reading = attack_sim.tamper_signature()
    result = detector.record(reading)
    return jsonify({
        **reading,
        "defense_result": result,
        "timestamp": str(reading["timestamp"])
    })


@app.route("/api/trigger-replay-attack")
def trigger_replay():
    reading = attack_sim.trigger_replay_attack()
    result = detector.record(reading)
    return jsonify({
        **reading,
        "defense_result": result,
        "timestamp": str(reading["timestamp"])
    })


@app.route("/api/trigger-jwt-tamper")
def trigger_jwt_tamper():
    attack_data = attack_sim.trigger_jwt_tamper(jwt_mgr)
    device_id = attack_data["device_id"]
    tampered_token = attack_data["tampered_token"]

    # Attempt verification — this SHOULD fail
    is_valid, reason = jwt_mgr.verify_token(tampered_token)

    # Log the attempt in the database
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO jwt_attacks
            (device_id, attack_type, token_snippet, result)
            VALUES (%s, %s, %s, %s)
            """,
            (device_id, "SIGNATURE_TAMPER",
             tampered_token[:20] + "...",
             "BLOCKED" if not is_valid else "BYPASSED")
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[JWT LOG ERROR] {e}")

    return jsonify({
        "device_id": device_id,
        "attack_type": "JWT_SIGNATURE_TAMPER",
        "token_snippet": tampered_token[:30] + "...",
        "verification_passed": is_valid,
        "rejection_reason": reason if not is_valid else None,
        "defense_active": True
    })


# ---------------------------------------------------------
# DEFENSE TOGGLE
# ---------------------------------------------------------

@app.route("/api/toggle-defense")
def toggle_defense():
    detector.defense_active = not detector.defense_active
    return jsonify({
        "defense_active": detector.defense_active
    })


# ---------------------------------------------------------
# DATA ENDPOINTS
# ---------------------------------------------------------

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

        query = """
            SELECT id, device_id, 'NORMAL_READING' as type,
                   CONCAT('Read: ', consumption_kwh, ' kWh') as detail,
                   timestamp
            FROM energy_readings
            WHERE is_attack = 0

            UNION ALL

            SELECT id, device_id, 'FDI_ATTACK' as type,
                   detection_reason as detail, timestamp
            FROM fdi_attacks

            UNION ALL

            SELECT id, device_id, 'CRYPTO_ATTACK' as type,
                   verification_status as detail, timestamp
            FROM crypto_attacks

            UNION ALL

            SELECT id, device_id, 'JWT_ATTACK' as type,
                   CONCAT(attack_type, ': ', result) as detail, timestamp
            FROM jwt_attacks

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

        def fetch_count(query):
            cursor.execute(query)
            row = cursor.fetchone()
            return row['COUNT(*)'] if isinstance(row, dict) else row[0]

        total_devices = fetch_count("SELECT COUNT(*) FROM devices")
        fdi_count = fetch_count("SELECT COUNT(*) FROM fdi_attacks")
        crypto_count = fetch_count("SELECT COUNT(*) FROM crypto_attacks")
        jwt_count = fetch_count("SELECT COUNT(*) FROM jwt_attacks")
        mitigated_count = fetch_count(
            "SELECT COUNT(*) FROM fdi_attacks WHERE mitigated = 1"
        )
        recent_fdi = fetch_count(
            "SELECT COUNT(*) FROM fdi_attacks WHERE timestamp >= NOW() - INTERVAL 15 SECOND"
        )
        recent_crypto = fetch_count(
            "SELECT COUNT(*) FROM crypto_attacks WHERE timestamp >= NOW() - INTERVAL 15 SECOND"
        )
        recent_jwt = fetch_count(
            "SELECT COUNT(*) FROM jwt_attacks WHERE timestamp >= NOW() - INTERVAL 15 SECOND"
        )

        is_under_attack = (recent_fdi > 0 or recent_crypto > 0 or recent_jwt > 0)

        return jsonify({
            "total_devices": total_devices,
            "fdi_attacks_detected": fdi_count,
            "crypto_failures": crypto_count,
            "jwt_attacks": jwt_count,
            "fdi_mitigated": mitigated_count,
            "status": "Under Attack" if is_under_attack else "Secure",
            "defense_active": detector.defense_active,
            "recent_fdi": recent_fdi,
            "recent_crypto": recent_crypto,
            "recent_jwt": recent_jwt
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()


@app.route("/api/ml-status")
def get_ml_status():
    """Return the current state of the ML models for each device."""
    return jsonify(detector.get_ml_status())


# ---------------------------------------------------------
# START THE SERVER
# ---------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=True
    )

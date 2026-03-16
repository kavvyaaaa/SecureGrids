import mysql.connector

# ---------------------------------------------------------
# DATABASE CONFIGURATION & INITIALIZATION
# ---------------------------------------------------------

def get_base_connection():
    """Builds a raw connection to MySQL without selecting a specific database yet."""
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="k123"
    )

def init_db():
    """
    Creates the 'smartgrids' database if it doesn't exist, and builds
    all the necessary tables for tracking devices and attacks.
    """
    try:
        conn = get_base_connection()
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS smartgrids")
        conn.commit()
        conn.close()

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id VARCHAR(50) PRIMARY KEY,
                device_name VARCHAR(100),
                device_type VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authentication_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                device_id VARCHAR(50),
                token TEXT,
                issued_at TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS energy_readings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                device_id VARCHAR(50),
                consumption_kwh FLOAT,
                timestamp TIMESTAMP,
                signature VARCHAR(255),
                is_attack BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fdi_attacks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                device_id VARCHAR(50),
                consumption_kwh FLOAT,
                timestamp TIMESTAMP,
                detection_reason VARCHAR(255),
                FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crypto_attacks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                device_id VARCHAR(50),
                timestamp TIMESTAMP,
                signature VARCHAR(255),
                verification_status VARCHAR(50),
                FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            )
        """)

        conn.commit()
    except Exception as e:
        print(f"Database initialization failed: {e}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()

def get_connection():
    """Builds a connection specifically tied to the 'smartgrids' database."""
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="k123",
        database="smartgrids"
    )
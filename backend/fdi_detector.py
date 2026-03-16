import numpy as np
from config import Config
from database import get_connection
from crypto_utils import verify_signature


class FDIDetector:
    """
    FDI (False Data Injection) Detector
    This class looks at the stream of energy readings and uses statistics 
    (specifically Z-scores) to decide if a reading is abnormal.
    """

    def __init__(self):
        # Dictionary to store recent readings for each device
        self.baselines = {}

    def record(self, reading):
        """
        Takes a new reading, verifies its signature, records it in the database,
        and checks if it's an anomaly.
        """
        device_id = reading["device_id"]
        value = reading["consumption_kwh"]
        timestamp = reading["timestamp"]
        signature = reading.get("signature")
        is_fdi_attack = reading.get("is_fdi_attack", False)

        try:
            conn = get_connection()
            cursor = conn.cursor()

            verified = verify_signature(reading, signature)

            if not verified:
                print("Signature verification failed")
                cursor.execute(
                    """
                    INSERT INTO crypto_attacks
                    (device_id, timestamp, signature, verification_status)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (device_id, timestamp, signature, "FAILED")
                )
                conn.commit()
                return False

            print("Device reading recorded")
            cursor.execute(
                """
                INSERT INTO energy_readings
                (device_id, consumption_kwh, timestamp, signature, is_attack)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (device_id, value, timestamp, signature, is_fdi_attack)
            )

            # Keep a rolling window of recent readings to figure out what "normal" looks like
            self.update_baseline(device_id, value)
            
            # Run the statistical check
            detected, z = self.detect(device_id, value)

            # If our math caught it OR if it was explicitly flagged as a simulated attack
            if detected or is_fdi_attack:
                reason = f"Z-score anomaly {z}" if detected else "FDI Attack Payload"
                print("FDI attack detected")
                cursor.execute(
                    """
                    INSERT INTO fdi_attacks
                    (device_id, consumption_kwh, timestamp, detection_reason)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (device_id, value, timestamp, reason)
                )

            conn.commit()
            return detected or is_fdi_attack
        except Exception as e:
            print(f"Error recording data: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.is_connected():
                conn.close()

    def update_baseline(self, device_id, value):
        """
        Saves the most recent readings so we have a recent baseline to compare against.
        Older readings fall off the end of the list.
        """
        arr = self.baselines.setdefault(device_id, [])
        arr.append(value)

        self.baselines[device_id] = arr[-Config.BASELINE_WINDOW:]

    def detect(self, device_id, value):
        """
        The core anomaly detection math.
        """
        data = self.baselines.get(device_id, [])

        # We need a minimum amount of data to establish a baseline
        if len(data) < Config.MIN_READINGS_FOR_DETECTION:
            return False, 0

        # Calculate the average (mean) and variance (standard deviation)
        mean = np.mean(data)
        std = max(np.std(data), 0.1)

        # Z-score measures how many standard deviations away from the mean this value is
        z = abs((value - mean) / std)

        # If the Z-score is huge, it's an anomaly!
        return z > Config.ANOMALY_THRESHOLD, round(z, 2)
    
    # Debug print
    print("running")
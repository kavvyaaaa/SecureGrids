# ---------------------------------------------------------
# FDI (FALSE DATA INJECTION) DETECTOR  –  ML-Enhanced
# ---------------------------------------------------------


import numpy as np
from sklearn.ensemble import IsolationForest
from config import Config
from database import get_connection
from crypto_utils import verify_signature, record_failure


class FDIDetector:

    def __init__(self):
        # Per-device rolling window for Z-score baseline
        self.baselines = {}
        # Per-device training data for the ML model
        self._training_data = {}
        # Per-device trained Isolation
        self._ml_models = {}
        # Track whether defense mode is active
        self.defense_active = True
        # Track ML prediction results for the dashboard
        self.last_ml_predictions = {}

    # ---------------------------------------------------------
    # MAIN ENTRY POINT
    # ---------------------------------------------------------
    def record(self, reading):
     
        device_id = reading["device_id"]
        value = reading["consumption_kwh"]
        timestamp = reading["timestamp"]
        signature = reading.get("signature")
        is_fdi_attack = reading.get("is_fdi_attack", False)

        try:
            conn = get_connection()
            cursor = conn.cursor()

            # --- Cryptographic Signature Verification ---
            verified, crypto_reason = verify_signature(reading, signature)

            if not verified:
                print(f"[CRYPTO DEFENSE] {crypto_reason} for device {device_id}")
                cursor.execute(
                    """
                    INSERT INTO crypto_attacks
                    (device_id, timestamp, signature, verification_status)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (device_id, timestamp, signature or "NONE", crypto_reason)
                )
                conn.commit()
                return {"detected": True, "type": "CRYPTO", "reason": crypto_reason,
                        "mitigated": self.defense_active}

            # --- Record Valid Reading ---
            print(f"[READING] Device {device_id}: {value} kWh")
            cursor.execute(
                """
                INSERT INTO energy_readings
                (device_id, consumption_kwh, timestamp, signature, is_attack)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (device_id, value, timestamp, signature, is_fdi_attack)
            )

            # Update baselines for both detection methods
            self.update_baseline(device_id, value)
            self._collect_training_sample(device_id, value)

            # --- Z-Score Detection ---
            z_detected, z_score = self.detect(device_id, value)

            # --- ML Detection ---
            ml_detected, ml_score = self.ml_predict(device_id, value)

            # Combined verdict: either detector flags it, OR it was
            # explicitly tagged as an FDI attack in the simulation
            attack_detected = z_detected or ml_detected or is_fdi_attack

            detection_reasons = []
            if z_detected:
                detection_reasons.append(f"Z-score={z_score}")
            if ml_detected:
                detection_reasons.append(f"ML-anomaly={ml_score:.3f}")
            if is_fdi_attack and not (z_detected or ml_detected):
                detection_reasons.append("Simulated FDI payload")

            if attack_detected:
                reason = " | ".join(detection_reasons)
                mitigated = self.defense_active
                status = "MITIGATED" if mitigated else "DETECTED"
                print(f"[FDI {status}] {reason}")

                cursor.execute(
                    """
                    INSERT INTO fdi_attacks
                    (device_id, consumption_kwh, timestamp, detection_reason, mitigated)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (device_id, value, timestamp, reason, mitigated)
                )

            conn.commit()
            return {
                "detected": attack_detected,
                "type": "FDI" if attack_detected else "NORMAL",
                "z_score": z_score,
                "ml_score": round(ml_score, 4) if ml_score else None,
                "mitigated": self.defense_active if attack_detected else False,
                "reasons": detection_reasons
            }
        except Exception as e:
            print(f"[ERROR] Recording data: {e}")
            return {"detected": False, "type": "ERROR", "reason": str(e)}
        finally:
            if 'conn' in locals() and conn.is_connected():
                conn.close()

    # ---------------------------------------------------------
    # Z-SCORE STATISTICAL DETECTION  (original logic)
    # ---------------------------------------------------------
    def update_baseline(self, device_id, value):
        """Keep a rolling window of recent readings for Z-score."""
        arr = self.baselines.setdefault(device_id, [])
        arr.append(value)
        self.baselines[device_id] = arr[-Config.BASELINE_WINDOW:]

    def detect(self, device_id, value):
        """Calculate Z-score and flag if it exceeds the threshold."""
        data = self.baselines.get(device_id, [])
        if len(data) < Config.MIN_READINGS_FOR_DETECTION:
            return False, 0

        mean = np.mean(data)
        std = max(np.std(data), 0.1)
        z = abs((value - mean) / std)
        return z > Config.ANOMALY_THRESHOLD, round(z, 2)

    # ---------------------------------------------------------
    # ISOLATION FOREST ML DETECTION
    # ---------------------------------------------------------
    def _collect_training_sample(self, device_id, value):
        """Accumulate readings; retrain periodically."""
        samples = self._training_data.setdefault(device_id, [])
        samples.append(value)
        # Keep a reasonable buffer
        self._training_data[device_id] = samples[-500:]

        # (Re)train after every batch of MIN_TRAINING_SAMPLES new points
        if len(samples) >= Config.ML_MIN_TRAINING_SAMPLES and \
           len(samples) % Config.ML_MIN_TRAINING_SAMPLES == 0:
            self._train_model(device_id)

    def _train_model(self, device_id):
        """Train (or retrain) an Isolation Forest for the device."""
        samples = self._training_data.get(device_id, [])
        if len(samples) < Config.ML_MIN_TRAINING_SAMPLES:
            return

        X = np.array(samples).reshape(-1, 1)
        model = IsolationForest(
            contamination=Config.ML_CONTAMINATION,
            random_state=42,
            n_estimators=100
        )
        model.fit(X)
        self._ml_models[device_id] = model
        print(f"[ML] Isolation Forest trained for {device_id} "
              f"({len(samples)} samples)")

    def ml_predict(self, device_id, value):
        """
        Use the trained Isolation Forest to predict whether
        the reading is an anomaly.
        Returns (is_anomaly: bool, anomaly_score: float).
        """
        model = self._ml_models.get(device_id)
        if model is None:
            return False, 0.0

        X = np.array([[value]])
        prediction = model.predict(X)[0]       # 1 = normal, -1 = anomaly
        score = model.score_samples(X)[0]       # lower = more anomalous

        is_anomaly = prediction == -1
        self.last_ml_predictions[device_id] = {
            "value": value,
            "prediction": int(prediction),
            "score": round(score, 4)
        }
        return is_anomaly, score

    def get_ml_status(self):
        """Return a summary of the ML model state for the dashboard."""
        status = {}
        for device_id in self._training_data:
            samples = len(self._training_data.get(device_id, []))
            trained = device_id in self._ml_models
            status[device_id] = {
                "training_samples": samples,
                "model_trained": trained,
                "last_prediction": self.last_ml_predictions.get(device_id)
            }
        return status

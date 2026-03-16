from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:

    DATA_DIR = BASE_DIR / "data"

    NUM_DEVICES = 7
    READING_INTERVAL = 120

    DEVICE_TYPES = {
        "Residential": 30,
        "Commercial": 80,
        "Industrial": 150
    }

    BASELINE_WINDOW = 20
    ANOMALY_THRESHOLD = 2.5
    MIN_READINGS_FOR_DETECTION = 5

    TOKEN_VALIDITY_MINUTES = 5

    HOST = "0.0.0.0"
    PORT = 5000

    JWT_SECRET = "SUPER_SECRET_KEY_CHANGE_THIS"
    JWT_ALGORITHM = "HS256"

    SIGNATURE_SECRET = "SMART_GRID_SIGNATURE_KEY"

    FDI_MULTIPLIER_RANGE = (3.0, 5.0)
import random
from datetime import datetime
import numpy as np

from config import Config
from database import get_connection


class SmartMeter:
   
    def __init__(self, device_id, name, device_type):

        self.device_id = device_id
        self.name = name
        self.device_type = device_type
        self.base_consumption = Config.DEVICE_TYPES[device_type]

        self.token = None # Authentication token

    def generate_normal_consumption(self):
       
        multiplier = random.uniform(0.8, 1.2)
        noise = np.random.normal(0, 2)
        return round(self.base_consumption * multiplier + noise, 2)

    def generate_fdi_attack(self):
        
        m1, m2 = Config.FDI_MULTIPLIER_RANGE

        return round(self.base_consumption * random.uniform(m1, m2), 2)

    def get_reading(self, attack=False):

        value = (
            self.generate_fdi_attack()
            if attack
            else self.generate_normal_consumption()
        )

        return {
            "device_id": self.device_id,
            "consumption_kwh": value,
            "timestamp": datetime.now(),
            "is_fdi_attack": attack
        }


class DeviceManager:

    def __init__(self):

        self.devices = []
        self.init_devices()

    def init_devices(self):

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True) if hasattr(conn.cursor(), 'dictionary') else conn.cursor()

            # First, check if devices already exist in DB
            cursor.execute("SELECT device_id, device_name, device_type FROM devices")
            existing_devices = cursor.fetchall()

            if existing_devices:
                for row in existing_devices:
                    if isinstance(row, dict):
                        device_id = row['device_id']
                        device_name = row['device_name']
                        device_type = row['device_type']
                    else:
                        device_id = row[0]
                        device_name = row[1]
                        device_type = row[2]
                    
                    device = SmartMeter(device_id, device_name, device_type)
                    self.devices.append(device)
                    
                # If we have enough devices, we can return
                if len(self.devices) >= Config.NUM_DEVICES:
                    conn.close()
                    return
            
            # Generate missing devices
            num_to_generate = Config.NUM_DEVICES - len(self.devices)
            start_idx = len(self.devices)

            for i in range(num_to_generate):
                device_type = random.choice(list(Config.DEVICE_TYPES.keys()))
                idx = start_idx + i
                device_id = f"SM_{idx+1:03d}"

                device = SmartMeter(
                    device_id,
                    f"{device_type}_Meter_{idx}",
                    device_type
                )

                self.devices.append(device)

                cursor.execute(
                    """
                    INSERT IGNORE INTO devices
                    (device_id, device_name, device_type)
                    VALUES (%s,%s,%s)
                    """,
                    (device.device_id, device.name, device.device_type)
                )

            conn.commit()
        except Exception as e:
            print(f"Error initializing devices: {e}")
        finally:
            if 'conn' in locals() and conn.is_connected():
                conn.close()

    def get_all_devices(self):
        return self.devices

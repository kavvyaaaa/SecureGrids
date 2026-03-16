import random
from datetime import datetime
from crypto_utils import generate_signature


class AttackSimulator:

    def __init__(self, devices):
        self.devices = devices

    def trigger_fdi_attack(self):

        device = random.choice(self.devices.get_all_devices())

        reading = device.get_reading(True)

        reading["signature"] = generate_signature(reading)

        return reading

    def tamper_signature(self):

        device = random.choice(self.devices.get_all_devices())

        reading = device.get_reading(False)

        reading["signature"] = "TAMPERED_SIGNATURE"

        return reading
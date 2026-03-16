import requests
import json
import time

BASE_URL = "http://localhost:5000/api"

def test_endpoint(endpoint):
    url = f"{BASE_URL}{endpoint}"
    print(f"\n--- Testing GET {endpoint} ---")
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        try:
            print(json.dumps(response.json(), indent=2))
        except:
            print(response.text)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    time.sleep(1) # wait for server if just started
    test_endpoint("/health")
    test_endpoint("/devices")
    test_endpoint("/fdi-alerts")
    test_endpoint("/security-dashboard")
    test_endpoint("/trigger-fdi-attack")
    test_endpoint("/tamper-signature")
    
    # Wait a bit for db insertions from triggers
    time.sleep(1)
    test_endpoint("/security-dashboard")
    test_endpoint("/fdi-alerts")

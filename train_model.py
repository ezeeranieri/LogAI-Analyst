import os
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from src.config import MODEL_PATH
from src.features import extract_features

# --- Training Data Constants ---
# Synthetic IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
# Use wider ranges to prevent model from learning to discriminate by specific IP

def generate_ip_pool(base_octets, count):
    """Generates a pool of varied IPs to avoid overfitting by specific IP."""
    ips = []
    for i in range(count):
        last_octet = (i % 254) + 1  # 1-254
        third_octet = base_octets[0] + (i // 254) % 10
        if third_octet > 255:
            third_octet = base_octets[0]
        ips.append(f"192.0.{third_octet}.{last_octet}")
    return ips

# Generate large IP pools to prevent model from memorizing specific IPs
NORMAL_IP_POOL = generate_ip_pool([2], 50)  # 50 different IPs for normal traffic
ANOMALY_IP_POOL = generate_ip_pool([50], 30)  # 30 different IPs for anomalies

# User pools to simulate more realistic behavior
NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "henry"]
ADMIN_USERS = ["admin", "root", "sysadmin", "webmaster"]

def generate_synthetic_data(n_samples=3000):
    """
    Generates synthetic log data for training.
    - Normal: 95% of data (Business hours, varied IPs, SUCCESS predominant).
    - Anomalies: 5% of data (atypical behavior: timing, auth patterns, etc).
    
    Realism improvements:
    - Includes varied users to detect probing
    - Simulates request bursts (timing anomalies)
    - Sophisticated attacks during business hours (not just midnight)
    - Multiple normal IPs can generate legitimate fail traffic (typos)
    
    Model learns behavior patterns beyond hour+status.
    """
    print(f"Generating {n_samples} synthetic data samples...")
    print(f"Normal IP pool: {len(NORMAL_IP_POOL)} IPs")
    print(f"Anomaly IP pool: {len(ANOMALY_IP_POOL)} IPs")
    
    data = []
    base_time = datetime.now()
    
    for i in range(n_samples):
        is_anomaly = np.random.random() < 0.05
        
        if not is_anomaly:
            # Normal data: realistic behavior
            hour = np.random.randint(8, 18)
            ip = np.random.choice(NORMAL_IP_POOL)
            user = np.random.choice(NORMAL_USERS)
            status = "SUCCESS" if np.random.random() < 0.95 else "FAIL"
            accion = f"Login attempt for user {user}"
            minute_offset = np.random.randint(0, 60)
            
        else:
            # Anomalies: various types of suspicious behavior
            anomaly_type = np.random.random()
            
            if anomaly_type < 0.3:
                # Type 1: Timing anomaly (request burst) -> High requests_per_minute
                hour = np.random.randint(0, 24)
                ip = np.random.choice(ANOMALY_IP_POOL)
                user = np.random.choice(NORMAL_USERS)
                status = "FAIL"
                accion = "Failed password authentication"
                # Burst timing: multiple requests in same minute (will be handled by loop index i)
                minute_offset = i % 60
                
            elif anomaly_type < 0.6:
                # Type 2: User probing -> High unique_users_per_ip
                hour = np.random.randint(0, 24)
                ip = np.random.choice(ANOMALY_IP_POOL)
                user = np.random.choice(NORMAL_USERS + ADMIN_USERS + ["guest", "test", "support"])
                status = "FAIL"
                accion = f"Invalid user {user}"
                minute_offset = np.random.randint(0, 60)
                
            else:
                # Type 3: Payload anomaly -> High url_entropy
                hour = np.random.randint(0, 24)
                ip = np.random.choice(ANOMALY_IP_POOL)
                user = "admin"
                status = "FAIL"
                # Complex/Random payload strings to trigger Shannon Entropy
                payloads = [
                    "GET /admin?id=1' OR '1'='1",
                    "POST /api/v1/exec?cmd=rm%20-rf%20/",
                    "GET /wp-content/plugins/revslider/temp/update_extract/revslider/ps_functions.php",
                    "GET /?<script>alert(z1)</script>"
                ]
                accion = np.random.choice(payloads)
                minute_offset = np.random.randint(0, 60)
            
        dt = base_time - timedelta(minutes=i//5) # 5 requests per minute avg
        dt = dt.replace(hour=hour, minute=minute_offset, second=np.random.randint(0, 60))
        
        data.append({
            'datetime': dt,
            'ip_origen': ip,
            'usuario': user,
            'status': status,
            'accion': accion,
            'url': accion if "GET" in str(accion) or "POST" in str(accion) else "/"
        })
        
    return pd.DataFrame(data)

# Note: extract_features is now imported from src.features to ensure
# training and inference use identical feature engineering

def train():
    # 1. Prepare data
    df = generate_synthetic_data()
    X = extract_features(df)
    
    # 2. Train Isolation Forest
    # Use same parameters as original detector
    print("Training Isolation Forest model...")
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    
    # 3. Save model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved successfully to: {MODEL_PATH}")

if __name__ == "__main__":
    train()

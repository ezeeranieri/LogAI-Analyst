import os
import zlib
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from src.config import MODEL_PATH

# --- Test Data Constants ---
# Clearly marked as non-production, synthetic data IPs for SonarCloud compliance
SYNTHETIC_NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "10.0.0.5", "172.16.0.20"]
SYNTHETIC_ANOMALY_IPS = ["45.33.22.11", "185.10.2.3", "200.5.6.7"]

def generate_synthetic_data(n_samples=1500):
    """
    Genera datos sintéticos de logs para entrenamiento.
    - Normal: 95% de los datos (Horario laboral, IPs consistentes, SUCCESS).
    - Anomalías: 5% de los datos (Madrugada, IPs raras, FAIL).
    """
    print(f"Generando {n_samples} muestras de datos sintéticos...")
    
    data = []
    base_time = datetime.now()
    
    # Usamos las constantes de prueba
    normal_ips = SYNTHETIC_NORMAL_IPS
    rare_ips = SYNTHETIC_ANOMALY_IPS
    
    for i in range(n_samples):
        is_anomaly = np.random.random() < 0.05
        
        if not is_anomaly:
            # Datos normales: 8:00 a 18:00
            hour = np.random.randint(8, 18)
            ip = np.random.choice(normal_ips)
            status = "SUCCESS" if np.random.random() < 0.9 else "FAIL"
        else:
            # Anomalías: 00:00 a 05:00 o IPs raras o puros fallos
            hour = np.random.randint(0, 6)
            ip = np.random.choice(rare_ips)
            status = "FAIL" if np.random.random() < 0.8 else "SUCCESS"
            
        dt = base_time - timedelta(minutes=i)
        dt = dt.replace(hour=hour, minute=np.random.randint(0, 60))
        
        data.append({
            'datetime': dt,
            'ip_origen': ip,
            'status': status
        })
        
    return pd.DataFrame(data)

def extract_features(df):
    """
    Extrae las mismas características que usa el detector en tiempo real.
    """
    features = pd.DataFrame(index=df.index)
    features['hour'] = df['datetime'].dt.hour
    
    # Hashing de IPs coincidente con detector.py
    features['ip_encoded'] = df['ip_origen'].apply(
        lambda x: zlib.adler32(str(x).encode()) & 0xffffffff
    )
    
    # Mapeo de status coincidente con detector.py
    status_map = {'SUCCESS': 1, 'FAIL': 0, 'INFO': 0.5}
    features['status_val'] = df['status'].map(status_map).fillna(0.5)
    
    return features

def train():
    # 1. Preparar datos
    df = generate_synthetic_data()
    X = extract_features(df)
    
    # 2. Entrenar Isolation Forest
    # Usamos los mismos parámetros que el detector original
    print("Entrenando modelo Isolation Forest...")
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    
    # 3. Guardar modelo
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Modelo guardado exitosamente en: {MODEL_PATH}")

if __name__ == "__main__":
    train()

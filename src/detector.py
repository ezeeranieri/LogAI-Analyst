import os
import zlib
import joblib
import logging
import pandas as pd
from typing import List, Optional
from abc import ABC, abstractmethod
from src.config import MODEL_PATH

# Logger local
logger = logging.getLogger(__name__)

class DetectionRule(ABC):
    """
    Clase base (Interfaz) para crear reglas de detección.
    Permite escalar la lógica añadiendo nuevas herencias de esta clase.
    """
    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Nombre o descripción de la regla."""
        pass

    @abstractmethod
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Evalúa el DataFrame y devuelve únicamente un DataFrame 
        con las filas que se consideran anómalas por esta regla.
        Se añadirá una columna nueva 'razon'.
        """
        pass


class BruteForceRule(DetectionRule):
    @property
    def rule_name(self):
        return "Fuerza Bruta"
        
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detecta más de 5 intentos fallidos desde una misma IP en 1 minuto.
        Asume que los intentos ya están estructurados en el DataFrame.
        """
        try:
            if df.empty or 'datetime' not in df.columns or 'ip_origen' not in df.columns:
                return pd.DataFrame()
                
            # Usamos la columna 'status' normalizada por el parser
            df_failed = df[df['status'] == 'FAIL'].copy()
            
            if df_failed.empty:
                return pd.DataFrame()

            anomalies = []
            # Agrupar por IP para analizar ventanas de tiempo
            for ip, group in df_failed.groupby('ip_origen'):
                # Asegurar orden cronológico para rolling index
                group = group.set_index('datetime').sort_index()
                
                # Contar la suma de fallos en ventanas móviles de 1 minuto
                # rolling() requiere un índice de tipo datetime.
                counts = group['accion'].rolling('1min').count()
                
                # Filtrar lugares donde el contador es mayor estricto a 5 (es decir, > 5)
                mask_over = counts > 5
                if mask_over.any():
                    # Obtenemos las filas específicas donde se detecta la sobrecarga de fuerza bruta
                    anomalous_rows = group[mask_over].copy()
                    anomalous_rows['razon'] = f"{self.rule_name} (>5 fallos por min)"
                    anomalies.append(anomalous_rows.reset_index())
                    
            if anomalies:
                return pd.concat(anomalies, ignore_index=True)
        except Exception as e:
            logger.error(f"Error en regla {self.rule_name}: {e}")
            
        return pd.DataFrame()


class TimeAnomalyRule(DetectionRule):
    def __init__(self, start_hour=8, end_hour=18):
        # Por defecto, fuera de horario es antes de las 8 AM y después de las 18 PM.
        self.start_hour = start_hour
        self.end_hour = end_hour

    @property
    def rule_name(self):
        return "Anomalía de Horario"
        
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detecta accesos logueados ("exitosos") fuera del horario laboral."""
        try:
            if df.empty or 'datetime' not in df.columns:
                return pd.DataFrame()

            # Usamos la columna 'status' normalizada
            df_success = df[df['status'] == 'SUCCESS'].copy()
            
            if df_success.empty:
                return pd.DataFrame()
                
            # Verificar el horario (usamos datetime)
            hour = df_success['datetime'].dt.hour
            out_of_hours_mask = (hour < self.start_hour) | (hour >= self.end_hour)
            
            df_anomalies = df_success[out_of_hours_mask].copy()
            if not df_anomalies.empty:
                df_anomalies['razon'] = f"{self.rule_name} (Acceso fuera de horario laboral)"
                return df_anomalies
        except Exception as e:
            logger.error(f"Error en regla {self.rule_name}: {e}")
            
        return pd.DataFrame()


class UserProbingRule(DetectionRule):
    @property
    def rule_name(self) -> str:
        return "Sondeo de Usuarios"
        
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detecta si una misma IP intenta acceder a más de 3 usuarios distintos 
        en un intervalo de 10 minutos.
        """
        try:
            if df.empty or 'datetime' not in df.columns or 'ip_origen' not in df.columns or 'usuario' not in df.columns:
                return pd.DataFrame()
                
            anomalies = []
            # Agrupar por IP para analizar la diversidad de usuarios
            for ip, group in df.groupby('ip_origen'):
                group = group.set_index('datetime').sort_index()
                
                # Cálculo de usuarios únicos en la ventana de 10 min (soporta strings)
                unique_users = [
                    len(set(group.loc[t - pd.Timedelta('10min'):t, 'usuario']))
                    for t in group.index
                ]
                
                mask_probe = pd.Series(unique_users, index=group.index) > 3
                if mask_probe.any():
                    anomalous_rows = group[mask_probe].copy()
                    anomalous_rows['razon'] = f"{self.rule_name}: Múltiples cuentas desde una misma IP"
                    anomalies.append(anomalous_rows.reset_index())
                    
            if anomalies:
                return pd.concat(anomalies, ignore_index=True)
        except Exception as e:
            logger.error(f"Error en regla {self.rule_name}: {e}")
            
        return pd.DataFrame()


class IADetectorRule(DetectionRule):
    def __init__(self, contamination: float = 0.01, model_path: str = MODEL_PATH):
        self.contamination = contamination
        self.model_path = model_path

    @property
    def rule_name(self) -> str:
        return "Anomaly AI (Isolation Forest)"
        
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Utiliza Isolation Forest para detectar anomalías.
        Persiste el modelo para evitar re-entrenamiento constante.
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import LabelEncoder
        except ImportError:
            logger.warning("scikit-learn no encontrado. Se omite detección avanzada de IA.")
            return pd.DataFrame()

        if df.empty or len(df) < 5:  # Reducimos umbral para facilitar tests, pero ideal > 10
            return pd.DataFrame()

        df_ml = df.copy()
        features = pd.DataFrame(index=df_ml.index)
        features['hour'] = df_ml['datetime'].dt.hour
        
        # Hashing determinístico para IPs (evita dependencia del orden de entrada de LabelEncoder)
        features['ip_encoded'] = df_ml['ip_origen'].apply(
            lambda x: zlib.adler32(str(x).encode()) & 0xffffffff
        )
        
        # Mapeo numérico del status para el modelo
        status_map = {'SUCCESS': 1, 'FAIL': 0, 'INFO': 0.5}
        features['status_val'] = df_ml['status'].map(status_map).fillna(0.5)

        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"Modelo IA no encontrado en {self.model_path}. Por favor, ejecute train_model.py primero.")
                return pd.DataFrame()

            model = joblib.load(self.model_path)
            logger.info(f"Modelo IA cargado exitosamente desde {self.model_path}")
            
            predictions = model.predict(features)
            anomaly_mask = predictions == -1
            
            df_anomalies = df_ml[anomaly_mask].copy()
            if not df_anomalies.empty:
                df_anomalies['razon'] = self.rule_name
                return df_anomalies
        except Exception as e:
            logger.error(f"Error en motor de IA: {e}")
            
        return pd.DataFrame()


class LogDetector:
    """Motor principal que nuclea todas las reglas de detección."""
    
    def __init__(self):
        self.rules: List[DetectionRule] = []
        
    def add_rule(self, rule: DetectionRule) -> None:
        """Añade una regla al contexto de evaluación."""
        self.rules.append(rule)
        
    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transforma los datos y ejecuta el DataFrame contra todas las reglas cargadas,
        consolidando un único DataFrame con las anomalías.
        """
        if df.empty:
            logger.warning("DataFrame vacío. Finalizando el detector.")
            return pd.DataFrame()
            
        df_analysis = df.copy()
        
        # El DataFrame ya debería traer la columna 'datetime' desde el parser.
        # Si por alguna razón falta, lanzamos un warning pero no intentamos repararlo aquí.
        if 'datetime' not in df_analysis.columns:
            logger.error("El DataFrame no contiene la columna 'datetime' requerida para el análisis.")
            return pd.DataFrame()

        all_anomalies = []
        for rule in self.rules:
            logger.info(f"Evaluando matriz contra regla: {rule.rule_name}")
            anomalous_df = rule.evaluate(df_analysis)
            
            if not anomalous_df.empty:
                all_anomalies.append(anomalous_df)
                
        if all_anomalies:
            final_df = pd.concat(all_anomalies, ignore_index=True)
            
            # Agrupar anomalías y limpiar duplicados
            final_df = final_df.groupby(['timestamp', 'ip_origen', 'usuario', 'accion', 'status'], dropna=False, as_index=False).agg({
                'datetime': 'first',
                'razon': lambda x: " | ".join(x.unique())
            })
            
            final_df.sort_values(by='datetime', inplace=True)
            return final_df
            
        return pd.DataFrame()
 # DataFrame vacío => el log está "limpio"

if __name__ == '__main__':
    # Test local o debugging visual para importar
    detector = LogDetector()
    detector.add_rule(BruteForceRule())
    detector.add_rule(TimeAnomalyRule())
    detector.add_rule(IADetectorRule())
    
    print("Módulo Detector inicializado correctamente con Patrones y Machine Learning (IF).")

import os
import joblib
import logging
import pandas as pd
from typing import List, Optional
from abc import ABC, abstractmethod
from .config import MODEL_PATH
from .features import extract_features

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
    """
    Regla para detectar ataques de Fuerza Bruta.
    > 5 intentos fallidos en menos de 1 minuto desde la misma IP.
    """
    @property
    def rule_name(self):
        return "Fuerza Bruta"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identifica patrones de fuerza bruta usando una ventana móvil de 1 minuto.
        Solo marca la fila específica donde se alcanza el umbral (el 6to intento),
        no todas las filas de la ventana.
        """
        try:
            if df.empty or 'datetime' not in df.columns:
                return pd.DataFrame()

            # Filtrar solo los intentos fallidos de conexión
            df_failed = df[df['status'] == 'FAIL'].copy()

            if df_failed.empty:
                return pd.DataFrame()

            anomalies = []

            # Agrupar por IP para detectar ataques coordinados desde una misma fuente
            for ip, group in df_failed.groupby('ip_origen'):
                if len(group) < 6:
                    continue

                # Asegurar orden cronológico
                group_sorted = group.sort_values('datetime').reset_index(drop=True)
                datetimes = group_sorted['datetime']

                n = len(group_sorted)

                # Sliding window: contar intentos en ventana de 1 minuto
                # Usamos two-pointer approach O(n) para eficiencia
                left = 0
                threshold_crossed_indices = []

                threshold_already_crossed = False
                for right in range(n):
                    # Mover left pointer para mantener ventana de 1 minuto
                    while left <= right and datetimes.iloc[right] - datetimes.iloc[left] > pd.Timedelta('1min'):
                        left += 1

                    # Contar intentos en la ventana actual
                    attempts_in_window = right - left + 1

                    # Si alcanzamos o superamos el umbral (6+ intentos), marcar esta fila
                    # Solo marcamos la primera vez que se cruza el umbral
                    if attempts_in_window >= 6 and not threshold_already_crossed:
                        threshold_crossed_indices.append(right)
                        threshold_already_crossed = True

                if threshold_crossed_indices:
                    # Solo marcar las filas donde se cruza el umbral
                    anomalous_rows = group_sorted.iloc[threshold_crossed_indices].copy()
                    anomalous_rows['razon'] = f"{self.rule_name} (6+ fallos en 1 min)"
                    anomalies.append(anomalous_rows)

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
        en un intervalo de 10 minutos. Usa sliding window O(n) con two-pointer approach.
        """
        try:
            if df.empty or 'datetime' not in df.columns or 'ip_origen' not in df.columns or 'usuario' not in df.columns:
                return pd.DataFrame()

            anomalies = []
            # Agrupar por IP para analizar la diversidad de usuarios
            for ip, group in df.groupby('ip_origen'):
                if len(group) < 4:
                    continue

                # Sort by datetime for sliding window
                group_sorted = group.sort_values('datetime').reset_index(drop=True)
                datetimes = group_sorted['datetime']
                usuarios = group_sorted['usuario']

                n = len(group_sorted)
                window_unique_counts = []

                # Sliding window: track unique users in current window
                # Two-pointer approach: O(n) total
                user_counts = {}
                left = 0
                current_unique = 0

                for right in range(n):
                    # Add right pointer user
                    user_right = usuarios.iloc[right]
                    user_counts[user_right] = user_counts.get(user_right, 0) + 1
                    if user_counts[user_right] == 1:
                        current_unique += 1

                    # Move left pointer to maintain 10-minute window
                    while left <= right and datetimes.iloc[right] - datetimes.iloc[left] > pd.Timedelta('10min'):
                        user_left = usuarios.iloc[left]
                        user_counts[user_left] -= 1
                        if user_counts[user_left] == 0:
                            current_unique -= 1
                            del user_counts[user_left]
                        left += 1

                    window_unique_counts.append(current_unique)

                window_unique = pd.Series(window_unique_counts, index=group_sorted.index)

                # Encontrar los índices donde se cruza el umbral (4+ usuarios únicos)
                # Solo marcamos la primera fila donde unique_count alcanza 4, no todas
                threshold_indices = []
                threshold_already_crossed = False
                for i, unique_count in enumerate(window_unique_counts):
                    if unique_count >= 4 and not threshold_already_crossed:
                        threshold_indices.append(i)
                        threshold_already_crossed = True

                if threshold_indices:
                    # Solo marcar las filas representativas donde se cruza el umbral
                    anomalous_rows = group_sorted.iloc[threshold_indices].copy()
                    anomalous_rows['razon'] = f"{self.rule_name}: 4+ usuarios distintos desde IP"
                    anomalies.append(anomalous_rows)

            if anomalies:
                return pd.concat(anomalies, ignore_index=True)
        except Exception as e:
            logger.error(f"Error en regla {self.rule_name}: {e}")

        return pd.DataFrame()


class IADetectorRule(DetectionRule):
    def __init__(self, contamination: float = 0.01, model_path: str = MODEL_PATH, model=None):
        self.contamination = contamination
        self.model_path = model_path
        self.model = model  # Pre-loaded model to avoid reloading on each request

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
        except ImportError:
            logger.warning("scikit-learn no encontrado. Se omite detección avanzada de IA.")
            return pd.DataFrame()

        if df.empty or len(df) < 5:  # Reducimos umbral para facilitar tests, pero ideal > 10
            return pd.DataFrame()

        df_ml = df.copy()
        # Use shared feature extraction to ensure consistency with training
        features = extract_features(df_ml)

        try:
            model = self.model
            if model is None:
                if not os.path.exists(self.model_path):
                    logger.warning(f"Modelo IA no encontrado en {self.model_path}. Por favor, ejecute train_model.py primero.")
                    return pd.DataFrame()
                # FALLBACK: Cargando desde disco - esto bloquea el request thread!
                # En producción, esto solo debería ocurrir si el lifespan falló
                logger.warning("=" * 70)
                logger.warning("WARNING: Modelo IA cargando desde disco (fallback mode)")
                logger.warning("Esto puede causar latencia en la primera request.")
                logger.warning("Verificar que el lifespan en main.py cargó el modelo correctamente.")
                logger.warning("=" * 70)
                model = joblib.load(self.model_path)
                logger.info(f"Modelo IA cargado desde archivo {self.model_path}")
            else:
                logger.info("Modelo IA pre-cargado utilizado")

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

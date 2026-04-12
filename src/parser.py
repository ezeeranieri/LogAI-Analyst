import pandas as pd
import re
import logging
from typing import List, Dict, Optional

# Configuración de logger local para el módulo
logger = logging.getLogger(__name__)

class AuthLogParser:
    """
    Clase para parsear archivos de logs de sistemas UNIX (Syslog, Auth.log).
    Extrae el Timestamp, la IP de origen, el Usuario y la Acción realizada.
    """
    
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        
        # Expresión regular principal para el formato típico de syslog
        # Ejemplo: "Oct 11 10:00:00 servername sshd[123]: Failed password for root from 192.168.1.1"
        self.syslog_pattern = re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"  # Timestamp (ej. Oct 11 10:00:00)
            r"(?P<hostname>\S+)\s+"                                       # Hostname
            r"(?P<process>[^:]+):\s+"                                    # Proceso / Servicio (ej. sshd[123])
            r"(?P<action>.*)$"                                           # Mensaje principal (Acción)
        )
        
        # Regex secundaria para extraer cualquier IP (IPv4) del mensaje
        self.ip_pattern = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")
        
        # Regex secundaria para extraer el nombre de usuario (basado en patrones comunes de autenticación)
        self.user_pattern = re.compile(r"(?:user\s+|for\s+(?:invalid user\s+)?|user=)(?P<user>[a-zA-Z0-9_.-]+)")

    def _parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Aplica las expresiones regulares a una línea de texto del log.
        """
        match = self.syslog_pattern.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        action_msg = data['action']
        
        # Intentar encontrar una IP dentro del mensaje de acción
        ip_match = self.ip_pattern.search(action_msg)
        ip_address = ip_match.group('ip') if ip_match else None
        
        # Intentar encontrar un usuario dentro del mensaje de acción
        user_match = self.user_pattern.search(action_msg)
        user = user_match.group('user') if user_match else None
        
        # Normalización del status basado en el mensaje
        status = "INFO"
        action_lower = action_msg.lower()
        if any(term in action_lower for term in ['fail', 'invalid', 'error', 'denied', 'refused']):
            status = "FAIL"
        elif any(term in action_lower for term in ['accept', 'success', 'granted', 'opened']):
            status = "SUCCESS"
        
        return {
            'timestamp': data['timestamp'],
            'ip_origen': ip_address,
            'usuario': user,
            'accion': action_msg,
            'status': status
        }

    def parse(self) -> pd.DataFrame:
        """
        Abre el archivo de log, lo procesa línea por línea previniendo errores,
        y devuelve todas las coincidencias tabuladas en un DataFrame de Pandas.
        """
        parsed_data: List[Dict[str, str]] = []
        
        try:
            # Usando utf-8 con ignore/replace por si el archivo presenta caracteres corruptos en algunas líneas
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    parsed_line = self._parse_line(line)
                    if parsed_line:
                        parsed_data.append(parsed_line)
                        
        except FileNotFoundError:
            logger.error(f"Error: El archivo de log '{self.file_path}' no fue encontrado.")
        except PermissionError:
            logger.error(f"Error: Permisos insuficientes para leer '{self.file_path}'.")
        except UnicodeDecodeError:
            logger.error(f"Error crítico: El archivo '{self.file_path}' está corrupto o es binario.")
        except Exception as e:
            logger.error(f"Error inesperado procesando el archivo '{self.file_path}': {e}")
            
        # Devolvemos el DataFrame con los datos extraídos
        df = pd.DataFrame(parsed_data)
        
        # Asegurarse de que el DF devuelto al menos contenga las columnas esperadas aunque esté vacío
        if df.empty:
            df = pd.DataFrame(columns=['timestamp', 'datetime', 'ip_origen', 'usuario', 'accion', 'status'])
            logger.warning("No se encontraron registros válidos o el archivo estaba vacío/corrupto.")
            return df

        # Conversión a datetime y corrección de año
        try:
            # Especificar formato para syslog estándar para mayor robustez en CI
            # Los formatos comunes son "Oct 11 10:00:00" (%b %d %H:%M:%S)
            df['datetime'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
            
            # Fallback si no pudo parsear con el formato explícito (ej. formatos no estándar)
            if df['datetime'].isna().all():
                df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')

            # Limpieza: Dropear filas que no tienen fecha válida (no se pueden analizar por reglas de tiempo)
            if df['datetime'].isna().any():
                count_na = df['datetime'].isna().sum()
                df = df.dropna(subset=['datetime']).copy()
                logger.warning(f"Se eliminaron {count_na} registros con timestamps ilegibles.")

            if not df.empty:
                current_year = pd.Timestamp.now().year
                df['datetime'] = df['datetime'].apply(
                    lambda x: x.replace(year=current_year) if pd.notnull(x) and x.year == 1900 else x
                )
        except Exception as e:
            logger.error(f"Error procesando la columna de fechas: {e}")
            # Si hay un error catastrófico en la conversión, devolvemos un DF vacío para evitar crasheos posteriores
            return pd.DataFrame(columns=['timestamp', 'datetime', 'ip_origen', 'usuario', 'accion', 'status'])

        return df

if __name__ == '__main__':
    # Test rápido de estructura
    print("Parser listo para integración API.")

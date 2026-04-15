import pandas as pd
import re
import logging
from typing import List, Dict, Optional, Tuple

# Configuración de logger local para el módulo
logger = logging.getLogger(__name__)

class AuthLogParser:
    """
    Clase para parsear archivos de logs de sistemas UNIX (Syslog, Auth.log).
    Extrae: Timestamp, Hostname, Proceso, PID, IP de origen, Usuario, Acción y Status.
    Soporta múltiples formatos comunes de sshd, PAM, sudo, etc.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.lines_read = 0
        self.lines_parsed = 0
        self.lines_discarded = 0

        # Expresión regular principal para el formato típico de syslog
        # Ejemplo: "Oct 11 10:00:00 servername sshd[123]: Failed password for user from <IP>"
        self.syslog_pattern = re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"  # Timestamp (ej. Oct 11 10:00:00)
            r"(?P<hostname>\S+)\s+"                                       # Hostname
            r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"               # Proceso y PID opcional (sshd[123])
            r"(?P<action>.*)$"                                           # Mensaje principal (Acción)
        )

        # Regex secundaria para extraer cualquier IP (IPv4) del mensaje
        self.ip_pattern = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")

        # Regex mejorada para extraer usuario - soporta múltiples formatos
        # Formatos: "user xxx", "for user", "for invalid user xxx", "user=xxx", "PAM: ... user xxx"
        self.user_pattern = re.compile(
            r"(?:user\s+(?:'=?'?)?|for\s+(?:invalid\s+)?user\s+|user\s*[=:]\s*)(?P<user>[a-zA-Z0-9_.-]+)",
            re.IGNORECASE
        )

        # Patrones específicos para formatos comunes de auth.log
        self.patterns = {
            'invalid_user': re.compile(r"invalid\s+user\s+(?P<user>\S+)", re.IGNORECASE),
            'failed_password': re.compile(r"failed\s+password\s+(?:for\s+)?(?:invalid\s+user\s+)?(?P<user>\S*)", re.IGNORECASE),
            'accepted_password': re.compile(r"accepted\s+password\s+for\s+(?P<user>\S+)", re.IGNORECASE),
            'session_opened': re.compile(r"session\s+opened\s+for\s+user\s+(?P<user>\S+)", re.IGNORECASE),
            'session_closed': re.compile(r"session\s+closed\s+for\s+user\s+(?P<user>\S+)", re.IGNORECASE),
            'authentication_failure': re.compile(r"authentication\s+failure", re.IGNORECASE),
            'pam_auth': re.compile(r"pam_\w+\(.*?\):\s+authentication\s+(?P<result>\w+)", re.IGNORECASE),
        }

    def _extract_user(self, action_msg: str) -> Optional[str]:
        """Extrae el usuario del mensaje usando múltiples patrones."""
        # Probar patrones específicos primero
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(action_msg)
            if match:
                user = match.groupdict().get('user')
                if user:
                    return user

        # Fallback al patrón general
        user_match = self.user_pattern.search(action_msg)
        if user_match:
            return user_match.group('user')

        return None

    def _determine_status(self, action_msg: str, process: str) -> str:
        """Determina el status basado en el contenido del mensaje."""
        action_lower = action_msg.lower()
        process_lower = process.lower()

        # Patrones de éxito
        success_terms = ['accept', 'success', 'granted', 'opened', 'authorized', 'authenticated']
        # Patrones de fallo
        fail_terms = ['fail', 'invalid', 'error', 'denied', 'refused', 'incorrect', 'bad', 'not allowed']
        # Patrones específicos de PAM/sshd
        if 'pam' in process_lower or 'sshd' in process_lower:
            if re.search(r'\b(accepted|opened|session opened)\b', action_lower):
                return "SUCCESS"
            if re.search(r'\b(failed|invalid|authentication failure|closed|rejected)\b', action_lower):
                return "FAIL"

        if any(term in action_lower for term in fail_terms):
            return "FAIL"
        if any(term in action_lower for term in success_terms):
            return "SUCCESS"

        return "INFO"

    def _parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Aplica las expresiones regulares a una línea de texto del log.
        """
        match = self.syslog_pattern.match(line)
        if not match:
            return None

        data = match.groupdict()
        action_msg = data['action']
        process = data.get('process', '')
        pid = data.get('pid')

        # Intentar encontrar una IP dentro del mensaje de acción
        ip_match = self.ip_pattern.search(action_msg)
        ip_address = ip_match.group('ip') if ip_match else None

        # Extraer usuario usando múltiples patrones
        user = self._extract_user(action_msg)

        # Determinar status
        status = self._determine_status(action_msg, process)

        return {
            'timestamp': data['timestamp'],
            'hostname': data['hostname'],
            'process': process,
            'pid': pid,
            'ip_origen': ip_address,
            'usuario': user,
            'accion': action_msg,
            'status': status
        }

    def get_stats(self) -> Dict[str, int]:
        """Devuelve estadísticas del último parsing."""
        return {
            'lines_read': self.lines_read,
            'lines_parsed': self.lines_parsed,
            'lines_discarded': self.lines_discarded,
            'parse_rate': (self.lines_parsed / self.lines_read * 100) if self.lines_read > 0 else 0
        }

    def parse(self) -> pd.DataFrame:
        """
        Abre el archivo de log, lo procesa línea por línea previniendo errores,
        y devuelve todas las coincidencias tabuladas en un DataFrame de Pandas.

        Logs estadísticas de líneas parseadas vs descartadas.
        """
        parsed_data: List[Dict[str, str]] = []
        self.lines_read = 0
        self.lines_parsed = 0
        self.lines_discarded = 0

        try:
            # Usando utf-8 con ignore/replace por si el archivo presenta caracteres corruptos
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, start=1):
                    self.lines_read += 1
                    line = line.strip()
                    if not line:
                        continue

                    parsed_line = self._parse_line(line)
                    if parsed_line:
                        parsed_data.append(parsed_line)
                        self.lines_parsed += 1
                    else:
                        self.lines_discarded += 1

            # Log estadísticas
            stats = self.get_stats()
            logger.info(f"Parsing completado: {stats['lines_read']} líneas leídas, "
                       f"{stats['lines_parsed']} parseadas ({stats['parse_rate']:.1f}%), "
                       f"{stats['lines_discarded']} descartadas")

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
            df = pd.DataFrame(columns=['timestamp', 'datetime', 'hostname', 'process', 'pid', 'ip_origen', 'usuario', 'accion', 'status'])
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
                # Inferir año correctamente para evitar problemas de跨年
                # Si el mes del log es posterior al mes actual, asumimos el año pasado
                from datetime import datetime
                current_date = datetime.now()

                def infer_year(log_date, current_date):
                    """Infiere el año correcto basado en la fecha actual y el mes del log.

                    Maneja dos edge cases:
                    1. Log de diciembre analizado en enero → año anterior
                    2. Log de enero analizado en diciembre → año actual (si diff < 6 meses)
                       o año anterior (si log es muy viejo, diff > 6 meses)
                    """
                    if pd.isnull(log_date):
                        return log_date

                    log_month = log_date.month
                    current_month = current_date.month

                    # Calcular diferencia de meses considerando el ciclo anual
                    month_diff = (current_month - log_month) % 12

                    # Si la diferencia es > 6 meses, asumimos que el log es del año pasado
                    # Esto maneja: Dec→Jan (diff=1, year-1) y Jan→Dec (diff=11, year-1 si log viejo)
                    if month_diff > 6:
                        # Log es de hace más de 6 meses → año pasado
                        return log_date.replace(year=current_date.year - 1)
                    elif log_month > current_month:
                        # Log de mes posterior en el calendario (ej: Dec en Jan)
                        return log_date.replace(year=current_date.year - 1)
                    else:
                        # Log reciente del año actual
                        return log_date.replace(year=current_date.year)

                df['datetime'] = df['datetime'].apply(
                    lambda x: infer_year(x, current_date) if pd.notnull(x) and x.year == 1900 else x
                )
        except Exception as e:
            logger.error(f"Error procesando la columna de fechas: {e}")
            # Si hay un error catastrófico en la conversión, devolvemos un DF vacío para evitar crasheos posteriores
            return pd.DataFrame(columns=['timestamp', 'datetime', 'hostname', 'process', 'pid', 'ip_origen', 'usuario', 'accion', 'status'])

        return df

if __name__ == '__main__':
    # Test rápido de estructura
    print("Parser listo para integración API.")

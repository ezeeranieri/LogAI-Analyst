import os
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env si existe
load_dotenv()

# Configuración de Seguridad
# Se recomienda usar un valor largo y complejo en producción vía .env
API_KEY = os.getenv("API_KEY", "dev-secret-key-12345")

# Configuración de Directorios (con fallbacks estables)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.getenv("DATA_DIR", "data")
MODEL_PATH = os.getenv("MODEL_PATH", os.path.join(DATA_DIR, "model.pkl"))
LOG_FILE = os.getenv("LOG_FILE", "app_production.log")

# Configuración de Red
# Se recomienda usar 127.0.0.1 en entornos locales para seguridad.
# Usar 0.0.0.0 solo cuando sea necesario (ej. dentro de Docker).
APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("APP_PORT", "8000"))

# Asegurar que las rutas absolutas sean consistentes para la validación de seguridad
ABS_DATA_DIR = os.path.abspath(DATA_DIR)

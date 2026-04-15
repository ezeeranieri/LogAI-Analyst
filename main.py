import logging
import os
import secrets
import joblib
from contextlib import asynccontextmanager
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Security, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from src.parser import AuthLogParser
from src.detector import LogDetector, BruteForceRule, TimeAnomalyRule, IADetectorRule, UserProbingRule
from src.config import ABS_DATA_DIR, LOG_FILE, API_KEY, APP_HOST, APP_PORT, MODEL_PATH, REDIS_URL, WORKERS
from src.utils import FileManager

# Constantes de Producción
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Configuración de logging profesional
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE)
    ]
)
logger = logging.getLogger("LogAI-API")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to load the ML model once at startup."""
    # Startup: Load model if available
    model = None
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info(f"Modelo IA pre-cargado en startup desde {MODEL_PATH}")
        except Exception as e:
            logger.warning(f"No se pudo cargar el modelo IA en startup: {e}")
    else:
        logger.warning(f"Archivo de modelo no encontrado en {MODEL_PATH}. El endpoint seguirá funcionando sin IA.")

    app.state.model = model
    yield
    # Shutdown: cleanup if needed
    logger.info("Shutdown del servidor...")

# Rate limiter setup with Redis backend for multi-worker support
# Falls back to in-memory if REDIS_URL is not set (development mode)
if REDIS_URL:
    limiter = Limiter(key_func=get_remote_address, storage_uri=REDIS_URL)
    logger.info(f"Rate limiting configured with Redis backend: {REDIS_URL}")
else:
    limiter = Limiter(key_func=get_remote_address)
    if WORKERS > 1:
        # CRITICAL: Multi-worker without Redis means rate limiting is per-process
        # Actual limit becomes 10/min * WORKERS, which defeats the purpose
        logger.error("=" * 80)
        logger.error("CRITICAL SECURITY WARNING: Running multi-worker without Redis!")
        logger.error(f"WORKERS={WORKERS} but REDIS_URL not set.")
        logger.error("Rate limiting is PER-PROCESS. Effective limit: 10/min * workers")
        logger.error("This means a single IP can make up to 10*{WORKERS} requests per minute!")
        logger.error("Set REDIS_URL for distributed rate limiting or set WORKERS=1")
        logger.error("=" * 80)
        raise RuntimeError("Multi-worker setup requires REDIS_URL for distributed rate limiting")
    else:
        logger.warning("Rate limiting using in-memory storage (single-worker mode)")

app = FastAPI(
    title="LogAI-Analyst",
    description="API para análisis de logs con IA y reglas heurísticas.",
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# --- Dependencias de Seguridad ---
async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key and secrets.compare_digest(api_key, API_KEY):
        return api_key
    raise HTTPException(
        status_code=403,
        detail="No se pudo validar la API Key. Acceso prohibido."
    )

class AnalysisResponse(BaseModel):
    status: str
    total_threats: int
    data: List[Dict[str, Any]]

@app.get("/")
async def root():
    return {"message": "LogAI-Analyst API operativa (Requiere Autenticación)."}

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes/Docker orchestrators."""
    from datetime import datetime
    return {
        "status": "healthy",
        "model_loaded": getattr(app.state, 'model', None) is not None,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/stats")
@limiter.limit("10/minute")
async def parse_stats(
    request: Request,
    file: UploadFile = File(...),
    authenticated: str = Depends(get_api_key)
):
    """
    Endpoint para obtener estadísticas de parsing de un archivo de logs.
    Útil para verificar qué tan bien el parser maneja un formato particular.
    Requiere header X-API-KEY.
    """
    # 1. Validación de extensión
    if file is None or not hasattr(file, 'filename') or file.filename is None:
        raise HTTPException(status_code=400, detail="Archivo no válido o no proporcionado.")

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".log", ".txt", ""]:
        raise HTTPException(status_code=400, detail="Extensión no válida.")

    temp_file_path = None
    try:
        # 2. Guardar archivo
        temp_file_path = await FileManager.save_upload(file, ABS_DATA_DIR, max_size=MAX_FILE_SIZE)

        # 3. Parsear y obtener estadísticas
        parser = AuthLogParser(temp_file_path)
        df_logs = parser.parse()
        stats = parser.get_stats()

        return {
            "status": "success",
            "filename": filename,
            "parsing_stats": {
                "lines_read": stats['lines_read'],
                "lines_parsed": stats['lines_parsed'],
                "lines_discarded": stats['lines_discarded'],
                "parse_rate_percent": round(stats['parse_rate'], 2)
            },
            "extracted_fields": list(df_logs.columns) if not df_logs.empty else [],
            "sample_records": min(len(df_logs), 5)
        }

    except Exception as e:
        logger.error(f"Error en endpoint /stats: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor. Por favor, contacte al administrador."
        )

    finally:
        if temp_file_path:
            FileManager.cleanup(temp_file_path)

@app.post("/analyze", response_model=AnalysisResponse)
@limiter.limit("10/minute")
async def analyze_logs(
    request: Request,
    file: UploadFile = File(...),
    authenticated: str = Depends(get_api_key)
):
    """
    Endpoint para subir y analizar un archivo de logs.
    Requiere header X-API-KEY.
    """
    # NOTA: La validación de tamaño se realiza DURANTE la lectura en FileManager.save_upload()
    # para evitar bypass cuando el cliente no envía Content-Length header.

    # 1. Validación de extensión
    if file is None or not hasattr(file, 'filename') or file.filename is None:
        raise HTTPException(status_code=400, detail="Archivo no válido o no proporcionado.")

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".log", ".txt", ""]:
        raise HTTPException(status_code=400, detail="Extensión no válida.")

    temp_file_path = None
    try:
        # 2. Gestión de archivos delegada a FileManager
        # La validación de tamaño (10MB) ocurre durante el streaming, no confía en Content-Length
        temp_file_path = await FileManager.save_upload(file, ABS_DATA_DIR, max_size=MAX_FILE_SIZE)

        # 4. Procesar con el Parser
        parser = AuthLogParser(temp_file_path)
        df_logs = parser.parse()
        
        if df_logs.empty:
            return AnalysisResponse(status="success", total_threats=0, data=[])

        # 5. Detección de Amenazas con Reglas Modulares
        detector = LogDetector()
        detector.add_rule(BruteForceRule())
        detector.add_rule(TimeAnomalyRule())
        detector.add_rule(UserProbingRule())
        # Inject pre-loaded model to avoid reloading on each request
        # Use getattr to handle case where lifespan hasn't run (e.g., in tests)
        model = getattr(app.state, 'model', None)
        detector.add_rule(IADetectorRule(model=model))
        
        anomalies_df = detector.run(df_logs)
        
        # 6. Formateo de Resultados
        results = []
        if not anomalies_df.empty:
            anomalies_df['datetime'] = anomalies_df['datetime'].astype(str)
            results = anomalies_df.to_dict(orient='records')
        
        return AnalysisResponse(
            status="success",
            total_threats=len(results),
            data=results
        )

    except Exception as e:
        logger.error(f"Error crítico en endpoint /analyze: {type(e).__name__}: {str(e)}", exc_info=True)
        # Mensaje genérico para no exponer detalles internos en producción
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor. Por favor, contacte al administrador."
        )
    
    finally:
        # 7. Limpieza delegada
        if temp_file_path:
            FileManager.cleanup(temp_file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

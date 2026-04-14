import logging
import os
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from src.parser import AuthLogParser
from src.detector import LogDetector, BruteForceRule, TimeAnomalyRule, IADetectorRule, UserProbingRule
from src.config import ABS_DATA_DIR, LOG_FILE, API_KEY, APP_HOST, APP_PORT
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

app = FastAPI(
    title="LogAI-Analyst",
    description="API para análisis de logs con IA y reglas heurísticas."
)

# --- Dependencias de Seguridad ---
async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
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

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_logs(
    file: UploadFile = File(...),
    authenticated: str = Depends(get_api_key)
):
    """
    Endpoint para subir y analizar un archivo de logs.
    Requiere header X-API-KEY.
    """
    # 1. Validación de tamaño
    if file.size and file.size > MAX_FILE_SIZE:
        logger.warning(f"Carga rechazada: Archivo demasiado grande.")
        raise HTTPException(status_code=413, detail="El archivo excede el límite de 10MB.")

    # 2. Validación de extensión
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".log", ".txt", ""]:
        raise HTTPException(status_code=400, detail="Extensión no válida.")

    temp_file_path = None
    try:
        # 3. Gestión de archivos delegada a FileManager
        temp_file_path = FileManager.save_upload(file, ABS_DATA_DIR)

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
        detector.add_rule(IADetectorRule())
        
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
        logger.error(f"Error crítico en endpoint /analyze: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail=f"Error interno del servidor: {type(e).__name__}"
        )
    
    finally:
        # 7. Limpieza delegada
        if temp_file_path:
            FileManager.cleanup(temp_file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

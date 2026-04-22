import logging
import os
import secrets
import joblib
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Security, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from src.parser import AuthLogParser
from src.pipeline import LogAnalysisPipeline
from src.detector import (
    LogDetector, BruteForceRule, TimeAnomalyRule, IsolationForestRule, UserProbingRule,
    SQLInjectionRule, XSSRule, PathTraversalRule, WebAttackRule
)
from src.config import ABS_DATA_DIR, LOG_FILE, API_KEY, APP_HOST, APP_PORT, MODEL_PATH, REDIS_URL, WORKERS
from src.utils import FileManager, ReportExporter

# Production Constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB upload limit
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Configure logging for production
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
    """
    Lifespan context manager for FastAPI application startup/shutdown.
    
    Loads the ML model once at startup to avoid cold-start latency on first request.
    Falls back to rule-based detection only if model loading fails.
    
    Args:
        app: FastAPI application instance
        
    Yields:
        None: Control to application after model loading
    """
    # Startup: Load ML model if available
    model = None
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info(f"ML model pre-loaded at startup from {MODEL_PATH}")
        except Exception as e:
            logger.warning(f"Failed to load ML model at startup: {e}")
    else:
        logger.warning(f"Model file not found at {MODEL_PATH}. API will work without ML detection.")

    app.state.model = model
    yield
    
    # Shutdown: cleanup logging
    logger.info("Server shutdown complete")

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
        logger.error(f"This means a single IP can make up to {10*WORKERS} requests per minute!")
        logger.error("Set REDIS_URL for distributed rate limiting or set WORKERS=1")
        logger.error("=" * 80)
        raise RuntimeError("Multi-worker setup requires REDIS_URL for distributed rate limiting")
    else:
        logger.warning("Rate limiting using in-memory storage (single-worker mode)")

app = FastAPI(
    title="LogAI-Analyst",
    description="API for log analysis with ML and heuristic rules.",
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# --- Security Dependencies ---
def get_api_key(api_key: str = Security(api_key_header)):
    if api_key and secrets.compare_digest(api_key, API_KEY):
        return api_key
    raise HTTPException(
        status_code=403,
        detail="API Key validation failed. Access denied."
    )

class AnalysisResponse(BaseModel):
    status: str
    total_threats: int
    data: List[Dict[str, Any]]

def _validate_upload_file(file: UploadFile) -> str:
    """
    Helper function to validate uploaded file.
    Returns the filename if valid, raises HTTPException otherwise.
    """
    if file is None or not hasattr(file, 'filename') or file.filename is None:
        raise HTTPException(status_code=400, detail="Invalid or missing file.")

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".log", ".txt", ""]:
        raise HTTPException(status_code=400, detail="Invalid file extension. Only .log and .txt files are allowed.")

    return filename

@app.get("/")
async def root():
    """
    Root endpoint providing API status and authentication requirement.
    
    Returns:
        dict: API status message indicating authentication is required
    """
    return {"message": "LogAI-Analyst API operational (Authentication Required)."}

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
    Endpoint to get parsing statistics from a log file.
    Useful to verify how well the parser handles a particular format.
    Requires X-API-KEY header.
    """
    # 1. File validation
    filename = _validate_upload_file(file)

    temp_file_path = None
    try:
        # 2. Save file
        temp_file_path = await FileManager.save_upload(file, ABS_DATA_DIR, max_size=MAX_FILE_SIZE)

        # 3. Parse and get statistics
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
        logger.error(f"Error in /stats endpoint: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal server error. Please contact administrator."
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

    # 1. Validación de archivo
    filename = _validate_upload_file(file)

    temp_file_path = None
    try:
        # 2. Gestión de archivos delegada a FileManager
        # La validación de tamaño (10MB) ocurre durante el streaming, no confía en Content-Length
        temp_file_path = await FileManager.save_upload(file, ABS_DATA_DIR, max_size=MAX_FILE_SIZE)

        # 4. Procesar con el Pipeline (Centraliza Parser, Normalización y Detector)
        # Dependency Injection: Model is passed to constructor
        model = getattr(app.state, 'model', None)
        pipeline = LogAnalysisPipeline(model=model)
        result = pipeline.run(temp_file_path)

        if result.df_raw.empty:
            return AnalysisResponse(status="success", total_threats=0, data=[])
        
        # 6. Formateo de Resultados
        results = []
        if not result.df_anomalies.empty:
            # We copy to avoid modifying the original during string conversion
            display_df = result.df_anomalies.copy()
            display_df['datetime'] = display_df['datetime'].astype(str)
            results = display_df.to_dict(orient='records')
        
        return AnalysisResponse(
            status="success",
            total_threats=len(results),
            data=results
        )

    except Exception as e:
        logger.error(f"Critical error in /analyze endpoint: {type(e).__name__}: {str(e)}", exc_info=True)
        # Generic message to avoid exposing internal details in production
        raise HTTPException(
            status_code=500,
            detail="Internal server error. Please contact administrator."
        )

    finally:
        # 7. Cleanup delegated
        if temp_file_path:
            FileManager.cleanup(temp_file_path)


class ExportRequest(BaseModel):
    """Request model for report export."""
    data: List[Dict[str, Any]]
    format: str = "json"
    filename: Optional[str] = None


class ExportResponse(BaseModel):
    """Response model for report export."""
    status: str
    message: str
    file_path: str
    file_info: Dict[str, Any]


@app.post("/export", response_model=ExportResponse)
@limiter.limit("20/minute")
async def export_report(
    request: Request,
    export_request: ExportRequest,
    authenticated: str = Depends(get_api_key)
):
    """
    Export analysis results to JSON or CSV format.

    Persists threat data to disk for audit trails, compliance,
    or integration with external SIEM systems.

    Args:
        export_request: JSON payload with threats data and export options
        request: FastAPI request object (for rate limiting)
        authenticated: API key validation result

    Returns:
        ExportResponse with file path and metadata

    Raises:
        HTTPException 400: If format is invalid or data is empty
        HTTPException 500: If export fails
    """
    try:
        # Validate format
        format_type = export_request.format.lower()
        if format_type not in ReportExporter.ALLOWED_FORMATS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid format. Allowed: {ReportExporter.ALLOWED_FORMATS}"
            )

        # Validate data
        if not export_request.data:
            raise HTTPException(
                status_code=400,
                detail="Cannot export empty data"
            )

        # Perform export
        file_path = ReportExporter.export(
            data=export_request.data,
            format_type=format_type,
            base_dir=ABS_DATA_DIR,
            filename=export_request.filename
        )

        # Get file metadata
        file_info = ReportExporter.get_report_info(file_path)

        logger.info(
            f"Report exported via API: {file_info['filename']} "
            f"({file_info['size_bytes']} bytes, {len(export_request.data)} records)"
        )

        return ExportResponse(
            status="success",
            message=f"Report exported successfully to {format_type.upper()}",
            file_path=file_path,
            file_info=file_info
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export failed: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to export report. Please try again."
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

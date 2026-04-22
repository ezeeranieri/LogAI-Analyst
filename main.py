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
from src.utils import FileManager, ReportExporter, sanitize_for_log

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
    """ Startup/shutdown context manager. """
    model = None
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info(f"ML model pre-loaded at startup from {MODEL_PATH}")
        except Exception as e:
            logger.warning(f"Failed to load ML model at startup: {sanitize_for_log(e)}")
    else:
        logger.warning(f"Model file not found at {MODEL_PATH}. API will work without ML detection.")

    app.state.model = model
    yield
    logger.info("Server shutdown complete")

# Rate limiter setup
if REDIS_URL:
    limiter = Limiter(key_func=get_remote_address, storage_uri=REDIS_URL)
    logger.info(f"Rate limiting configured with Redis backend: {sanitize_for_log(REDIS_URL)}")
else:
    limiter = Limiter(key_func=get_remote_address)
    if WORKERS > 1:
        logger.error("CRITICAL SECURITY WARNING: Running multi-worker without Redis!")
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
    """ Validates uploaded file metadata. """
    if file is None or not hasattr(file, 'filename') or file.filename is None:
        raise HTTPException(status_code=400, detail="Invalid or missing file.")

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".log", ".txt", ""]:
        raise HTTPException(status_code=400, detail="Invalid file extension.")

    return filename

@app.get("/")
async def root():
    return {"message": "LogAI-Analyst API operational (Authentication Required)."}

@app.get("/health")
async def health_check():
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
    """ Endpoint to get parsing statistics. """
    filename = _validate_upload_file(file)
    temp_file_path = None
    try:
        temp_file_path = await FileManager.save_upload(file, ABS_DATA_DIR, max_size=MAX_FILE_SIZE)
        parser = AuthLogParser(temp_file_path)
        df_logs = parser.parse()
        stats = parser.get_stats()

        return {
            "status": "success",
            "filename": filename,
            "parsing_stats": {
                "lines_read": stats['lines_read'],
                "lines_parsed": stats['lines_parsed'],
                "parse_rate_percent": round(stats['parse_rate'], 2)
            },
            "extracted_fields": list(df_logs.columns) if not df_logs.empty else []
        }
    except Exception as e:
        logger.error(f"Error in /stats (User: {sanitize_for_log(get_remote_address(request))}): {sanitize_for_log(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error.")
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
    """ Endpoint to analyze a log file. """
    filename = _validate_upload_file(file)
    temp_file_path = None
    try:
        temp_file_path = await FileManager.save_upload(file, ABS_DATA_DIR, max_size=MAX_FILE_SIZE)
        model = getattr(app.state, 'model', None)
        pipeline = LogAnalysisPipeline(model=model)
        result = pipeline.run(temp_file_path)

        results = []
        if not result.df_anomalies.empty:
            display_df = result.df_anomalies.copy()
            display_df['datetime'] = display_df['datetime'].astype(str)
            results = display_df.to_dict(orient='records')
        
        return AnalysisResponse(status="success", total_threats=len(results), data=results)
    except Exception as e:
        logger.error(f"Critical error in /analyze (File: {sanitize_for_log(filename)}): {sanitize_for_log(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error.")
    finally:
        if temp_file_path:
            FileManager.cleanup(temp_file_path)

class ExportRequest(BaseModel):
    data: List[Dict[str, Any]]
    format: str = "json"
    filename: Optional[str] = None

class ExportResponse(BaseModel):
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
    """ Export analysis results securely. """
    try:
        format_type = export_request.format.lower()
        if format_type not in ReportExporter.ALLOWED_FORMATS:
            raise HTTPException(status_code=400, detail="Invalid format.")

        if not export_request.data:
            raise HTTPException(status_code=400, detail="Empty data.")

        file_path = ReportExporter.export(
            data=export_request.data,
            format_type=format_type,
            base_dir=ABS_DATA_DIR,
            filename=export_request.filename
        )

        file_info = ReportExporter.get_report_info(file_path)
        logger.info(
            f"Report exported via API: {sanitize_for_log(file_info['filename'])} "
            f"by {sanitize_for_log(get_remote_address(request))}"
        )

        return ExportResponse(
            status="success",
            message=f"Report exported safely to {format_type.upper()}",
            file_path=file_path,
            file_info=file_info
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export failed for {sanitize_for_log(get_remote_address(request))}: {sanitize_for_log(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to export report.")

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting server on {APP_HOST}:{APP_PORT}")
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)

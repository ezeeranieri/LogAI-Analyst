import json
import csv
import uuid
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import aiofiles
from fastapi import UploadFile, HTTPException

logger = logging.getLogger("LogAI-Utils")

def sanitize_for_log(data: Any) -> str:
    """
    Sanitizes user-provided data for safe logging.
    Replaces control characters like newlines to prevent Log Injection.
    """
    if data is None:
        return "None"
    
    # Convert to string and replace CRLF/LF with a safe placeholder
    clean_data = str(data).replace("\n", " [NL] ").replace("\r", " [CR] ")
    return clean_data

class FileManager:
    """
    Utility class for managing file persistence and cleanup
    on the server under security standards.
    """

    @staticmethod
    async def save_upload(file: UploadFile, base_dir: str, max_size: int = None) -> str:
        """
        Safely saves an uploaded file using a sanitized name (UUID).
        Validates actual size during reading to prevent Content-Length header bypass.
        """
        # 1. Prepare directory with Pathlib
        base_path = Path(base_dir).resolve()
        temp_dir = base_path / "temp_uploads"
        temp_dir.mkdir(parents=True, exist_ok=True)

        # 2. Generate sanitized filename
        unique_id = uuid.uuid4().hex
        original_ext = Path(file.filename or "").suffix.lower()
        # Only allow specific extensions if provided, but here we just keep original safely
        temp_file_path = temp_dir / f"{unique_id}{original_ext}"

        # 3. Physical async save with streaming (8KB chunks) + size validation
        logger.debug(f"Saving sanitized file: {unique_id}{original_ext}")
        total_bytes = 0
        try:
            async with aiofiles.open(temp_file_path, "wb") as buffer:
                while chunk := await file.read(8192):  # 8KB chunks
                    total_bytes += len(chunk)
                    if max_size and total_bytes > max_size:
                        await buffer.close()
                        if temp_file_path.exists():
                            temp_file_path.unlink()
                        raise HTTPException(
                            status_code=413,
                            detail=f"File exceeds limit of {max_size / (1024 * 1024):.1f}MB"
                        )
                    await buffer.write(chunk)
        except Exception as e:
            if temp_file_path.exists():
                temp_file_path.unlink()
            if isinstance(e, HTTPException):
                raise
            logger.error(f"Failed to save upload: {sanitize_for_log(e)}")
            raise HTTPException(status_code=500, detail="Error saving uploaded file")

        logger.debug(f"File saved: {unique_id}{original_ext} ({total_bytes} bytes)")
        return str(temp_file_path)

    @staticmethod
    def cleanup(file_path: str) -> None:
        """
        Safely removes a file from the system.
        """
        path = Path(file_path)
        if path.exists() and path.is_file():
            try:
                path.unlink()
                logger.debug(f"File cleanup completed: {sanitize_for_log(path.name)}")
            except Exception as e:
                logger.error(f"Could not delete file {sanitize_for_log(file_path)}: {sanitize_for_log(e)}")


class ReportExporter:
    """
    Utility class for exporting analysis results to persistent formats (JSON, CSV).
    Files are saved with unique IDs and timestamps for traceability.
    """

    ALLOWED_FORMATS = {"json", "csv"}

    @staticmethod
    def _ensure_reports_dir(base_path: Path) -> Path:
        """Creates and returns the reports directory path."""
        reports_dir = base_path / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        return reports_dir

    @staticmethod
    def _generate_filename(format_type: str) -> str:
        """Generates a unique filename with timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        return f"report_{timestamp}_{unique_id}.{format_type}"

    @classmethod
    def export_json(cls, data: List[Dict[str, Any]], base_dir: Any, filename: Optional[str] = None) -> str:
        """Exports analysis results to JSON format."""
        if not data:
            raise ValueError("Cannot export empty data")

        # Ensure reports directory exists
        base_path = Path(base_dir).resolve()
        reports_dir = cls._ensure_reports_dir(base_path)

        if filename:
            # Use .name to prevent Path Traversal (takes only the basename)
            clean_filename = f"{Path(filename).name}.json"
        else:
            clean_filename = cls._generate_filename("json")

        file_path = reports_dir / clean_filename
        
        export_data = {
            "export_metadata": {
                "timestamp": datetime.now().isoformat(),
                "format": "json",
                "record_count": len(data)
            },
            "threats": data
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON report exported: {sanitize_for_log(clean_filename)} ({len(data)} records)")
        return str(file_path)

    @classmethod
    def export_csv(cls, data: List[Dict[str, Any]], base_dir: Any, filename: Optional[str] = None) -> str:
        """Exports analysis results to CSV format."""
        if not data:
            raise ValueError("Cannot export empty data")

        # Ensure reports directory exists
        base_path = Path(base_dir).resolve()
        reports_dir = cls._ensure_reports_dir(base_path)

        if filename:
            clean_filename = f"{Path(filename).name}.csv"
        else:
            clean_filename = cls._generate_filename("csv")

        file_path = reports_dir / clean_filename

        flattened_data = []
        for record in data:
            flat_record = record.copy()
            for key, value in list(flat_record.items()):
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        flat_record[f"{key}_{sub_key}"] = sub_value
                    del flat_record[key]
                elif isinstance(value, list):
                    flat_record[key] = ", ".join(str(v) for v in value)
            flattened_data.append(flat_record)

        fieldnames = set()
        for record in flattened_data:
            fieldnames.update(record.keys())
        fieldnames = sorted(fieldnames)

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_data)

        logger.info(f"CSV report exported: {sanitize_for_log(clean_filename)} ({len(data)} records)")
        return str(file_path)

    @classmethod
    def export(cls, data: List[Dict[str, Any]], format_type: str, base_dir: str, filename: Optional[str] = None) -> str:
        """
        Generic export method with strict security validation.
        """
        format_type = format_type.lower()
        if format_type not in cls.ALLOWED_FORMATS:
            raise ValueError(f"Unsupported format: {format_type}")

        # Strict Path Validation
        base_path = Path(base_dir).resolve()
        reports_dir = cls._ensure_reports_dir(base_path)
        
        if format_type == "json":
            file_path_str = cls.export_json(data, base_dir, filename)
        else:
            file_path_str = cls.export_csv(data, base_dir, filename)
            
        # Defense in depth: Verify the final path is actually inside the reports dir
        file_path = Path(file_path_str)
        final_path = file_path.resolve()
        if not str(final_path).startswith(str(reports_dir.resolve())):
            # This shouldn't happen due to .name usage, but good for security auditing
            if final_path.exists():
                final_path.unlink()
            raise PermissionError("Path Traversal attempt detected and blocked.")

        return str(final_path)

    @staticmethod
    def get_report_info(file_path: str) -> Dict[str, Any]:
        """Returns metadata about an exported report file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Report not found: {sanitize_for_log(file_path)}")

        stats = path.stat()
        return {
            "filename": path.name,
            "path": str(path),
            "size_bytes": stats.st_size,
            "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "format": path.suffix.lower().replace(".", "")
        }

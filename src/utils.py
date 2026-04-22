import os
import uuid
import json
import csv
import aiofiles
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import UploadFile, HTTPException

logger = logging.getLogger("LogAI-Utils")

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

        Args:
            file: Uploaded file
            base_dir: Base directory to save
            max_size: Maximum allowed size in bytes (optional)

        Returns:
            Absolute path of saved file

        Raises:
            HTTPException: If file exceeds max_size
        """
        # 1. Prepare directory
        temp_dir = os.path.join(base_dir, "temp_uploads")
        os.makedirs(temp_dir, exist_ok=True)

        # 2. Generate sanitized filename
        unique_id = uuid.uuid4().hex
        extension = os.path.splitext(file.filename)[1].lower()
        temp_file_path = os.path.join(temp_dir, f"{unique_id}{extension}")

        # 3. Physical async save with streaming (8KB chunks) + size validation
        # Avoids loading large files entirely into memory
        logger.debug(f"Saving sanitized file: {unique_id}{extension}")
        total_bytes = 0
        async with aiofiles.open(temp_file_path, "wb") as buffer:
            while chunk := await file.read(8192):  # 8KB chunks
                total_bytes += len(chunk)
                if max_size and total_bytes > max_size:
                    # Delete partial file and raise error
                    await buffer.close()
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds limit of {max_size / (1024 * 1024):.1f}MB"
                    )
                await buffer.write(chunk)

        logger.debug(f"File saved: {unique_id}{extension} ({total_bytes} bytes)")
        return temp_file_path

    @staticmethod
    def cleanup(file_path: str) -> None:
        """
        Safely removes a file from the system.
        """
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.debug(f"File cleanup completed: {os.path.basename(file_path)}")
            except Exception as e:
                logger.error(f"Could not delete file {file_path}: {e}")


class ReportExporter:
    """
    Utility class for exporting analysis results to persistent formats (JSON, CSV).
    Files are saved with unique IDs and timestamps for traceability.
    """

    ALLOWED_FORMATS = {"json", "csv"}

    @staticmethod
    def _ensure_reports_dir(base_dir: str) -> str:
        """Creates and returns the reports directory path."""
        reports_dir = os.path.join(base_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        return reports_dir

    @staticmethod
    def _generate_filename(format_type: str) -> str:
        """Generates a unique filename with timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        return f"report_{timestamp}_{unique_id}.{format_type}"

    @classmethod
    def export_json(cls, data: List[Dict[str, Any]], base_dir: str, filename: Optional[str] = None) -> str:
        """
        Exports analysis results to JSON format.

        Args:
            data: List of threat dictionaries to export
            base_dir: Base directory for reports
            filename: Optional custom filename (without extension)

        Returns:
            Absolute path of exported file

        Raises:
            ValueError: If data is empty or invalid
        """
        if not data:
            raise ValueError("Cannot export empty data")

        reports_dir = cls._ensure_reports_dir(base_dir)

        if filename:
            filename = f"{filename}.json"
        else:
            filename = cls._generate_filename("json")

        file_path = os.path.join(reports_dir, filename)

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

        logger.info(f"JSON report exported: {filename} ({len(data)} records)")
        return file_path

    @classmethod
    def export_csv(cls, data: List[Dict[str, Any]], base_dir: str, filename: Optional[str] = None) -> str:
        """
        Exports analysis results to CSV format.

        Args:
            data: List of threat dictionaries to export
            base_dir: Base directory for reports
            filename: Optional custom filename (without extension)

        Returns:
            Absolute path of exported file

        Raises:
            ValueError: If data is empty or invalid
        """
        if not data:
            raise ValueError("Cannot export empty data")

        reports_dir = cls._ensure_reports_dir(base_dir)

        if filename:
            filename = f"{filename}.csv"
        else:
            filename = cls._generate_filename("csv")

        file_path = os.path.join(reports_dir, filename)

        # Flatten nested dictionaries for CSV compatibility
        flattened_data = []
        for record in data:
            flat_record = record.copy()
            # Handle nested dicts by prefixing keys
            for key, value in list(flat_record.items()):
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        flat_record[f"{key}_{sub_key}"] = sub_value
                    del flat_record[key]
                elif isinstance(value, list):
                    flat_record[key] = ", ".join(str(v) for v in value)
            flattened_data.append(flat_record)

        # Get all unique fieldnames across all records
        fieldnames = set()
        for record in flattened_data:
            fieldnames.update(record.keys())
        fieldnames = sorted(fieldnames)

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_data)

        logger.info(f"CSV report exported: {filename} ({len(data)} records)")
        return file_path

    @classmethod
    def export(cls, data: List[Dict[str, Any]], format_type: str, base_dir: str, filename: Optional[str] = None) -> str:
        """
        Generic export method that dispatches to format-specific exporters.

        Args:
            data: List of threat dictionaries to export
            format_type: Export format - "json" or "csv"
            base_dir: Base directory for reports
            filename: Optional custom filename (without extension)

        Returns:
            Absolute path of exported file

        Raises:
            ValueError: If format_type is not supported
        """
        format_type = format_type.lower()
        if format_type not in cls.ALLOWED_FORMATS:
            raise ValueError(f"Unsupported format: {format_type}. Allowed: {cls.ALLOWED_FORMATS}")

        if format_type == "json":
            return cls.export_json(data, base_dir, filename)
        else:
            return cls.export_csv(data, base_dir, filename)

    @staticmethod
    def get_report_info(file_path: str) -> Dict[str, Any]:
        """
        Returns metadata about an exported report file.

        Args:
            file_path: Path to the report file

        Returns:
            Dictionary with file metadata
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Report not found: {file_path}")

        stats = os.stat(file_path)
        return {
            "filename": os.path.basename(file_path),
            "path": file_path,
            "size_bytes": stats.st_size,
            "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "format": os.path.splitext(file_path)[1].lower().replace(".", "")
        }

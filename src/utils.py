import os
import uuid
import aiofiles
import logging
from fastapi import UploadFile

logger = logging.getLogger("LogAI-Utils")

class FileManager:
    """
    Clase de utilidad para gestionar la persistencia y limpieza de archivos 
    en el servidor bajo estándares de seguridad.
    """
    
    @staticmethod
    async def save_upload(file: UploadFile, base_dir: str) -> str:
        """
        Guarda un archivo subido de forma segura usando un nombre sanitizado (UUID).
        Devuelve la ruta absoluta del archivo guardado.
        """
        # 1. Preparar directorio
        temp_dir = os.path.join(base_dir, "temp_uploads")
        os.makedirs(temp_dir, exist_ok=True)

        # 2. Generar nombre de archivo sanitizado
        unique_id = uuid.uuid4().hex
        extension = os.path.splitext(file.filename)[1].lower()
        temp_file_path = os.path.join(temp_dir, f"{unique_id}{extension}")

        # 3. Guardado físico async con streaming (8KB chunks)
        # Evita cargar archivos grandes completamente en memoria
        logger.info(f"Guardando archivo sanitizado: {unique_id}{extension}")
        async with aiofiles.open(temp_file_path, "wb") as buffer:
            while chunk := await file.read(8192):  # 8KB chunks
                await buffer.write(chunk)

        return temp_file_path

    @staticmethod
    def cleanup(file_path: str) -> None:
        """
        Elimina un archivo del sistema de forma segura.
        """
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.info(f"Limpieza de archivo completada: {os.path.basename(file_path)}")
            except Exception as e:
                logger.error(f"No se pudo eliminar el archivo {file_path}: {e}")

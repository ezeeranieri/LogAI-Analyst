import os
import uuid
import shutil
import logging
from fastapi import UploadFile
from typing import Tuple

logger = logging.getLogger("LogAI-Utils")

class FileManager:
    """
    Clase de utilidad para gestionar la persistencia y limpieza de archivos 
    en el servidor bajo estándares de seguridad.
    """
    
    @staticmethod
    def save_upload(file: UploadFile, base_dir: str) -> str:
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
        
        # 3. Guardado físico
        logger.info(f"Guardando archivo sanitizado: {unique_id}{extension}")
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
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

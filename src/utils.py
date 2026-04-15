import os
import uuid
import aiofiles
import logging
from fastapi import UploadFile, HTTPException

logger = logging.getLogger("LogAI-Utils")

class FileManager:
    """
    Clase de utilidad para gestionar la persistencia y limpieza de archivos
    en el servidor bajo estándares de seguridad.
    """

    @staticmethod
    async def save_upload(file: UploadFile, base_dir: str, max_size: int = None) -> str:
        """
        Guarda un archivo subido de forma segura usando un nombre sanitizado (UUID).
        Valida el tamaño real durante la lectura para evitar bypass del header Content-Length.

        Args:
            file: Archivo subido
            base_dir: Directorio base para guardar
            max_size: Tamaño máximo permitido en bytes (opcional)

        Returns:
            Ruta absoluta del archivo guardado

        Raises:
            HTTPException: Si el archivo excede max_size
        """
        # 1. Preparar directorio
        temp_dir = os.path.join(base_dir, "temp_uploads")
        os.makedirs(temp_dir, exist_ok=True)

        # 2. Generar nombre de archivo sanitizado
        unique_id = uuid.uuid4().hex
        extension = os.path.splitext(file.filename)[1].lower()
        temp_file_path = os.path.join(temp_dir, f"{unique_id}{extension}")

        # 3. Guardado físico async con streaming (8KB chunks) + validación de tamaño
        # Evita cargar archivos grandes completamente en memoria
        logger.info(f"Guardando archivo sanitizado: {unique_id}{extension}")
        total_bytes = 0
        async with aiofiles.open(temp_file_path, "wb") as buffer:
            while chunk := await file.read(8192):  # 8KB chunks
                total_bytes += len(chunk)
                if max_size and total_bytes > max_size:
                    # Eliminar archivo parcial y lanzar error
                    await buffer.close()
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"El archivo excede el límite de {max_size / (1024 * 1024):.1f}MB."
                    )
                await buffer.write(chunk)

        logger.info(f"Archivo guardado: {unique_id}{extension} ({total_bytes} bytes)")
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

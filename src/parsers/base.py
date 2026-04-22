from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
import pandas as pd

class BaseParser(ABC):
    """Abstract base class for all log parsers."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.lines_read = 0
        self.lines_parsed = 0
        self.lines_discarded = 0

    @abstractmethod
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parses a single line and returns a dictionary of extracted data."""
        pass

    def get_stats(self) -> Dict[str, int]:
        """Returns processing statistics."""
        return {
            'lines_read': self.lines_read,
            'lines_parsed': self.lines_parsed,
            'lines_discarded': self.lines_discarded,
            'parse_rate': (self.lines_parsed / self.lines_read * 100) if self.lines_read > 0 else 0
        }

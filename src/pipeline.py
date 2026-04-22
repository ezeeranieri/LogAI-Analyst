import logging
import pandas as pd
from typing import Optional, Any
from .parser import AuthLogParser
from .detector import (
    LogDetector, BruteForceRule, TimeAnomalyRule, IsolationForestRule,
    UserProbingRule, SQLInjectionRule, XSSRule, PathTraversalRule, WebAttackRule
)
from .normalization import normalize_df
from .config import MODEL_PATH

logger = logging.getLogger(__name__)

from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class AnalysisResult:
    """
    Structured container for log analysis results.
    Standardizes output for API and Dashboard consumers.
    """
    df_raw: pd.DataFrame
    df_anomalies: pd.DataFrame
    stats: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    version: str = "1.2"

    @property
    def total_logs(self) -> int:
        return len(self.df_raw)

    @property
    def total_anomalies(self) -> int:
        return len(self.df_anomalies)

class LogAnalysisPipeline:
    """
    Orchestrates the entire log analysis flow:
    Parser -> Normalization -> Detection Rules -> Result Aggregation.
    
    This encapsulation makes the system easier to test, maintain, 
    and deploy across different entry points (API, CLI, Dashboard).
    """

    def __init__(self, detector: Optional[LogDetector] = None, model: Optional[Any] = None):
        """
        Initializes the pipeline with a detector and an optional ML model.
        
        Args:
            detector: Custom LogDetector instance.
            model: Pre-loaded ML model for IsolationForestRule.
        """
        self.model = model
        self.detector = detector or self._build_default_detector()

    def _build_default_detector(self) -> LogDetector:
        """Helper to assemble a detector with the standard rule set."""
        detector = LogDetector()
        detector.add_rule(BruteForceRule())
        detector.add_rule(TimeAnomalyRule())
        detector.add_rule(UserProbingRule())
        detector.add_rule(SQLInjectionRule())
        detector.add_rule(XSSRule())
        detector.add_rule(PathTraversalRule())
        detector.add_rule(WebAttackRule())
        
        # Dependency Injection: Add ML rule only if model is provided
        if self.model:
            detector.add_rule(IsolationForestRule(model=self.model))
            logger.debug("IsolationForestRule injected via pipeline constructor.")
        else:
            logger.warning("LogAnalysisPipeline: No ML model provided. IsolationForestRule (Advanced Diagnostics) will be omitted.")
            
        return detector

    def run(self, file_path: str, progress_callback: Optional[Any] = None) -> AnalysisResult:
        """
        Executes the analysis pipeline on a log file.
        
        Args:
            file_path: Path to the log file.
            progress_callback: Optional function (curr, total) for UI feedback.
            
        Returns:
            An AnalysisResult object containing data and metadata.
        """
        start_time = datetime.now()
        logger.info(f"Starting pipeline for: {file_path}")
        
        # 1. Parsing
        parser = AuthLogParser(file_path)
        df_raw = parser.parse(progress_callback=progress_callback)
        
        if df_raw.empty:
            logger.warning("Pipeline received empty or unparsable log file.")
            return AnalysisResult(df_raw=df_raw, df_anomalies=pd.DataFrame())

        # 2. Normalization (In-place for memory optimization, as per Senior refactor)
        df_normalized = normalize_df(df_raw)

        # 3. Detection
        df_anomalies = self.detector.run(df_normalized)
        
        # 4. Preparation of structured results
        latency = (datetime.now() - start_time).total_seconds() * 1000
        
        result = AnalysisResult(
            df_raw=df_raw,
            df_anomalies=df_anomalies,
            stats=parser.get_stats(),
            metadata={
                "file_path": file_path,
                "latency_ms": latency,
                "pipeline_version": "1.2",
                "rules_active": [type(r).__name__ for r in self.detector.rules]
            }
        )
        
        logger.info(f"Pipeline complete. Detected {len(df_anomalies)} anomalies in {latency:.2f}ms.")
        return result

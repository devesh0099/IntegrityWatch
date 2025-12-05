from abc import ABC, abstractmethod
from typing import Any
from ..core.result import TechniqueResult
from integritywatch.utils.logger import get_logger


class BaseDetector(ABC):
    
    def __init__(self, name: str):
        self.name = name
        self.severity = "UNKNOWN"
        self.logger = get_logger(f"browser_monitor.{self.__class__.__name__}")
        self.raw_violations: list[dict[str, Any]] = []
    
    def load_data(self, violations: list[dict[str, Any]]):
        self.raw_violations = violations
        self.logger.debug(f"Loaded {len(violations)} raw violations")
    
    def filter_violations(self, violation_types: list[str]) -> list[dict[str, Any]]:
        filtered = [
            v for v in self.raw_violations 
            if v.get('type') in violation_types
        ]
        self.logger.debug(f"Filtered {len(filtered)} violations of types: {violation_types}")
        return filtered
    
    @abstractmethod
    def scan(self) -> TechniqueResult:
        pass
    
    def monitor(self) -> TechniqueResult:
        return self.scan()
    
    def safe_scan(self) -> TechniqueResult:
        try:
            self.logger.info(f"Running detection: {self.name}")
            result = self.scan()
            
            if result.detected:
                self.logger.warning(f"DETECTED: {result.details}")
            else:
                self.logger.info(f"Clean: {result.details}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Detection failed: {str(e)}", exc_info=True)
            return TechniqueResult(
                name=self.name,
                detected=False,
                severity=self.severity,
                details="Detection check failed",
                error=str(e)
            )
    
    def safe_monitor(self) -> TechniqueResult:
        try:
            result = self.monitor()
            
            if result.detected:
                self.logger.warning(f"DETECTED: {result.details}")
            else:
                self.logger.debug(f"Clean: {result.details}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Monitoring failed: {str(e)}", exc_info=True)
            return TechniqueResult(
                name=self.name,
                detected=False,
                severity=self.severity,
                details="Monitoring check failed",
                error=str(e)
            )

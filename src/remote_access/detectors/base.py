from abc import ABC, abstractmethod
from src.remote_access.core.result import TechniqueResult
from src.utils.logger import get_logger

class BaseDetector(ABC):
    def __init__(self):
        self.logger = get_logger(f"remote.{self.__class__.__name__}")
        self.name = "Generic Remote Detector"

    @abstractmethod
    def detect(self) -> TechniqueResult:
        pass

    def safe_detect(self) -> TechniqueResult:
        try:
            self.logger.debug(f"Running detector: {self.name}")
            return self.detect()
        except Exception as e:
            self.logger.error(f"Detector '{self.name}' failed: {e}", exc_info=True)
            return TechniqueResult(
                name=self.name,
                detected=False,
                tier="LOW",
                details=f"Detector crashed: {str(e)}",
                error=str(e)
            )

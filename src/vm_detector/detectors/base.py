from abc import ABC, abstractmethod
import os

from ..core.result import TechniqueResult
from ..core.logger import get_logger
from src.platform.base import get_current_platform, is_windows

class BaseDetector(ABC):
    """Abstract base class for all VM/sandbox detectors."""
    
    def __init__(self, name: str, supported_platforms: list[str], requires_admin: bool = False):
        self.name = name
        self.supported_platforms = supported_platforms
        self.requires_admin = requires_admin
        self.logger = get_logger(f'detector.{name.lower().replace(" ", "_")}')
        self._current_platform = get_current_platform()
    
    def is_platform_supported(self) -> bool:
        if not self.supported_platforms:  # Empty list = all platforms
            return True
        return self._current_platform in self.supported_platforms
    
    def is_admin(self) -> bool:
        try:
            if is_windows():
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else: 
                return os.geteuid() == 0
        except Exception:
            return False
    
    @abstractmethod
    def detect(self) -> TechniqueResult:
        pass
    
    def safe_detect(self) -> TechniqueResult:
        if not self.is_platform_supported():
            self.logger.debug(f"Skipping - unsupported platform: {self._current_platform}")
            return TechniqueResult(
                name=self.name,
                detected=False,
                details=f"Unsupported platform: {self._current_platform}",
                error="Platform not supported"
            )
        
        if self.requires_admin and not self.is_admin():
            self.logger.warning(f"Skipping - requires admin privileges")
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Requires elevated privileges",
                error="Insufficient permissions"
            )
        
        try:
            self.logger.info(f"Running detection: {self.name}")
            result = self.detect()
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
                details="Detection check failed",
                error=str(e)
            )

from ...base import BaseDetector
from ....core.result import TechniqueResult
from ....platform.base import is_linux, is_windows

class PCIDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="PCI Device Detection",
                         supported_platforms=['windows','linux'],
                         requires_admin=False
        )

    def detect(self) -> TechniqueResult:
        if is_windows():
            return self._check_windows()
        if is_linux():
            return self._check_linux()
        else: # Redundant but still good for checking
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Platform not supported."
            )
            
        
            

    def _check_linux():
        pass

    def _check_windows():
        pass



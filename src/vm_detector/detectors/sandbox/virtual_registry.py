from ..base import BaseDetector
from ...core.result import TechniqueResult

class VirtualRegistryDetector(BaseDetector):
    
    def __init__(self):
        super().__init__(name="Virtual Registry Detection",
                         supported_platforms=['windows'],
                         requires_admin=False
        )

    def detect(self) -> TechniqueResult:
        self.logger.debug("Checking for registry virtualization...")

        try:
            from ...platform.windows import get_registry_object_path

            expected_path = r'\REGISTRY\USER'
            actual_path = get_registry_object_path(expected_path)

            if actual_path is None:
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    error="Failed to query register object path."
                )

            if actual_path != expected_path:
                self.logger.info(f"Registry virtualization detected: {actual_path}")
                return TechniqueResult(
                    name=self.name,
                    detected=True,
                    details=f"Detected Sandboxie via registry path: {actual_path}"
                )
            
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="No registry virtualization detected."
            )
            
        except Exception as e:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error=f"Failed to check registry virtualization: {e}"
            )

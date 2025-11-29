from ..base import BaseDetector
from ...core.result import TechniqueResult

from src.utils.platform.windows import get_remote_metrics, get_session_protocol

class RDPSessionDetector(BaseDetector):

    def __init__(self):
        
        super().__init__(
            name="RDP Session Detection",
            supported_platforms=['windows'],
            requires_admin=False
            )
    
    def scan(self) -> TechniqueResult:
        is_remote_metric = get_remote_metrics()
        protocol = get_session_protocol()

        # Check 1: Remote Session Checking of RDP
        if is_remote_metric:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details="Active RDP Session deecte via System Metrics."
            )
        
        # Check 2: Multiple Concurrent User Detection
        if protocol == 2:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details="Active RDP Protocol detected for concurrent users."
            )
        
        return TechniqueResult(
            name=self.name,
            detected=False,
            details="No RDP Protocol found."
        )

    def monitor(self) -> TechniqueResult:
        is_remote_metric = get_remote_metrics()

        # Only Checking remote metric as it is easy on hardware for continous checking.
        if is_remote_metric:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details="Active RDP Session deecte via System Metrics."
            )
        
        return TechniqueResult(
            name=self.name,
            detected=False,
            details="No RDP Protocol found."
        )
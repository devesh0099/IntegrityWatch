from ...base import BaseDetector
from ....core.result import TechniqueResult

class HypervisorBitDetector(BaseDetector):
    # Detecting VM's by checking hypervisor present bit in CPUID leaf 1.

    def __init__(self):
        super().__init__(
            name="CPUID Hypervisor Bit",
            supported_platforms=["windows", 'linux', 'macos'],
            requires_admin=False
        )

    def detect(self) ->TechniqueResult:
        try:
            from ....platform import base
        except ImportError:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="CPU platform module not available"
            )
        
        features = base.get_cpuid_features()

        if not features:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Could not read CPUID features"
            )
        
        ecx = features.get('ecx', 0)

        hypervisor_bit = (ecx >> 31) & 1

        if hypervisor_bit == 1:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details=f"Hypervisor present bit is SET (CPUID leaf 1, ECX bit 31 = 1)"
            )
        else:
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Hypervisor present bit is CLEAR (ECX bit 31 = 0)."
            )

from ...base import BaseDetector
from ....core.result import TechniqueResult

class HypervisorBitDetector(BaseDetector):
    # Detecting VM's by checking hypervisor present bit in CPUID leaf 1.

    def __init__(self):
        super().__init__(
            name="CPUID Hypervisor Bit",
            supported_platforms=[],
            requires_admin=False
        )

    def detect(self) ->TechniqueResult:
        self.logger.info("Checking CPU Hypervisor Present bit...")
        try:
            from src.utils.platform import base
        except ImportError:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="CPU platform module not available"
            )
        
        features = base.get_cpuid_features()

        if not features:
            self.logger.error("Failed to read CPUID features")
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Could not read CPUID features"
            )
        
        ecx = features.get('ecx', 0)
        hypervisor_bit = (ecx >> 31) & 1

        self.logger.debug(f"CPUID leaf 1 ECX: 0x{ecx:08X}, Bit 31: {hypervisor_bit}")

        if hypervisor_bit == 1:
            self.logger.info("Hypervisor bit set.")
            return TechniqueResult(
                name=self.name,
                detected=True,
                details=f"Hypervisor present bit is SET (CPUID leaf 1, ECX bit 31 = 1)"
            )
        else:
            self.logger.info("Hypervisor bit clear.")
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Hypervisor present bit is CLEAR (ECX bit 31 = 0)."
            )

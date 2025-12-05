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

    def detect(self) -> TechniqueResult:
        self.logger.info("Checking CPU Hypervisor Present bit...")
        
        try:
            from src.utils.platform import base
        except ImportError:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="CPU platform module not available"
            )
        
        # Check 1: Check hypervisor bit
        features = base.get_cpuid_features()
        if not features:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Could not read CPUID features"
            )
        
        ecx = features.get('ecx', 0)
        hypervisor_bit = (ecx >> 31) & 1
        
        self.logger.debug(f"CPUID leaf 1 ECX: 0x{ecx:08X}, Bit 31: {hypervisor_bit}")
        
        # If bit is 0, definitely not a VM
        if hypervisor_bit == 0:
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Hypervisor present bit is CLEAR (not a VM)"
            )
        
        # Check 2: Bit is 1 - Verify with leaf 0x40000000 EAX
        try:
            eax, ebx, ecx_hv, edx = base.get_cpuid_registers(0x40000000)
            
            self.logger.debug(f"CPUID 0x40000000 EAX: 0x{eax:08X}")
            
            # Checking if eax is empty or not
            if eax >= 0x40000000:
                return TechniqueResult(
                    name=self.name,
                    detected=True,
                    details=f"Hypervisor detected (EAX=0x{eax:08X})"
                )
            else:
                # False positive
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    details="Hypervisor bit set but no VM (Hyper-V host or WSL)"
                )
        except Exception as e:
            self.logger.warning(f"Failed to verify hypervisor: {e}")
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Unable to verify hypervisor presence"
            )
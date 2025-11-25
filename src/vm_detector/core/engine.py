from ...utils.logger import get_logger

from .result import DetectionResult, TechniqueResult, VERDICT_BLOCK, VERDICT_CLEAN, VERDICT_FLAG
from ..detectors.base import BaseDetector

from ..detectors.hardware.cpu.hypervisor_bit import HypervisorBitDetector
from ..detectors.hardware.cpu.vmid import CPUIDVendorDetector
from ..detectors.hardware.firmware.pci_devices import PCIDetector
from ..detectors.hardware.firmware.smbios_tables import SMBIOSDetector
from ..detectors.hardware.firmware.kernel_objects import KernelObjectDetector
from ..detectors.hardware.network.mac_address import MACAddressDetector
from ..detectors.sandbox.virtual_registry import VirtualRegistryDetector

TIER_MAPPING = {
            "CPUID Hypervisor Bit": "CRITICAL",
            "CPUID Vendor String": "CRITICAL",
            "Virtual Registry Detection": "CRITICAL", 
            
            "Firmware Table Scan": "HIGH",
            "PCI Device Detection": "HIGH",
            "Kernel Object Detection": "HIGH",
            
            "MAC Address Check": "LOW"
        }


class DetectionEngine:
    def __init__(self):
        self.logger = get_logger("vm_detector.engine")
        self.detectors: list[BaseDetector] = self._load_detectors()

        self.TIER_MAPPING = TIER_MAPPING

    def _load_detectors(self) -> list[BaseDetector]:
        return [
            HypervisorBitDetector(),
            CPUIDVendorDetector(),
            VirtualRegistryDetector(),
            SMBIOSDetector(),
            PCIDetector(),
            KernelObjectDetector(),
            MACAddressDetector(),
        ]
    
    def run(self) -> DetectionResult:
        result = DetectionResult()

        self.logger.info("Starting detection engine...")

        for detector in self.detectors:
            try:
                tech_res = detector.safe_detect()

                tech_res.tier = self.TIER_MAPPING.get(tech_res.name, "LOW")

                if tech_res.detected:
                    if tech_res.tier == "CRITICAL":
                        result.critical_hits += 1
                    elif tech_res.tier == "HIGH":
                        result.high_hits += 1
                    elif tech_res.tier == "LOW":
                        result.low_hits += 1
                
                result.techniques.append(tech_res)
            
            except Exception as e:
                self.logger.error(f"Detector {detector.name} failed {e}")
                # Added the Failed test as False
                err_res = TechniqueResult(
                    name=detector.name,
                    detected=False,
                    tier=self.TIER_MAPPING.get(detector.name, "LOW"),
                    error=str(e)
                )
                result.techniques.append(err_res)

        self._apply_logic(result)

        return result
    
    def _apply_logic(self, result: DetectionResult):
        # Decision Tree for Comprehensive Analysis

        critical_detection = result.critical_hits > 0
        high_detection = result.high_hits > 0
        low_detection = result.low_hits > 0

        if critical_detection:
            result.verdict = VERDICT_BLOCK
            
            # Check for Sandbox specifically (Special Case)
            is_sandbox = any(t.name == "Virtual Registry Detection" and t.detected for t in result.techniques)
            
            if is_sandbox:
                result.reason = "Sandbox Isolation Detected (Critical)"
            elif high_detection and low_detection:
                result.reason = "Standard Virtual Machine (No Evasion)"
            elif high_detection and not low_detection:
                result.reason = "VM Detected (Lazy Evasion: MAC Spoofed)"
            elif not high_detection and not low_detection:
                result.reason = "High-Sophistication Evasion (Hidden Firmware and MAC)"
            else:
                result.reason = "Virtual Machine Detected (CPU Level)"

        elif high_detection:
            result.verdict = VERDICT_BLOCK
            if low_detection:
                result.reason = "Hardened VM Detected (CPU Hidden)"
            else:
                result.reason = "Elite Evasion Attempt (CPU & MAC Hidden, Firmware Exposed)"

        elif low_detection:
            # The False Positive Case
            result.verdict = VERDICT_FLAG
            result.reason = "Suspicious Environment (Manual Review)"

        else:
            result.verdict = VERDICT_CLEAN
            result.reason = "System appears clean"

        
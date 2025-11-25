from src.utils.logger import get_logger
from src.remote_access.core.result import DetectionResult, TechniqueResult, VERDICT_BLOCK, VERDICT_FLAG, VERDICT_CLEAN
from src.remote_access.detectors.base import BaseDetector

class DetectionEngine:
    def __init__(self):
        self.logger = get_logger("remote.engine")
        self.detectors: list[BaseDetector] = self._load_detectors()

    def _load_detectors(self) -> list[BaseDetector]:
        return []

    def run(self) -> DetectionResult:
        self.logger.info("Starting Remote Access Detection Scan...")
        result = DetectionResult()

        # 1. Run all detectors
        for detector in self.detectors:
            tech_result = detector.safe_detect()
            result.techniques.append(tech_result)

            if tech_result.detected:
                if tech_result.tier == "CRITICAL":
                    result.critical_hits += 1
                elif tech_result.tier == "HIGH":
                    result.high_hits += 1
                elif tech_result.tier == "LOW":
                    result.low_hits += 1

        self._apply_verdict_logic(result)
        
        return result

    def _apply_verdict_logic(self, result: DetectionResult):
        critical = result.critical_hits > 0
        high = result.high_hits > 0
        low = result.low_hits > 0

        if critical:
            result.verdict = VERDICT_BLOCK
            result.reason = "Active Remote Control Detected (Critical)"
        
        elif high:
            result.verdict = VERDICT_BLOCK 
            result.reason = "Remote Access Tool Running (High Confidence)"

        elif low:
            result.verdict = VERDICT_FLAG
            result.reason = "Suspicious Background Service or Artifact"
            
        else:
            result.verdict = VERDICT_CLEAN
            result.reason = "No remote access tools detected"
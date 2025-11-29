from src.utils.logger import get_logger
from src.remote_access.core.result import DetectionResult, TechniqueResult, VERDICT_BLOCK, VERDICT_FLAG, VERDICT_CLEAN, VERDICT_SKIPPED
from src.remote_access.detectors.base import BaseDetector

import threading
import time
from typing import Callable

from ..detectors.rdp_session.rdp_session import RDPSessionDetector
from ..detectors.process_detector.process_detection import ProcessDetector

TIER_MAPPING = {
    "RDP Session Detection": "CRITICAL",
    "Process Detection": "CRITICAL"
}

class DetectionEngine:
    def __init__(self):
        self.logger = get_logger("remote.engine")
        self.detectors: list[BaseDetector] = self._load_detectors()
        self.current_violations: dict[str, TechniqueResult] = {}
        self.TIER_MAPPING = TIER_MAPPING

        self._monitoring = False
        self._monitor_thread = None
        self._stop_event = threading.Event()
        self._successful_detector_names = set()

    def _load_detectors(self) -> list[BaseDetector]:
        return [
            RDPSessionDetector(),
            ProcessDetector()
        ]

    def run(self) -> DetectionResult:
        self.logger.info("Starting Remote Access Baseline Detection Scan...")
        result = DetectionResult()

        # Running all detectors
        for detector in self.detectors:
            tech_result = detector.safe_scan()
            
            if tech_result.error == None:
                self._successful_detector_names.add(tech_result.name)
            
            tech_result.tier = self.TIER_MAPPING.get(tech_result.name, "LOW")

            if tech_result.detected:
                if tech_result.tier == "CRITICAL":
                    result.critical_hits += 1
                elif tech_result.tier == "HIGH":
                    result.high_hits += 1
                elif tech_result.tier == "LOW":
                    result.low_hits += 1
            
            result.techniques.append(tech_result)

        # Updating Violation list
        for tech in result.techniques:
            if tech.detected:
                self.current_violations[tech.name] = tech

        self._apply_verdict_logic(result)
        
        return result

    def start_monitoring(self, 
                         interval: int = 5, 
                         display_callback: Callable[[DetectionResult], None] = None,
                         heartbeat_callback: Callable[[dict], None] = None
                         ): # Starts a new thread for background monitoring every 5 seconds
        if self._monitoring:
            self.logger.warning("Monitoring already active.")
            return
        
        self._monitoring = True
        self._stop_event.clear()

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval, display_callback, heartbeat_callback),
            daemon=True
        )

        self._monitor_thread.start()
        self.logger.info(f"Remote Access Monitoring started (Interval: {interval}s)")
    
    def stop_monitoring(self):
        self._monitoring = False
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
        self.logger.info("Monitoring stopped.")

    def _monitor_loop(self, interval: int, display_callback, heartbeat_callback): # Function to run on thread
        while not self._stop_event.is_set():
            cycle_result = DetectionResult()
            
            for detector in self.detectors:
                if detector.name not in self._successful_detector_names:
                    continue
                tech_result = detector.safe_monitor()
                tech_result.tier = self.TIER_MAPPING.get(tech_result.name, "LOW")

                if tech_result.detected:
                    if tech_result.tier == "CRITICAL":
                        cycle_result.critical_hits += 1
                    elif tech_result.tier == "HIGH":
                        cycle_result.high_hits += 1
                    elif tech_result.tier == "LOW":
                        cycle_result.low_hits += 1
                    
                cycle_result.techniques.append(tech_result)

            self._apply_verdict_logic(cycle_result)

            if heartbeat_callback:
                payload = cycle_result.to_heartbeat_dict()
                heartbeat_callback(payload)

            if cycle_result.verdict == VERDICT_BLOCK:
                self.logger.critical(f"Blocking Violation: {cycle_result.reason}")

                if display_callback:
                    display_callback(cycle_result)

                self._stop_event.set()
                self._monitoring = False
                break

            elif cycle_result.verdict == VERDICT_FLAG:
                is_new_violation = False

                for tech in cycle_result.techniques:
                    if tech.detected and tech.name not in self.current_violations:
                        self.current_violations[tech.name] = tech
                        is_new_violation = True
                
                if is_new_violation:
                    self.logger.warning(f"Flagged: {cycle_result.reason}")
                    
            if display_callback:
                display_callback(cycle_result)

            self._stop_event.wait(timeout=interval)


    def _apply_verdict_logic(self, result: DetectionResult):
        if not result.techniques:
            result.verdict = "SKIPPED"
            result.reason = "No detection modules were active."
            return
        
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
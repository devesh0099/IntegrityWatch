import json
from pathlib import Path
from datetime import datetime
from typing import Any
import threading

from src.config import config

from .result import DetectionResult, TechniqueResult, VERDICT_BLOCK, VERDICT_FLAG, VERDICT_PASS
from ...utils.logger import get_logger

from ..detectors.base import BaseDetector
from ..detectors.screen_share import ScreenShareDetector
from ..detectors.tab_switching import TabSwitchingDetector
from ..detectors.malicious_extension import MaliciousExtensionDetector
from ..detectors.dom_manipulation import DOMManipulationDetector

SEVERITY_MAPPING = {
    "Screen Sharing Detection": "CRITICAL",
    "Malicious Extension Detection": "CRITICAL",
    "DOM Manipulation Detection": "CRITICAL",
    "Tab Switching Detection": "HIGH"
}

class DetectionEngine:
    def __init__(self, browser_dir: Path):
        self.browser_dir = Path(browser_dir)
        self.logger = get_logger("browser_monitor.engine")

        self.violations_file = self._find_violations_file()
        self.raw_violations: list[dict[str, Any]] = []

        self.detectors: list[BaseDetector] = self._load_detectors()
        self.current_violations: dict[str, TechniqueResult] = {}
        self.SEVERITY_MAPPING = SEVERITY_MAPPING

        self._monitoring = False
        self._monitor_thread = None
        self._stop_event = threading.Event()
        self._successful_detector_names = set()
        self._last_violation_count = 0

    def _find_violations_file(self) -> Path:
        session_file = self.browser_dir / 'violations.json'
        if session_file.exists():
            return session_file
        
        return session_file
    
    def _load_detectors(self) -> list[BaseDetector]:
        return [
            ScreenShareDetector(),
            TabSwitchingDetector(),
            MaliciousExtensionDetector(),
            DOMManipulationDetector()
        ]
    
    def load_data(self) -> bool:
        if not self.violations_file.exists():
            self.logger.warning(f"Violations file not found: {self.violations_file}")
            return False
        
        try:
            with open(self.violations_file, 'r') as f:
                self.raw_violations = json.load(f)

            self.logger.info(f"Loaded {len(self.raw_violations)} violations")

            for detector in self.detectors:
                detector.load_data(self.raw_violations)

            return True
        
        except Exception as e:
            self.logger.error(f"Failed to load violations: {e}")
            return False
        
    def run(self) -> DetectionResult:
        self.logger.info("Starting Browser Monitoring Baseline Analysis...")
        report = DetectionResult()
        report.session_id = self.browser_dir.name

        for detector in self.detectors:
            result = detector.safe_scan()

            if result.error is None:
                self._successful_detector_names.add(result.name)

            result.severity = self.SEVERITY_MAPPING.get(result.name, "LOW")

            if result.detected:
                if result.severity == "CRITICAL":
                    report.critical_violations += 1
                elif result.severity == "HIGH":
                    report.high_violations += 1
                elif result.severity == "MEDIUM":
                    report.medium_violations += 1
                elif result.severity == "LOW":
                    report.low_violations += 1
            
            report.violations.append(result)
        
        for detector in report.violations:
            if detector.detected:
                self.current_violations[detector.name] = detector

        report.total_violations = sum(v.count for v in report.violations if v.detected)
        report.exam_duration_minutes = self._calculate_duration()

        self._apply_logic(report)
        self._last_violation_count = len(self.raw_violations)

        return report
    
    def check_current_state(self) -> DetectionResult:
        result = DetectionResult()
        result.session_id = self.browser_dir.name
        
        if not self.load_data():            
            result.verdict = "SKIPPED"
            result.reason = "Waiting for browser monitoring to start"
            return result
                
        if len(self.raw_violations) == self._last_violation_count:            
            result.verdict = "SKIPPED"
            result.reason = "No new activity"
            return result
        
        self._last_violation_count = len(self.raw_violations)
        for detector in self.detectors:
            if detector.name not in self._successful_detector_names:
                continue
                        
            tech_result = detector.safe_scan()
            tech_result.severity = self.SEVERITY_MAPPING.get(tech_result.name, "LOW")
            
            if tech_result.detected:
                if tech_result.severity == "CRITICAL":
                    result.critical_violations += 1
                elif tech_result.severity == "HIGH":
                    result.high_violations += 1
                elif tech_result.severity == "MEDIUM":
                    result.medium_violations += 1
                elif tech_result.severity == "LOW":
                    result.low_violations += 1
                
                result.violations.append(tech_result)
        
        result.total_violations = sum(v.count for v in result.violations if v.detected)
        result.exam_duration_minutes = self._calculate_duration()

        self._apply_logic(result)
                
        for violation in result.violations:
            if violation.detected:
                self.current_violations[violation.name] = violation
        
        return result

    def _calculate_duration(self) -> float:
        if not self.raw_violations:
            return 0.0
        
        timestamps = [v.get('timestamp', 0) for v in self.raw_violations if v.get('timestamp')]
        
        if not timestamps:
            return 0.0
        
        duration_ms = max(timestamps) - min(timestamps)
        return duration_ms / 1000 / 60
    
    def _apply_logic(self, report: DetectionResult):
        if not report.violations:
            report.verdict = "SKIPPED"
            report.reason = "No detectors were active."
            return
        
        critical_detected = report.critical_violations > 0
        high_detected = report.high_violations > 0
        medium_detected = report.medium_violations > 0
        
        allow_suspicious_websites = config.get("browser", "allow_suspicious_websites", False)
        allow_suspicious_extensions = config.get("browser", "allow_suspicious_extensions", False)
        
        is_screen_share = any(
            v.name == "Screen Sharing Detection" and v.detected
            for v in report.violations
        )
        
        is_malicious_extension = any(
            v.name == "Malicious Extension Detection" and v.detected
            for v in report.violations
        )
        
        is_dom_manipulation = any(
            v.name == "DOM Manipulation Detection" and v.detected
            for v in report.violations
        )
        
        is_tab_switching = any(
            v.name == "Tab Switching Detection" and v.detected
            for v in report.violations
        )
        
        flag_count = 0
        block_reasons = []
        
        if is_screen_share:
            block_reasons.append("Screen Sharing Detected (Critical)")
        
        if is_dom_manipulation:
            block_reasons.append("DOM manipulation detected by extension")
        
        if is_malicious_extension:
            if not allow_suspicious_extensions:
                block_reasons.append("Malicious Extension Detected with Dangerous Permissions (Critical)")
            else:
                flag_count += 1
        
        if is_tab_switching:
            if not allow_suspicious_websites:
                block_reasons.append("High-Severity Violations (Communication Apps)")
            else:
                flag_count += 1
        
        if medium_detected and report.total_violations >= 10:
            flag_count += 1
        
        if block_reasons:
            report.verdict = VERDICT_BLOCK
            report.reason = ", ".join(block_reasons)
        elif flag_count > 0:
            report.verdict = VERDICT_FLAG
            if flag_count == 1:
                if is_malicious_extension and allow_suspicious_extensions:
                    report.reason = "Suspicious Extension Detected (Manual Review Required)"
                elif is_tab_switching and allow_suspicious_websites:
                    report.reason = "Suspicious Tab Activity Detected (Manual Review Required)"
                else:
                    report.reason = "Suspicious Activity Detected (Manual Review Required)"
            else:
                report.reason = f"Multiple violations detected ({flag_count} types) - Manual Review Required"
        elif medium_detected:
            report.verdict = VERDICT_PASS
            report.reason = "Minor Violations Within Acceptable Limits"
        else:
            report.verdict = VERDICT_PASS
            report.reason = "Clean exam session - no violations detected"

    def _to_heartbeat_dict(self, report: DetectionResult) -> dict:
        return {
            "module": "browser_monitor",
            "timestamp": datetime.now().isoformat(),
            "session_id": report.session_id,
            "verdict": report.verdict,
            "reason": report.reason,
            "total_violations": report.total_violations,
            "severity_counts": {
                "critical": report.critical_violations,
                "high": report.high_violations,
                "medium": report.medium_violations,
                "low": report.low_violations
            },
            "violations": [v.to_dict() for v in report.violations if v.detected]
        }

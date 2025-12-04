from typing import Any
from .base import BaseDetector
from ..core.result import TechniqueResult


class DOMManipulationDetector(BaseDetector):
    def __init__(self):
        super().__init__("DOM Manipulation Detection")
        self.severity = "UNKNOWN"
    
    def scan(self) -> TechniqueResult:
        dom_violations = self.filter_violations([
            'FOREIGN_EXTENSION_SCRIPT',
            'EXTENSION_ELEMENT_INJECTED',
            'SUSPICIOUS_OVERLAY',
            'LARGE_CODE_PASTE',
            'PROGRAMMATIC_INPUT'
        ])
        
        if not dom_violations:
            return TechniqueResult(
                name=self.name,
                detected=False,
                severity=self.severity,
                details="No DOM manipulation detected",
                count=0
            )
        
        violation_counts = {}
        for violation in dom_violations:
            vtype = violation.get('type', 'UNKNOWN')
            violation_counts[vtype] = violation_counts.get(vtype, 0) + 1
        
        details_parts = []
        if violation_counts.get('FOREIGN_EXTENSION_SCRIPT'):
            details_parts.append(f"{violation_counts['FOREIGN_EXTENSION_SCRIPT']} foreign script(s)")
        if violation_counts.get('EXTENSION_ELEMENT_INJECTED'):
            details_parts.append(f"{violation_counts['EXTENSION_ELEMENT_INJECTED']} injected element(s)")
        if violation_counts.get('SUSPICIOUS_OVERLAY'):
            details_parts.append(f"{violation_counts['SUSPICIOUS_OVERLAY']} overlay(s)")
        if violation_counts.get('LARGE_CODE_PASTE'):
            details_parts.append(f"{violation_counts['LARGE_CODE_PASTE']} large paste(s)")
        if violation_counts.get('PROGRAMMATIC_INPUT'):
            details_parts.append(f"{violation_counts['PROGRAMMATIC_INPUT']} programmatic input(s)")
        
        details_str = "DOM manipulation detected: " + ", ".join(details_parts)
        
        self.logger.warning(f"DOM manipulation: {violation_counts}")
        
        return TechniqueResult(
            name=self.name,
            detected=True,
            severity=self.severity,
            details=details_str,
            count=len(dom_violations)
        )

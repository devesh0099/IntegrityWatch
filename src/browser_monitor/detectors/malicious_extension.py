from .base import BaseDetector
from ..core.result import TechniqueResult


class MaliciousExtensionDetector(BaseDetector):
    def __init__(self):
        super().__init__("Malicious Extension Detection")
        self.severity = "UNKNOWN"
    
    def scan(self) -> TechniqueResult:
        malicious_ext_violations = self.filter_violations([
            'MALICIOUS_EXTENSION_DETECTED'
        ])
        
        if not malicious_ext_violations:
            return TechniqueResult(
                name=self.name,
                detected=False,
                severity=self.severity,
                details="No suspicious extensions detected",
                count=0
            )
        
        detected_extensions = []
        for violation in malicious_ext_violations:
            details = violation.get('details', {})
            ext_name = details.get('extensionName', 'Unknown')
            permissions = details.get('permissions', [])
            
            detected_extensions.append({
                'name': ext_name,
                'permissions': permissions
            })
        
        extension_names = [ext['name'] for ext in detected_extensions]
        details_str = f"Detected {len(detected_extensions)} suspicious extension(s): {', '.join(extension_names)}"
        
        self.logger.warning(f"Malicious extensions detected: {extension_names}")
        
        return TechniqueResult(
            name=self.name,
            detected=True,
            severity=self.severity,
            details=details_str,
            count=len(detected_extensions)
        )

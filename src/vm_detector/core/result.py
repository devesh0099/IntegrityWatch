from dataclasses import dataclass, field
from typing import Optional

STATUS_CLEAN = "CLEAN"
STATUS_VM_DETECTED = "VM_DETECTED"
STATUS_EVASION = "EVASION_DETECTED"
STATUS_SANDBOX = "SANDBOX_BLOCKED"


@dataclass
class TechniqueResult:
    name: str
    detected: bool
    details: str = ""
    error: Optional[str] = None

    def is_detected(self) -> bool:
        return self.detected
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'detected': self.detected,
            'details': self.details,
            'error': self.error
        }

@dataclass
class DetectionResult:
    techniques: list[TechniqueResult] = field(default_factory=list)
    status: str = STATUS_CLEAN # CLEAN, VM_DETECTED, EVASION, SANDBOX
    mix_detected: bool = False
    true_count: int = 0
    total_count: int = 0


    def is_blocked(self) -> bool:
        return self.status != STATUS_CLEAN

    def get_summary(self) -> str:
        if self.status == STATUS_CLEAN:
            return "No VM or sandbox detected."
        elif self.status == STATUS_SANDBOX:
            return "Sandbox isolatoin detected."
        elif self.status == STATUS_EVASION:
            triggered = [t.name for t in self.techniques if t.detected]
            bypassed = [t.name for t in self.techniques if not t.detected and not t.error]
            return (f"Evasion attempt detected ({self.true_count}/{self.total_count} mixed)\n"
                   f"  Triggered: {', '.join(triggered)}\n"
                   f"  Bypassed: {', '.join(bypassed)}")
        else:
            triggered = [t.name for t in self.techniques if t.detected]
            return f"VM detected = {', '.join(triggered)}"


    def is_mixed(self) -> bool:
        if(0 < self.true_count and self.true_count < len(self.techniques)):
            return True
        return False
    
    def to_dict(self) -> dict:
        return {
            'status': self.status,
            'is_blocked': self.is_blocked(),
            'mix_detected': self.mix_detected,
            'true_count': self.true_count,
            'total_count': self.total_count,
            'summary': self.get_summary(),
            'techniques': [t.to_dict() for t in self.techniques]
        }

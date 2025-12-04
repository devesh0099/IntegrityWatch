from dataclasses import dataclass, field
from typing import Optional
import json
from datetime import datetime, timezone

from src.utils.colors import RED, GREEN, PURPLE, YELLOW, CYAN, BOLD, RESET, BLUE

VERDICT_BLOCK = "BLOCK"
VERDICT_FLAG = "FLAG"
VERDICT_CLEAN = "ALLOW"

@dataclass
class TechniqueResult:
    name: str
    detected: bool
    tier: str = "UNKNOWN"
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
    verdict: str = VERDICT_CLEAN
    reason: str = "System appears clean passes all the test."

    critical_hits: int = 0
    high_hits: int = 0
    low_hits: int = 0

    def to_json(self) -> str:
        data = {
            "module": "vm_detector",
            "verdict": self.verdict,
            "reason": self.reason,
            "tier_summary": {
                "critical_triggers": self.critical_hits,
                "high_hits": self.high_hits,
                "low_hits": self.low_hits
            },
            "details": [t.to_dict() for t in self.techniques],
            "meta": {
                "version":"0.1.0",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }

        return json.dumps(data, indent=2)

    def display(self):
        print(f"\n{BOLD}{CYAN}>>> VM EVASION MODULE{RESET}")
        print(f"{CYAN}{'-'*60}{RESET}")

        sorted_techs = sorted(self.techniques, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "LOW": 2}.get(x.tier, 99))

        for tech in sorted_techs:
            if tech.detected:
                status_color = RED
                status_text = "DETECTED"
            else:
                status_color = GREEN
                status_text = "PASS"

            tier_color = PURPLE if tech.tier == "CRITICAL" else (YELLOW if tech.tier == "HIGH" else CYAN)

            print(f"[{tier_color}{tech.tier:^8}{RESET}] {tech.name:<35} [{status_color}{status_text:^8}{RESET}]")

            if tech.detected:
                print(f"    {YELLOW}↳ {tech.details}{RESET}")
            if tech.error:
                print(f"    {RED}↳ ERROR: {tech.error}{RESET}")
        
        verdict_color = RED if self.verdict == "BLOCK" else (YELLOW if self.verdict == "FLAG" else GREEN)
        print(f"{CYAN}{'-'*60}{RESET}")
        print(f"VM VERDICT: {verdict_color}{self.verdict}{RESET} | {self.reason}")

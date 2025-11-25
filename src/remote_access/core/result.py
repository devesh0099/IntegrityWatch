from dataclasses import dataclass, field
from typing import Optional, List
import json
from datetime import datetime, timezone

VERDICT_BLOCK = "BLOCK"
VERDICT_FLAG = "FLAG"
VERDICT_CLEAN = "ALLOW"

@dataclass
class TechniqueResult:
    name: str
    detected: bool
    tier: str = "UNKNOWN"  # CRITICAL, HIGH, LOW
    details: str = ""      
    error: Optional[str] = None

    def is_detected(self) -> bool:
        return self.detected
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'detected': self.detected,
            'tier': self.tier,
            'details': self.details,
            'error': self.error
        }

@dataclass
class DetectionResult:
    techniques: List[TechniqueResult] = field(default_factory=list)
    verdict: str = VERDICT_CLEAN
    reason: str = "No remote access tools detected."

    critical_hits: int = 0
    high_hits: int = 0
    low_hits: int = 0

    def to_json(self) -> str:
        data = {
            "module": "remote_access",
            "verdict": self.verdict,
            "reason": self.reason,
            "tier_summary": {
                "critical_hits": self.critical_hits,
                "high_hits": self.high_hits,
                "low_hits": self.low_hits
            },
            "details": [t.to_dict() for t in self.techniques],
            "meta": {
                "version": "0.1.0",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        return json.dumps(data, indent=2)

    def display(self):
        RED = '\033[91m'
        GREEN = '\033[92m'
        PURPLE = '\033[95m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'
        RESET = '\033[0m'

        print(f"\n{BOLD}{CYAN}>>> REMOTE ACCESS MODULE{RESET}")
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
        print(f"REMOTE VERDICT: {verdict_color}{self.verdict}{RESET} | {self.reason}")

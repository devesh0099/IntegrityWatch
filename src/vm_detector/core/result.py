from dataclasses import dataclass, field
from typing import Optional
import json
from datetime import datetime, timezone
from pathlib import Path
from ...config import config

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
    
    def save(self):
        if not config.get("output", "save_json"):
            return
        
        file_path = config.get("output", "json_path")
        output_path = Path(file_path)

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path,"w") as f:
                f.write(self.to_json())

            return str(output_path)
        except Exception as e:
            return None


    def display(self):
        RED = '\033[91m'
        GREEN = '\033[92m'
        PURPLE = '\033[95m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'
        RESET = '\033[0m'

        print(f"\n{BOLD}{CYAN}INTEGRITY WATCH v0.1.0{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}SCANNING HOST ENVIRONMENT...{RESET}\n")

        # Sort techniques by Tier for display: CRITICAL -> HIGH -> LOW
        sorted_techs = sorted(self.techniques, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "LOW": 2}.get(x.tier, 99))

        for tech in sorted_techs:
            if tech.detected:
                status_color = RED
                status_text = "DETECTED"
            else:
                status_color = GREEN
                status_text = "PASS"

            tier_color = PURPLE if tech.tier == "CRITICAL" else (YELLOW if tech.tier == "HIGH" else CYAN)

            # Format: [TIER] Name ........... [ STATUS ]
            line = f"[{tier_color}{tech.tier:8}{RESET}] {tech.name:<30} [{status_color}{status_text:^8}{RESET}]"
            print(line)

            if tech.detected:
                print(f"    {YELLOW}↳ {tech.details}{RESET}")
            if tech.error:
                print(f"    {RED}↳ ERROR: {tech.error}{RESET}")
        
        print(f"\n{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}ANALYSIS COMPLETED.{RESET}")
        
        verdict_color = RED if self.verdict == VERDICT_BLOCK else (YELLOW if self.verdict == VERDICT_FLAG else GREEN)
        print(f">> VERDICT:  {verdict_color}{BOLD}{self.verdict}{RESET}")
        print(f">> REASON:   {self.reason}")
        print(f"{CYAN}{'='*60}{RESET}\n")

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import json
from datetime import datetime, timezone

from integritywatch.utils.colors import RED, GREEN, PURPLE, YELLOW, CYAN, BOLD, RESET, BLUE

import sys

VERDICT_BLOCK = "BLOCK"
VERDICT_FLAG = "FLAG"
VERDICT_CLEAN = "ALLOW"
VERDICT_SKIPPED = "SKIPPED"

@dataclass
class TechniqueResult:
    name: str
    detected: bool
    tier: str = "UNKNOWN"  # CRITICAL, HIGH, LOW
    details: str = ""      
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def is_detected(self) -> bool:
        return self.detected
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'detected': self.detected,
            'tier': self.tier,
            'details': self.details,
            'error': self.error,
            'data': self.data
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

            if tech.error == "Platform not supported":
                continue

            tier_color = PURPLE if tech.tier == "CRITICAL" else (YELLOW if tech.tier == "HIGH" else CYAN)

            print(f"[{tier_color}{tech.tier:^8}{RESET}] {tech.name:<35} [{status_color}{status_text:^8}{RESET}]")

            if tech.detected:
                print(f"    {YELLOW}↳ {tech.details}{RESET}")
            if tech.error:
                print(f"    {RED}↳ ERROR: {tech.error}{RESET}")
        
        verdict_color = RED if self.verdict == "BLOCK" else (YELLOW if self.verdict == "FLAG" else GREEN)
        print(f"{CYAN}{'-'*60}{RESET}")
        print(f"REMOTE VERDICT: {verdict_color}{self.verdict}{RESET} | {self.reason}")
    
    def display_monitor(self):
        timestamp = datetime.now().strftime("%H:%M:%S")

        if self.verdict == VERDICT_CLEAN:
            print(f"\r{BLUE}[{timestamp}]{RESET} Monitor Status: {GREEN}SECURE{RESET} | Scanning active...", end="", flush=True)
        
        elif self.verdict == VERDICT_SKIPPED:
             print(f"\r{BLUE}[{timestamp}]{RESET} Monitor Status: {YELLOW}IDLE{RESET}   | {self.reason}", end="", flush=True)
        
        else:
            print(f"\r{' ' * 80}\r", end="") 
            
            if self.verdict == VERDICT_BLOCK:
                tag_color = RED
            else: 
                tag_color = YELLOW

            print(f"{tag_color}{BOLD}{'-'*60}{RESET}")
            print(f"{tag_color}{BOLD}SECURITY ALERT [{timestamp}]{RESET}")
            print(f"{tag_color}{BOLD}{'-'*60}{RESET}")
            print(f"VERDICT: {tag_color}{self.verdict}{RESET}")
            print(f"REASON : {self.reason}")
            

            print(f"\n{BOLD}Violations Detected:{RESET}")
            for tech in self.techniques:
                if tech.detected:
                    print(f"  • {tag_color}{tech.name}{RESET}")
                    print(f"    ↳ {tech.details}")
            
            print(f"{tag_color}{'-'*60}{RESET}\n")
            
            sys.stdout.flush()

    def to_heartbeat_dict(self) -> dict:
        violations_list = []
        for tech in self.techniques:
            if tech.detected:
                violations_list.append({
                    "module": tech.name,
                    "severity": tech.tier,
                    "details": tech.details,
                    "data": tech.data 
                })

        return {
            "type": "heartbeat",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": self.verdict,
            "summary": {
                "total_checks_run": len(self.techniques),
                "critical_violations": self.critical_hits,
                "high_violations": self.high_hits
            },
            "active_violations": violations_list
        }

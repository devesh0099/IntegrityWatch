from dataclasses import dataclass, field
from typing import Optional
import json
from datetime import datetime, timezone

from integritywatch.utils.colors import RED, GREEN, PURPLE, YELLOW, CYAN, BOLD, RESET, BLUE

VERDICT_BLOCK = "BLOCK"
VERDICT_FLAG = "FLAG"
VERDICT_PASS = "PASS"

@dataclass
class TechniqueResult:
    name: str
    detected: bool
    severity: str = "UNKNOWN"
    details: str = ""
    count: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'name':self.name,
            'detected': self.detected,
            'severity': self.severity,
            'details': self.details,
            'count': self.count,
            'error': self.error
        }
    
@dataclass
class DetectionResult:
    violations: list[TechniqueResult] = field(default_factory=list)
    verdict: str = VERDICT_PASS
    reason: str = "Clean exam session - no violations detected"

    critical_violations: int = 0
    high_violations: int = 0
    medium_violations: int = 0
    low_violations: int = 0

    session_id: str = ""
    total_violations: int = 0
    exam_duration_minutes: float = 0.0

    def to_json(self) -> str:
        data = {
            "module": "browser_monitor",
            "session_id": self.session_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "exam_duration_minutes": round(self.exam_duration_minutes, 2),
            "severity_summary": {
                "critical": self.critical_violations,
                "high": self.high_violations,
                "medium": self.medium_violations,
                "low": self.low_violations
            },
            "total_violations": self.total_violations,
            "violations": [v.to_dict() for v in self.violations],
            "meta": {
                "version": "0.1.0",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        return json.dumps(data, indent=2)
    
    def display(self):
        print(f"\n{BOLD}{CYAN}>>> BROWSER MOINTORING SYSTEM{RESET}")
        print(f"{CYAN}{'-'*60}{RESET}")

        sorted_violations = sorted(
            self.violations,
            key=lambda x: {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3
            }.get(x.severity, 99)
        )

        for violation in sorted_violations:
            if violation.detected:
                status_color = RED
                status_text = "DETECTED"
            else:
                status_color = GREEN
                status_text = "Monitoring.."

            severity_color = PURPLE if violation.severity == "CRITICAL" else (YELLOW if violation.severity == "HIGH" else CYAN)

            count_str = f" ({violation.count}x)" if violation.count > 1 else ""
            print(f"[{severity_color}{violation.severity:^8}{RESET}]{violation.name:<35} [{status_color}{status_text:^8}{RESET}]{count_str}")

            if violation.detected:
                print(f"  {YELLOW}↳ {violation.details}{RESET}")
            
            if violation.error:
                print(f"  {RED}↳ ERROR: {violation.error}{RESET}")

        verdict_color = RED if self.verdict == VERDICT_BLOCK else (YELLOW if self.verdict == VERDICT_FLAG else GREEN)

        print(f"{CYAN}{'-'*60}{RESET}")
        print(f"VERDICT: {verdict_color}{self.verdict}{RESET} | {self.reason}")
        print(f"Duration: {self.exam_duration_minutes:.1f} min")

    def display_monitor(self):
        import sys
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if self.verdict == VERDICT_PASS:
            print(f"\r{BLUE}[{timestamp}]{RESET} Browser Monitor: {GREEN}CLEAN{RESET} | No violations detected...", end="", flush=True)
        elif self.verdict == "SKIPPED":
            print(f"\r{BLUE}[{timestamp}]{RESET} Browser Monitor: {YELLOW}IDLE{RESET} | {self.reason}", end="", flush=True)
        else:
            print(f"\r{' ' * 80}\r", end="")
            
            if self.verdict == VERDICT_BLOCK:
                tag_color = RED
            else:
                tag_color = YELLOW
            
            print(f"{tag_color}{BOLD}{'-'*60}{RESET}")
            print(f"{tag_color}{BOLD}BROWSER SECURITY ALERT [{timestamp}]{RESET}")
            print(f"{tag_color}{BOLD}{'-'*60}{RESET}")
            print(f"VERDICT: {tag_color}{self.verdict}{RESET}")
            print(f"REASON : {self.reason}")
            
            print(f"\n{BOLD}Violations Detected:{RESET}")
            for violation in self.violations:
                if violation.detected:
                    print(f"  • {tag_color}{violation.name}{RESET}")
                    print(f"    ↳ {violation.details}")
            
            print(f"{tag_color}{'-'*60}{RESET}\n")
            sys.stdout.flush()

import sys
import json
from datetime import datetime, timezone
from pathlib import Path

from src.config import config
from src.utils.logger import setup_logging, get_logger

from src.vm_detector.main import run_checks as VMEngine
from src.remote_access.main import run_checks as RemoteEngine
from src.core.report import ScanReport

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

root_logger = setup_logging()
logger = get_logger("main")

def print_header():
    print(f"\n{BOLD}INTEGRITY WATCH v0.1.0{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print("SCANNING HOST ENVIRONMENT...\n")

def get_final_reason(vm_result, remote_result, final_verdict):
    if final_verdict == "ALLOW":
        return "System appears clean"
    
    if final_verdict == "BLOCK":
        if vm_result.verdict == "BLOCK":
            return f"VM Detected: {vm_result.reason}"
        if remote_result.verdict == "BLOCK":
            return f"Remote Access Detected: {remote_result.reason}"
            
    if final_verdict == "FLAG":
        if vm_result.verdict == "FLAG":
            return f"VM Suspicion: {vm_result.reason}"
        if remote_result.verdict == "FLAG":
            return f"Remote Access Suspicion: {remote_result.reason}"
            
    return "Multiple security anomalies detected."

def print_summary(verdict, reason):
    verdict_color = GREEN
    if verdict == "BLOCK":
        verdict_color = RED
    elif verdict == "FLAG":
        verdict_color = YELLOW

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}ANALYSIS COMPLETED.{RESET}")
    print(f">> VERDICT:  {verdict_color}{verdict}{RESET}")
    print(f">> REASON:   {reason}")
    print(f"{CYAN}{'='*60}{RESET}\n")

def calculate_final_verdict(vm_result, remote_result):
    if vm_result.verdict == "BLOCK" or remote_result.verdict == "BLOCK":
        return "BLOCK"
    if vm_result.verdict == "FLAG" or remote_result.verdict == "FLAG":
        return "FLAG"
    return "ALLOW"

def save_report(report):
    if config.get("output", "save_json"):
        try:
            path_str = config.get("output", "json_path")
            if not path_str:
                print("Error: JSON output path not configured.")
                return

            path = Path(path_str)
            path.parent.mkdir(parents=True, exist_ok=True)

            json_output = report.to_json()
            
            with open(path, "w") as f:
                f.write(json_output)
                
            print(f"Report saved successfully to: {path}")
        except Exception as e:
            print(f"Failed to save report: {e}")

def main():
    try:
        print_header()
        logger.info("Integrity Watch Agent Starting...")
        
        logger.info("Running VM Detection Module...")
        vm_result = VMEngine()
        
        logger.info("Running Remote Access Module...")
        remote_result = RemoteEngine()
        
        final_verdict = calculate_final_verdict(vm_result, remote_result)
        final_reason = get_final_reason(vm_result, remote_result, final_verdict)

        
        report = ScanReport(
            session_id="LOCAL", 
            timestamp=datetime.now(timezone.utc).isoformat(),
            vm_detection=json.loads(vm_result.to_json()),
            remote_access=json.loads(remote_result.to_json()),
            final_verdict=final_verdict
        )
        
        print_summary(final_verdict, final_reason)

        save_report(report)
        
        sys.exit(1 if final_verdict == "BLOCK" else 0)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Scan interrupted by user.{RESET}")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Scan execution failed: {e}")
        print(f"\n{RED}CRITICAL ERROR: Scan execution failed. Check logs for details.{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
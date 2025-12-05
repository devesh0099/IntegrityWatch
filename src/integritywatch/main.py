import sys
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
import time

from integritywatch.config import config
from integritywatch.utils.logger import setup_logging, get_logger
from integritywatch.utils.colors import RED, GREEN, YELLOW, CYAN, BOLD, RESET

from integritywatch.vm_detector.main import run_checks as VMEngine
from integritywatch.remote_access.main import run_checks as RemoteEngine
from integritywatch.browser_monitor.main import run_checks as BrowserTabEngine

from integritywatch.core.report import ScanReport

VERDICT_PASS = "PASS"
VERDICT_CLEAN = "ALLOW"
VERDICT_BLOCK = "BLOCK"
VERDICT_FLAG = "FLAG"


root_logger = setup_logging()
logger = get_logger("main")

class MonitoringCoordinator:
    def __init__(self, browser_engine, remote_engine, interval=5):
        self.browser_engine = browser_engine
        self.remote_engine = remote_engine
        self.interval = interval
        self.logger = get_logger("coordinator")
        
        self._monitoring = False
        self._monitor_thread = None
        self._stop_event = threading.Event()
    
    def start(self, heartbeat_callback=None):
        if self._monitoring:
            self.logger.warning("Monitoring already active")
            return
        
        self._monitoring = True
        self._stop_event.clear()
        
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(heartbeat_callback,),
            daemon=True
        )
        self._monitor_thread.start()
        self.logger.info(f"Unified monitoring started (Interval: {self.interval}s)")
    
    def stop(self):
        self._monitoring = False
        self._stop_event.set()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
        
        self.logger.info("Monitoring stopped")
    
    def _monitor_loop(self, heartbeat_callback):
        is_flagged = False
        while not self._stop_event.is_set():
            browser_result = self.browser_engine.check_current_state()
            remote_result = self.remote_engine.check_current_state()
            
            is_blocked = False
            block_reason = None
            
            if browser_result.verdict == VERDICT_BLOCK:
                is_blocked = True
                block_reason = f"Browser: {browser_result.reason}"
            elif remote_result.verdict == VERDICT_BLOCK:
                is_blocked = True
                block_reason = f"Remote Access: {remote_result.reason}"
            
            if browser_result.verdict == VERDICT_FLAG or remote_result.verdict == VERDICT_FLAG:
                is_flagged = True
            
            if heartbeat_callback:
                status = "BLOCKED" if is_blocked else ("FLAGGED" if is_flagged else "CLEAN")
                
                combined_payload = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": status,
                    "browser_monitor": {
                        "verdict": browser_result.verdict,
                        "total_violations": browser_result.total_violations,
                        "violations": [v.to_dict() for v in browser_result.violations if v.detected]
                    } if browser_result.total_violations > 0 else {"verdict": "PASS", "total_violations": 0},
                    "remote_access": {
                        "verdict": remote_result.verdict,
                        "techniques": [t.to_dict() for t in remote_result.techniques if t.detected]
                    } if remote_result.techniques else {"verdict": "CLEAN"}
                }
                
                if is_blocked:
                    combined_payload["reason"] = block_reason
                
                heartbeat_callback(combined_payload)
            
            if is_blocked:
                self.logger.critical(f"BLOCKING VIOLATION: {block_reason}")
                
                print(f"\r{' ' * 80}\r", end="", flush=True)
                print(f"\n{RED}{BOLD}>>> INTEGRITY FAILED{RESET}")
                print(f"{RED}Reason: {block_reason}{RESET}\n")
                
                if browser_result.verdict == VERDICT_BLOCK:
                    browser_result.display_monitor()
                
                if remote_result.verdict == VERDICT_BLOCK:
                    remote_result.display_monitor()
                
                self._stop_event.set()
                self._monitoring = False
                break
            
            if is_flagged:
                print(f"\r{' ' * 80}\r", end="", flush=True)
                
                if browser_result.verdict == VERDICT_FLAG:
                    browser_result.display_monitor()
                
                if remote_result.verdict == VERDICT_FLAG:
                    remote_result.display_monitor()
            
            if not is_flagged and not is_blocked:
                timestamp = datetime.now().strftime("%H:%M:%S")
                BLUE = '\033[94m'
                GREEN = '\033[92m'
                RESET = '\033[0m'
                
                print(f"\r[{BLUE}{timestamp}{RESET}] Browser: {GREEN}CLEAN{RESET} | Remote: {GREEN}SECURE{RESET} | Monitoring active...", end="", flush=True)
            
            self._stop_event.wait(timeout=self.interval)

def print_header():
    print(f"\n{BOLD}INTEGRITY WATCH v0.1.0{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print("SCANNING HOST ENVIRONMENT...\n")

def get_final_reason(vm_result, remote_result, browser_result, final_verdict):
    if final_verdict == "ALLOW":
        return "System appears clean"
    
    reasons = []
    
    if final_verdict == "BLOCK":
        if vm_result.verdict == "BLOCK":
            reasons.append(f"VM: {vm_result.reason}")
        if remote_result.verdict == "BLOCK":
            reasons.append(f"Remote Access: {remote_result.reason}")
        if browser_result.verdict == "BLOCK":
            reasons.append(f"Browser: {browser_result.reason}")
        
        return " | ".join(reasons) if reasons else "Unknown blocking violation"
    
    if final_verdict == "FLAG":
        if vm_result.verdict == "FLAG":
            reasons.append(f"VM: {vm_result.reason}")
        if remote_result.verdict == "FLAG":
            reasons.append(f"Remote: {remote_result.reason}")
        if browser_result.verdict == "FLAG":
            reasons.append(f"Browser: {browser_result.reason}")
        
        return " | ".join(reasons) if reasons else "Multiple security anomalies detected"
    
    return "Unknown status"

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

def calculate_final_verdict(vm_result, remote_result, browser_result):
    if vm_result.verdict == "BLOCK" or remote_result.verdict == "BLOCK" or browser_result.verdict == "BLOCK":
        return "BLOCK"
    if vm_result.verdict == "FLAG" or remote_result.verdict == "FLAG" or browser_result.verdict == "FLAG":
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

def save_heartbeat_to_disk(payload: dict):
    try:
        base_dir = config.get("output", "heartbeat") or "results/heartbeat/"
        os.makedirs(base_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"heartbeat_{timestamp}.json"
        filepath = os.path.join(base_dir, filename)
        
        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)
            
    except Exception as e:
        logger.error(f"Failed to write heartbeat file: {e}")


def main():
    try:
        print_header()
        logger.info("Integrity Watch Agent Starting...")
        
        logger.info("Running VM Detection Module...")
        vm_result = VMEngine()
        
        logger.info("Running Remote Access Module...")
        remote_result, remote_engine = RemoteEngine()
        
        logger.info("Running Browser Tab Detection Module...")
        
        browser_dir = Path.home() / ".integritywatch" / "runtime" / "browser"
        browser_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Writing Start Command for Native Host")

        logger.info("Deleting Previous files.")
        for file in browser_dir.glob("*"):
            if file.is_file():
                try:
                    file.unlink()
                    logger.debug(f"Removed old file: {file}")
                except Exception as e:
                    logger.warning(f"Could not remove {file}: {e}")
        
        time.sleep(0.1) # For combatting some time issues
        command_file = browser_dir / 'command.json'
        try:
            with open(command_file, 'w') as f:
                json.dump({'command': 'START_MONITORING', 'timestamp': datetime.now().timestamp()}, f)
            logger.info("Sent START_MONITORING command to native host")
        except Exception as e:
            logger.warning(f"Failed to write command file: {e}")
        
        browser_result, browser_engine = BrowserTabEngine(browser_dir)

        final_verdict = calculate_final_verdict(vm_result, remote_result, browser_result)
        final_reason = get_final_reason(vm_result, remote_result, browser_result, final_verdict)
        
        report = ScanReport(
            session_id="LOCAL",
            timestamp=datetime.now(timezone.utc).isoformat(),
            vm_detection=json.loads(vm_result.to_json()),
            remote_access=json.loads(remote_result.to_json()),
            browser_tab=json.loads(browser_result.to_json()),
            final_verdict=final_verdict
        )
        
        print_summary(final_verdict, final_reason)
        save_report(report)
        
        interval = config.get("monitoring","monitoring_interval", 5)
        
        if final_verdict == "ALLOW" or final_verdict == "FLAG"  :
            
            coordinator = MonitoringCoordinator(
                browser_engine=browser_engine,
                remote_engine=remote_engine,
                interval=interval
            )
            
            coordinator.start(heartbeat_callback=save_heartbeat_to_disk)
            
            print(f"\n{GREEN}>>> Unified Monitoring Active{RESET}")
            print(f"Monitoring browser violations and remote access every {interval}s")
            input("\n[Press ENTER to stop monitoring]\n")
            try:
                command_file = browser_dir / 'command.json'
                with open(command_file, 'w') as f:
                    json.dump({'command': 'STOP_MONITORING', 'timestamp': datetime.now().timestamp()}, f)
                logger.info("Sent STOP_MONITORING command")
            except:
                pass
            print("Stopping...")
            coordinator.stop()
        
        sys.exit(1 if final_verdict == "BLOCK" else 0)
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted by user{RESET}")
        if 'coordinator' in locals():
            coordinator.stop()

        if 'browser_dir' in locals():
            try:
                command_file = browser_dir / 'command.json'
                with open(command_file, 'w') as f:
                    json.dump({'command': 'STOP_MONITORING', 'timestamp': datetime.now().timestamp()}, f)
                logger.info("Sent STOP_MONITORING command")
            except:
                pass
        sys.exit(130)
        
    except Exception as e:
        logger.critical(f"Execution failed: {e}", exc_info=True)
        print(f"\n{RED}CRITICAL ERROR: {e}{RESET}")
        try:
            command_file = browser_dir / 'command.json'
            with open(command_file, 'w') as f:
                json.dump({'command': 'STOP_MONITORING', 'timestamp': datetime.now().timestamp()}, f)
            logger.info("Sent STOP_MONITORING command")
        except:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
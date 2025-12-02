import sys
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from src.config import config
from src.utils.logger import setup_logging, get_logger

from src.vm_detector.main import run_checks as VMEngine
from src.remote_access.main import run_checks as RemoteEngine
from src.remote_access.main import start_monitoring
from src.core.report import ScanReport

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

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
        while not self._stop_event.is_set():
            browser_result = self.browser_engine.check_current_state()
            remote_result = self.remote_engine.check_current_state()
            
            combined_payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "browser_monitor": json.loads(browser_result.to_json()) if browser_result.total_violations > 0 else None,
                "remote_access": json.loads(remote_result.to_json()) if remote_result.techniques else None
            }
            
            if heartbeat_callback:
                heartbeat_callback(combined_payload)
            
            should_block = False
            block_reason = None
            
            if browser_result.verdict == "BLOCK":
                should_block = True
                block_reason = f"Browser: {browser_result.reason}"
            elif remote_result.verdict == "BLOCK":
                should_block = True
                block_reason = f"Remote Access: {remote_result.reason}"
            
            if should_block:
                self.logger.critical(f"BLOCKING VIOLATION: {block_reason}")
                print(f"\n{RED}{BOLD}>>> INTEGRITY FAILED{RESET}")
                print(f"{RED}Reason: {block_reason}{RESET}\n")
                
                if browser_result.total_violations > 0:
                    browser_result.display()
                if remote_result.techniques:
                    remote_result.display()
                
                self._stop_event.set()
                self._monitoring = False
                break
            
            if browser_result.verdict == "FLAG":
                self.logger.warning(f"Browser flagged: {browser_result.reason}")
                browser_result.display()
            
            if remote_result.verdict == "FLAG":
                self.logger.warning(f"Remote flagged: {remote_result.reason}")
                remote_result.display()
            
            self._stop_event.wait(timeout=self.interval)

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
        
        interval = config.get("monitoring","monitoring_interval", 5)
        
        if final_verdict == "ALLOW":
            from src.browser_monitor.core.engine import DetectionEngine as BrowserEngine
            
            runtime_dir = Path("runtime/sessions")
            runtime_dir.mkdir(parents=True, exist_ok=True)
            session_dir = runtime_dir / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            session_dir.mkdir(exist_ok=True)
            
            browser_engine = BrowserEngine(session_dir)
            
            logger.info("Running Browser Monitoring baseline scan...")
            browser_result = browser_engine.run()
            browser_result.display()
            
            if browser_result.verdict == "BLOCK":
                print(f"\n{RED}Cannot start monitoring: Browser violations detected{RESET}")
                sys.exit(1)
            
            coordinator = MonitoringCoordinator(
                browser_engine=browser_engine,
                remote_engine=remote_engine,
                interval=interval
            )
            
            coordinator.start(heartbeat_callback=save_heartbeat_to_disk)
            
            print(f"\n{GREEN}>>> Unified Monitoring Active{RESET}")
            print(f"Monitoring browser violations and remote access every {interval}s")
            input("\n[Press ENTER to stop monitoring]\n")
            
            print("Stopping...")
            coordinator.stop()
        
        sys.exit(1 if final_verdict == "BLOCK" else 0)
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted by user{RESET}")
        if 'coordinator' in locals():
            coordinator.stop()
        sys.exit(130)
        
    except Exception as e:
        logger.critical(f"Execution failed: {e}", exc_info=True)
        print(f"\n{RED}CRITICAL ERROR: {e}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
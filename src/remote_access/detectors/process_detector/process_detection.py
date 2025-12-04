from src.config import config
from src.utils.platform.base import is_windows, is_linux, is_macos

from ...constants import PROCESS_BLOCKLIST, SUSPICIOUS_PORTS, KNOWN_REMOTE_ACCESS_DOMAINS, PORT_TO_TOOL, COMMON_FALLBACK_PORTS, COMMON_LEGITIMATE_PORTS
from ..base import BaseDetector
from ...core.result import TechniqueResult
from typing import Any, Optional

class ProcessDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="Process Detection",
            supported_platforms=[],
            requires_admin=False
        )

        self.logger.info("Initializing Process Detector...")

        self.blocked_names = set()
        for category, processes in PROCESS_BLOCKLIST.items():
            self.blocked_names.update(p.lower() for p in processes)

        self._load_network_utilities()

    def _load_network_utilities(self):
        try:
            if is_windows():
                from src.utils.platform import windows
                self.get_connections = windows.get_tcp_connections_for_pid
                self.reverse_dns = windows.reverse_dns_lookup
                self.logger.info("Network detection: Windows utilities loaded")
            
            elif is_linux():
                from src.utils.platform import linux
                self.get_connections = linux.get_tcp_connections_for_pid
                self.reverse_dns = linux.reverse_dns_lookup
                self.logger.info("Network detection: Linux utilities loaded")
            
            elif is_macos():
                from src.utils.platform import macos
                self.get_connections = macos.get_tcp_connections_for_pid
                self.reverse_dns = macos.reverse_dns_lookup
                self.logger.info("Network detection: macOS utilities loaded")

            else:
                self.logger.warning("Network detection not available on this platform.")
        
        except ImportError as e:
            self.logger.warning(f"Network detection unavailable: {e}")
            
        

    def scan(self) -> TechniqueResult:
        self.logger.info("Scanning running processes...")

        try:
            processes = self._enumerate_processes()
            
            if not processes:
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    details="Process enumeration failed.",
                    error="Unable to enumerate processes"
                )
            
            self.logger.debug(f"Found {len(processes)} running processes")

            threats = []
            
            # Check 1: Simple String Based Matching
            self.logger.info("Checking running processes names with blocklist")
            for proc in processes:
                if proc['name'].lower() in self.blocked_names:
                    tier = self._get_tier(proc['name'])
                    threats.append({
                        'name': proc['name'],
                        'pid':proc['pid'],
                        'path':proc['path'],
                        'tier': tier,
                        'detection_method': 'process_name'
                    })
                    self.logger.debug(f"Found Threat {proc['name']} with pid {proc['pid']}")
            

            network_threats = self._detect_by_network_behavior(processes)
            threats.extend(network_threats)

            if threats:
                critical = [t for t in threats if t['tier'] == 'CRITICAL']
                low = [t for t in threats if t['tier'] == 'LOW']
                unknown = [t for t in threats if t['tier'] == 'UNKNOWN']
                threat_list = []

                if critical:
                    tier = 'CRITICAL'
                    threat_list = critical
                    summary = f"Critical remote access tool(s) detected"
                
                elif low:
                    tier = 'LOW'
                    threat_list = low
                    summary = f"Screen Sharing service(s) detected"

                else:
                    tier = 'UNKNOWN'
                    threat_list = unknown
                    summary = f"Screen Sharing service(s) detected"

                unique_names = []
                seen = set()

                for t in threat_list:
                    name = t.get('name', 'Unknown')

                    if name.lower() not in seen:
                        unique_names.append(name)
                        seen.add(name.lower())
                    
                
                if len(unique_names) <= 3:
                    details = f"{summary}:- {', '.join(unique_names)}"
                else:
                    details = f"{summary}:- {', '.join(unique_names[:3])} (and {len(unique_names) - 3} more)"

                return TechniqueResult(
                    name=self.name,
                    detected=True,
                    tier=tier,
                    details=details,
                    data={'threats': threats}
                )
            
            else:
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    details=f"No blocked processes found ({len(processes)} processes checked)"
                )
        
        except Exception as e:
            self.logger.error(f"Process scan failed: {e}", exc_info=True)
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Process scan error",
                error=str(e)
            )
        
    def _detect_by_network_behavior(self, processes: list[dict]) -> list[dict]:
        threats = []

        self.logger.info("Checking running processes with known ports")
        for proc in processes:
            if proc['name'].lower() in self.blocked_names:
                continue

            suspicious = self._analyze_connections(proc['pid'], proc['name'])

            if suspicious:
                threats.append({
                    'name': proc['name'],
                    'pid': proc['pid'],
                    'path': proc['path'],
                    'tier': 'CRITICAL',
                    'detection_method': suspicious['method'],
                    'details': suspicious['details']
                })
        
        return threats
    
    def _analyze_connections(self, pid: int, process_name: str) -> Optional[dict]:
        try:
            connections = self.get_connections(pid)

            if not connections:
                return None
            
            for conn in connections:
                if conn['state'] != 'ESTABLISHED':
                    continue
                
                # Check 2: PORT Based Blocking
                if conn['local_port'] in SUSPICIOUS_PORTS:
                    tool = PORT_TO_TOOL.get(conn['local_port'], 'Unknown Remote Access Tool')

                    self.logger.debug(f"Found suspicious local port with {tool} on port {conn['local_port']} and pid {conn['pid']}")
                    return {
                        'method': 'network_port',
                        'details': f"Connecting to {tool} port {conn['local_port']} ({conn['remote_addr']})"
                    }
                
                if conn['remote_port'] in SUSPICIOUS_PORTS:
                    tool = PORT_TO_TOOL.get(conn['remote_port'], 'Unknown Remote Access Tool')

                    self.logger.debug(f"Found suspicious remote port with {tool} on port {conn['remote_port']} and pid {conn['pid']}")
                    return {
                        'method': 'network_port',
                        'details': f"Connecting to {tool} port {conn['remote_port']} ({conn['remote_addr']})"
                    }
                
                # Check 3: Reverse Domain Lookup for unidentified or fallback ports
                self.logger.info("Checking running processes with reverse dns lookup")
                if conn['remote_port'] in COMMON_FALLBACK_PORTS or conn['remote_port'] not in COMMON_LEGITIMATE_PORTS:
                    hostname = self.reverse_dns(conn['remote_addr'])

                    if hostname:
                        for domain in KNOWN_REMOTE_ACCESS_DOMAINS:
                            if domain in hostname.lower():
                                self.logger.debug(f"Found {hostname} on port {conn['remote_port']} and pid {conn['pid']}")
                                return {
                                    'method': 'network_reverse_domain_lookup',
                                    'details': f"Connecting to {hostname} on port {conn['remote_port']} (remote access infrastructure)"
                                }
                
            return None
        
        except Exception as e:
            self.logger.debug(f"Connection analysis failed for PID {pid}: {e}")
            return None


    def _check_if_active(self, pid: int) -> bool:
        try:
            connections = self.get_connections(pid)

            for conn in connections:
                if conn['state'] == 'ESTABLISHED':
                    return True
                
            return False
        
        except Exception:
            return False

    def _get_tier(self, process_name: str) -> str:
        name_lower = process_name.lower()

        allow_conference = config.get('remote_access',"allow_conference_tools", False)

        critical_categories = [
            'commercial_tools',
            'vnc_variants', 
            'windows_native',
            'browser_extensions',
            'admin_tools',
            'screen_recording',
            'virtual_camera',
            'streaming_software'
        ]

        for category in critical_categories:
            if category in PROCESS_BLOCKLIST:
                category_procs = [p.lower() for p in PROCESS_BLOCKLIST[category]]
                if name_lower in category_procs:
                    return 'CRITICAL'
                
        if 'conference_tools_sharing' in PROCESS_BLOCKLIST:
            conference_procs = [p.lower() for p in PROCESS_BLOCKLIST['conference_tools_sharing']]
            if name_lower in conference_procs:
                if allow_conference:
                    return 'LOW'     
                else:
                    return 'CRITICAL'
        
        return 'UNKOWN'
    
    def _enumerate_processes(self) -> list[dict[str, Any]]:
        from src.utils.platform.base import is_windows, is_linux, is_macos

        if is_windows():
            from src.utils.platform.windows import enumerate_processes
            
            processes = enumerate_processes()
            self.logger.info(f"WMI: Enumerated {len(processes)} processes")
            return processes
        
        elif is_linux():
            from src.utils.platform.linux import enumerate_processes

            processes = enumerate_processes()
            self.logger.info(f"Linux: Enumerated {len(processes)} processes")
            return processes

        elif is_macos():
            from src.utils.platform.macos import enumerate_processes
            
            processes = enumerate_processes()
            self.logger.info(f"Linux: Enumerated {len(processes)} processes")
            return processes
        return []
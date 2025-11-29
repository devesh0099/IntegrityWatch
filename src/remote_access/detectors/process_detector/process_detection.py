from ..base import BaseDetector
from ...core.result import TechniqueResult
from src.remote_access.constants import PROCESS_BLOCKLIST
from typing import Any

class ProcessDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="Process Detection",
            supported_platforms=[],
            requires_admin=False
        )

        self.blocked_names = set()
        for category, processes in PROCESS_BLOCKLIST.items():
            self.blocked_names.update(p.lower() for p in processes)
    
    def scan(self) -> TechniqueResult:
        self.logger.info("Scanning running processes...")

        try:
            processes = self._enumerate_processes()
            # print(processes)
            if not processes:
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    details="Process enumeration failed.",
                    error="Unable to enumerate processes"
                )
            
            self.logger.debug(f"Found {len(processes)} running processes")

            threats = []
            for proc in processes:
                if proc['name'].lower() in self.blocked_names:
                    tier = self._get_tier(proc['name'])
                    threats.append({
                        'name': proc['name'],
                        'pid':proc['pid'],
                        'path':proc['path'],
                        'tier': tier
                    })
            
            if threats:
                critical = [t for t in threats if t['tier'] == 'CRITICAL']
                low = [t for t in threats if t['tier'] == 'LOW']
                unknown = [t for t in threats if t['tier'] == 'UNKNOWN']
                threat_list = []

                if critical:
                    tier = 'CRITICAL'
                    threat_list = critical
                    names = [t['name'] for t in critical]
                    summary = f"Critical remote access tool(s) detected:\n"
                
                elif low:
                    tier = 'LOW'
                    threat_list = low
                    names = [t['name'] for t in low]
                    summary = f"Screen Sharing service(s) detected:\n"

                else:
                    tier = 'UNKNOWN'
                    threat_list = unknown
                    names = [t['name'] for t in unknown]
                    summary = f"Screen Sharing service(s) detected:\n"

                unique_names = []
                seen = set()

                for t in threat_list:
                    name = t.get('name', 'Unknown')

                    if name.lower() not in seen:
                        unique_names.append(name)
                        seen.add(name.lower())
                    
                
                if len(unique_names) <= 3:
                    details = f"{summary}: {', '.join(unique_names)}"
                else:
                    details = f"{summary}: {', '.join(unique_names[:3])} (and {len(unique_names) - 3} more)"

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
        
    def _get_tier(self, process_name: str) -> str:
        name_lower = process_name.lower()

        critical_categories = [
            'commercial_tools',
            'vnc_variants', 
            'windows_native',
            'browser_extensions',
            'admin_tools'
        ]

        for category in critical_categories:
            if category in PROCESS_BLOCKLIST:
                category_procs = [p.lower() for p in PROCESS_BLOCKLIST[category]]
                if name_lower in category_procs:
                    return 'CRITICAL'
                
        if 'conference_tools_sharing' in PROCESS_BLOCKLIST:
            conference_procs = [p.lower() for p in PROCESS_BLOCKLIST['conference_tools_sharing']]
            if name_lower in conference_procs:
                return 'LOW'
            
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
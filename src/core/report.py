from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json

@dataclass
class ScanReport:
    session_id: str
    timestamp: str

    vm_detection: dict  
    remote_access: dict 
    browser_tab: dict

    final_verdict: str  
    
    def to_json(self):
        return json.dumps(asdict(self), indent=2)
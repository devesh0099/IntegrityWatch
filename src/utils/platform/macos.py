import subprocess
from typing import Any

def run_sysctl(key: str) -> str:
    try:
        result = subprocess.run(['sysctl', '-n', key],
                                capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return ""
    
def check_hypervisor_feature() -> bool:
    features = run_sysctl('machdep.cpu.features')
    return 'hypervisor' in features.lower()

def enumerate_processes() -> list[dict[str, Any]]:
    import subprocess
    processes = []

    try:
        result = subprocess.run(
            ['ps', '-eo', 'pid,comm'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    try:
                        pid = int(parts[0])
                        command = parts[1]
                        name = command.split('/')[-1]

                        processes.append({
                            'name': name,
                            'pid': pid,
                            'path': command,
                            'cmdline': ''
                        })
                    except:
                        continue
        
        return processes
    except Exception:
        return []
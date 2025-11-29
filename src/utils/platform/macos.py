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
    
def get_tcp_connections_for_pid(pid: int) -> list[dict]:
    import subprocess

    try:
        result = subprocess.run(
            ['-lsof', '-iTCP', '-n', '-P','-p', str(pid)],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return []
        
        connections = []
        lines = result.stdout.strip().split('\n')[1:]

        for line in lines:
            parts = line.split()

            if len(parts) < 9:
                continue

            name = parts[8]

            if '->' not in name:
                continue

            local, remote = name.split('->')
            local_addr, local_port = local.rsplit(':', 1)
            
            remote_parts = remote.split()
            remote_addr, remote_port = remote_parts[0].rsplit(':', 1)
            
            state = remote_parts[1].strip('()') if len(remote_parts) > 1 else 'UNKNOWN'
            
            connections.append({
                'local_addr': local_addr,
                'local_port': int(local_port),
                'remote_addr': remote_addr,
                'remote_port': int(remote_port),
                'state': state,
                'pid': pid
            })
        
        return connections
        
    except:
        return []
    
def reverse_dns_lookup(ip_address: str) -> str:
    try:
        import socket
        result = socket.gethostbyaddr(ip_address)
        return result[0]
    except:
        return ""
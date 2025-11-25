import subprocess

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
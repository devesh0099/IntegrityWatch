def read_proc_cpuinfo() -> str:
    try:
        with open('proc/cpuinfo', 'r') as f:
            return f.read()
    except:
        return ""
    
def check_hypervisor_flag() -> bool: 
    """Check is any hypervisor flag present in CPU info."""
    cpuinfo = read_proc_cpuinfo()
    return 'hypervisor' in  cpuinfo.lower()

def read_dmi_file(filename: str) -> str:
    try:
        with open(f'/sys/class/dmi/id/{filename}', 'r') as f:
            return f.read().strip()
    except:
        return ""
    
def get_firmware_info() -> dict:
    return {
        'sys_vendor': read_dmi_file('sys_vendor'),
        'product_name': read_dmi_file('product_name'),
        'bios_vendor': read_dmi_file('bios_vendor'),
        'bios_version': read_dmi_file('bios_version')
    }

def get_network_macs() -> list[dict]:
    import os
    macs = []
    try:
        net_path = '/sys/class/net'
        for iface in os.listdir(net_path):
            mac_file = f'{net_path}/{iface}/address'
            if os.path.exists(mac_file):
                with open(mac_file) as f:
                    mac = f.read().strip()
                    if mac and mac != '00:00:00:00:00:00':
                        macs.append({
                            'mac':mac,
                            'interface': iface
                        })
    except:
        pass
    return macs
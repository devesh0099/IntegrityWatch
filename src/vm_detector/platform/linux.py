def read_proc_cpuinfo() -> str:
    try:
        with open('/proc/cpuinfo', 'r') as f:
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

def get_acpi_tables() -> list:
    try:
        import os
        acpi_path = '/sys/firmware/acpi/tables/'

        file_tables = []

        if not os.path.exists(acpi_path):
            return []
        
        for filename in os.listdir(acpi_path):
            if filename in ['.', '..', 'dynamic','data']:
                continue
            
            # Skipping if the current file is a directory.
            full_path = os.path.join(acpi_path, filename)
            if os.path.isdir(full_path):
                continue

            file_tables.append(os.path.join(acpi_path, filename))
        return file_tables
    except:
        return []
    
def get_pci_device_ids() -> list[tuple[int, int]]:
    try:
        import os
        base_path = '/sys/bus/pci/devices/'
        devices = []

        for device_entry in os.listdir(base_path):
            vendor_file = os.path.join(base_path,device_entry,"vendor")
            device_file = os.path.join(base_path,device_entry,"device")

            try:
                with open(vendor_file, 'r') as vf:
                    vendor_id = int(vf.read().strip(), 16)
                
                with open(device_file, 'r') as df:
                    device_id = int(df.read().strip(), 16)
                
                devices.append((vendor_id, device_id))

            except: # unable to open pci device files
                continue

        return devices
    except (IOError, OSError, PermissionError) as e:
        return []
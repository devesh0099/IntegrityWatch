import platform as plat

def get_current_platform() -> str:
    return plat.system().lower()

def is_windows() -> bool:
    return get_current_platform() == 'windows'

def is_linux() -> bool:
    return get_current_platform() == 'linux'

def is_macos() -> bool:
    return get_current_platform() == 'darwin'

def get_cpuid_registers(leaf: int) -> tuple:
    # Execute the given instruction and return raw register values.
    try:
        from cpuid import cpuid
        return cpuid(leaf)
    except:
        return (0,0,0,0)

def get_cpuid_vendor(leaf: int) -> str:
    try:
        from cpuid import cpuid
        import struct
        
        eax, ebx, ecx, edx = cpuid(leaf)
        
        if leaf == 0:
            vendor = struct.pack('<III', ebx, edx, ecx).decode('ascii', errors='ignore')
            return vendor.strip()
        else:
            vendor1 = struct.pack('<III', ebx, ecx, edx).decode('ascii', errors='ignore').strip()
            
            if vendor1 and len(vendor1) >= 3:
                if not all(c in '@\x00 ' for c in vendor1):
                    return vendor1
            
            vendor2 = struct.pack('<III', ebx, edx, ecx).decode('ascii', errors='ignore').strip()
            if vendor2 and len(vendor2) >= 3:
                if not all(c in '@\x00 ' for c in vendor2):
                    return vendor2
            
            return
    except:
        return


def get_cpuid_features() -> dict:
    # Get CPU feature flags from CPUID leaf 1
    try:
        from cpuid import cpuid
        eax,ebx,ecx,edx = cpuid(1)

        return {
            'eax':eax,
            'ebx':ebx,
            'ecx':ecx,
            'edx':edx
        }
    except:
        return {}
    
def get_mac_addresses() -> list:
    mac_addresses=[]

    try:
        if is_windows():
            mac_addresses = _get_mac_windows()
        elif is_linux():
            mac_addresses = _get_mac_linux()
        elif is_macos():
            mac_addresses = _get_mac_macos()

    except Exception as e:
        import logging
        logging.warning(f"Failed to get MAC addresses: {e}")

    return mac_addresses

def _get_mac_windows() -> list:
    import subprocess
    import re

    mac_addresses = []

    try:
        import wmi
        c = wmi.WMI()
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if interface.MACAddress:
                mac = interface.MACAddress.replace('-', ':').upper()
                mac_addresses.append(mac)
    except:
        pass
    
    return mac_addresses

def _get_mac_linux() -> list:
    import os

    mac_addresses = []
    net_path = '/sys/class/net/'

    try:
        if not os.path.exists(net_path):
            return []
        
        for interface in os.listdir(net_path):
            if interface == 'lo':
                continue

            address_file = os.path.join(net_path, interface, 'address')
            
            if os.path.exists(address_file):
                try:
                    with open(address_file, 'r') as f:
                        mac = f.read().strip().upper()
                        # Validate MAC format
                        if len(mac) == 17 and mac.count(':') == 5:
                            mac_addresses.append(mac)
                except:
                    continue        
    except:
        pass

    return mac_addresses

def _get_mac_macos() -> list:
    import subprocess
    import re
    
    mac_addresses = []
    
    try:
        result = subprocess.run(
            ['ifconfig'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Parse ifconfig output for "ether XX:XX:XX:XX:XX:XX"
            for line in result.stdout.split('\n'):
                if 'ether' in line:
                    match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', line, re.IGNORECASE)
                    if match:
                        mac = match.group(0).upper()
                        mac_addresses.append(mac)
    except:
        pass
    
    return mac_addresses

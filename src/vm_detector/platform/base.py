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

def get_cpu_vendor() -> str:
    # Get CPUID vendor string from EBX+ECX+EDX at specified leaf.
    try:
        from cpuinfo import get_cpu_info
        
        info = get_cpu_info()


        eax, ebx, ecx, edx = cpuid(0)

        # Packing into bytes
        vendor_bytes = struct.pack('<III', ebx,edx,ecx)

        # Converting to ASCII string
        vendor_str = vendor_bytes.decode('ascii', errors='replace')

        return vendor_str.rstrip('\x00') # Removing NULL terminator
    
    except Exception:
        return ""
    

def get_hypervisor_vendor(leaf: int = 0x40000000) -> str:
    try:
        from cpuid import cpuid
        import struct
        
        eax, ebx, ecx, edx = cpuid(leaf)
        
        # Hypervisor leaves use EBX + ECX + EDX order
        vendor_bytes = struct.pack('<III', ebx, ecx, edx)
        vendor_str = vendor_bytes.decode('ascii', errors='replace')
        return vendor_str.rstrip('\x00')
        
    except Exception:
        return ""

def get_cpuid_vendor(leaf: int) -> str:
    try:
        from cpuinfo import get_cpu_info
        
        info = get_cpu_info()

        if leaf == 0:
            # Get CPU vendor
            vendor = info.get('vendor_id_raw', '')
            return vendor
        
        elif leaf == 0x40000000 or leaf == 0x40000100:
            flags = info.get('flags', [])

            if 'hypervisor' in flags:
                brand = info.get('brand_raw', '').lower()

                # Check for VM keywords in brand/model
                if 'vmware' in brand:
                    return 'VMwareVMware'
                elif 'virtualbox' in brand or 'vbox' in brand:
                    return 'VBoxVBoxVBox'
                elif 'qemu' in brand or 'kvm' in brand:
                    return 'KVMKVMKVM'
                elif 'microsoft' in brand or 'hyper-v' in brand:
                    return 'Microsoft Hv'
                elif 'xen' in brand:
                    return 'XenVMMXenVMM'
                else:
                    # Generic hypervisor detected, but can't identify vendor
                    return 'hypervisor'
            return ""
        
        return ""
    except Exception:
        return ""


def get_cpuid_features() -> dict:
    # Get CPU feature flags from CPUID leaf 1
    try:
        from cpuinfo import get_cpu_info
        
        info = get_cpu_info()
        flags = info.get('flags', [])

        ecx = 0
        if 'hypervisor' in flags:
            ecx = (1 << 31)  # Set bit 31
        
        return {
            'eax': 0,
            'ebx': 0,
            'ecx': ecx,
            'edx': 0
        }
    except Exception:
        return {}
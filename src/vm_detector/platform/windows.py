def get_cpu_info() -> dict:
    try:
        import wmi
        c = wmi.WMI()
        cpu = c.Win32_Processor()[0]
        return {
            'manufacturer': cpu.Manufacturer,
            'name': cpu.Name,
            'description': cpu.Description
        }
    except Exception as e:
        return {'error': f"Error Getting CPU Information via WMI, Error: {str(e)}"}

def get_firmware_info() -> dict:
    try:
        import wmi
        c = wmi.WMI()
        bios = c.Win32_BIOS()[0]
        system = c.Win32_ComputerSystem()[0]
        return {
            'bios_manufacturer': bios.Manufacturer,
            'bios_version': bios.Version,
            'system_manufacturer': system.Manufacturer,
            'system_model': system.Model
        }
    except Exception as e:
        return {'error': f"Error in Getting Firmware info in Windows, error: {str(e)}"}
    
def get_network_adapters() -> list[dict]:
    try:
        import wmi
        c = wmi.WMI()
        adapters = []
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.MACAddress:
                adapters.append({
                    'mac': nic.MACAddress,
                    'description': nic.Description
                })
        return adapters
    except Exception:
        return []
    
def enumerate_firmware_tables(provider: str) -> list:
    # For a given firmware table provider ex:ACPI,RSMB we are returning list of all the table id's present for that table provider.
    # Like 20 tables of ACPI and 32 tables for RSMB
    try:
        import ctypes
        from ctypes import wintypes
        import struct

        # Nested Helper function for cleaner imports
        def string_to_dword(s: str) -> int:
            if len(s) != 4:
                raise ValueError("String must be exactly 4 characters.")
            return struct.unpack('>I', s.encode('ascii'))[0]

        # Loading Kernel32 DLL for 'EnumSystemFirmwareTables' a Windows API Function
        kernel32 = ctypes.windll.kernel32
        enum_func = kernel32.EnumSystemFirmwareTables

        # We are defining Function Signature for the API Function
        enum_func.argtypes = [
            wintypes.DWORD, # Provider signature
            ctypes.c_void_p, # Pointer to our Buffer location
            wintypes.DWORD # Size of our Buffer location
        ]
        enum_func.restype = wintypes.UINT # Define the API Function return type

        provider_sig = string_to_dword(provider)
        
        #* STANDARD TWO CALL PATTERN for Windows API function.

        # Call 1: To get the required buffer size for the buffer.
        size_needed = enum_func(provider_sig, None, 0)
        if size_needed == 0:
            return []

        if size_needed % 4 != 0:
            return []

        # Allocating the size needed for fetching all the table ids.
        buffer = ctypes.create_string_buffer(size_needed)

        # Call 2: To get the all table id's present for the specific table provider.
        bytes_returned = enum_func(provider_sig, buffer, size_needed)

        if bytes_returned != size_needed:
            return []

        # Parsing the allocated buffer into list of DWORDs to return 
        table_ids = []
        num_tables = size_needed // 4
        for i in range(num_tables):
            offset = i * 4
            table_id = struct.unpack('>I', buffer.raw[offset:offset+4])[0] # Converting RAW binary back to integer in big endian.
            table_ids.append(table_id)

        return table_ids
    except Exception:
        return []




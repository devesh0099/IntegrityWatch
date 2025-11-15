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

        # Converting provider string into DWORD in big endian
        provider_bytes = provider.encode('ascii')
        if len(provider_bytes) != 4:
            return []
        provider_sig = struct.unpack('>I', provider_bytes)[0]
        

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

def fetch_firmware_table(provider: str, table_id: int) -> bytes:
    # Fetches RAW binary data for a specific firmware table.
    try:
        import ctypes
        from ctypes import wintypes
        import struct

        # Converting provider to DWORD (big-endian)
        provider_bytes = provider.encode('ascii')
        if len(provider_bytes) != 4:
            return b''
        provider_sig = struct.unpack('>I', provider_bytes)[0]

        # Loading kernel32 DLL's
        kernel32 = ctypes.windll.kernel32
        get_table_func = kernel32.GetSystemFirmwareTable

        #Defining API function signature
        get_table_func.argtypes = [
            wintypes.DWORD, # Provider Signature
            wintypes.DWORD, # Table ID
            ctypes.c_void_p, # Pointer to Buffer
            wintypes.DWORD # Buffer Size to be reserved
        ]
        get_table_func.restype = wintypes.UINT #Return type for function signature

        #Call 1: Get table size
        size_needed = get_table_func(provider_sig, table_id, None, 0)
        if size_needed == 0:
            return b""
        
        # Safety check: 8MB max table
        MAX_TABLE_SIZE = 8 * 1024 * 1024
        if size_needed > MAX_TABLE_SIZE:
            return b''
        
        buffer = ctypes.create_string_buffer(size_needed)

        # Call 2: Fetching the Actual table into the buffer
        bytes_returned = get_table_func(provider_sig, table_id, buffer, size_needed)

        if bytes_returned != size_needed:
            return b''
        
        return buffer.raw
    except Exception:
        return b''



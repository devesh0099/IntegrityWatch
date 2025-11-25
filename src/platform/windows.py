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

def get_pci_device_ids() -> list[tuple[int, int]]:
    try:
        import winreg
        devices = []

        pci_root = r"SYSTEM\CurrentControlSet\Enum\PCI"

        try:
            root_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                pci_root,
                0,
                winreg.KEY_READ
            )
        except OSError:
            return []
        
        # Start of enumeration

        device_index = 0
        while True:
            try:
                device_name = winreg.EnumKey(root_key, device_index)
                device_index += 1

                vendor_id, device_id = _parse_device_name(device_name)
                if vendor_id is not None and device_id is not None:
                    devices.append((vendor_id, device_id))
            
            except OSError:
                break
        
        winreg.CloseKey(root_key)
        return devices

    except Exception:
        return []
    
def _parse_device_name(device_name: str) -> tuple:
    vendor_id = None
    device_id = None

    ven_pos = device_name.find('VEN_')
    if ven_pos != -1:
        try:
            vendor_str = device_name[ven_pos + 4:ven_pos + 8]
            vendor_id = int(vendor_str, 16)
        except (ValueError, IndexError):
            pass

    dev_pos = device_name.find('DEV_')
    if dev_pos != -1:
        try:
            dev_start = dev_pos + 4
            dev_end = device_name.find('&', dev_start)
            if dev_end == -1:
                dev_end = len(device_name)

            device_str = device_name[dev_start:dev_end]
            device_id = int(device_str, 16)
        except (ValueError, IndexError):
            pass
    
    return vendor_id, device_id

def check_kernel_object(object_path: str) -> bool:
    try:
        import ctypes
        from ctypes import wintypes

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0X00000001
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Function 1
        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE
        ]
        CreateFileW.restype = wintypes.HANDLE

        # Function 2
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HANDLE]
        CloseHandle.restype = wintypes.BOOL

        handle = CreateFileW(
            object_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            0,
            None
        )

        if handle != INVALID_HANDLE_VALUE and handle != 0:
            CloseHandle(handle)
            return True
        
        return False
    
    except Exception as e:
        return False
    
def get_registry_object_path(key_path: str) -> str | None:
    try:
        import ctypes
        from ctypes import wintypes


        ntdll = ctypes.WinDLL('ntdll')
        
        # Defining structure for low level C functions
        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ('Length', wintypes.USHORT),
                ('MaximumLength', wintypes.USHORT),
                ('Buffer', wintypes.LPWSTR)
            ]
        
        
        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ('Length', wintypes.ULONG),
                ('RootDirectory', wintypes.HANDLE),
                ('ObjectName', ctypes.POINTER(UNICODE_STRING)),
                ('Attributes', wintypes.ULONG),
                ('SecurityDescriptor', wintypes.LPVOID),
                ('SecurityQualityOfService', wintypes.LPVOID)
            ]
        
        
        class OBJECT_NAME_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('Name', UNICODE_STRING)
            ]
        
        # Define Function 1
        NtOpenKey = ntdll.NtOpenKey
        NtOpenKey.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            ctypes.POINTER(OBJECT_ATTRIBUTES)
        ]
        NtOpenKey.restypes = wintypes.LONG

        # Define Function 2
        NtQueryObject = ntdll.NtQueryObject
        NtQueryObject.argtypes = [
            wintypes.HANDLE,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG)
        ]
        NtQueryObject.restype = wintypes.LONG
        # Define Function 3
        NtClose = ntdll.NtClose
        NtClose.argtypes = [wintypes.HANDLE]
        NtClose.restype = wintypes.LONG

        # Preparing registry key path
        key_path_unicode = UNICODE_STRING()
        key_path_unicode.Buffer = key_path
        key_path_unicode.Length = len(key_path) * 2
        key_path_unicode.MaximumLength = key_path_unicode.Length * 2

        # Preparing object attributes
        obj_attr = OBJECT_ATTRIBUTES()
        obj_attr.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        obj_attr.RootDirectory = None
        obj_attr.ObjectName = ctypes.pointer(key_path_unicode)
        obj_attr.Attributes = 0x00000040 # OBJ_CASE_INSENSITIVE
        obj_attr.SecurityDescriptor = None
        obj_attr.SecurityQualityOfService = None


        hKey = wintypes.HANDLE()
        KEY_READ = 0x20019

        status = NtOpenKey(ctypes.byref(hKey), KEY_READ, ctypes.byref(obj_attr))
        if status < 0:
            return None
        
        try:
            buffer = ctypes.create_string_buffer(1024)
            returned_length = wintypes.ULONG()
            ObjectNameInformation = 1

            status = NtQueryObject(
                hKey,
                ObjectNameInformation,
                buffer,
                1024,
                ctypes.byref(returned_length)
            )

            if status < 0:
                return None
            
            obj_name_info = ctypes.cast(
                buffer,
                ctypes.POINTER(OBJECT_NAME_INFORMATION)
            ).contents

            name_length = obj_name_info.Name.Length // 2
            returned_path = obj_name_info.Name.Buffer[:name_length]

            return returned_path

        finally:
            NtClose(hKey)
    
    except Exception:
        return None
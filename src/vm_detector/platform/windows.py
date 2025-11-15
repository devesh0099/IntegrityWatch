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

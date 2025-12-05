from typing import Any

TCP_STATE = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}

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
    
def enumerate_processes() -> list[dict[str, Any]]:
    import os
    processes = []

    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    name = f.read().strip()
                
                path = ''
                try:
                    path = os.readlink(f'/proc/{pid}/exe')
                except:
                    pass

                processes.append({
                    'name': name,
                    'pid': int(pid),
                    'path': path,
                    'cmdline': ''
                })
            except:
                continue

        return processes
    
    except Exception:
        return []

def get_tcp_connections_for_pid(pid: int) -> list[dict]:
    try:
        import os

        tcp_data = _parse_proc_net_tcp()

        socket_inodes = _get_socket_inodes_for_pid(pid)

        connections = []
        for conn in tcp_data:
            if conn['inode'] in socket_inodes:
                connections.append({
                    'local_addr': conn['local_addr'],
                    'local_port': conn['local_port'],
                    'remote_addr': conn['remote_addr'],
                    'remote_port': conn['remote_port'],
                    'state': conn['state'],
                    'pid': pid
                })

        return connections
    
    except Exception:
        return []
    
def _parse_proc_net_tcp() -> list[dict]:
    connections = []

    try:
        with open('/proc/net/tcp', 'r') as f:
            lines = f.readlines()[1:]

        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue

            local_addr, local_port = _parse_address(parts[1])
            remote_addr, remote_port = _parse_address(parts[2])
            state_hex = parts[3]
            inode = int(parts[9])

            connections.append({
                'local_addr': local_addr,
                'local_port': local_port,
                'remote_addr': remote_addr,
                'remote_port': remote_port,
                'state': TCP_STATE.get(state_hex, 'UNKNOWN'),
                'inode': inode
            })

        return connections
    except:
        return []
    
def _parse_address(addr_str: str) -> tuple:
    addr_hex, port_hex = addr_str.split(':')

    ip_int = int(addr_hex, 16)
    ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
    
    port = int(port_hex, 16)
    return ip, port
                
def _get_socket_inodes_for_pid(pid: int) -> set:
    import os
    inodes = set()

    try:
        fd_dir = f'/proc/{pid}/fd'

        for fd_name in os.listdir(fd_dir):
            try:
                link = os.readlink(f'{fd_dir}/{fd_name}')

                if link.startswith('socket:['):
                    inode = int(link[8:-1])
                    inodes.add(inode)
            except:
                continue
    except:
        pass

    return inodes

def reverse_dns_lookup(ip_address: str) -> str:
    try:
        import socket
        result = socket.gethostbyaddr(ip_address)
        return result[0]
    except:
        return ""
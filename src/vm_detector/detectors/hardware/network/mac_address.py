from ...base import BaseDetector
from ....core.result import TechniqueResult

VM_MAC_PREFIXES = {
    # VMware
    '00:05:69': 'VMware',
    '00:0C:29': 'VMware',
    '00:1C:14': 'VMware',
    '00:50:56': 'VMware',
    '00:0F:4B': 'VMware',
    '00:1C:42': 'VMware (Parallels clash)',
    
    # Oracle VirtualBox
    '08:00:27': 'VirtualBox',
    
    # Microsoft Hyper-V / Virtual PC
    '00:03:FF': 'Microsoft Virtual PC',
    '00:12:5A': 'Microsoft Hyper-V',
    '00:15:5D': 'Microsoft Hyper-V',
    '00:17:FA': 'Microsoft Hyper-V',
    '00:1D:D8': 'Microsoft Hyper-V',
    '00:25:AE': 'Microsoft Hyper-V',
    
    # Parallels
    '00:1C:42': 'Parallels',
    
    # Xen
    '00:16:3E': 'Xen',
    
    # QEMU/KVM
    '52:54:00': 'QEMU/KVM',
    
    # Red Hat Virtualization
    '00:1A:4A': 'Red Hat KVM',
    
    # Amazon EC2
    '02:00:00': 'Amazon EC2 (legacy)',
    '02:01:00': 'Amazon EC2',
    '12:00:00': 'Amazon EC2',
    '12:01:00': 'Amazon EC2',
    
    # Google Cloud
    '42:01:0A': 'Google Cloud',
    
    # Azure
    '00:0D:3A': 'Microsoft Azure',
    
    # Nutanix
    '50:6B:8D': 'Nutanix AHV',
    
    # Proxmox
    'BC:24:11': 'Proxmox',
    
    # bhyve (FreeBSD)
    '58:9C:FC': 'bhyve',
}

class MACAddressDetector(BaseDetector):

    def __init__(self):
        super().__init__(
            name="MAC Address Check",
            supported_platforms=['windows', 'linux', 'macos'],
            requires_admin=False
        )
    
    def detect(self) -> TechniqueResult:
        try:
            from ....platform import base
        except ImportError:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Platform base module not available"
            )
        
        # Get all MAC addresses on the system
        self.logger.info("Enumerating network interfaces...")
        mac_addresses = base.get_mac_addresses()

        if not mac_addresses:
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="No network interfaces found",
                error="Could not enumerate MAC addresses"
            )

        self.logger.debug(f"Found {len(mac_addresses)} network interfaces")
        
        for mac in mac_addresses:
            self.logger.debug(f"Checking MAC: {mac}")
            
            oui = mac[:8].upper()  # Format: XX:XX:XX
            
            # Check against known VM prefixes
            if oui in VM_MAC_PREFIXES:
                vendor = VM_MAC_PREFIXES[oui]
                self.logger.info(f"VM MAC prefix detected: {oui} ({vendor})")
                
                return TechniqueResult(
                    name=self.name,
                    detected=True,
                    details=f"VM-specific MAC address detected: {mac} (OUI: {oui}, Vendor: {vendor})"
                )
        
        self.logger.info("No VM MAC prefixes detected")
        return TechniqueResult(
            name=self.name,
            detected=False,
            details=f"All {len(mac_addresses)} network adapters have non-VM MAC addresses"
        )

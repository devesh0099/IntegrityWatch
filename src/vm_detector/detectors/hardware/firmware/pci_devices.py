from ...base import BaseDetector
from ....core.result import TechniqueResult
from src.utils.platform.base import is_linux, is_windows

# VM PCI ID Database 
VM_PCI_SIGNATURES = {
    # VirtualBox - Vendor 0x80EE
    (0x80EE, 0xCAFE): "VirtualBox",
    (0x80EE, 0xBEEF): "VirtualBox",
    
    # VMware - Vendor 0x15AD
    (0x15AD, 0x0405): "VMware",  # SVGA II Adapter
    (0x15AD, 0x0740): "VMware",  # Virtual Machine Communication Interface
    (0x15AD, 0x0770): "VMware",  # USB2 EHCI Controller
    (0x15AD, 0x0790): "VMware",  # PCI bridge
    (0x15AD, 0x07A0): "VMware",  # PCI Express Root Port
    (0x15AD, 0x07E0): "VMware",  # SATA AHCI controller
    
    # QEMU/KVM - Vendor 0x1AF4 (virtio) and 0x1B36 (Red Hat)
    (0x1AF4, 0x1000): "QEMU/KVM (virtio-net)",
    (0x1AF4, 0x1001): "QEMU/KVM (virtio-blk)",
    (0x1AF4, 0x1002): "QEMU/KVM (virtio-balloon)",
    (0x1AF4, 0x1003): "QEMU/KVM (virtio-console)",
    (0x1AF4, 0x1004): "QEMU/KVM (virtio-rng)",
    (0x1AF4, 0x1005): "QEMU/KVM (virtio-mem)",
    (0x1AF4, 0x1009): "QEMU/KVM (virtio-fs)",
    (0x1B36, 0x0001): "QEMU (qxl)",
    (0x1B36, 0x0100): "QEMU",
    
    # Microsoft Hyper-V - Vendor 0x1414
    (0x1414, 0x5353): "Hyper-V",  
    
    # Parallels - Vendor 0x1AB8
    (0x1AB8, 0x4000): "Parallels",
    (0x1AB8, 0x4005): "Parallels",
    
    # Xen - Vendor 0x5853
    (0x5853, 0x0001): "Xen",
    (0x5853, 0xC000): "Xen",
}

# Vendor-only detection
VM_VENDOR_IDS = {
    0x80EE: "VirtualBox",
    0x15AD: "VMware", 
    0x1AF4: "QEMU/KVM (virtio)",
    0x1B36: "QEMU/KVM (Red Hat)",
    0x1AB8: "Parallels",
}

class PCIDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="PCI Device Detection",
                         supported_platforms=['windows','linux'],
                         requires_admin=False
        )

    def detect(self) -> TechniqueResult:
        if is_windows():
            return self._check_windows()
        elif is_linux():
            return self._check_linux()
        else: # Redundant but still good for checking
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Platform not supported."
            )
    
    def _check_devices(self, devices) -> TechniqueResult:
        for device in devices:
            vendor_id, device_id = device
            if device in VM_PCI_SIGNATURES:
                self.logger.info(f"PCI Match Found: {device} for {VM_PCI_SIGNATURES[device]}") 
                return TechniqueResult(
                    name=self.name,
                    detected=True,
                    details=f"Found {device} for {VM_PCI_SIGNATURES[device]}"
                )
            
            if vendor_id in VM_VENDOR_IDS:
                self.logger.info(f"PCI Vendor Match: {vendor_id} for {VM_VENDOR_IDS[vendor_id]}") 

                return TechniqueResult(
                    name=self.name,
                    detected=True,
                    details=f"Found Vendor ID {vendor_id} for {VM_VENDOR_IDS[vendor_id]}"
                )
        
        return TechniqueResult(
            name=self.name,
            detected=False,
            details=f"No Default Vendor ID or Device ID found in PCI Devices"
        )


    def _check_linux(self) -> TechniqueResult:
        from src.utils.platform.linux import get_pci_device_ids
      
        self.logger.info("Enumerating PCI Device Drivers in Linux....")
        devices = get_pci_device_ids()
        if not devices:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Unable to enumerate PCI devices on this system."
            )
        
        self.logger.debug(f"Found {len(devices)} PCI devices, chekcing signatures...")
        result = self._check_devices(devices)
    
        return result


    def _check_windows(self) -> TechniqueResult:
        from src.utils.platform.windows import get_pci_device_ids

        self.logger.info("Enumerating PCI devices on Windows...")
        devices = get_pci_device_ids()

        if not devices:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Unable to enumerate PCI devices on Windows."
            )
        
        self.logger.debug(f"Found {len(devices)} PCI devices, chekcing signatures...")
        result = self._check_devices(devices)
        return result

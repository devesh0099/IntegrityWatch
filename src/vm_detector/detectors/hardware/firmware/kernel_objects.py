from ...base import BaseDetector
from ....core.result import TechniqueResult

VM_KERNEL_OBJECTS = {
    # Hyper-V - Source: VMAware + al-khaser
    r'\\.\VmGenerationCounter': 'Hyper-V',
    r'\\.\VmGid': 'Hyper-V',
    
    # VirtualBox - Source: al-khaser + personal testing
    r'\\.\VBoxMiniRdrDN': 'VirtualBox',
    r'\\.\VBoxGuest': 'VirtualBox',          
    r'\\.\VBoxTrayIPC': 'VirtualBox',
    r'\\.\pipe\VBoxMiniRdDN': 'VirtualBox',
    r'\\.\pipe\VBoxTrayIPC': 'VirtualBox',
    
    # VMware - Source: al-khaser 
    r'\\.\HGFS': 'VMware',
    r'\\.\vmci': 'VMware',
}

class KernelObjectDetector(BaseDetector):
      
    def __init__(self):
        super().__init__(
            name="Kernel Object Detection",
            supported_platforms=['windows'],
            requires_admin=False
        )

    def detect(self) -> TechniqueResult:
        self.logger.info("Checking Kernel Driver Objects...")

        try:
            from src.platform.windows import check_kernel_object
            
            for device_path, vm_name in VM_KERNEL_OBJECTS.items():
                if check_kernel_object(device_path):
                    self.logger.info(f"Found VM device: {device_path}")
                    return TechniqueResult(
                        name=self.name,
                        detected=True,
                        details=f"Detected {vm_name} via device: {device_path}"
                    )
                
            return TechniqueResult(
                name=self.name,
                detected=False,
                details=f"Checked {len(VM_KERNEL_OBJECTS)} device objects, none found"
            )
        
        except Exception as e:
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="Error in Checking.",
                error=f"Unable to check VM device objects {e}"
            )
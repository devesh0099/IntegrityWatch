from ...base import BaseDetector
from ....core.result import TechniqueResult
from ....platform.base import is_windows, is_linux, get_current_platform

class SMBIOSDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="SMBIOS Firmware",
                         supported_platforms=['windows', 'linux'],
                         requires_admin=False
        )
    
    def detect(self) -> TechniqueResult:
        # Getting Firmware info for different OSes
        firmware = None
        if(is_windows()):
            from ....platform import windows
            firmware = windows.get_firmware_info()
        elif(is_linux()): 
            from ....platform import linux
            firmware = linux.get_firmware_info()

        if 'error' in firmware:
            return TechniqueResult(
                name=self.name,
                detected=False,
                details=f"Failed to query firmware in {get_current_platform()}",
                error=firmware['error']
            )
        
        vm_indicators = [
            'vmware', 'virtualbox', 'qemu', 'kvm',
            'hyper-v', 'xen', 'parallels', 'innotek'
        ]

        fields_checked = []
        detected_in = []

        for key, value in firmware.items():
            if value:
                value_lower = str(value).lower()
                fields_checked.append(f"{key}={value}")

                for indicator in vm_indicators:
                    if indicator in value_lower:
                        detected_in.append(f"{key}: {value}")
                        
        
        if detected_in:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details=f"VM indicators found - {', '.join(detected_in)}"
            )
        else:
            return TechniqueResult(
                name=self.name,
                detected=False,
                details=f"No VM signatures in firmware ({len(fields_checked)}) fields checked)"
            )
        
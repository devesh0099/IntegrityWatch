from ...base import BaseDetector
from ....core.result import TechniqueResult

VM_VENDOR_STRINGS = {
    'VMwareVMware': 'VMware',
    'VBoxVBoxVBox': 'VirtualBox',
    'KVMKVMKVM': 'KVM',
    'Microsoft Hv': 'Hyper-V',
    'XenVMMXenVMM': 'Xen',
    'prl hyperv': 'Parallels',
    'TCGTCGTCGTCG': 'QEMU',
    'bhyve bhyve': 'bhyve (FreeBSD)'
}
VM_KEYWORDS = [
    'vmware',
    'vbox',
    'qemu',
    'kvm',
    'xen',
    'hyperv',
    'parallels'
]

class CPUIDVendorDetector(BaseDetector):

    def __init__(self):
        super().__init__(
            name="CPUID Vendor String",
            supported_platforms=[],
            requires_admin=False
        )

    def detect(self) -> TechniqueResult:
        self.logger.info("Scanning CPUID Vendor strings...")
        try:
            from src.utils.platform import base
        except ImportError:
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="CPU platform module not available"
            )
        
        #Check 1: Checking for leaf 0x40000000 (hypervisor vendor - standard)
        result = self._check_leaf(base, 0x40000000)
        if result['detected']:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details=result['details']
            )
        
        #Check 2: Checking for leaf 0x40000100 (hypervisor vendor - extended)
        result = self._check_leaf(base, 0x40000100)
        if result['detected']:
            return TechniqueResult(
                name=self.name,
                detected=True,
                details=result['details']
            )
    
        return TechniqueResult(
            name=self.name,
            detected=False,
            details="No VM vendor strings found in CPUID"
        )
    
    def _check_leaf(self, cpu_module, leaf: int) -> dict:
        vendor_str = cpu_module.get_cpuid_vendor(leaf)

        if not vendor_str:
            self.logger.warning(f"No String found for the leaf 0x{leaf:08X}")
            return {'detected': False}
        
        self.logger.debug(f"Leaf 0x{leaf:08X} returned: '{vendor_str}'")

        # Checking Against known VM vendors
        for vm_vendor, vm_name in VM_VENDOR_STRINGS.items():
            if vm_vendor in vendor_str or vendor_str in vm_vendor:
                return {
                    'detected':True,
                    'details': f"VM vendor '{vm_name}' detected at CPUID leaf 0x{leaf:08X}: '{vendor_str}'"
                }
            
        # Checking for partial matches
        vendor_lower = vendor_str.lower()
        for keyword in VM_KEYWORDS:
            if keyword in vendor_lower:
                return {
                    'detected': True,
                    'details': f"Suspicious vendor string at CPUID leaf 0x{leaf:08X}: '{vendor_str}'"
                }
        
        return {'detected': False}



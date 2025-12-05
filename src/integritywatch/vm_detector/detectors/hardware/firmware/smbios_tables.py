import struct
from ...base import BaseDetector
from ....core.result import TechniqueResult
from integritywatch.utils.platform.base import is_windows, is_linux, get_current_platform, get_cpuid_vendor

# Constants based on Signatures found in VM's
VM_SIGNATURES = [
    b'Parallels Software', b'Parallels(R)', b'innotek', b'Oracle', 
    b'VirtualBox', b'vbox', b'VBOX', b'VMware, Inc.', b'VMware', 
    b'VMWARE', b'VMW0003', b'QEMU', b'pc-q35', b'Q35 +', b'FWCF', 
    b'BOCHS', b'BXPC', b'ovmf', b'edk ii unknown', b'WAET', 
    b'S3 Corp.', b'Virtual Machine', b'VS2005R2', b'Xen'
]
HARDENER_MARKER = b'777777'
AMD_SHORT = b'Advanced Micro Devices'
AMD_FULL = b'Advanced Micro Devices, Inc.'

class SMBIOSDetector(BaseDetector):
    def __init__(self):
        needs_admin = is_linux()
        super().__init__(
            name="Firmware Table Scan",
            supported_platforms=['windows', 'linux'],
            requires_admin=needs_admin
        )

        self._cpu_vendor = None
    
    def detect(self) -> TechniqueResult:
        if self._cpu_vendor is None:
            try:
                self._cpu_vendor = get_cpuid_vendor(0)
                self.logger.debug(f"CPU Vendor: {self._cpu_vendor}")
            except Exception as e:
                self.logger.warning(f"Could not get CPU vendor: {e}")
                self._cpu_vendor = "" 
        if is_windows():
            return self._detect_windows()
        elif is_linux():
            return self._detect_linux()
        return TechniqueResult(
            name=self.name,
            detected=False,
            details="Platform not supported"
        )

    def _detect_windows(self) -> TechniqueResult:
        # Checks applied to detect windows running in VM.
        try:
            from integritywatch.utils.platform import windows

            # ------------Started Scanning for ACPI Tables--------
            self.logger.info("Scanning ACPI tables (Windows).....")
            acpi_ids = windows.enumerate_firmware_tables('ACPI')
            if not acpi_ids:
                self.logger.warning("Could not enumerate ACPI tables. Falling back to WMI.")
                return self._detect_fallback()
            
            # Checking if HPET table exist or not.
            self.found_hpet = 0x54455048 in acpi_ids

            # Scan ACPI tables
            for table_id in acpi_ids:
                table_data = windows.fetch_firmware_table('ACPI', table_id)
                if not table_data:
                    continue

                result = self._scan_table(table_data, is_acpi=True)
                if result['detected']:
                    return TechniqueResult(
                        name=self.name,
                        detected=True,
                        details=result['details']
                    )

            # -----------Started Scanning for SMBIOS Table Scan------------
            self.logger.info("Scanning SMBIOS (RSMB) tables....")
            rsmb_ids = windows.enumerate_firmware_tables('RSMB')
            for table_id in rsmb_ids:
                table_data = windows.fetch_firmware_table('RSMB', table_id)
                if not table_data:
                    continue

                # For SMBIOS table, only brand detection is relevant
                result = self._scan_table(table_data, is_acpi=False)
                if result['detected']:
                    return TechniqueResult(
                        name=self.name,
                        detected=True,
                        details=result['details']
                    )
            
            # Checking if HPET table exist or not.
            if not self.found_hpet: # Encountered False Positive
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    details="HPET ACPI table absent"
                )
            
            # If everything is good, then system is clean
            return TechniqueResult(
                name=self.name,
                detected=False,
                details="System is Clean in Firmware Tables"
            )

        except Exception as e:
            self.logger.error(f"Firmware scan failed: {e}. Falling back to WMI.")
            return self._detect_fallback()

    def _scan_table(self, table_data: bytes, is_acpi: bool) -> dict:
        # Performs scan of compelte table data looking for VM signature.
        search_data = table_data.lower()

        # Check 1: Brand Detection
        for signature in VM_SIGNATURES:
            if search_data.find(signature.lower()) != -1:
                # Special Handling of 'Xen' string
                if signature == b'Xen':
                    if search_data.find(b'pxen') != -1: # Both 'Xen' and 'pxen' should be there in VM
                        continue
                return {
                    'detected': True,
                    'details': f"VM brand signature found: '{signature.decode('ascii', errors='replace')}'"
                }
        
        # If the table is not of ACPI skip rest of the checks
        if not is_acpi or len(table_data) < 36: # Min size for header fields
            return {'detected': False}
        
        # Check 2: Hardener Tool Detection ('777777' marker)
        oem_id = table_data[10:16]
        oem_table_id = table_data[16:24]
        if HARDENER_MARKER in oem_id or HARDENER_MARKER in oem_table_id:
            return {
                'detected': True,
                'details': f"VMwareHardenedLoader artifact found in OEMID/OEMTableID"
            }
        
        signature = table_data[0:4]
        header_len = struct.unpack_from('<I', table_data, 4)[0] # Used little endian because it is parsing bytes that are on CPU in that order.

        # Check 3: AMD Manufacturer String Spoofing
        has_short = AMD_SHORT in table_data
        has_full = AMD_FULL in table_data
        cpu_vendor = self._cpu_vendor
        
        if (has_short and not has_full) or ((cpu_vendor != "AuthenticAMD" and cpu_vendor != "") and (has_short or has_full)):
            return {
                'detected': True, 
                'details': "Spoofed AMD manufacturer string detected (short form without Inc.)"
            }        

        # Check 4: FADT-Table Specific Checks
        if signature == b'FACP':
            # Check for valid header length
            if header_len > len(table_data):
                return {
                    'detected': True,
                    'details': f"Corrupt ACPI header in FADT: Declared length ({header_len}) > actual length ({len(table_data)})"
                }
            
            # Check Buffer Size Validation
            # It needs atleast 84 bytes to read P_Lvl2_Lat and P_Lvl3_Lat
            if len(table_data) < 84:
                return {
                    'detected': True,
                    'details': f"FADT buffer too small: {len(table_data)} bytes (expected >= 84)"
                }
            
            # Checking latency values of P_Lv12_lat and P_Lvl3_Lat
            p_lv12_lat = struct.unpack_from('<H', table_data, 80)[0]
            p_lv13_lat = struct.unpack_from('<H', table_data, 82)[0]

            if p_lv12_lat == 0x0FFF or p_lv13_lat == 0x0FFF:
                return {
                    'detected': True,
                    'details': f"invalid FADT C-state latency values: P_Lv12={hex(p_lv12_lat)}, P_Lv13={hex(p_lv13_lat)}"
                }
        
        # If no check passed table is cleaned
        return {'detected': False}
    
    def _detect_linux(self) -> TechniqueResult:
        self.logger.info("Enumerating ACPI tables (Linux)...")
        try:
            from integritywatch.utils.platform import linux
            table_files = linux.get_acpi_tables()

            if not table_files:
                return TechniqueResult(
                    name=self.name,
                    detected=False,
                    details="ACPI path not found.",
                    error="ACPI Table Files not found."
                )
            for filename in table_files:
                self.logger.debug(f"Scanning table file: {filename}")
                try: #Opening each table in ACPI table path
                    with open(filename, 'rb') as f:
                        table_data = f.read()
                        result = self._scan_table(table_data, is_acpi=True)
                        if result['detected']:
                            return TechniqueResult(
                                name=self.name,
                                detected=True,
                                details=f"VM artifact in {filename}: {result['details']}"
                            )
                except Exception as e:
                    self.logger.warning(f"Could not read or scan {filename}: {e}")

            return TechniqueResult(
                name=self.name,
                detected=False,
                details="No VM artifacts found in Linux ACPI tables"
            )
        except Exception as e:
            self.logger.error(f"ACPI table scan failed: {e}.")
            return TechniqueResult(
                name=self.name,
                detected=False,
                error="Unable to do ACPI table scan {e}"
            )


    def _detect_fallback(self) -> TechniqueResult:
        # Fallback Test of firmware
        # Getting Firmware info for different OSes
        firmware = None
        if(is_windows()):
            from integritywatch.utils.platform import windows
            firmware = windows.get_firmware_info()
        elif(is_linux()): 
            from integritywatch.utils.platform import linux
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
        
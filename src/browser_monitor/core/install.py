import os
import sys
import json
from pathlib import Path

from ...utils.browser import get_all_browser_native_host_paths, install_native_host_manifest_unix, install_native_host_manifest_windows, get_installed_chromium_browsers
from ...utils.logger import get_logger
from ...utils.platform.base import get_current_platform

class NativeHostInstaller:
    def __init__(self):
        self.logger = get_logger('browser_monitor.installer')
        self.system = get_current_platform()

        self.native_host_script = Path(__file__).parent / 'native_host.py'

        if not self.native_host_script.exists():
            raise FileNotFoundError(f"Native host script not found: {self.native_host_script}")
        
        
    def install(self) -> dict[str, bool]:
        self.logger.info(f"Installing native host for platform: {self.system}")
        installed_browsers = get_installed_chromium_browsers()

        if not installed_browsers:
            self.logger.warning("No Chromium browsers detected!")
            print("Please install Chrome, Brave, Edge or another Chromium browser.")
        
        self.logger.info(f"Detected browsers: {', '.join(installed_browsers)}")

        if self.system in ['linux', 'darwin']:
            os.chmod(self.native_host_script, 0o755)

        native_host_path = self._prepare_native_host()

        manifest_content = self._generate_manifest(native_host_path)

        if self.system == 'windows':
            return self._install_windows(manifest_content, native_host_path)
        elif self.system in ['linux', 'darwin']:
            return self._install_unix(manifest_content)
        else:
            self.logger.error(f"Unsupported platform: {self.system}")
            return {}

    def _prepare_native_host(self) -> Path:
        if self.system == 'windows':
            bat_wrapper = self.native_host_script.parent / 'native_host.bat'
            python_exe = sys.executable

            bat_content = f'@echo off\n"{python_exe}" "{self.native_host_script}" %*\n'

            with open(bat_wrapper, 'w') as f:
                f.write(bat_content)

            self.logger.info(f"Created Windows wrapper: {bat_wrapper}")
            return bat_wrapper.resolve()
        else:
            return self.native_host_script.resolve()

        
    def _generate_manifest(self, native_host_path: Path) -> dict:
        return {
            "name": "com.integritywatch.host",
            "description": "IntegrityWatch Browser Monitor Native Host",
            "path": str(native_host_path),
            "type": "stdio",
            "allowed_origins": [
                "chrome-extension://ofpgknjhjfgimdgeekfoilllehhkikie/"
            ]
        }
    
    def _install_windows(self, manifest_content: dict, native_host_path: Path) -> dict[str, bool]:
        browser_paths = get_all_browser_native_host_paths()

        if not browser_paths:
            self.logger.error("No browser paths found")
            return {}
        
        results = {}
    
        for browser_name, manifest_dir in browser_paths.items():
            try:
                manifest_dir.mkdir(parents=True, exist_ok=True)
                
                manifest_file = manifest_dir / 'com.integritywatch.host.json'
                
                with open(manifest_file, 'w') as f:
                    json.dump(manifest_content, f, indent=2)
                
                self.logger.info(f"{browser_name}: Manifest written to {manifest_file}")
                
                success = install_native_host_manifest_windows(manifest_file)
                
                if success:
                    self.logger.info(f"{browser_name}: Registry key created")
                    results[browser_name] = True
                else:
                    self.logger.error(f"{browser_name}: Failed to create registry key")
                    results[browser_name] = False
            
            except Exception as e:
                self.logger.error(f"{browser_name}: Failed - {e}")
                results[browser_name] = False
        
        return results


    def _install_unix(self, manifest_content: dict) -> dict[str, bool]:
        browser_paths = get_all_browser_native_host_paths()

        if not browser_paths:
            self.logger.error("No browser paths found")
            return {}
        
        results = {}

        for browser_name, browser_path in browser_paths.items():
            try:
                browser_path.mkdir(parents=True, exist_ok=True)

                manifest_file = browser_path / 'com.integritywatch.host.json'
                with open(manifest_file, 'w') as f:
                    json.dump(manifest_content, f, indent=2)

                self.logger.info(f"{browser_name}: Installed to {manifest_file}")
                results[browser_name] = True
            
            except Exception as e:
                self.logger.error(f"{browser_name}: Failed - {e}")
                results[browser_name] = False

        return results
    

def main():
    print("=" * 60)
    print("IntegrityWatch Native Host Installer")
    print("=" * 60)

    try:
        # print("here")
        installer = NativeHostInstaller()
        results = installer.install()

        if results and any(results.values()):
            installer.logger.info(f"Installation result:\n{results}")
            sys.exit(0)
        else:
            print("Installation Failed check logs!")
            sys.exit(0)
    
    except Exception as e:
        print(f"Installation error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
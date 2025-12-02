import os
from .platform.base import is_linux, is_macos, is_windows
from pathlib import Path
from typing import Optional

def get_all_browser_native_host_paths() -> dict[str, Path]:
    browser_paths = {}
    
    if is_windows():
        localappdata = Path(os.path.expandvars('%LOCALAPPDATA%'))
        appdata = Path(os.path.expandvars('%APPDATA%'))
        
        potential_browsers = {
            'Chrome': localappdata / 'Google' / 'Chrome' / 'NativeMessagingHosts',
            'Brave': localappdata / 'BraveSoftware' / 'Brave-Browser' / 'NativeMessagingHosts',
            'Edge': localappdata / 'Microsoft' / 'Edge' / 'NativeMessagingHosts',
            'Chromium': localappdata / 'Chromium' / 'NativeMessagingHosts',
            'Opera': appdata / 'Opera Software' / 'Opera Stable' / 'NativeMessagingHosts',
            'Opera GX': appdata / 'Opera Software' / 'Opera GX Stable' / 'NativeMessagingHosts',
            'Vivaldi': localappdata / 'Vivaldi' / 'NativeMessagingHosts',
            'Yandex': localappdata / 'Yandex' / 'YandexBrowser' / 'NativeMessagingHosts',
        }
    elif is_linux():
        home = Path.home()
        potential_browsers = {
            'Chrome': home / '.config' / 'google-chrome' / 'NativeMessagingHosts',
            'Brave': home / '.config' / 'BraveSoftware' / 'Brave-Browser' / 'NativeMessagingHosts',
            'Edge': home / '.config' / 'microsoft-edge' / 'NativeMessagingHosts',
            'Chromium': home / '.config' / 'chromium' / 'NativeMessagingHosts',
            'Opera': home / '.config' / 'opera' / 'NativeMessagingHosts',
            'Vivaldi': home / '.config' / 'vivaldi' / 'NativeMessagingHosts',
            'Yandex': home / '.config' / 'yandex-browser' / 'NativeMessagingHosts',
        }
    
    elif is_macos():
        home = Path.home()
        app_support = home / 'Library' / 'Application Support'
        
        potential_browsers = {
            'Chrome': app_support / 'Google' / 'Chrome' / 'NativeMessagingHosts',
            'Brave': app_support / 'BraveSoftware' / 'Brave-Browser' / 'NativeMessagingHosts',
            'Edge': app_support / 'Microsoft Edge' / 'NativeMessagingHosts',
            'Chromium': app_support / 'Chromium' / 'NativeMessagingHosts',
            'Opera': app_support / 'com.operasoftware.Opera' / 'NativeMessagingHosts',
            'Vivaldi': app_support / 'Vivaldi' / 'NativeMessagingHosts',
            'Yandex': app_support / 'Yandex' / 'YandexBrowser' / 'NativeMessagingHosts',
        }
    
    else:
        return {}
    
    for browser_name, path in potential_browsers.items():
        browser_dir = path.parent
        if browser_dir.exists():
            browser_paths[browser_name] = path
    
    return browser_paths

def install_native_host_manifest_windows(manifest_path: Path) -> bool:
    try:
        import winreg
        
        reg_path = r"SOFTWARE\Google\Chrome\NativeMessagingHosts\com.integritywatch.host"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, str(manifest_path))
        winreg.CloseKey(key)
        
        return True
        
    except Exception as e:
        import logging
        logging.error(f"Failed to install Windows native host manifest: {e}")
        return False

def install_native_host_manifest_unix(manifest_content: dict, target_paths: list[Path]) -> dict[str, bool]:
    import json
    import logging
    
    results = {}
    
    for target_path in target_paths:
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            manifest_file = target_path / 'com.integritywatch.host.json'
            with open(manifest_file, 'w') as f:
                json.dump(manifest_content, f, indent=2)
            
            results[str(target_path)] = True
            
        except Exception as e:
            logging.error(f"Failed to install manifest to {target_path}: {e}")
            results[str(target_path)] = False
    
    return results

def get_installed_chromium_browsers() -> list[str]:
    browser_paths = get_all_browser_native_host_paths()
    return list(browser_paths.keys())

def get_primary_browser_path() -> Optional[Path]:
    browser_paths = get_all_browser_native_host_paths()
    
    if not browser_paths:
        return None
    
    # Priority order according to market share
    priority = ['Chrome', 'Edge', 'Chromium', 'Brave', 'Vivaldi', 'Opera', 'Opera GX', 'Yandex']
    
    for browser in priority:
        if browser in browser_paths:
            return browser_paths[browser]
    
    return next(iter(browser_paths.values()))
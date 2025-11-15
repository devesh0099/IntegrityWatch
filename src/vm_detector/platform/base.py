import platform as plat

def get_current_platform() -> str:
    return plat.system().lower()

def is_windows() -> bool:
    return get_current_platform() == 'windows'

def is_linux() -> bool:
    return get_current_platform() == 'linux'

def is_macos() -> bool:
    return get_current_platform() == 'darwin'
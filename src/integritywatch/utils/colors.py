from .platform.base import is_windows

if is_windows():
    try:
        from colorama import init, Fore, Style
        init(autoreset=True)
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        CYAN = Fore.CYAN
        PURPLE = Fore.MAGENTA
        BOLD = Style.BRIGHT
        RESET = Style.RESET_ALL
    except ImportError:
        print("Warning: colorama not installed. Run: pip install colorama")
        RED = GREEN = YELLOW = BLUE = CYAN = PURPLE = BOLD = RESET = ''
else:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    PURPLE = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

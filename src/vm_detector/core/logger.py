import logging
import sys
import os
from pathlib import Path
from ...config import config

def setup_logging():
    # Read Configuration from file
    console_enabled = config.get("logging", "console_output")
    console_lvl_str = config.get("logging", "console_level", "INFO")
    
    file_enabled = config.get("logging", "file_output")
    file_path = config.get("logging", "file_path")
    file_lvl_str = config.get("logging", "file_level", "DEBUG")

    root = logging.getLogger('vm_detector')
    root.setLevel(logging.DEBUG)
    
    if root.hasHandlers():
        root.handlers.clear()

    formatter = logging.Formatter('[%(levelname)s] %(name)s: %(message)s')

    if console_enabled:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        
        console_level = getattr(logging, console_lvl_str.upper(), logging.INFO)
        console.setLevel(console_level)
        
        root.addHandler(console)

    if file_enabled and file_path:
        try:
            log_path = Path(file_path)
            if log_path.parent: 
                log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(str(log_path), mode='a') # Append mode
            file_handler.setFormatter(formatter)
            
            file_level = getattr(logging, file_lvl_str.upper(), logging.DEBUG)
            file_handler.setLevel(file_level)
            
            root.addHandler(file_handler)
            
        except Exception as e:
            print(f"[ERROR] Failed to setup file logging: {e}", file=sys.stderr)

    return root

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f'vm_detector.{name}')

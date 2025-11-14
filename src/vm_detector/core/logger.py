import logging
import sys


def setup_logging(level: str = 'INFO'):
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    formatter = logging.Formatter(
        '[%(levelname)s] %(name)s: %(message)s'
    )
    
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    
    root = logging.getLogger('vm_detector')
    root.setLevel(numeric_level)
    root.addHandler(console)
    
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f'vm_detector.{name}')

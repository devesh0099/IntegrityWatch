#!/usr/bin/env python3
import sys

def main_wrapper():
    from integritywatch.main import main as real_main
    real_main()

def install_wrapper():
    from integritywatch.browser_monitor.core.install import main as install_main
    install_main()

if __name__ == "__main__":
    main_wrapper()

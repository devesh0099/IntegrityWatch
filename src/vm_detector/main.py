import sys
from .core.engine import DetectionEngine
from .core.logger import setup_logging

def run_checks(): # Main Entry point for VM Detector Module
    setup_logging(level='DEBUG') # Set Level to DEBUG for testing and Level to ERROR for production

    engine = DetectionEngine()
    result = engine.run()
    return result

if __name__ == "__main__":
    # When run directly as a script, we want to see the output
    setup_logging(level='INFO')
    
    engine = DetectionEngine()
    result = engine.run()
    
    # 1. Display the Forensic Dashboard (User UI)
    result.display()
    
    # 2. (Optional) Print JSON if piped to another tool
    print(result.to_json())
    
    # 3. Exit code based on block (for shell scripts)
    # if result.verdict == "BLOCK":
    #     sys.exit(1)
    # else:
    #     sys.exit(0)


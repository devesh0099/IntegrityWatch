from .core.engine import DetectionEngine
from .core.logger import setup_logging

def run_checks(): # Main Entry point for VM Detector Module
    setup_logging(level='DEBUG') # Set Level to DEBUG for testing and Level to ERROR for production

    engine = DetectionEngine()
    result = engine.run()
    return result

if __name__ == "__main__":
    setup_logging()
    
    engine = DetectionEngine()
    result = engine.run()
    
    result.display()
    
    saved_path = result.save()
    if saved_path:
        print(f"Report saved to: {saved_path}")


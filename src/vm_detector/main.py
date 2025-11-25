from .core.engine import DetectionEngine
from ..utils.logger import setup_logging

def run_checks(): # Main Entry point for VM Detector Module
    setup_logging() 

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


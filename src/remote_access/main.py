from .core.engine import DetectionEngine
from ..utils.logger import setup_logging
from .core.result import DetectionResult

def run_checks(): # Main Entry point for Remote Detection Module

    engine = DetectionEngine()
    result = engine.run()
    result.display()

    return result

def start_monitoring(heartbeat_callback,interval:int = 5):
    engine = DetectionEngine()
    engine.start_monitoring(
        interval=interval,
        display_callback=display_callback,
        heartbeat_callback=heartbeat_callback
        )
    return engine

def display_callback(result: DetectionResult):
    result.display_monitor()    

if __name__ == "__main__":
    setup_logging()
    
    engine = DetectionEngine()
    result = engine.run()
    
    result.display()

from pathlib import Path
from .core.engine import DetectionEngine
from ..utils.logger import get_logger


def run_scan(session_dir: Path):
    logger = get_logger("browser_monitor")
    
    try:
        engine = DetectionEngine(session_dir)
        
        if not engine.load_data():
            logger.warning("No violation data found")
        
        result = engine.run()
        result.display()
        
        return result, engine
        
    except Exception as e:
        logger.error(f"Browser monitoring failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    from datetime import datetime
    from ..utils.logger import setup_logging
    
    setup_logging()
    
    session_dir = Path("runtime/sessions") / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_dir.mkdir(parents=True, exist_ok=True)
    
    result, engine = run_scan(session_dir)

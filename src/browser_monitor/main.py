from pathlib import Path
from .core.engine import DetectionEngine
from ..utils.logger import get_logger


def run_checks(session_dir: Path):
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
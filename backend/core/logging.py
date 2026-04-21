import os
import sys
import logging
from pathlib import Path

_logger_configured = False

def setup_logger(name: str) -> logging.Logger:
    global _logger_configured
    
    # Base paths relative to backend root
    # __file__ is core/logging.py, parent is core, parent.parent is backend
    BACKEND_ROOT = Path(__file__).resolve().parent.parent
    LOG_DIR = BACKEND_ROOT / "data" / "logs"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE = LOG_DIR / "sentinel.log"

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers in multiprocessing / Uvicorn reload
    if not logger.handlers and not _logger_configured:
        # Wash root handlers to be completely clean
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] -> %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(formatter)
        
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
        
        # Propagate cleanly
        logger.propagate = False
        _logger_configured = True

    return logger

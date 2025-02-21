from rich.console import Console
import logging
from .config import LOG_FORMAT, LOG_LEVEL, LOG_FILE

def setup_logger():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logger()
console = Console() 
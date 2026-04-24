import logging
from rich.logging import RichHandler
from ._console import console


def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("binsmasher")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    rh = RichHandler(console=console, rich_tracebacks=True, markup=True)
    rh.setLevel(logging.INFO)
    logger.addHandler(rh)
    fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s"))
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    return logger

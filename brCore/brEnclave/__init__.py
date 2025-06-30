import logging
import os
from pathlib import Path

import Enclave


brEnclFormat = logging.Formatter(
        "{asctime}.{msecs} - [{thread} {module}.{funcName}:({lineno})] - [{levelname}] - {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
logger = logging.getLogger("brSecurity")
logger.propagate = False
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(f'temp/brSecurity.log', mode='a')
console_handler = logging.StreamHandler()
file_handler.setFormatter(brEnclFormat)
console_handler.setFormatter(brEnclFormat)
logger.addHandler(file_handler)

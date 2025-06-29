import logging
import os
from pathlib import Path

import Enclave

# Check for temp directory
tempdir = Path("temp/")
if tempdir.is_dir():
    pass
else:
    try:
        os.mkdir("temp/")
    except OSError:
        logging.error("Couldn't create temp directory!", exc_info=True)
    except Exception as e:
        logging.error("Unknown error when creating temp directory!", exc_info=True)


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

from pathlib import Path
import os

# Core Version (Will be used to check versions of other nodes)
BR_VERSION = "0.0.1-alpha"

# Import logging factory for global log creation
import logging
from .loggingfactory import setDefault, createNewLogger

# Check for or create Temp dir
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

# Once our temp is created,
setDefault()

# create our general logs
brLog = createNewLogger("backrooms-net")

# Low level socket logs
brAgentLog = createNewLogger("brNodeAgent")
brServeLog = createNewLogger("brNodeServe")
brNodeHsLog = createNewLogger("brNodeHandshakes")

# Sockets and network
import brCore.brSockets
from brCore.brSockets.brNodeAgent import brSocketAgent

# Enclave
import brCore.brEnclave
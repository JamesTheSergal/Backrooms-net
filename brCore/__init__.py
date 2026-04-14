from pathlib import Path
import os
import time

# Core Version (Will be used to check versions of other nodes)
BR_VERSION = "0.0.1-alpha"

# Console thing
from brCore.consolefancy import printstartfancy
printstartfancy(BR_VERSION)

# Import logging factory for global log creation
import logging
from .loggingfactory import setDefault, createNewLogger

# Import settings class
from .settings import brSettings

brCoreSettings = brSettings()

def matchLogLevel(strLevel:str, ):
    match setLogLevel:
        case "debug":
            return logging.DEBUG
        case "info":
            return logging.INFO
        case _:
            print("Log level not recognized. Defaulting to info.")
            return logging.INFO

setLogLevel = brCoreSettings.getStrSetting("logging", "globalLogLevel")
logLevel = matchLogLevel(setLogLevel)

if not brCoreSettings.settingsExisted:
    logging.warning("Settings did not exist on startup. 'BR.conf' has been created. Please check the values and restart.")
    exit()
else:
    pass

# Sockets and network
import brCore.brSockets
import brCore.brNodeNet
from brCore.brNodeNet import brNodeNetworkCore
from brCore.brNodeNet.brDHT import brDHT

# Enclave
import brCore.brEnclave
from brCore.brEnclave import notrustvars
from brCore.brEnclave import Enclave
from brCore.brEnclave import EnclaveStorage

# Web server
import brCore.brWebServer
from brCore.brWebServer import brWebCore, brWebDefaults, brWebElements, webResponder

from pathlib import Path
import os

# Core Version (Will be used to check versions of other nodes)
BR_VERSION = "0.0.1-alpha"

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


# Check for or create Temp dir
tempdir = Path("temp/")
if tempdir.is_dir():
    pass
else:
    try:
        os.mkdir("temp/")
    except OSError:
        logging.error("Couldn't create temp directory!", exc_info=True)
        exit()
    except Exception as e:
        logging.error("Unknown error while creating temp directory!", exc_info=True)
        exit()

# Once our temp is created, set default logger format
setDefault()

# create our general logs
brGeneralLog = createNewLogger("brMainLog", "temp/", level=logLevel)
brWebLog = createNewLogger("brWebCore", "temp/", level=logLevel)
brEnclaveLog = createNewLogger("brWebCore", "temp/", level=logLevel)
brSecurityLog = createNewLogger("brSecurity", "temp/", level=logLevel)

# Low level socket logs
brAgentLog = createNewLogger("brNodeAgent", "temp/", level=logLevel)
brServeLog = createNewLogger("brNodeServe", "temp/", level=logLevel)
brNodeHsLog = createNewLogger("brNodeHandshakes", "temp/", level=logLevel)
brDHTLog = createNewLogger('kademlia', "temp/", level=logLevel)


# Console thing
from brCore.consolefancy import printstartfancy

# Sockets and network
import brCore.brSockets
from brCore.brSockets.brNodeAgent import brSocketAgent
import brCore.brNodeNet
from brCore.brNodeNet import brNodeNetworkCore
from brCore.brNodeNet.brDHT import brDHT

# Enclave
import brCore.brEnclave
from brCore.brEnclave import notrustvars
from brCore.brEnclave import Enclave

# Web server
import brCore.brWebServer
from brCore.brWebServer import brWebCore, brWebDefaults, brWebElements, webResponder

# Establish the main Enclave for the node
mainEnclave = Enclave("main")
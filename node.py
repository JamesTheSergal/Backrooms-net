import logging
from pathlib import Path
import time
import platform 
import uuid
import hashlib
from core import loggingfactory
from core import notrustvars as enc
from core import brWebCore
from core import brWebElements
from core import consolefancy


BR_VERSION = "0.0.1-alpha"
RESPONDER_PORT = 80


def publishWebServerStats(localenc:enc.enclave, webServer: brWebCore.brWebServer):
    localenc.updateEntry("brWebCore_errors", webServer.errors)
    localenc.updateEntry("brWebCore_incomingBytes", webServer.handledIncomingBytes)
    localenc.updateEntry("brWebCore_outgoingBytes", webServer.handledOutgoingBytes)
    localenc.updateEntry("brWebCore_requests", webServer.respondedToRequests)
    localenc.updateEntry("brWebCore_connections", len(webServer.connections))

def node():

    # Print our fancy thing
    consolefancy.printstartfancy(BR_VERSION)

    logging.info("Node initilization...")
    
    tempfile = Path(f'temp/000_default.encl')

    if tempfile.is_file():
        localenc = enc.enclave("000_default")
    else:
        localenc = enc.enclave("000_default", True)

    logging.info("Enclave loaded...")

    # Setup our webCore
    webServer = brWebCore.brWebServer(debug=True)
    brWebUI = brWebElements.brWebUIModule()
    webServer.buildRoute(webServer.route.GET_ROUTE, "/", brWebUI.brUIRoot)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/announce", brWebUI.brAnnounce)
    webServer.buildRoute(webServer.route.POST_ROUTE, "/announce/publickey", brWebUI.brAnnouncePost)
    webServer.startServer()

    try:
        while True:
            time.sleep(5)
            # Publish web server stats to enclave
            publishWebServerStats(localenc, webServer)
            

    except KeyboardInterrupt:
        logging.info("Got keyboard inturrupt.")
        webServer.shutdown = True
        logging.info("Saving persistence data...")
        localenc.saveEnclaveFile(overwrite=True)
        webServer.shutdownServer()
        logging.info("Main thread exiting...")
    
    
if __name__ == "__main__":
    node()

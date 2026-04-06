import logging
from pathlib import Path
import time
from brCore import loggingfactory
from brCore import notrustvars as enc
from brCore import mainEnclave, brCoreSettings
from brCore.brWebServer import brWebCore
from brCore import printstartfancy
from brCore import settings
from brCore import brNodeNetworkCore
from brCore import brWebElements
from brCore import BR_VERSION
from brCore import mainDHT


def publishWebServerStats(mainEnclave:enc.enclave, webServer: brWebCore.brWebServer):
    mainEnclave.updateEntry("brWebCore_errors", webServer.errors)
    mainEnclave.updateEntry("brWebCore_incomingBytes", webServer.handledIncomingBytes)
    mainEnclave.updateEntry("brWebCore_outgoingBytes", webServer.handledOutgoingBytes)
    mainEnclave.updateEntry("brWebCore_requests", webServer.respondedToRequests)
    mainEnclave.updateEntry("brWebCore_connections", len(webServer.connections))

def publishNodeServerStats(mainEnclave:enc.enclave, nodeServer: brNodeNetworkCore.brNodeServer):
    mainEnclave.updateEntry("brNodeNetwork_incomingBytes", nodeServer.handledIncomingBytes)
    mainEnclave.updateEntry("brNodeNetwork_outgoingBytes", nodeServer.handledOutgoingBytes)
    mainEnclave.updateEntry("brNodeNetwork_requests", nodeServer.respondedToRequests)

def node():
    logging.info("Node initilization...")

    # Get key values we need for webserver and application
    webservAddress = brCoreSettings.getStrSetting('network', 'bind-address')
    webPort = brCoreSettings.getIntSetting('network', 'webresponder-port')
    brNodePort = brCoreSettings.getIntSetting('network', 'brNode-port')
    friendlyName = brCoreSettings.getStrSetting('network', 'friendly-node-name')
    debug = brCoreSettings.getBoolSetting('logging', 'debug')
  
    # Final info printout of settings
    logging.info(f"Backrooms configured to run a webserver on: {webservAddress}:{webPort}")
    logging.info(f"Node name: {friendlyName}")
    
    #tempfile = Path(f'temp/{enclName}.encl')

    #if tempfile.is_file():
    #    localenc = enc.enclave(enclName)
    #else:
    #    localenc = enc.enclave(enclName, True)

    #logging.info("Enclave loaded...")

    # Setup our webCore
    webServer = brWebCore.brWebServer(bindAddress=webservAddress, httpPort=webPort, debug=debug)
    brWebUI = brWebElements.brWebUIModule(mainEnclave)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/", brWebUI.brUIRoot)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/stats", brWebUI.statsPage)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/pubkey", brWebUI.ourPublicKey)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/requestuuid", brWebUI.clientGetUUID4)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/announce", brWebUI.brAnnounce)
    webServer.buildRoute(webServer.route.POST_ROUTE, "/announce/publickey", brWebUI.brAnnouncePost)
    webServer.startServer()
    time.sleep(5)

    nodeServer = brNodeNetworkCore.brNodeServer(mainEnclave, webservAddress, brNodePort, webPort, debug)
    nodeServer.startServer()

    # Bring up DHT Server as well

    if not webServer.running:
        logging.error("Webserver hasn't opened in the expected time! Exiting main thread...")
        logging.info("Saving persistence data...")
        mainEnclave.saveEnclaveFile(overwrite=True)
        exit()
    
    try:
        mainDHT.setRequest(friendlyName, mainEnclave.returnData("PublicKey").save_pkcs1())
        mainDHT.asyncThread.start()
        while True:
            time.sleep(5)
            # Publish web server stats to enclave
            publishWebServerStats(mainEnclave, webServer)
            publishNodeServerStats(mainEnclave, nodeServer)
            
            
    except KeyboardInterrupt:
        logging.info("Got keyboard inturrupt.")
        mainDHT.shutdownServer()
        nodeServer.shutdownServer()
        webServer.shutdownServer()
        logging.info("Saving persistence data...")
        mainEnclave.saveEnclaveFile(overwrite=True)
        logging.info("Main thread exiting...")
    
    
if __name__ == "__main__":
    node()

import logging
import subprocess
import os
from pathlib import Path
import time
import platform 

# Check Python Version
current_version = platform.python_version_tuple()
if current_version[0] == '3' and int(current_version[1]) <= 10:
    logging.critical("Python 3.11 or greater is required to run this application.")
    exit()

# For the off chance
if current_version[0] != '3':
    logging.critical("Python 3.11 or greater is required to run this application.")
    exit()
    
def autoVenv():
    venvcreated = False
    
    if os.path.exists('venv'):
        print("Found existing venv...")
    else:
        try:
            print("Creating venv...")
            subprocess.run(['python3', '-m', 'venv', 'venv'], check=True)
            print("Created virtual eviroment...")
            venvcreated = True
        except Exception as e:
            print(f"Failed to create virtual enviroment! You may need to create one yourself! Error: {e}")
            exit()
        
    # Add script for Windows later
    activate_script = "bash venv/bin/activate"
    try:
        print("Activating venv...")
        subprocess.run(activate_script, shell=True, check=True)
        print("venv is active.")
        
    except Exception as e:
        print(f"Failed to activate venv! Error: {e}")
        exit()
    
    if venvcreated:
        print("Running pip to install required packages.")
        try:
            subprocess.run(['venv/bin/pip', 'install', '-r', 'requirements.txt'])
        except Exception as e:
            print(f"pip process failed while installing required packages! Error: {e}")
            exit()
    
    print("Finished setup.")
    
    if venvcreated:
        print("Setup was completed, please restart the program.")
        exit()
    
autoVenv()

from core import BR_VERSION
from core.Logging import loggingfactory
from core.brSecurity import notrustvars as enc
from core.brWebServer import brWebCore
from core.brNetwork import brNodeNetworkCore
from core.brWebServer import brWebElements
from core.brTerminal import consolefancy
from core.PLV import settings



def publishWebServerStats(localenc:enc.enclave, webServer: brWebCore.brWebServer):
    localenc.updateEntry("brWebCore_errors", webServer.errors)
    localenc.updateEntry("brWebCore_incomingBytes", webServer.handledIncomingBytes)
    localenc.updateEntry("brWebCore_outgoingBytes", webServer.handledOutgoingBytes)
    localenc.updateEntry("brWebCore_requests", webServer.respondedToRequests)
    localenc.updateEntry("brWebCore_connections", len(webServer.connections))

def publishNodeServerStats(localenc:enc.enclave, nodeServer: brNodeNetworkCore.brNodeServer):
    localenc.updateEntry("brNodeNetwork_incomingBytes", nodeServer.handledIncomingBytes)
    localenc.updateEntry("brNodeNetwork_outgoingBytes", nodeServer.handledOutgoingBytes)
    localenc.updateEntry("brNodeNetwork_requests", nodeServer.respondedToRequests)
    

        

def node():

    # Print our fancy thing
    consolefancy.printstartfancy(BR_VERSION)
    loggingfactory.setDefault()
    logging.info("Node initilization...")

    # Load our settings
    nodeSettings = settings.brSettings()

    if not nodeSettings.settingsExisted:
        logging.warning("Settings did not exist on startup. 'BR.conf' has been created. Please check the values and restart.")
        exit()
    else:
        pass

    # Get key values we need for webserver and application
    webservAddress = nodeSettings.getStrSetting('network', 'bind-address')
    webPort = nodeSettings.getIntSetting('network', 'webresponder-port')
    brNodePort = nodeSettings.getIntSetting('network', 'brNode-port')
    friendlyName = nodeSettings.getStrSetting('network', 'friendly-node-name')
    debug = nodeSettings.getBoolSetting('security', 'debug')
    enclName = nodeSettings.getStrSetting('security', 'enclave-name')
    anonlog = nodeSettings.getStrSetting('security', 'anon-logging')

    # Run several tests on settings

    if debug:
        logging.warning("Debug is set to TRUE! (ONLY DO THIS IF YOU KNOW WHAT YOU ARE DOING!!!)")
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if debug == True and anonlog == True:
        logging.critical(
            "\n---- WARNING ----\n"
            "Using DEBUG mode and using the anonymous logging mode at the same time can log data that\n"
            "could be used to identify your machine! Please reconsider! (Thanks for the logs tho <3)\n"
            "---- WARNING ----\n"
        )
        time.sleep(8)
    
    # Final info printout of settings
    logging.info(f"Backrooms configured to run a webserver on: {webservAddress}:{webPort}")
    logging.info(f"Node name: {friendlyName}")
    
    tempfile = Path(f'temp/{enclName}.encl')

    if tempfile.is_file():
        localenc = enc.enclave(enclName)
    else:
        localenc = enc.enclave(enclName, True)

    logging.info("Enclave loaded...")

    # Setup our webCore
    webServer = brWebCore.brWebServer(bindAddress=webservAddress, httpPort=webPort, debug=debug)
    brWebUI = brWebElements.brWebUIModule(localenc)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/", brWebUI.brUIRoot)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/stats", brWebUI.statsPage)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/pubkey", brWebUI.ourPublicKey)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/requestuuid", brWebUI.clientGetUUID4)
    webServer.buildRoute(webServer.route.GET_ROUTE, "/announce", brWebUI.brAnnounce)
    webServer.buildRoute(webServer.route.POST_ROUTE, "/announce/publickey", brWebUI.brAnnouncePost)
    webServer.startServer()
    time.sleep(5)

    nodeServer = brNodeNetworkCore.brNodeServer(localenc, webservAddress, brNodePort, webPort, debug)
    nodeServer.startServer()

    if not webServer.running:
        logging.error("Webserver hasn't opened in the expected time! Exiting main thread...")
        logging.info("Saving persistence data...")
        localenc.saveEnclaveFile(overwrite=True)
        exit()
    


    try:
        while True:
            time.sleep(5)
            # Publish web server stats to enclave
            publishWebServerStats(localenc, webServer)
            publishNodeServerStats(localenc, nodeServer)
            

    except KeyboardInterrupt:
        logging.info("Got keyboard inturrupt.")
        webServer.shutdownServer()
        nodeServer.shutdownServer()
        publishWebServerStats(localenc, webServer)
        logging.info("Saving persistence data...")
        localenc.saveEnclaveFile(overwrite=True)
        logging.info("Main thread exiting...")
    
    
if __name__ == "__main__":
    node()

import logging
import os
from pathlib import Path
import time
from brCore import loggingfactory
from brCore import brWebCore, brNodeNetworkCore, brWebElements, brDHT
from brCore import brCoreSettings
from brCore import logLevel
from brCore import BR_VERSION
from brCore import Enclave, EnclaveStorage
from names_generator import generate_name


def publishWebServerStats(mainEnclave:Enclave, webServer: brWebCore.brWebServer):
    mainEnclave.updateEntry("brWebCore_errors", webServer.errors)
    mainEnclave.updateEntry("brWebCore_incomingBytes", webServer.handledIncomingBytes)
    mainEnclave.updateEntry("brWebCore_outgoingBytes", webServer.handledOutgoingBytes)
    mainEnclave.updateEntry("brWebCore_requests", webServer.respondedToRequests)
    mainEnclave.updateEntry("brWebCore_connections", len(webServer.connections))

def publishNodeServerStats(mainEnclave:Enclave, nodeServer: brNodeNetworkCore.brNodeServer):
    mainEnclave.updateEntry("brNodeNetwork_incomingBytes", nodeServer.socketControl.handledIncomingBytes)
    mainEnclave.updateEntry("brNodeNetwork_outgoingBytes", nodeServer.socketControl.handledOutgoingBytes)
    mainEnclave.updateEntry("brNodeNetwork_requests", nodeServer.socketControl.respondedToRequests)

class brNode:
    
    def __init__(self, bindip:str=None, webport:int=None, brNodePort:int=None, runmulti:bool=False):
        
        self.temppath = "temp/"
        
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
        
        if runmulti:
            self.friendlyName = generate_name(style="underscore")
            self.temppath = self.temppath+self.friendlyName+"/"
            os.mkdir(self.temppath)
            loggingfactory.setDefault(self.temppath)
        else:
            self.friendlyName = brCoreSettings.getStrSetting('network', 'friendly-node-name')
            loggingfactory.setDefault(self.temppath)
        
        
        # Check for defaults
        if bindip is None:
            self.webservAddress = brCoreSettings.getStrSetting('network', 'bind-address')
        if webport is None:
            self.webPort = brCoreSettings.getIntSetting('network', 'webresponder-port')
        if brNodePort is None:
            self.brNodePort = brCoreSettings.getIntSetting('network', 'brNode-port')
    
        # Run several tests on settings
        self.debug = brCoreSettings.getBoolSetting('logging', 'debug')
        anonlog = brCoreSettings.getStrSetting('logging', 'anon-logging')

        if self.debug:
            logging.warning("Debug is set to TRUE! (ONLY DO THIS IF YOU KNOW WHAT YOU ARE DOING!!!)")
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        if self.debug == True and anonlog == True:
            logging.critical(
                "\n---- WARNING ----\n"
                "Using DEBUG mode and using the anonymous logging mode at the same time can log data that\n"
                "could be used to identify your machine! Please reconsider! (Thanks for the logs tho <3)\n"
                "---- WARNING ----\n"
            )
            time.sleep(8)
        
        self.testing = brCoreSettings.getBoolSetting("production", "testing")

    def startEnclave(self, enclaveName:str="000_default"):
        if enclaveName is None:
            self.mainEnclave = Enclave(enclaveName, pathtouse=self.temppath)
        else:
            self.mainEnclave = Enclave(brCoreSettings.getStrSetting('enclave','enclave-name'), pathtouse=self.temppath)
        self.enclaveDHTStorage = EnclaveStorage(self.mainEnclave)
        
    def startWebServer(self, bindAddress:str="0.0.0.0", port:int=11000, debug:bool=False):
        self.webServer = brWebCore.brWebServer(bindAddress=bindAddress, httpPort=port, debug=debug)
        self.brWebUI = brWebElements.brWebUIModule(self.mainEnclave)
        self.webServer.buildRoute(brWebCore.brWebServer.route.GET_ROUTE, "/", self.brWebUI.brUIRoot)
        self.webServer.buildRoute(brWebCore.brWebServer.route.GET_ROUTE, "/stats", self.brWebUI.statsPage)
        self.webServer.buildRoute(brWebCore.brWebServer.route.GET_ROUTE, "/pubkey", self.brWebUI.ourPublicKey)
        self.webServer.buildRoute(brWebCore.brWebServer.route.GET_ROUTE, "/requestuuid", self.brWebUI.clientGetUUID4)
        self.webServer.buildRoute(brWebCore.brWebServer.route.GET_ROUTE, "/announce", self.brWebUI.brAnnounce)
        self.webServer.buildRoute(brWebCore.brWebServer.route.POST_ROUTE, "/announce/publickey", self.brWebUI.brAnnouncePost)
        self.webServer.buildRoute(brWebCore.brWebServer.route.GET_ROUTE, "/insecureannounce", self.brWebUI.insecureAnnounce)
        self.webServer.buildRoute(brWebCore.brWebServer.route.POST_ROUTE, "/insecureannounce", self.brWebUI.insecureAnnouncePost)
        self.webServer.startServer()
        logging.info(f"Backrooms configured to run a webserver on: {bindAddress}:{port}")
        time.sleep(5)
        if not self.webServer.running:
            logging.error("Webserver hasn't opened in the expected time! Exiting main thread...")
            logging.info("Saving persistence data...")
            self.mainEnclave.saveEnclaveFile(overwrite=True)
            exit()
    
    def startDHT(self, port:int=None, dhtid=None): 
        if port is None:
            dhtport = brCoreSettings.getIntSetting('network', 'brDHT-port')
        else:
            dhtport = port
        
        if self.mainEnclave.isEncKey("DHTid"):
            self.mainDHT = brDHT(self.enclaveDHTStorage, dhtport, self.mainEnclave.returnData("DHTid"))
        else:
            self.mainDHT = brDHT(self.enclaveDHTStorage, dhtport)
            self.mainEnclave.insertData("DHTid", self.mainDHT.dhtServer.node.id)
            logging.info("Saved newly generated DHT ID to the Enclave.")
            
        if self.mainEnclave.isEncKey("dhtbootstrap"):
            logging.info("Found bootstrap entry in Enclave")
            self.mainDHT.setBootstrapList(self.mainEnclave.returnData("dhtbootstrap"))
        self.mainDHT.asyncThread.start()
        
    def startNodeServer(self, brNodeBindAddress:str="0.0.0.0", brNodePort:int=13337, debug:bool=False):
        self.nodeServer = brNodeNetworkCore.brNodeServer(self.mainEnclave, self.mainDHT, brNodeBindAddress, brNodePort, self.webServer.httpPort, debug)
        self.nodeServer.startServer()
        logging.info(f"Node name: {self.friendlyName}")
        
    def serverLoop(self):
        try:
            while True:
                time.sleep(5)
                publishWebServerStats(self.mainEnclave, self.webServer)
                publishNodeServerStats(self.mainEnclave, self.nodeServer)
        except KeyboardInterrupt:
            logging.info("Got keyboard inturrupt.")
            futureBootStrap = self.mainDHT.shutdownServer()
            self.mainEnclave.updateEntry("dhtbootstrap", futureBootStrap, create=True)
            self.nodeServer.shutdownServer()
            self.webServer.shutdownServer()
            logging.info("Saving persistence data...")
            self.mainEnclave.saveEnclaveFile(overwrite=True)
            logging.info("Main thread exiting...")



    
    
    
        
            
            
    
    
    


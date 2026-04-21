import logging
import os
from pathlib import Path
import time
from brCore import loggingfactory
from brCore import brWebCore, brController, brWebElements, brDHT
from brCore.brWebServer import setup_webserver
from brCore import brCoreSettings
from brCore import logLevel
from brCore import BR_VERSION
from brCore import Enclave, EnclaveStorage
from names_generator import generate_name
from brCore.stats import statHandler




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
        self.brWebUI = brWebElements.brWebUIModule(self.mainEnclave, self.nodeServer, self.webServer)
        setup_webserver(self.webServer, self.brWebUI)
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
        
    def startNodeServer(self, brNodeBindAddress:str="0.0.0.0"):
        self.nodeServer = brController.brNodeServer(self.mainEnclave, self.mainDHT, self.webPort)
        self.nodeServer.startServer()
        logging.info(f"Node name: {self.friendlyName}")
        
    def serverLoop(self):
        stats = statHandler(self.mainEnclave, self.webServer, self.nodeServer)
        try:
            while True:
                stats.runUpdates()
                time.sleep(5)
  
        except KeyboardInterrupt:
            logging.info("Got keyboard inturrupt.")
            futureBootStrap = self.mainDHT.shutdownServer()
            self.mainEnclave.updateEntry("dhtbootstrap", futureBootStrap, create=True)
            self.nodeServer.shutdownServer()
            self.webServer.shutdownServer()
            logging.info("Saving persistence data...")
            self.mainEnclave.saveEnclaveFile(overwrite=True)
            logging.info("Main thread exiting...")



    
    
    
        
            
            
    
    
    


from .brWebServer.brWebCore import brWebServer
from .brEnclave.Enclave import Enclave
from .brNodeNet.brNodeNetworkCore import brNodeServer
import time

class statHandler:
    
    def __init__(self, mainEnclave:Enclave, webServer:brWebServer, nodeServer:brNodeServer):
        self.enc = mainEnclave
        self.webServer = webServer
        self.nodeServer = nodeServer
        
    def runUpdates(self):
        time.sleep(1)
        self.publishWebServerStats()
        time.sleep(1)
        self.publishNodeServerStats()
    
    def publishWebServerStats(self):
        self.enc.updateEntry("brWebCore_errors", self.webServer.errors)
        self.enc.updateEntry("brWebCore_incomingBytes", self.webServer.handledIncomingBytes)
        self.enc.updateEntry("brWebCore_outgoingBytes", self.webServer.handledOutgoingBytes)
        self.enc.updateEntry("brWebCore_requests", self.webServer.respondedToRequests)
        self.enc.updateEntry("brWebCore_connections", len(self.webServer.connections))

    def publishNodeServerStats(self):
        self.enc.updateEntry("brNodeNetwork_incomingBytes", self.nodeServer.socketControl.handledIncomingBytes)
        self.enc.updateEntry("brNodeNetwork_outgoingBytes", self.nodeServer.socketControl.handledOutgoingBytes)
        self.enc.updateEntry("brNodeNetwork_requests", self.nodeServer.socketControl.respondedToRequests)
        
    def publishRouteCount(self):
        try:
            routelist = self.enc.returnData("nodeRoutes")
            count = len(routelist)
            self.enc.updateEntry("routeCount", count)
        except Enclave.enclaveValueDoesNotExist:
            pass
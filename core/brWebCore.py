import pprint
import socket
import logging
from pathlib import Path
import threading
import uuid
import os
from chardet.universaldetector import UniversalDetector
import mimetypes
from core import loggingfactory

logger = loggingfactory.createNewLogger("brWebCore")


class brWebServer:

    class brWebServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    class brEncodingConfidenceLow(brWebServerException):
        """Exception raised when we can't deturmine the encoding of a packet"""

        def __init__(self, reason) -> None:
            self.message = "Low confidence in detected charset"
            self.reason = reason
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}: {self.reason}"

    class brRouteInvalid(brWebServerException):
        """Exception raised when a route is invalid"""

        def __init__(self, reason) -> None:
            self.message = "Web Server route is invalid"
            self.reason = reason
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}: {self.reason}"
    
    class brDuplicateRoute(brWebServerException):
        """Exception raised when there is a duplicate route"""

        def __init__(self, virtualPath) -> None:
            self.message = "Web Server route is invalid"
            self.virtualpath = virtualPath
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}: {self.virtualpath}"
        
    class requestResponse:

        # Constants for replies
        WEB_OK = "HTTP/1.1 200 OK"
        BAD_REQUEST = "HTTP/1.1 400 Bad Request"
        NOT_FOUND = "HTTP/1.1 404 Not Found"
        TEAPOT = "HTTP/1.1 418 I'm a teapot"
        SERVER_ERROR = "HTTP/1.1 500 Internal Server Error"
        #
        #
        # Constants for connection states
        KEEP_ALIVE = "keep-alive"
        CLOSE_CONN = "close"
        #
        #
        # Fake server types
        spoofServerTypes = {
            "default": "Server: Apache/2.4.62-3",
        }
        
        def __init__(self, data:bytes, serverStatus: str, connectionType: str, serverType:str=spoofServerTypes["default"]) -> None:
            self.serverStatus = serverStatus
            self.contentLength = 0
            self.serverType = serverType
            self.contentType = ""
            self.connectionType = "Connection: " + connectionType
            self.databody = data
            
        def setBodySize(self):
            self.contentLength = len(self.databody)
            return self
        
        def setContentType(self, path):
            mime_type, encoding = mimetypes.guess_type(path)
            if mime_type is None:
                mime_type = "text/html"
            self.contentType = "Content-Type: " + mime_type
            return self
        
        def buildPacket(self):
            packet = b''
            packet += bytes(self.serverStatus + "\r\n", 'utf-8')
            packet += bytes(self.serverType + "\r\n", 'utf-8')
            packet += bytes("Content-Length: " + str(self.contentLength) + "\r\n", 'utf-8')
            packet += bytes(self.connectionType  + "\r\n", 'utf-8')
            packet += bytes(self.contentType + "\r\n", 'utf-8')
            packet += bytes("\r\n", 'utf-8')

            packet += self.databody
            return packet

    class packetParser:

        def __init__(self, connection: socket.socket, rawpacket: bytes) -> None:

            self.refConnection = connection
            
            # Bytes here
            packetBytes = rawpacket

            # Final Protocol seperator will be chosen later
            bytepattern = None
            bpLength = None

            # Char sets we support
            compatibleBytePatterns = {
                "ascii": bytes("\r\n", "ascii"),
                "utf-8": bytes("\r\n", "utf-8"),
            }
            bytePatternLengths = {
                "ascii": len(compatibleBytePatterns["ascii"]),
                "utf-8": len(compatibleBytePatterns["utf-8"])
            }

            # Flag to say we found a compatibleBytePattern
            compatibleBytePattern = False

            # Establish variables we will need
            self.isRequest = False
            self.requestType = ""
            self.requestPath = ""
            self.httpVersion = ""

            self.emptyPacket = False
            self.packetSize = len(packetBytes)
            self.totalSize = self.packetSize # Will be used as total measure including if we have post data
            self.bodyData = b''
            self.headers = {}

            logger.debug(f'Packet is {self.packetSize} Bytes')

            # Check to see if we have an empty packet

            if len(packetBytes) != 0:

                # Attempt to detect our CharSet
                detector = UniversalDetector()
                for bytePart in packetBytes:
                    detector.feed(bytePart)
                    if detector.done: break
                detector.close()

                # See what we guessed the encoding is
                encoding = detector.result["encoding"]
                confidence = detector.result["confidence"]

                if confidence < 0.85:
                    raise brWebServer.brEncodingConfidenceLow(pprint.pformat(detector.result))
                else:
                    self.encoding = encoding
                    if self.encoding in compatibleBytePatterns.keys():
                        compatibleBytePattern = True
                        bytepattern = compatibleBytePatterns[self.encoding]
                        bpLength = bytePatternLengths[self.encoding]

                # Debug really quick
                logger.debug(f'Encoding "{self.encoding}" at {confidence} confidence.')
                
                if compatibleBytePattern:

                    bodyDataIndex = packetBytes.index(b'\r\n\r\n')
                    
                    self.bodyData = packetBytes[bodyDataIndex:len(packetBytes)]
                    self.bodyDataLength = len(self.bodyData)
                    headerData = packetBytes[0:bodyDataIndex]

                    headerSplit = headerData.split(bytepattern)
                    #logger.debug(f'{pprint.pformat(headerSplit)}')
                    logger.debug(f'Found {len(headerSplit)} possible header entries')

                    for rawEntry in headerSplit:
                        headerEntry = rawEntry.decode(self.encoding)
                        if headerEntry == '':
                            break
                        header = headerEntry.split(": ")
                        if len(header) > 1:
                            self.headers[header[0]] = header[1]
                    
                    requestHeader = headerSplit[0]
                    requestHeaderSplit = requestHeader.decode(self.encoding).split(" ")

                    if len(requestHeaderSplit) < 3:
                        logger.warning(f'Bad request header: {requestHeader} -> {pprint.pformat(headerData)}')
                    else:
                        self.isRequest = True
                        self.requestType = requestHeaderSplit[0]
                        self.requestPath = requestHeaderSplit[1]
                        self.httpVersion = requestHeaderSplit[2]
                    
                else:
                    logger.warning("Incompatable encoding. Cannot continue.")
                    self.bodyData = packetBytes

            
            else:
                # We had an empty packet, outside logic will handle this.
                self.emptyPacket = True
                logger.debug("Got empty packet")

        def isGet(self):
            if self.requestType == "GET":
                return True
            else:
                return False
        
        def isHead(self):
            if self.requestType == "HEAD":
                return True
            else:
                return False
            
        def isPost(self):
            if self.requestType == "POST":
                return True
            else:
                return False
        
        def isOptions(self):
            if self.requestType == "OPTIONS":
                return True
            else:
                return False
            
        def getRequestedHost(self):
            if "Host" in self.headers.keys():
                return self.headers["Host"]
            else:
                return None
        
        def getRequestedConnectionType(self):
            if "Connection" in self.headers.keys():
                return self.headers["Connection"]
            else:
                return None
        
        def getUserAgent(self):
            if "User-Agent" in self.headers.keys():
                return self.headers["User-Agent"]
            else:
                return None
            
        def getReferer(self):
            if "Referer" in self.headers.keys():
                return self.headers["Referer"]
            else:
                return None

        def getContentLength(self):
            if "Content-Length" in self.headers.keys():
                content_length = int(self.headers["Content-Length"])
                return content_length
            else:
                return None
            
        def getRemainderOfPostData(self):
            currentBytes = self.bodyData
            self.refConnection.setblocking(False)

            if self.isPost() and self.getContentLength():
                expectedLength = self.getContentLength()+4 # Add four because our actual data is not inclusive of dataBody bytes
                while self.bodyDataLength != expectedLength:
                    try:
                        msg = self.refConnection.recv(1024)
                        if not msg:
                            break
                    except BlockingIOError:
                        logger.warning(f'Did not receive last message when receiving post data. Expected Bytes: {expectedLength} Got: {self.bodyDataLength}')
                        break
                        
                    currentBytes += msg
                    self.bodyDataLength += len(msg)
                
                self.bodyData = currentBytes
                self.refConnection.setblocking(True)
                self.totalSize = self.packetSize + len(self.bodyData)
                logger.debug("Post receive finished.")
                
    class route:

        POST_ROUTE = "POST"
        GET_ROUTE = "GET"
        HEAD_ROUTE = "HEAD"
        OPTIONS_ROUTE = "OPTIONS"

        class getRoute():

            def __init__(self, virtualPath: str, physicalPath:str="", virtualResponder:object|None=None) -> None:
                self.virtualPath = virtualPath
                self.physicalPath = physicalPath
                self.virtualResponder = virtualResponder
                self.context: brWebServer.packetParser = None

                if Path(self.physicalPath).is_dir() and self.physicalPath != "":
                    raise brWebServer.brRouteInvalid(f'"{self.physicalPath}" cannot be a directory!')
                
                if physicalPath != "" and virtualResponder is not None:
                    raise brWebServer.brRouteInvalid(f'We cannot serve both a physical path and a virtual path!')
                
                if not virtualPath.startswith("/"):
                    raise brWebServer.brRouteInvalid(f'Invalid virtual path! {self.virtualPath} <- does not start at root!')
            
            def addContext(self, context: object):
                self.context = context
                return self

            def respond(self):
                if self.virtualResponder is not None:
                    return self.virtualResponder(self.context)
                else:
                    pass
                
        class postRoute():

            def __init__(self, virtualPath: str, virtualResponder:object) -> None:
                self.virtualPath = virtualPath
                self.virtualResponder = virtualResponder
                self.context: brWebServer.packetParser = None
                
                if not virtualPath.startswith("/"):
                    raise brWebServer.brRouteInvalid(f'Invalid virtual path! {self.virtualPath} <- does not start at root!')
            
            def addContext(self, context: object):
                self.context = context
                return self

            def respond(self):
                return self.virtualResponder(self.context)

    def __init__(self, bindAddress:str="127.0.0.1", httpPort:int=80, securePort:int=443, webRoot=None, debug=False) -> None:

        # If debug is set, we will log at the lowest level + debug timings
        self.debug = debug
        # ------------

        # Network setup
        self.bindAddress = bindAddress
        self.httpPort = httpPort
        self.securePort = securePort
        # ------------

        # If we do want to serve actual files, we need a web Root
        self.webRoot = webRoot
        # ------------

        # Main dictonaries that will make up our web structure
        self.getRoutes:dict[str][object] = {}
        self.postRoutes:dict[str][object] = {}
        self.optionRoutes:dict[str][object] = {}
        self.headRoutes:dict[str][object] = {}
        # ------------

        # Connection Pool
        self.connections = []
        # ------------

        # Threads
        self.mainThread:threading.Thread = None
        self.webThreads:list[threading.Thread] = []
        self.thrLock = threading.Lock()
        # ------------

        # Default 404 route
        self.fourOhFour = None
        # ------------

        # server state flags
        self.running = False
        self.shutdown = False
        # ------------

        # Stats
        self.statsLock = threading.Lock()
        self.handledIncomingBytes = 0
        self.handledOutgoingBytes = 0
        self.respondedToRequests = 0
        self.errors = 0
        # ------------

    def buildRoute(self, routeType:str, virtualPath:str, virtualResponder:object|None=None, physicalPath:str=""):

        if routeType == brWebServer.route.GET_ROUTE:
            newRoute = brWebServer.route.getRoute(
                        virtualPath=virtualPath, 
                        physicalPath=physicalPath, 
                        virtualResponder=virtualResponder
            )
            if virtualPath not in self.getRoutes.keys():
                self.getRoutes[virtualPath] = newRoute
            else:
                raise brWebServer.brDuplicateRoute(virtualPath + " " + routeType)
            
        elif routeType == brWebServer.route.POST_ROUTE:
            newRoute = brWebServer.route.postRoute(
                        virtualPath=virtualPath,  
                        virtualResponder=virtualResponder
            )
            if virtualPath not in self.postRoutes.keys():
                self.postRoutes[virtualPath] = newRoute
            else:
                raise brWebServer.brDuplicateRoute(virtualPath + " " + routeType)
            
        if routeType == "404":
            newRoute = brWebServer.route.getRoute(
                virtualPath="/404",
                virtualResponder=virtualResponder
            )
            if virtualPath not in self.getRoutes.keys():
                self.getRoutes[virtualPath] = newRoute
            else:
                raise brWebServer.brDuplicateRoute(virtualPath + " " + routeType)

    def startServer(self):
        logger.info("Started server.")
        if not self.running:
            self.mainThread = threading.Thread(name="brWebCoreMain", target=self.__mainLoop__, args=[])
            self.mainThread.start()

    def shutdownServer(self):
        self.shutdown = True
        logger.info("Sent shutdown signal - Main Thread is now waiting...")
        self.mainThread.join()

    def __mainLoop__(self):
        self.running = True

        # Check a few defaults
        if self.fourOhFour is None:

            # Imports for various defaults
            # We import here to avoid a circular import error
            from core import brWebDefaults  

            logger.warning("No custom 404 route set - using default...")
            self.buildRoute("404", "/404", brWebDefaults.defaultFourOhFour)

        # Announce our number of routes
        logger.info(f'Server starting with {len(self.getRoutes.keys())} GET routes and {len(self.postRoutes.keys())} POST routes.')

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindAddress, self.httpPort))
            soc.listen(4)
            soc.settimeout(1.0)
        except Exception as e:
            logger.exception("Error occured when creating socket!", exc_info=True)
            self.running = False
            return
        
        while self.shutdown is False:
            try:
                connection, address = soc.accept()
                spawnThread = threading.Thread(target=self.__connectionThread__, args=[connection, address])
                self.webThreads.append(spawnThread)
                spawnThread.start()
            except socket.timeout:
                # This is normal. It gives us time to loop and check threads.

                deadThreads = []
                for thr in self.webThreads:
                    if not thr.is_alive():
                        deadThreads.append(thr)

                for thr in deadThreads:
                    self.webThreads.remove(thr)
        
        # Broke out of loop. We must be shutting down.
        logger.info("Main loop received shutdown, refusing new connections.")
        logger.info(f'Waiting for {len(self.webThreads)} threads to shutdown...')

        while len(self.webThreads) > 0:
            logger.info(f'Waiting for {len(self.webThreads)} threads to shutdown...')
            for thr in self.webThreads:
                thr.join(timeout=5.0)
                if not thr.is_alive():
                    logger.info(f'Thread {thr.native_id} shutdown...')
                    self.webThreads.remove(thr)
                
        logger.info("All threads closed. Exiting main loop.")

    def __debugToFile__(data: bytes, id, count):
        tempdir = Path(f'temp/{id}')
        if not tempdir.is_dir():
            os.mkdir(f'temp/{id}')
        with open(f'temp/{id}/{str(count)}.packet', 'ab') as df:
            df.write(data)
        logger.debug(f'Wrote packet to: temp/{id}/{str(count)}.packet')

    def __router__(self, parseResult: packetParser):
        if parseResult.isRequest:
            reqPath = parseResult.requestPath
            if parseResult.requestType == brWebServer.route.GET_ROUTE:
                if reqPath in self.getRoutes.keys():
                    routeRunner: brWebServer.route.getRoute = self.getRoutes[reqPath]
                    reply: brWebServer.requestResponse = routeRunner.addContext(parseResult).respond()
                    return reply.setContentType(parseResult.requestPath)
                else:
                    #Uh-oh! 404!
                    routeRunner: brWebServer.route.getRoute = self.getRoutes["/404"]
                    reply: brWebServer.requestResponse = routeRunner.addContext(parseResult).respond()
                    return reply.setContentType(parseResult.requestPath)
            elif parseResult.requestType == brWebServer.route.POST_ROUTE:
                parseResult.getRemainderOfPostData()
                if reqPath in self.postRoutes.keys():
                    routeRunner: brWebServer.route.getRoute = self.postRoutes[reqPath]
                    reply: brWebServer.requestResponse = routeRunner.addContext(parseResult).respond()
                    return reply.setContentType(parseResult.requestPath)
                else:
                    #Uh-oh! 404!
                    routeRunner: brWebServer.route.getRoute = self.getRoutes["/404"]
                    reply: brWebServer.requestResponse = routeRunner.addContext(parseResult).respond()
                    return reply.setContentType(parseResult.requestPath)
            elif parseResult.requestType == brWebServer.route.HEAD_ROUTE:
                pass
            elif parseResult.requestType == brWebServer.route.OPTIONS_ROUTE:
                pass
            else:
                logger.warning(f'Unrecognized request method: {parseResult.requestPath}')

    def __handleServerError__(self):

        # Imports for various defaults
        from core import brWebDefaults

        reply: brWebServer.requestResponse = brWebDefaults.defaultServerError()
        packet = reply.setContentType("500").setBodySize().buildPacket()
        return packet

    def __connectionThread__(self, connection: socket.socket, address):

        netAddress = address[0]
        netPort = address[1]
        debugCount = 0
        debugID = uuid.uuid4()
        ourHandledBytes = 0
        ourOutgoingBytes = 0
        ourHandledRequests = 0
        ourErrors = 0

        # Make sure we do a Thread Safe lock! 
        with self.thrLock:
            self.connections.append(connection)
        
        logger.info(f'Accepted connection from {netAddress}:{netPort}')

        while not self.shutdown:

            # Attempt to receive data and handle issues
            try:
                rawpacket = connection.recv(1024)
            except:
                break
            # Finished handling exceptions

            if self.debug:
                brWebServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount += 1

            # Processing here --

            # Parse the packet to get key details
            try:
                parsingResult = brWebServer.packetParser(connection, rawpacket)
            except Exception as e:
                logger.exception("Critical error when processing client packet!", exc_info=True)
                brWebServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount+= 1
                ourErrors+= 1
                packet = self.__handleServerError__()

            # See if we need to hand to router
            if parsingResult.emptyPacket:
                logger.debug("Received an empty packet. Client disconnect.")
                connection.close()
                break
            
            #---# El_Casi #---# - Backrooms-net didn't respect client wishes
            if parsingResult.getRequestedConnectionType() == brWebServer.requestResponse.CLOSE_CONN:
                logger.debug("Client requested connection to close. Closing connection.")
                connection.close()
                break
            #---

            # Hand off to router to get the full reply
            try:
                reply = self.__router__(parsingResult)

                # After we go through the router, we should be able to get an accurate measure of bytes handled
                ourHandledBytes += parsingResult.totalSize

                packet = reply.setBodySize().buildPacket()
            except Exception as e:
                logger.exception("Critical error when processing request!", exc_info=True)
                brWebServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount+= 1
                ourErrors+= 1
                packet = self.__handleServerError__()


            # End of processing

            brWebServer.__debugToFile__(packet, debugID, debugCount)
            debugCount += 1
            connection.sendall(packet)
            ourHandledRequests+= 1
            ourOutgoingBytes+= len(packet)
            

        
        # We broke out, find out why!
        if self.shutdown:
            logger.info("Thread got shutdown signal.")
        else:
            if self.debug:
                logger.info(f'Thread shutting down - Handled {debugCount} packets.')
            else:
                logger.info(f'Thread shutting down.')
        
        # Publish our stats really quick
        with self.statsLock:
            self.handledIncomingBytes += ourHandledBytes
            self.handledOutgoingBytes += ourOutgoingBytes
            self.respondedToRequests += ourHandledRequests
            self.errors += ourErrors

        with self.thrLock:
            self.connections.remove(connection)



class brWebPage:

    def __init__(self) -> None:
        self.bodyData = b''
        self.responseStatus: str = ""

    def addContent(self, content: str|bytes):
        if isinstance(content, bytes):
            self.bodyData += content
        else:
            self.bodyData += content.encode('utf-8')

    def setOK(self):
        self.responseStatus = brWebServer.requestResponse.WEB_OK
        pass

    def setNotFound(self):
        self.responseStatus = brWebServer.requestResponse.NOT_FOUND
        pass

    def setError(self):
        self.responseStatus = brWebServer.requestResponse.SERVER_ERROR
        pass

    def setBadRequest(self):
        self.responseStatus = brWebServer.requestResponse.BAD_REQUEST
        pass

    def buildResponse(self, context: brWebServer.packetParser):

        reply = brWebServer.requestResponse(
            data=self.bodyData,
            serverStatus=self.responseStatus,
            connectionType=context.getRequestedConnectionType()
        )

        # Make sure to clear as data here is persistent
        self.bodyData = b''
        self.responseStatus = ""

        return reply
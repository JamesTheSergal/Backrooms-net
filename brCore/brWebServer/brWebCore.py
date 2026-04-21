import pprint
import socket
import logging
from pathlib import Path
import threading
import uuid
import os
from chardet.universaldetector import UniversalDetector
import mimetypes
from . import brWebLog
from ..upnphelper import configureUPNP, removeUPNP

logger = brWebLog


class brWebServer:
    """Core HTTP web server implementation for the Backrooms-net project.

    Provides functionality to bind to a port, handle HTTP requests/responses,
    manage custom routes for GET/POST/etc, serve static files from a web root,
    and support UPNP port forwarding. Uses threading for concurrent connections.
    """

    class brWebServerException(Exception):
        """Base exception class for brWebServer related errors."""

        pass

    class brEncodingConfidenceLow(brWebServerException):
        """Exception raised when character encoding detection confidence is too low.

        Raised by packetParser when chardet cannot confidently determine the
        encoding of an incoming HTTP request.
        """

        def __init__(self, reason) -> None:
            """Initialize the encoding confidence exception.

            Args:
                reason: The detection result details from UniversalDetector.
            """
            self.message = "Low confidence in detected charset"
            self.reason = reason
            super().__init__(self.message)

        def __str__(self):
            """Return string representation of the exception."""
            return f"{self.message}: {self.reason}"

    class brRouteInvalid(brWebServerException):
        """Exception raised when a route configuration is invalid.

        This can occur for issues like using a directory as a file path,
        conflicting physical/virtual paths, or paths not starting with '/'.
        """

        def __init__(self, reason) -> None:
            """Initialize the route invalid exception.

            Args:
                reason: Description of why the route is invalid.
            """
            self.message = "Web Server route is invalid"
            self.reason = reason
            super().__init__(self.message)

        def __str__(self):
            """Return string representation of the exception."""
            return f"{self.message}: {self.reason}"
    
    class brDuplicateRoute(brWebServerException):
        """Exception raised when attempting to register a duplicate route."""

        def __init__(self, virtualPath) -> None:
            """Initialize the duplicate route exception.

            Args:
                virtualPath: The path that was duplicated.
            """
            self.message = "Web Server route is invalid"
            self.virtualpath = virtualPath
            super().__init__(self.message)

        def __str__(self):
            """Return string representation of the exception."""
            return f"{self.message}: {self.virtualpath}"
        
    class requestResponse:
        """HTTP response packet builder.

        Constructs properly formatted HTTP/1.1 response packets with headers
        and body. Supports different status codes and connection behaviors.
        Includes server type spoofing capabilities.
        """

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
            """Initialize a new HTTP response.

            Args:
                data: Response body as bytes.
                serverStatus: Full status line (e.g. HTTP/1.1 200 OK).
                connectionType: Connection header value ('keep-alive' or 'close').
                serverType: Server header value for fingerprint spoofing.
            """
            self.serverStatus = serverStatus
            self.contentLength = 0
            self.serverType = serverType
            self.contentType = ""
            self.connectionType = "Connection: " + connectionType
            self.databody = data
            
        def setBodySize(self):
            """Calculate and set the Content-Length header from the body.

            Returns:
                Self for method chaining.
            """
            self.contentLength = len(self.databody)
            return self
        
        def setContentType(self, path):
            """Set the Content-Type header by guessing MIME type from path.

            Uses Python's mimetypes module. Defaults to text/html if unknown.

            Args:
                path: File path or URL path to determine MIME type from.

            Returns:
                Self for method chaining.
            """
            mime_type, encoding = mimetypes.guess_type(path)
            if mime_type is None:
                mime_type = "text/html"
            self.contentType = "Content-Type: " + mime_type
            return self
        
        def buildPacket(self):
            """Assemble the complete HTTP response packet as bytes.

            Includes status line, headers, and body with proper CRLF separators.

            Returns:
                bytes: Complete HTTP response ready to send over socket.
            """
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
        """Parses raw HTTP request bytes into structured data.

        Uses chardet for encoding detection and splits headers/body.
        Supports GET, POST, HEAD, OPTIONS. For POST requests, can fetch
        remaining body data if Content-Length indicates more data is coming.
        """

        def __init__(self, connection: socket.socket, rawpacket: bytes) -> None:
            """Parse a raw HTTP request packet.

            Args:
                connection: The client socket (used for additional POST data).
                rawpacket: Raw bytes received from the client.

            Raises:
                brEncodingConfidenceLow: If encoding detection confidence < 0.85.
            """
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
            """Check if this was a GET request.

            Returns:
                bool: True if requestType is GET.
            """
            if self.requestType == "GET":
                return True
            else:
                return False
        
        def isHead(self):
            """Check if this was a HEAD request.

            Returns:
                bool: True if requestType is HEAD.
            """
            if self.requestType == "HEAD":
                return True
            else:
                return False
            
        def isPost(self):
            """Check if this was a POST request.

            Returns:
                bool: True if requestType is POST.
            """
            if self.requestType == "POST":
                return True
            else:
                return False
        
        def isOptions(self):
            """Check if this was an OPTIONS request.

            Returns:
                bool: True if requestType is OPTIONS.
            """
            if self.requestType == "OPTIONS":
                return True
            else:
                return False
            
        def getRequestedHost(self):
            """Get the Host header value.

            Returns:
                str|None: The requested host or None if not present.
            """
            if "Host" in self.headers.keys():
                return self.headers["Host"]
            else:
                return None
        
        def getRequestedConnectionType(self):
            """Get the Connection header value.

            Returns:
                str|None: The connection type or None if not present.
            """
            if "Connection" in self.headers.keys():
                return self.headers["Connection"]
            else:
                return None
        
        def getUserAgent(self):
            """Get the User-Agent header value.

            Returns:
                str|None: The user agent string or None.
            """
            if "User-Agent" in self.headers.keys():
                return self.headers["User-Agent"]
            else:
                return None
            
        def getReferer(self):
            """Get the Referer header value.

            Returns:
                str|None: The referer URL or None.
            """
            if "Referer" in self.headers.keys():
                return self.headers["Referer"]
            else:
                return None

        def getContentLength(self):
            """Get the Content-Length header as integer.

            Returns:
                int|None: Content length or None if header missing.
            """
            if "Content-Length" in self.headers.keys():
                content_length = int(self.headers["Content-Length"])
                return content_length
            else:
                return None
            
        def getRemainderOfPostData(self):
            """For POST requests, receive any remaining body data.

            Sets socket to non-blocking temporarily to read additional chunks
            until Content-Length is satisfied. Updates bodyData and totalSize.
            """
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
        """Route definitions and handlers for the web server.

        Contains subclasses for different HTTP methods (GET, POST).
        Routes map virtual paths to either physical files or callback responders.
        """

        POST_ROUTE = "POST"
        GET_ROUTE = "GET"
        HEAD_ROUTE = "HEAD"
        OPTIONS_ROUTE = "OPTIONS"

        class getRoute():
            """Represents a GET (or similar) route.

            Can serve either a static file from physicalPath or call a virtualResponder
            function that returns a requestResponse object.
            """

            def __init__(self, virtualPath: str, physicalPath:str="", virtualResponder:object|None=None) -> None:
                """Create a new GET route.

                Args:
                    virtualPath: URL path starting with '/'.
                    physicalPath: Optional filesystem path to serve.
                    virtualResponder: Optional callable that generates dynamic response.

                Raises:
                    brRouteInvalid: If configuration is invalid (directory as file,
                                   conflicting path types, or bad virtual path).
                """
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
                """Attach request context to this route before responding.

                Args:
                    context: The packetParser instance with request details.

                Returns:
                    Self for method chaining.
                """
                self.context = context
                return self

            def respond(self):
                """Execute the route handler and return response.

                If virtualResponder is set, calls it with context.
                For physical paths, this is currently a no-op (handled elsewhere?).

                Returns:
                    requestResponse: The HTTP response object.
                """
                if self.virtualResponder is not None:
                    return self.virtualResponder(self.context)
                else:
                    pass
                
        class postRoute():
            """Represents a POST route.

            Unlike GET, POST routes only support virtual responders (callbacks).
            """

            def __init__(self, virtualPath: str, virtualResponder:object) -> None:
                """Create a new POST route.

                Args:
                    virtualPath: URL path starting with '/'.
                    virtualResponder: Callable that processes the POST request.

                Raises:
                    brRouteInvalid: If virtual path doesn't start with '/'.
                """
                self.virtualPath = virtualPath
                self.virtualResponder = virtualResponder
                self.context: brWebServer.packetParser = None
                
                if not virtualPath.startswith("/"):
                    raise brWebServer.brRouteInvalid(f'Invalid virtual path! {self.virtualPath} <- does not start at root!')
            
            def addContext(self, context: object):
                """Attach request context to this route before responding.

                Args:
                    context: The packetParser instance.

                Returns:
                    Self for chaining.
                """
                self.context = context
                return self

            def respond(self):
                """Execute the POST handler.

                Returns:
                    The result of calling virtualResponder with context.
                """
                return self.virtualResponder(self.context)

    def __init__(self, bindAddress:str="127.0.0.1", httpPort:int=80, securePort:int=443, webRoot=None, debug=False) -> None:
        """Initialize the brWebServer instance.

        Args:
            bindAddress: IP address to bind the server to.
            httpPort: Port for HTTP traffic (default 80).
            securePort: Port for HTTPS (currently unused in this implementation).
            webRoot: Base directory for serving static files.
            debug: Enable debug logging and packet dumping to files.
        """
        # If debug is set, we will log at the lowest level + debug timings
        self.debug = debug
        # ------------

        # Network setup
        self.bindAddress = bindAddress
        self.httpPort = httpPort
        self.securePort = securePort
        self.externalIP = None
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

        if debug:
            logger.level = logging.DEBUG
    
    def buildRoute(self, routeType:str, virtualPath:str, virtualResponder:object|None=None, physicalPath:str=""):
        """Register a new route with the server.

        Supports GET, POST, and special "404" handler registration.

        Args:
            routeType: One of GET_ROUTE, POST_ROUTE, or "404".
            virtualPath: The URL path to register.
            virtualResponder: Function to call for dynamic responses.
            physicalPath: Filesystem path for static file serving.

        Raises:
            brDuplicateRoute: If the route already exists.
            brRouteInvalid: Propagated from route constructors.
        """
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
        
        if self.running:
            logger.info(f'Dynamically added {virtualPath} to the running server config')

    def removeRoute(self, virtualPath:str):
        if virtualPath not in self.getRoutes.keys():
            raise brWebServer.brRouteInvalid("Route cannot be removed if it hasn't been set up!")
        else:
            self.getRoutes.pop(virtualPath)
            logger.info(f'Dynamically removed: {virtualPath} from the running server config')
    
    def startServer(self):
        """Start the web server.

        Configures UPNP port forwarding if possible, then launches the main
        listening thread. Sets up default 404 handler if none was provided.
        """
        #result = configureUPNP(self.httpPort, "TCP", "Backrooms-net Web Dashboard")
        #if result is not False:
        #    self.externalIP = result
        #    logger.info("UPNP configured for Web Server.")
        
        logger.info("Started server.")
        if not self.running:
            self.mainThread = threading.Thread(name="brWebCoreMain", target=self.__mainLoop__, args=[])
            self.mainThread.start()

    def shutdownServer(self):
        """Gracefully shutdown the server.

        Removes UPNP mapping, signals shutdown, waits for main thread to exit.
        """
        removeUPNP(self.httpPort, "TCP")
        self.shutdown = True
        logger.info("Sent shutdown signal - Main Thread is now waiting...")
        self.mainThread.join()

    def __mainLoop__(self):
        """Main server loop. Binds socket, accepts connections, and spawns
        handler threads. Periodically cleans up dead threads. Sets up default
        404 page using brWebDefaults if none registered. Runs until shutdown
        signal is received.
        """
        self.running = True

        # Check a few defaults
        if self.fourOhFour is None:

            # Imports for various defaults
            # We import here to avoid a circular import error
            from brCore.brWebServer import brWebDefaults  

            logger.warning("No custom 404 route set - using default...")
            self.buildRoute("404", "/404", brWebDefaults.defaultFourOhFour)

        # Announce our number of routes
        logger.info(f'Server starting with {len(self.getRoutes.keys())} GET routes and {len(self.postRoutes.keys())} POST routes.')

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindAddress, self.httpPort))
            soc.listen(4)
            soc.settimeout(1.0)
        except PermissionError:
            # May be system reserved port on Linux
            if self.httpPort < 1024:
                logger.exception("Error with permissions! Some Linux distros don't allow binding to ports below 1024, or possible other error!", exc_info=True)
                self.running = False
                return
            # Or it isn't. Oops.
            else:
                logger.exception("Error binding to port! Permissions error!", exc_info=True)
                self.running = False
                return
        except Exception as e:
            logger.exception("Error occured when creating socket!", exc_info=True)
            self.running = False
            return
        
        while not self.shutdown:
            try:
                connection, address = soc.accept()
                spawnThread = threading.Thread(target=self.__connectionThread__, name="brWebCore-Thread", args=[connection, address])
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
        logger.info("Main web loop received shutdown, refusing new connections.")
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
        """Debug helper to write raw packets to timestamped files.

        Only used when debug=True. Creates per-connection directories.

        Note: This is a static method but defined inside the class.
        """
        tempdir = Path(f'temp/{id}')
        if not tempdir.is_dir():
            os.mkdir(f'temp/{id}')
        with open(f'temp/{id}/{str(count)}.packet', 'ab') as df:
            df.write(data)
        logger.debug(f'Wrote packet to: temp/{id}/{str(count)}.packet')

    def __router__(self, parseResult: packetParser):
        """Route an incoming parsed request to the appropriate handler.

        Looks up the path in the registered routes dictionary. For POST,
        ensures all body data is received first. Falls back to 404 handler
        for unknown paths. Uses the route's respond() method.

        Args:
            parseResult: The packetParser instance with request details.

        Returns:
            requestResponse: The response object from the route handler.
        """
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
        from brCore.brWebServer import brWebDefaults

        """Generate a generic 500 Internal Server Error response.

        Uses default error page from brWebDefaults.

        Returns:
            bytes: Complete HTTP error response packet.
        """
        reply: brWebServer.requestResponse = brWebDefaults.defaultServerError()
        packet = reply.setContentType("500").setBodySize().buildPacket()
        return packet

    def __connectionThread__(self, connection: socket.socket, address):
        """Handle a single client connection in its own thread.

        Receives packets, parses them, routes requests, sends responses.
        Tracks statistics per thread and aggregates to server totals.
        Supports debug packet logging to files. Handles clean disconnection
        based on client Connection header or empty packets.

        Args:
            connection: Client socket.
            address: (ip, port) tuple of client.
        """
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
    """Helper class for building dynamic web page responses.

    Allows accumulation of HTML content and setting of appropriate HTTP status.
    The buildResponse method converts it into a requestResponse object.
    """

    def __init__(self) -> None:
        """Initialize a new web page builder with empty content and status."""
        self.bodyData = b''
        self.responseStatus: str = ""

    def addContent(self, content: str|bytes):
        """Append content to the page body.

        Args:
            content: Either a string (will be UTF-8 encoded) or bytes.
        """
        if isinstance(content, bytes):
            self.bodyData += content
        else:
            self.bodyData += content.encode('utf-8')

    def setOK(self):
        """Set response status to 200 OK."""
        self.responseStatus = brWebServer.requestResponse.WEB_OK
        pass

    def setNotFound(self):
        """Set response status to 404 Not Found."""
        self.responseStatus = brWebServer.requestResponse.NOT_FOUND
        pass

    def setError(self):
        """Set response status to 500 Internal Server Error."""
        self.responseStatus = brWebServer.requestResponse.SERVER_ERROR
        pass

    def setBadRequest(self):
        """Set response status to 400 Bad Request."""
        self.responseStatus = brWebServer.requestResponse.BAD_REQUEST
        pass

    def buildResponse(self, context: brWebServer.packetParser):
        """Create a requestResponse from the accumulated page content.

        Resets internal state after building (bodyData and status cleared).

        Args:
            context: The packetParser to determine connection type from.

        Returns:
            requestResponse: Fully configured response object.
        """
        reply = brWebServer.requestResponse(
            data=self.bodyData,
            serverStatus=self.responseStatus,
            connectionType=context.getRequestedConnectionType()
        )

        # Make sure to clear as data here is persistent
        self.bodyData = b''
        self.responseStatus = ""

        return reply
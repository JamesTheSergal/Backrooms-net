from enum import Enum
import io
import logging
import os
import socket
import threading
import uuid
import pyqrcode
import pprint
from core import notrustvars

from node import BR_VERSION

class webResponderRequest:

    def __init__(self, msg: bytes) -> None:

        # Some initial values
        self.badRequest = False
        self.closeConnection = False
        self.messageString = ""
        self.headers = {}
        self.data = None
        self.requestType = None
        self.requestPath = None
        self.httpVersion = None

        # First of all, handle if the client has disconnected, or if we don't receive anything
        
        if not msg or msg == b'':
            self.badRequest = True
            self.closeConnection = True
        else:

            # Handle the possibility of a client not sending us UTF-8 data

            try:
                self.messageString = msg.decode("utf-8")
            except UnicodeDecodeError:
                logging.warning("Client sent us data that was not in UTF-8 format.", exc_info=True)
                self.badRequest = True

            if self.badRequest == False:

                # Parse the packet and see what it is

                requestRawSplit = self.messageString.split("\r\n")
                
                # Parse headers from the packet
                for entry in requestRawSplit:
                    if entry == '':
                        break
                    headersplit = entry.split(": ")
                    if len(headersplit) > 1:
                        self.headers[headersplit[0]] = headersplit[1]

                rawRequestHeader = requestRawSplit[0]
                requestHeaderSplit = rawRequestHeader.split(" ")

                if len(requestHeaderSplit) < 3:
                    self.badRequest = True
                else:
                    self.requestType = requestHeaderSplit[0]
                    self.requestPath = requestHeaderSplit[1]
                    self.httpVersion = requestHeaderSplit[2]
                
                self.data = self.messageString.split("\r\n")[-1]
                self.dataLength = len(self.data.encode("utf-8"))


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

    def getRemainderOfPostData(self, connection: socket.socket):
        currentBytes = self.data.encode("utf-8")
        logging.debug(f'Starting receive POST data with {len(currentBytes)} Bytes')

        logging.debug(f'Post: {self.isPost()} and Content-length: {self.getContentLength()}')

        connection.setblocking(False)

        if self.isPost() and self.getContentLength():
            expectedLength = self.getContentLength()
            logging.debug(f'Evaluate -> {self.dataLength} != {expectedLength}')
            while self.dataLength != expectedLength:
                logging.debug(f'Bytes Needed: {self.getContentLength()} - Current Bytes: {self.dataLength} - Diff: {self.getContentLength()-self.dataLength}')

                try:
                    msg = connection.recv(1024)
                    if not msg:
                        break
                except BlockingIOError:
                    logging.warning("Didn't receive a last message. Finishing.")
                    break
                    
                currentBytes += msg
                self.dataLength += len(msg)
            
            self.data = currentBytes.decode("utf-8")
            connection.setblocking(True)
            logging.debug("Receive finished.")


    # Custom Backrooms-net Headers

    def getClientUUID(self):
        if "client-uuid" in self.headers.keys():
            return self.headers["client-uuid"]
        else:
            return None
        
class webResponderResponse:

    class backRoomsWebUI:

        def __init__(self) -> None:
            self.content = ""

        def genHeader(self):
            content = (
                "<head>\n"
                "<title>Backrooms-net Node</title>\n"
                '<meta name="twitter:title" content="Backrooms-net Node">\n'
                '<meta name="twitter:description" content="A secure node based communications network.">\n'
                "</head>\n"
                "<html>\n"
                "<h1>Hello from the backrooms!&nbsp;</h1>\n"
                "<hr />\n"
            )
            self.content += content
            return self

        def genBody(self, internalElements):
            content = (
                "<body>\n"
                f'{internalElements}'
                "</body>\n"
            )
            self.content += content
            return self

        def genForm(self, postEndpoint, formName, dataName, formButtonText):
            content = (
                f'<form action={postEndpoint} method="post">\n'
                f'<label for="{dataName}">{formName}</label>\n'
                f'<input type="text" id="{dataName}" name="{dataName}"><br>\n'
                f'<input type="submit" value="{formButtonText}">\n'
            )
            return content
        
        def genTextBody(self, someText):
            content = (
                "<body>\n"
                f'<p>{someText}</p>\n'
                "</body>\n"
            )
            self.content += content
            return self
        
        def fourOhFour(self):
            content = (
                "<body>\n"
                "<p>404! Sorry, we didn't find that route!</p>\n"
                "</body>\n"
            )
            self.content += content
            return self

        def genFooter(self):
            content = (
                '<hr />\n'
               f'<pre><em>Running Backrooms-net node <span style="text-decoration: underline;">{BR_VERSION}</span></em></pre>\n'
            )
            self.content += content
            return self
        
        def makeQR(data):
            pass

    def __init__(self, responseStatus: str, connectionType: str) -> None:
        self.responseStatus = responseStatus
        self.contentType = "Content-Type: text/html; charset=UTF-8"
        self.connection = connectionType
        self.server = "Server: Apache/2.4.62-3"
        self.contentLength = 0
        self.bodyData = ""

    def setBodySize(self):
        self.contentLength = len(self.bodyData)
        return self

    def buildPacket(self):
        packet = ""
        packet += self.responseStatus + "\r\n"
        packet += self.server + "\r\n"
        packet += "Content-Length: "+str(self.contentLength) + "\r\n"
        packet += self.connection + "\r\n"
        packet += self.contentType + "\r\n"
        packet += "\r\n"
        packet += self.bodyData
        return packet.encode("utf-8")

class webResponderRouter:

    # Constants for replies
    WEB_OK = "HTTP/1.1 200 OK"
    BAD_REQUEST = "HTTP/1.1 400 Bad Request"
    NOT_FOUND = "HTTP/1.1 404 Not Found"
    TEAPOT = "HTTP/1.1 418 I'm a teapot"
    SERVER_ERROR = "HTTP/1.1 500 Internal Server Error"
    #
    #
    # Constants for connection states
    KEEP_ALIVE = "Connection: keep-alive"
    CLOSE_CONN = "Connection: close"
    #
    #


    def handleGet(connection: socket.socket, request: webResponderRequest, enclave: notrustvars.enclave):

        # First we must deturmine a few things about this get request.

        if request.getRequestedConnectionType() == "close":
            # Client intends to close this connection after the request
            responseConnectionType = webResponderRouter.CLOSE_CONN
        elif request.getRequestedConnectionType() == "keep-alive":
            # Client will make more requests after
            responseConnectionType = webResponderRouter.KEEP_ALIVE
        else:
            logging.warning(f'Client requested an undefined connection type! {request.getRequestedConnectionType()=}')
            responseConnectionType = webResponderRouter.CLOSE_CONN

        # Now check the request path and build the page

        if request.requestPath:
            logging.debug(f'Client asked for: {request.requestPath}')

        if request.requestPath == "/":
            response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
            uiBuilder = webResponderResponse.backRoomsWebUI()
            uiBuilder = uiBuilder.genHeader().genBody("Hello world!").genFooter()
            response.bodyData = uiBuilder.content
            return response.setBodySize()
        
        if request.requestPath == "/route":
            response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
            uiBuilder = webResponderResponse.backRoomsWebUI()
            uiBuilder = uiBuilder.genHeader().genBody("Enter a UUID into the address bar to start!").genFooter()
            response.bodyData = uiBuilder.content
            return response.setBodySize()
        
        if request.requestPath == "/pubkey":
            publickey: str = enclave.returnData("PublicKey").save_pkcs1().decode("utf-8")
            response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
            response.bodyData = publickey
            return response.setBodySize()
        
        if request.requestPath == "/askuuid4":
            idget = uuid.uuid4()
            response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
            response.bodyData = idget
            return response.setBodySize()
        
        if request.requestPath == "/announce":
            response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
            uiBuilder = webResponderResponse.backRoomsWebUI()
            uiBuilder = uiBuilder.genHeader().genBody(
                uiBuilder.genForm("/announce/publickey", "Your Public Key", "client-uuid", "Submit")
            ).genFooter()
            response.bodyData = uiBuilder.content
            return response.setBodySize()
        

        # Next check for non-absolute paths. Paths that have IDs, or something else in the request path to identify what the client wants.
        if request.requestPath.startswith("/route/"):
            feilds = request.requestPath.split("/")
            if len(feilds) > 2:
                routeID = feilds[2]
                response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
                uiBuilder = webResponderResponse.backRoomsWebUI()
                uiBuilder = uiBuilder.genHeader().genTextBody(f'Route: {routeID}').genFooter()
                response.bodyData = uiBuilder.content
                return response.setBodySize()
            else:
                response = webResponderResponse(webResponderRouter.NOT_FOUND, responseConnectionType)
                uiBuilder = webResponderResponse.backRoomsWebUI()
                uiBuilder = uiBuilder.genHeader().fourOhFour().genFooter()
                response.bodyData = uiBuilder.content
                return response.setBodySize()
        # Our checks fell through, default with a 404!
        response = webResponderResponse(webResponderRouter.NOT_FOUND, responseConnectionType)
        uiBuilder = webResponderResponse.backRoomsWebUI()
        uiBuilder = uiBuilder.genHeader().fourOhFour().genFooter()
        response.bodyData = uiBuilder.content
        return response.setBodySize()

    def handlePost(connection: socket.socket, request: webResponderRequest, enclave: notrustvars.enclave):

        # First we must deturmine a few things about this get request.
        
        if request.getRequestedConnectionType() == "close":
            # Client intends to close this connection after the request
            responseConnectionType = webResponderRouter.CLOSE_CONN
        elif request.getRequestedConnectionType() == "keep-alive":
            # Client will make more requests after
            responseConnectionType = webResponderRouter.KEEP_ALIVE
        else:
            logging.warning(f'Client requested an undefined connection type! {request.getRequestedConnectionType()=}')
            responseConnectionType = webResponderRouter.CLOSE_CONN

        if request.requestPath:
            logging.debug(f'Client asked for: {request.requestPath}')

        if request.requestPath == "/announce/publickey":
            logging.debug("Receiving the remainder of the post data...")
            request.getRemainderOfPostData(connection)
            logging.debug("Receive complete")
            response = webResponderResponse(webResponderRouter.WEB_OK, responseConnectionType)
            logging.debug(f'Client claims to be: {request.getClientUUID()}')
            response.bodyData = request.data
            return response.setBodySize()
        

class webResponderController:

    def __init__(self, backlog, bindaddr, port, secureEnclave: notrustvars.enclave, debug: bool) -> None:
        self.backlog = backlog
        self.bindaddr = bindaddr
        self.port = port
        self.secureEnclave = secureEnclave
        self.nodeRunning = False
        self.shutdownSignal = False
        self.debug = debug

        self.connections = []
        self.connAcceptThread = None

    def startWebResponder(self):
        self.connAcceptThread = threading.Thread(name="connAcceptThread", target=self.__responderLoop__, args=[]).start()

    def __responderLoop__(self):
        logging.info("Started main web responder loop for accepting connections...")
        self.nodeRunning = True

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindaddr, self.port))
            soc.listen(self.backlog)
            soc.settimeout(1.0)
        except Exception as e:
            logging.exception("Error occured when creating socket!", exc_info=True)
            self.nodeRunning = False
            return
        
        while self.shutdownSignal is False:
            try:
                socket_connection, address = soc.accept()
                logging.debug("Accepting connection from client...")
                #connections.append(socket_connection)
                threading.Thread(target=self.webResponder, args=[socket_connection, address]).start()
                #logging.info(f'Active connections: {len(connections)}')
            except socket.timeout:
                # This is a normal timeout that let's us check for the shutdown signal
                pass
            

        if self.shutdownSignal is True:
            logging.info("Node loop got shutdown signal. Shutting down...")
            #soc.close()
            #logging.info("Closed socket.")
            self.nodeRunning = False
                
    def webResponder(self, connection: socket.socket, address):
        logging.debug("Starting webresponder connection thread...")

        # Append our connection for accurate count
        self.connections.append(connection)

        # For debugging - TODO: Make this more elegant
        conuuid = str(uuid.uuid4())
        os.mkdir(f'temp/{conuuid}')
        packetcount = 0

        # Main Responder loop

        while self.shutdownSignal is False:
            try:
                
                msg = connection.recv(1024)

                # Each received packet is written for debugging purposes for now
                with open(f'temp/{conuuid}/{str(packetcount)}.packet', 'a') as df:
                    df.write(msg.decode())
                packetcount+=1
                logging.debug(f'Message from {address[0]}:{address[1]} - {len(msg.decode())} bytes')

                # Figure out what the client wants, handle routes, handle errors and disconnect
                # Create our request object to respond to the client
                clientRequest = webResponderRequest(msg)

                # If this was set True, we need to close because of a bad request, or nothing was in the message.
                if not clientRequest.badRequest:
                    if clientRequest.isGet():
                        response: webResponderResponse = webResponderRouter.handleGet(connection, clientRequest, self.secureEnclave)
                        packet = response.buildPacket()
                    if clientRequest.isPost():
                        response: webResponderResponse = webResponderRouter.handlePost(connection, clientRequest, self.secureEnclave)
                        packet = response.buildPacket()

                    #---# El_Casi #---# - Backrooms-net didn't respect client wishes
                    if response.connection == webResponderRouter.CLOSE_CONN: 
                        logging.debug("Client requested connection close.")
                        connection.sendall(packet)
                        connection.close()
                        self.remove_connection(connection)
                        break
                    #---# El_Casi #---#

                else:
                    # If this evals to true, there wasn't anything in the message and we close.
                    if (clientRequest.badRequest and clientRequest.closeConnection):
                        connection.close()
                        self.remove_connection(connection)
                        logging.debug("Client message indicates normal connection close.")
                        break

                    # Client must have sent weird data. Close immediately. TODO: Add better way to handle
                    if clientRequest.badRequest:
                        connection.close()
                        self.remove_connection(connection)
                        logging.warning("Closed connection due to bad request/strange data sent from client. (Possible security risk?)")
                        break

                
                
                connection.sendall(packet)
                packetcount+=1
                with open(f'temp/{conuuid}/{str(packetcount)}.packet', 'a') as df:
                    df.write(packet.decode("utf-8"))
                
                logging.debug("Thread exit...")
                

                
            except TimeoutError:
                logging.error("Timeout! Closed connection...")
                break
            except ConnectionResetError:
                logging.exception("Connection force close!", exc_info=True)
                break
            except Exception as e:
                logging.exception(f'Error while handling responder connection!', exc_info=True)
                break

        logging.debug(f'Thread handled {packetcount} packets')

    def remove_connection(self, conn: socket.socket):
        if conn in self.connections:
            conn.close()
            self.connections.remove(conn)
            logging.debug(f'Removed connection. Active connections: {len(self.connections)}')
        else:
            logging.error(f'Attempted to close a connection that does not exist!!! Active connections: {len(self.connections)}')

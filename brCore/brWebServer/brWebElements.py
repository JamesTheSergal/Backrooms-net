import time

from brCore.brWebServer.brWebCore import brWebServer
from brCore.brWebServer.brWebCore import brWebPage
from brCore.brEnclave.notrustvars import enclave
from brCore.loggingfactory import timeProfiler
from brCore import BR_VERSION
from brCore.brNodeNet.brController import brNodeServer
from brCore.brNodeNet.brEndpoint import brEndpoint
from brCore.brNodeNet.events import EndPointEvent, EventType, DHTRequest
from brCore.brSockets.netconnection import netconnection
import threading
import json
import uuid
import urllib.parse  # Add this import for parsing form data
from . import brWebLog

logger = brWebLog


# I did not write this
# Code is from: https://stackoverflow.com/questions/12523586/python-format-size-application-converting-b-to-kb-mb-gb-tb
def humanbytes(B):
    """Return the given bytes as a human friendly KB, MB, GB, or TB string."""
    B = float(B)
    KB = float(1024)
    MB = float(KB ** 2) # 1,048,576
    GB = float(KB ** 3) # 1,073,741,824
    TB = float(KB ** 4) # 1,099,511,627,776

    if B < KB:
        return '{0} {1}'.format(B,'Bytes' if 0 == B > 1 else 'Byte')
    elif KB <= B < MB:
        return '{0:.2f} KB'.format(B / KB)
    elif MB <= B < GB:
        return '{0:.2f} MB'.format(B / MB)
    elif GB <= B < TB:
        return '{0:.2f} GB'.format(B / GB)
    elif TB <= B:
        return '{0:.2f} TB'.format(B / TB)

def genStyle():
    """Matrix / cyberpunk dark theme - black background with neon green accents."""
    return (
        "<style>\n"
        "    body {\n"
        "        background-color: #000000;\n"
        "        color: #00ff41;\n"
        "        font-family: 'Courier New', 'Lucida Console', monospace;\n"
        "        line-height: 1.5;\n"
        "        margin: 20px;\n"
        "    }\n"
        "    h1, h2, h3, h4 {\n"
        "        color: #00ff41;\n"
        "        text-shadow: 0 0 10px #00ff41;\n"
        "    }\n"
        "    a {\n"
        "        color: #00ff80;\n"
        "        text-decoration: none;\n"
        "        margin-right: 25px;\n"          # ← more spacing
        "        transition: all 0.2s;\n"
        "    }\n"
        "    a:hover {\n"
        "        color: #00ff41;\n"
        "        text-shadow: 0 0 15px #00ff41, 0 0 25px #00ff41;\n"
        "        text-decoration: underline;\n"
        "        text-underline-offset: 4px;\n"
        "    }\n"
        "    hr {\n"
        "        border: 0;\n"
        "        height: 2px;\n"
        "        background: linear-gradient(to right, transparent, #00aa33, transparent);\n"
        "        margin: 20px 0;\n"
        "    }\n"
        "    table {\n"
        "        border-collapse: collapse;\n"
        "        width: 100%;\n"
        "        border: 2px solid #00aa33;\n"
        "        background-color: #000000;\n"
        "        box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);\n"
        "    }\n"
        "    th, td {\n"
        "        color: #00ff41 !important;\n"     # ← force green text
        "        padding: 12px 10px;\n"
        "        border: 1px solid #003d1f;\n"
        "    }\n"
        "    th {\n"
        "        background-color: #001a00;\n"
        "        text-shadow: 0 0 8px #00ff41;\n"
        "        font-weight: bold;\n"
        "    }\n"
        "    tr:nth-child(even) {\n"
        "        background-color: #000f00;\n"
        "    }\n"
        "    tr:hover {\n"
        "        background-color: #002200;\n"
        "    }\n"
        "    input, button, textarea {\n"
        "        background-color: #000000;\n"
        "        color: #00ff41;\n"
        "        border: 2px solid #00aa33;\n"
        "        font-family: 'Courier New', monospace;\n"
        "        padding: 8px;\n"
        "    }\n"
        "    input:focus, button:focus {\n"
        "        outline: none;\n"
        "        box-shadow: 0 0 12px #00ff41;\n"
        "        border-color: #00ff41;\n"
        "    }\n"
        "    form {\n"
        "        margin: 20px 0;\n"
        "        padding: 15px;\n"
        "        border: 1px dashed #003d1f;\n"
        "    }\n"
        "</style>\n"
    )
       

def genHeader():
        content = (
            "<head>\n"
            "<title>Backrooms-net Node</title>\n"
            '<meta name="twitter:title" content="Backrooms-net Node">\n'
            '<meta name="twitter:description" content="A secure node based communications network.">\n'
            "</head>\n"
            + genStyle() +
            "<html>\n"
        )
        return content

def genNavBar(links:dict={}):
    navContent = (
        "<h1>Hello from the backrooms!</h1>\n"   # removed &nbsp; clutter
        "<nav style='margin-bottom: 15px;'>\n"   # ← semantic nav + margin
    )

    for key in links.keys():
        navContent += f'<a href="{links[key]}">{key}</a>&nbsp;'
    navContent += "\n</p>\n<hr />\n"    
    return navContent
     
def genBody(internalContent):
    content = (
        "<body>\n"
        + internalContent +
        "</body>\n"
    )
    return content

def genFooter():
    content = (
        "</html>\n"
        '<hr />\n'
        f'<pre><em>Running Backrooms-net node <span style="text-decoration: underline;">{BR_VERSION}</span></em></pre>\n'
    )
    return content

def genIPPortForm(postEndpoint, ipLabel, ipName, portLabel, portName, buttonText):
    content = (
        f'<form action="{postEndpoint}" method="post">\n'
        f'<label for="{ipName}">{ipLabel}</label>\n'
        f'<input type="text" id="{ipName}" name="{ipName}" placeholder="e.g., 192.168.1.1"><br>\n'
        f'<label for="{portName}">{portLabel}</label>\n'
        f'<input type="number" id="{portName}" name="{portName}" placeholder="e.g., 8080" min="1" max="65535"><br>\n'
        f'<input type="submit" value="{buttonText}">\n'
        f'</form>\n'
    )
    return content

def genForm(postEndpoint, formName, dataName, formButtonText):
        content = (
            f'<form action={postEndpoint} method="post">\n'
            f'<label for="{dataName}">{formName}</label>\n'
            f'<input type="text" id="{dataName}" name="{dataName}"><br>\n'
            f'<input type="submit" value="{formButtonText}">\n'
            f'</form>\n'
        )
        return content
    
def genFileForm(postEndpoint, formName, dataName, formButtonText):
    content = (
        f'<form action="{postEndpoint}" method="post" enctype="multipart/form-data">\n'
        f'<label for="{dataName}">{formName}</label>\n'
        f'<input type="file" id="{dataName}" name="{dataName}">\n'
        f'<input type="submit" value="{formButtonText}">\n'
        f'</form>\n'
    )
    return content

def genTable(headers: list, rows: list, caption: str = None):
    """Generate an HTML table.
    
    Args:
        headers: List of column header strings
        rows: List of lists (each inner list is a row of cells)
        caption: Optional table caption/title
    """
    #content = '<table border="1" cellpadding="6" style="border-collapse: collapse;">\n' # Changed for dark theme
    content = '<table>\n'
    
    if caption:
        content += f'  <caption><strong>{caption}</strong></caption>\n'
    
    # Header row
    content += '  <thead>\n    <tr>\n'
    for header in headers:
        # For th element: style="background-color: #f0f0f0;
        content += f'      <th text-align:left;">{header}</th>\n'
    content += '    </tr>\n  </thead>\n'
    
    # Data rows
    content += '  <tbody>\n'
    for row in rows:
        content += '    <tr>\n'
        for cell in row:
            content += f'      <td>{cell}</td>\n'
        content += '    </tr>\n'
    content += '  </tbody>\n</table>\n'
    
    return content

class brWebUIModule(brWebPage):

    def __init__(self, secureEnclave: enclave, node_server:brNodeServer, web_server:brWebServer) -> None:
        brWebPage.__init__(self)
        super().__init__()
        self.secureEnclave = secureEnclave # Threading locks are already implemented in the Enclave
        self.node_server = node_server
        self.web_server = web_server
        pass
    
    def connectnode(self, context: brWebServer.packetParser):
        self.addContent(
            genHeader() +
            genNavBar() +
            genBody(
                "<h2>External Node Connection Form</h2>\n" +
                "<p>Enter the IP address and port to connect to. This data will be stored in the Enclave for later use.</p>\n" +
                genIPPortForm("/connectnode", "IP Address", "ip_address", "Port", "port", "Submit")
            ) +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
    
    def connectnodePost(self, context: brWebServer.packetParser):
        try:
            # Parse the POST body (assumes application/x-www-form-urlencoded)
                                                                         #TODO: BUG. brWebCore post submission logic issue
                                                                         #when parsing the packet, bodyData is set as packetBytes[bodyDataIndex:len(packetBytes)], 
                                                                         #where bodyDataIndex is the position of b'\r\n\r\n'. 
                                                                         #This means bodyData starts with the literal bytes b'\r\n\r\n' (which decodes to '\r\n\r\n'), 
                                                                         #followed by the actual form data.
            body_str = context.bodyData.decode('utf-8').lstrip('\r\n')  # Strip leading \r\n\r\n to get clean form data
            parsed = urllib.parse.parse_qs(body_str)
            
            ip = parsed.get('ip_address', [''])[0].strip()
            port_str = parsed.get('port', ['0'])[0].strip()
            
            # Basic validation
            if not ip or not port_str.isdigit():
                raise ValueError("Invalid IP or port provided.")
            
            port = int(port_str)
            
            # Store in Enclave
            
            self.node_server.connect_to_node(ip, port)
            
            self.addContent(
                genHeader() +
                genNavBar() +
                genBody(
                    "<h2>Success</h2>\n" +
                    f"<p>Data submitted: IP={ip}, Port={port}. Stored in Enclave.</p>\n"
                ) +
                genFooter()
            )
            self.setOK()
        except Exception as e:
            logger.error(f"Error processing form submission: {e}")
            self.addContent(
                genHeader() +
                genNavBar() +
                genBody(
                    "<h2>Error</h2>\n" +
                    "<p>Failed to process submission. Please check your input and try again.</p>\n"
                ) +
                genFooter()
            )
            self.setError()
        
        return self.buildResponse(context)

    def brUIRoot(self, context: brWebServer.packetParser):
        ip = self.node_server.externalIP
        port = self.node_server.node_port
        endpoints = len(self.node_server.router.active_endpoints)
        routes = len(self.node_server.router.active_routes)
        
        self.addContent(
            genHeader() +
            genBody(
                genNavBar(
                      {
                        "Our Public Key": "/pubkey",
                        "Connect To Node": "/connectnode",
                        "Open Secure Route": "/announce",
                        "Stats": "/stats",
                      }
                ) +
                f'Welcome to the backrooms!\n' +
                f'<hr />'+
                f'<h4>Node Information</h4>'+
                f'<p>External IP:{ip}</p>\n' +
                f'<p>Node port:{port}</p>\n' +
                f'<p>Number of endpoints:{endpoints}</p>\n' +
                f'<p>Number of routes:{routes}</p>\n' 
            ) +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
        
    def brAnnouncePost(self, context: brWebServer.packetParser):
        self.addContent(context.bodyData)
        self.setOK()
        return self.buildResponse(context)

    def brAnnounce(self, context: brWebServer.packetParser):
        self.addContent(
            genHeader() +
            genNavBar() +
            genForm("/announce/publickey", "Your Public Key", "client-pub-key", "Submit") +
            genFileForm("/announce/publickey", "Or a public key file", "client-pub-key", "Submit") +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)

    def ourPublicKey(self, context: brWebServer.packetParser):
        pubkey = self.secureEnclave.returnData("PublicKey")
        strkey = pubkey.save_pkcs1().decode('utf-8')
        self.addContent(strkey)
        self.setOK()
        return self.buildResponse(context)
    
    def statsPage(self, context: brWebServer.packetParser):
        
        node_table_headers = ["Node ID", "IP Address", "Port", "Last Seen"]
        node_table_data = []
        
        for node in self.node_server.knownNodes:            
            new_row = [
                f'<a href="http://{node.nodeIP}:{node.webPort}">{str(node.localNodeID)}</a>',
                node.nodeIP,
                str(node.nodePort),
                f'{int((time.time() - node.lastSeen) / 60)} minutes ago'
            ]
            node_table_data.append(new_row)
            
        route_table_headers = ["Route ID", "Type", "From ID", "To ID"]
        route_table_data = []
        
        for active_route in self.node_server.router.active_routes:
            new_row = [
                str(active_route.routeID),
                str(active_route.routeType.name),
                str(active_route.connectingFrom),
                str(active_route.connectingTo)
            ]
            route_table_data.append(new_row)
            
        endpoint_table_headers = ["Endpoint ID", "Last seen"]
        endpoint_table_data = []
        
        for endpoint_key in self.node_server.router.active_endpoints.keys():
            active_endpoint:brEndpoint = self.node_server.router.active_endpoints[endpoint_key]
            new_row = [
                str(active_endpoint.endpoint_uuid),
                f'{int((time.time() - active_endpoint.last_seen) / 60)} minutes ago'
            ]
            endpoint_table_data.append(new_row)
        
        
        webInBytes = self.web_server.handledIncomingBytes
        webOutBytes = self.web_server.handledOutgoingBytes
        webRequests = self.web_server.respondedToRequests
        webErrors = self.web_server.errors
        webConnections = len(self.web_server.connections)
        
        nodeInBytes = 0#self.secureEnclave.returnData("brNodeNetwork_incomingBytes")
        nodeOutBytes = 0#self.secureEnclave.returnData("brNodeNetwork_outgoingBytes")
        nodeRequests = 0#self.secureEnclave.returnData("brNodeNetwork_requests")
        
        for route in self.node_server.connection_manager.trackedConnections:
            route:netconnection
            nodeOutBytes += route.bytesout
            nodeInBytes += route.bytesin
            nodeRequests += route.totalrequests


        self.addContent(
            genHeader() +
            genNavBar() +
            genBody(
                 f'<h4>Web Server stats</h4>'+
                 f'<p>We have handled {humanbytes(webInBytes)} In</p>\n' +
                 f'<p>We have handled {humanbytes(webOutBytes)} Out</p>\n' +
                 f'<p>We have handled {webRequests} Requests</p>\n' +
                 f'<p>We have had {webErrors} Errors</p>\n' +
                 f'<p>We currently have {webConnections} Connections</p>\n'+
                 f'<hr />'+
                 f'<h4>Node Network stats</h4>'+
                 f'<p>We have handled {humanbytes(nodeInBytes)} In</p>\n' +
                 f'<p>We have handled {humanbytes(nodeOutBytes)} Out</p>\n' +
                 f'<p>We have handled {nodeRequests} Requests</p>\n' +
                 f'<p>We are apart of {len(self.node_server.router.active_routes)} active routes</p>\n' +
                 f'<p>We have seen {self.node_server.total_events} node network events</p>\n' +
                 f'<hr />'+
                 f'<h4>Active Node List</h4>'+
                 genTable(node_table_headers, node_table_data) +
                 f'<h4>Active Routes List</h4>' +
                 genTable(route_table_headers, route_table_data) +
                 f'<h4>Registered Endpoints</h4>' +
                 genTable(endpoint_table_headers, endpoint_table_data)
            ) +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
    
    ###
    ### Utilities provided by the node to non-browser clients
    ###
    
    def clientGetUUID4(self, context: brWebServer.packetParser):
         self.addContent(
              str(uuid.uuid4())
         )
         self.setOK()
         return self.buildResponse(context)
     
    def getControllerUUID(self, context: brWebServer.packetParser):
        self.addContent(
            str(self.node_server.uuid)
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getDHTPort(self, context: brWebServer.packetParser):
        self.addContent(
            str(self.node_server.dht.serverport)
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getDHTlongID(self, context:brWebServer.packetParser):
        self.addContent(
            str(self.node_server.dht.returnDHTLongID())
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getDHTNeighborCount(self, context:brWebServer.packetParser):
        self.addContent(
            str(len(self.node_server.dht.dhtServer.bootstrappable_neighbors()))
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getDHTBootstrappableNeighbors(self, context:brWebServer.packetParser):
        self.addContent(
            json.dumps(self.node_server.dht.dhtServer.bootstrappable_neighbors())
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getDHTStorageEntryCount(self, context:brWebServer.packetParser):
        self.addContent(
            str(len(self.node_server.dht.dhtServer.storage.data))
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getNodePort(self, context: brWebServer.packetParser):
        self.addContent(
            str(self.node_server.node_port)
        )
        self.setOK()
        return self.buildResponse(context)
    
    def getNodeFriends(self, context: brWebServer.packetParser):
        friends = {"friends": []}
        for node in self.node_server.knownNodes:
            formatted_node = {node.localNodeID: {
                "nodeip": node.nodeIP,
                "webport": node.webPort,
                "nodeport": node.nodePort,
                "friendlyName": node.friendlyName
            }}
            friends["friends"].append(formatted_node)
        self.addContent(
            json.dumps(friends)
        )
        self.setOK()
        return self.buildResponse(context)
    
    def createEndpoint(self, context: brWebServer.packetParser):
        
        new_endpoint = brEndpoint() # Create new object for client
        endpoint_info = {
            "uuid": str(new_endpoint.endpoint_uuid),
            "session_token": new_endpoint.session_secret
        }
        
        self.addContent(
            json.dumps(endpoint_info)
        )
        self.setOK()
        self.node_server.event_queue.put(EndPointEvent(EventType.NEW_ENDPOINT_CLIENT, new_endpoint))
        
        return self.buildResponse(context)
    
    def listEndpointsOnNode(self, context: brWebServer.packetParser):
        endpoints = {"endpoints": []}
        for token in self.node_server.router.active_endpoints.keys():
            endpoint:brEndpoint = self.node_server.endPoints[token]
            endpoints["endpoints"].append({
                "uuid": str(endpoint.endpoint_uuid),
                "last_seen": endpoint.last_seen,
            })
            
            if endpoint.identity is not None:
                endpoints["endpoints"].append({
                    "public_key": endpoint.identity.publicKey.save_pkcs1().decode('utf-8')
                })
                
        endpoint_list = json.dumps(endpoints)
        self.addContent(endpoint_list)
        self.setOK()
        return self.buildResponse(context)
    
    def endpointDHTKeyHistory(self, context: brWebServer.packetParser):
        try:
            token = context.headers["token"]
        except KeyError:
            self.setBadRequest()
            self.addContent("One or more headers is incorrect")
            return self.buildResponse(context)
        
        if token in self.node_server.endPoints.keys():
            endpoint:brEndpoint = self.node_server.endPoints[token].seenNow()
            
            history = {
                "get": endpoint.getdhthistory,
                "set": endpoint.setdhthistory
            }
        
            self.addContent(
                json.dumps(history)
            )
            self.setOK()
            return self.buildResponse(context)
        else:
            self.setNotFound()
            self.addContent("Token does not exist")
            return self.buildResponse(context)
        
    def endpointDHTAccess(self, context: brWebServer.packetParser):
        try:
            token = context.headers["token"]
            operation = context.headers["operation"]
            dhtkey = context.headers["dhtkey"]
        except KeyError:
            self.setBadRequest()
            self.addContent("One or more headers is incorrect")
            return self.buildResponse(context)
        
        if token in self.node_server.endPoints.keys():
            endpoint:brEndpoint = self.node_server.endPoints[token].seenNow()
            match operation:
                case "GET":
                    request_id = str(uuid.uuid4())
                    self.node_server.dht.get(dhtkey, request_id)
                    endpoint.add_dht_key_get_history(dhtkey)
                    self.addContent(str(request_id))
                    self.setOK()
                    return self.buildResponse(context)
                case "SET":
                    if context.bodyDataLength > 0:
                        self.node_server.dht.set(dhtkey, context.bodyData.decode("utf-8").lstrip('\r\n'))
                        endpoint.add_dht_key_set_history(dhtkey)
                        self.setOK()
                        return self.buildResponse(context)
                    else:
                        self.setBadRequest()
                        self.addContent("data must be sent in the body of the request")
                        return self.buildResponse(context)
                    pass
                case _:
                    self.setBadRequest()
                    self.addContent("operation can only be GET or SET")
                    return self.buildResponse(context)
            
        else:
            self.setNotFound()
            self.addContent("Token does not exist")
            return self.buildResponse(context)
    
    def endpointDHTRetreive(self, context: brWebServer.packetParser):
        try:
            token = context.headers["token"]
            request_id = context.headers["request_id"]
        except KeyError:
            self.setBadRequest()
            self.addContent("One or more headers is incorrect")
            return self.buildResponse(context)
    
        if token in self.node_server.endPoints.keys():
            endpoint:brEndpoint = self.node_server.endPoints[token].seenNow()
            
            if request_id in self.node_server.dht.requestresults.keys():
                self.addContent(self.node_server.dht.requestresults[request_id])
                self.setOK()
                return self.buildResponse(context)
            else:
                self.setNotFound()
                self.addContent("dht result was not found or has expired")
                return self.buildResponse(context)
        
        else:
            self.setNotFound()
            self.addContent("Token does not exist")
            return self.buildResponse(context)
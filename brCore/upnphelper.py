import socket
import miniupnpc

def openPublicPort(port:int, protocol:str, description:str):
    pass

def get_local_ip():
    try:
        # Create a socket and connect to a public DNS server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None
    
def configureUPNP(port:int, protocol:str, description:str):
        # Create a UPnP object
        upnp = miniupnpc.UPnP()
        # Discover UPnP devices (this scans your network for IGDs)
        upnp.discoverdelay = 200  # Delay in ms for discovery
        upnp.discover()
        # Select the first IGD found (usually your router)
        upnp.selectigd()
        # Get your external (public) IP (useful for logging or verification)
        external_ip = upnp.externalipaddress()
        local_ip = get_local_ip()
        
        if local_ip:
            #try:
            result_dht = upnp.addportmapping(port, protocol, local_ip, port, description, '')
            #except ConflictInMappingEntry
        
            if result_dht:
                return external_ip
            else:
                return False
        else:
            return False
        
def removeUPNP(port:int, protocol:str):
        upnp = miniupnpc.UPnP()
        # Discover UPnP devices (this scans your network for IGDs)
        upnp.discoverdelay = 200  # Delay in ms for discovery
        upnp.discover()
        # Select the first IGD found (usually your router)
        upnp.selectigd()
        upnp.deleteportmapping(port, protocol)
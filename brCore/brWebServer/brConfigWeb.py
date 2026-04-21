from .brWebCore import brWebServer
from .brWebElements import brWebUIModule

def setup_webserver(webServer:brWebServer, webui:brWebUIModule):
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/", webui.brUIRoot)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats", webui.statsPage)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/pubkey", webui.ourPublicKey)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/announce", webui.brAnnounce)
    webServer.buildRoute(brWebServer.route.POST_ROUTE, "/announce/publickey", webui.brAnnouncePost)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/connectnode", webui.connectnode)
    webServer.buildRoute(brWebServer.route.POST_ROUTE, "/connectnode", webui.connectnodePost)
    
    ###
    # Non-browser client stuff
    ##
    
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/tools/requestuuid", webui.clientGetUUID4)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/tools/createendpoint", webui.createEndpoint)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/tools/dht/keyhistory", webui.endpointDHTKeyHistory)
    webServer.buildRoute(brWebServer.route.POST_ROUTE, "/tools/dht", webui.endpointDHTAccess)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/tools/dht/response", webui.endpointDHTRetreive)
    
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/controllerid", webui.getControllerUUID)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/endpoints", webui.listEndpointsOnNode)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/nodefriends", webui.getNodeFriends)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/dht", webui.getDHTlongID)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/dht/port", webui.getDHTPort)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/dht/storage", webui.getDHTStorageEntryCount)
    webServer.buildRoute(brWebServer.route.GET_ROUTE, "/stats/dht/bootstrap", webui.getDHTBootstrappableNeighbors)
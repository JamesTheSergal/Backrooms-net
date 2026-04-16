from node import brNode

mainNode = brNode(runmulti=True)
mainNode.startEnclave()
mainNode.startDHT(port=23339)
mainNode.startWebServer("0.0.0.0", 11001, False)
mainNode.startNodeServer("0.0.0.0", 13338, False)
mainNode.serverLoop()
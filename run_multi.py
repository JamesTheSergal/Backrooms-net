from node import brNode

mainNode = brNode(runmulti=True)
mainNode.startEnclave()
mainNode.startDHT(port=23339)
mainNode.startNodeServer("0.0.0.0")
mainNode.startWebServer("0.0.0.0", 11001, False)

mainNode.serverLoop()
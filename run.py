from node import brNode

mainNode = brNode()
mainNode.startEnclave()
mainNode.startDHT()
mainNode.startNodeServer("0.0.0.0")
mainNode.startWebServer("0.0.0.0", 11000, False)
mainNode.serverLoop()
from node import brNode

mainNode = brNode()
mainNode.startEnclave()
mainNode.startDHT()
mainNode.startWebServer("0.0.0.0", 11000, False)
mainNode.startNodeServer("0.0.0.0", 13337, False)
mainNode.serverLoop()
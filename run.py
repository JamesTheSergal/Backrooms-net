from node import brNode

mainNode = brNode()
mainNode.startEnclave()
mainNode.startDHT()
mainNode.startWebServer("127.0.0.1", 11000, False)
mainNode.startNodeServer("127.0.0.1", 13337, False)
mainNode.serverLoop()
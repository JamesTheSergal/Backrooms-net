from node import brNode

mainNode = brNode(runmulti=True)
mainNode.startEnclave()
mainNode.startDHT(port=23339)
mainNode.startWebServer("127.0.0.1", 11001, False)
mainNode.startNodeServer("127.0.0.1", 13338, False)
mainNode.serverLoop()
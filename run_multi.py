from node import brNode

mainNode = brNode(runmulti=True)
mainNode.startEnclave()
mainNode.startDHT(port=23339)
mainNode.serverLoop()
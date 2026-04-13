from node import brNode

mainNode = brNode()
mainNode.startEnclave()
mainNode.startDHT()
mainNode.serverLoop()
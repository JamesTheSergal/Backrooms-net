from node import brNode
import random

port = random.randrange(12001, 18000)

mainNode = brNode(runmulti=True)
mainNode.startEnclave()
mainNode.startDHT(port)
with open("dhts.txt", "a") as file:
    file.write(f"ip:{port}\n")

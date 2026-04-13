from brCore.brSockets.brPacket import brPacket
import pprint


packet = brPacket().buildPacket(brPacket.brMessageType.READY)


print("Full packet: ")
print(f"Length: {len(packet)}")
print("Hex:")
print(pprint.pformat(packet.hex(" ", 1)))
print("Raw:")
print(pprint.pformat(packet))
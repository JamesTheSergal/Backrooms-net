BR_VERSION = "0.0.1-alpha"
PLV_VERSION = "0.0.1-alpha" # Project launch vehicle
SUPPORTED_HANDSHAKES = ["0.0.1-alpha"]

# Always logging first
import core.Logging
import core.addonSystem

# Attempt to call for a global logger to get this show on the road
core_logger = core.Logging.createNewLogger("node.log")
core_logger.info(f"Backroom-net Core version: {BR_VERSION}")
core_logger.info(f"Platform Launch Vehicle (PLV) version: {PLV_VERSION}")
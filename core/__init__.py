# Import core first and let PLV work itself out.
import core
# Import our default backup logger config
import PLV.Logging
# Attempt to call for a global logger to get this show on the road
core_logger = PLV.Logging.classic.createNewLogger("main.log")
core_logger.info(f"Platform Launch Vehicle (PLV) version: {PLV_VERSION}")

# Now import security 
import Security
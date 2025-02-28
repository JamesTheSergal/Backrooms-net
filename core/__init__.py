# Import core first and let PLV work itself out.
from core import PLV

from core.PLV import Logging, Scheduler, AddonSystem

# Attempt to call for a global logger to get this show on the road
core_logger = PLV.Logging.classic.createNewLogger("main.log")
core_logger.info(f"Platform Launch Vehicle (PLV) version: {PLV.PLV_VERSION}")

# Now import security 
import Security
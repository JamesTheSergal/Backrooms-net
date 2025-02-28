PLV_VERSION = "0.0.1-alpha" # Project launch vehicle

# Initilize logging so we can output
import core.PLV.Logging as Logging
import core.PLV.Logging.classic
import core.PLV.Logging.extended
import core.PLV.Logging.profiler

PLVGlobalLogger = Logging.classic.createNewLogger("PLV-App.log")

import core.PLV.AddonSystem as AddonSystem
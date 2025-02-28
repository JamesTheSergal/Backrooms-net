PLV_VERSION = "0.0.1-alpha" # Project launch vehicle

# Initilize logging so we can output

import core.PLV.Logging as PLVLog
PLVGlobalLogger = PLVLog.createNewLogger("PLV-APP")

import core.PLV.AddonSystem as AddonSystem
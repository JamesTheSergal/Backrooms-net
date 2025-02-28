from core.PLV import PLVGlobalLogger as logger
import core.PLV 
logger.info("Starting Addon system initilization...")

from core.PLV.AddonSystem.Addon import v1
from core.PLV.AddonSystem.Addon.v1 import AddonDefaultSettings, properties

logger.info("Completed import chain. Looking for addons in external folder.")

import addons
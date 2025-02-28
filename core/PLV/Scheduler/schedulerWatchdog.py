import time
from core.PLV.Scheduler import logger

def watchdogThread(self):
    
    while True:
        logger.info("Scheduler watchdog is still running!")
        time.sleep(60)
import logging
import time
import brCore
import asyncio


def minimal():
    brCore.printstartfancy(brCore.BR_VERSION)
    logging.info("Node initilization...")
    
    # Load our settings
    nodeSettings = brCore.settings.brSettings()

    if not nodeSettings.settingsExisted:
        logging.warning("Settings did not exist on startup. 'BR.conf' has been created. Please check the values and restart.")
        exit()
    else:
        pass
    
    friendlyName = nodeSettings.getStrSetting('network', 'friendly-node-name')
    DHTPort = nodeSettings.getIntSetting('network', 'brDHT-port')
    
    mainDHT = brCore.brDHT(DHTPort)
    mainDHT.start()

    
    try:
        while True:
            time.sleep(5)

    except KeyboardInterrupt:
        logging.info("Got keyboard inturrupt.")
        logging.info("Main thread exiting...")

if __name__ == "__main__":
    minimal()
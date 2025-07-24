import logging
import time
import brCore
import asyncio
from brCore import Enclave


def minimal():
    brCore.printstartfancy(brCore.BR_VERSION)
    logging.info("Node initilization...")
    
    # Load our settings
    nodeSettings = brCore.settings.brSettings()

    # Tell user to update settings
    if not nodeSettings.settingsExisted:
        logging.warning("Settings did not exist on startup. 'BR.conf' has been created. Please check the values and restart.")
        exit()
    else:
        pass
    
    friendlyName = nodeSettings.getStrSetting('network', 'friendly-node-name')
    DHTPort = nodeSettings.getIntSetting('network', 'brDHT-port')
    
    mainDHT = brCore.brDHT(DHTPort)
    
    try:  
        mainDHT.setRequest(friendlyName, "Hello")
        mainDHT.asyncloop.run_forever()

    except KeyboardInterrupt:
        logging.info("Got keyboard inturrupt.")
        brCore.mainEnclave.saveEnclaveFile(overwrite=True)
        logging.info("Main thread exiting...")

if __name__ == "__main__":
    minimal()
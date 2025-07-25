import logging
import time
import brCore
import asyncio
from brCore import Enclave, mainDHT


def minimal():
    brCore.printstartfancy(brCore.BR_VERSION)
    logging.info("Node initilization...")
    
    # Load our settings
    nodeSettings = brCore.brCoreSettings

    # Tell user to update settings
    if not nodeSettings.settingsExisted:
        logging.warning("Settings did not exist on startup. 'BR.conf' has been created. Please check the values and restart.")
        exit()
    else:
        pass
    
    friendlyName = nodeSettings.getStrSetting('network', 'friendly-node-name')
    
    try:  
        mainDHT.setRequest(friendlyName, brCore.mainEnclave.returnData("PublicKey").save_pkcs1())
        mainDHT.asyncloop.run_forever()

    except KeyboardInterrupt:
        logging.info("Got keyboard inturrupt.")
        brCore.mainEnclave.saveEnclaveFile(overwrite=True)
        logging.info("Main thread exiting...")

if __name__ == "__main__":
    minimal()
import os
import configparser
from names_generator import generate_name

class brSettings():

    def __init__(self):
        self.settingsExisted = False
        self.settingsObj:configparser.ConfigParser = None

        if not os.path.isfile("BR.conf"):
            settings = configparser.ConfigParser()
            
            # Defaults
            settings['security'] = {
                'enclave-name': "000_default",
                'dump-enclave-at-exit': False
                
            }

            settings['network'] = {
                'bind-address': '127.0.0.1',
                'webresponder-port': 23332,
                'brNode-port': 23334,
                'brDHT-port': 23338,
                'friendly-node-name': generate_name(style="underscore")
            }
            settings['enclave'] = {
                'enclave-name': "000_default",
                'dump-enclave-at-exit': False
                
            }
            settings['logging'] = {
                'globalLogLevel': "info",
                'enclaveLogLevel': "info",
                'debug': True,
                'anon-logging': False
            }
            settings['production'] = {
                'testing': False,
            }

            with open("BR.conf", 'w') as configfile:
                settings.write(configfile)
            
            self.settingsObj = settings

        else:
            self.settingsExisted = True
            settings = configparser.ConfigParser()
            settings.read("BR.conf")
            self.settingsObj = settings

    def getStrSetting(self, cfgsection:str, item:str):
        #TODO: Add exception for config parser NoOptionError
        return self.settingsObj.get(cfgsection, item)
    
    def getIntSetting(self, cfgsection:str, item:str):
        return self.settingsObj.getint(cfgsection, item)
    
    def getBoolSetting(self, cfgsection:str, item:str):
        return self.settingsObj.getboolean(cfgsection, item)

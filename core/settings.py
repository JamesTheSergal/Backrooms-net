import os
import configparser

class brSettings():

    def __init__(self):
        self.settingsExisted = False
        self.settingsObj:configparser.ConfigParser = None

        if not os.path.isfile("BR.conf"):
            settings = configparser.ConfigParser()
            settings['network'] = {
                'bind-address': '127.0.0.1',
                'webresponder-port': 80
            }
            settings['security'] = {
                'debug': True,
                'enclave-name': "000_default",
                'anon-logging': True
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
        return self.settingsObj.get(cfgsection, item)
    
    def getIntSetting(self, cfgsection:str, item:str):
        return self.settingsObj.getint(cfgsection, item)
    
    def getBoolSetting(self, cfgsection:str, item:str):
        return self.settingsObj.getboolean(cfgsection, item)

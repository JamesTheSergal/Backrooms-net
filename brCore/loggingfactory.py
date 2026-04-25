import logging
import time
from dataclasses import dataclass

def setDefault(logpath:str=""):
    logging.basicConfig(
            encoding="utf-8",
            format="{asctime}.{msecs} - [{thread} {module}.{funcName}:({lineno})] - [{levelname}] - {message}",
            style="{",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO,
            handlers=[
                logging.FileHandler(logpath+"node.log", mode='a'),
                logging.StreamHandler()
            ]
    )

def getDefaultLogger():
    return logging.getLogger()

def createNewLogger(name, path="./", level=logging.DEBUG):

    defaultformat = logging.Formatter(
        "{asctime}.{msecs} - [{thread} {module}.{funcName}:({lineno})] - [{levelname}] - {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    

    if name not in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(name)

        logger.setLevel(level)
        logger.propagate = False

        file_handler = logging.FileHandler(f'{path+name}.log', mode='a')
        console_handler = logging.StreamHandler()

        file_handler.setFormatter(defaultformat)
        console_handler.setFormatter(defaultformat)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    else:
        logger = logging.getLogger(name)

    return logger

class timeProfiler:

    def __init__(self, name) -> None:
        self.name = name

    def timeindex():
      # Time in milliseconds
      return int(time.time() * 1000)

    def difference(first, last):
        return last - first

    def deltaCheck(self, timestamp: int, offset: int):
        if self.timeindex() < (timestamp+offset):
            return True
        else:
            return False

    def reportPrecisionTime(self, func):
        def inner(name:str):
            start = self.timeindex()
            func()
            end = self.timeindex()
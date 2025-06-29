import logging
import time

def setDefault():
    logging.basicConfig(
            encoding="utf-8",
            format="{asctime}.{msecs} - [{thread} {module}.{funcName}:({lineno})] - [{levelname}] - {message}",
            style="{",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO,
            handlers=[
                logging.FileHandler("node.log", mode='a'),
                logging.StreamHandler()
            ]
    )

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
        self.a = 0
        self.b = 0
        self.logger = createNewLogger(name+"_timeProfiler", "./temp/")

    def s(self):
        self.a = time.time()

    def e(self):
        self.b = time.time()
        diff = round(int(self.b * 1000) - int(self.a * 1000), 2)
        self.logger.debug(f'{self.name} took {diff}ms')
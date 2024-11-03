import logging

logging.basicConfig(
        encoding="utf-8",
        format="{asctime}.{msecs} - [{thread} {module}.{funcName}:({lineno})] - [{levelname}] - {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler("node.log", mode='a'),
            logging.StreamHandler()
        ]
)

def createNewLogger(name):

    defaultformat = logging.Formatter(
        "{asctime}.{msecs} - [{thread} {module}.{funcName}:({lineno})] - [{levelname}] - {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    

    if name not in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(name)

        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        file_handler = logging.FileHandler(f'{name}.log', mode='a')
        console_handler = logging.StreamHandler()

        file_handler.setFormatter(defaultformat)
        console_handler.setFormatter(defaultformat)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    else:
        logger = logging.getLogger(name)

    return logger
BR_VERSION = "0.0.1-alpha"

# Set up logging for this module
from .loggingfactory import setDefault, createNewLogger
setDefault()

# create our general logs
brLog = createNewLogger("backrooms-net")

# Low level socket logs
brAgentLog = createNewLogger("brNodeAgent")
brServeLog = createNewLogger("brNodeServe")
brNodeHsLog = createNewLogger("brNodeHandshakes")

import brCore.brSockets
from brCore.brSockets.brNodeAgent import brSocketAgent
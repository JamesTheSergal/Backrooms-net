from .. import BR_VERSION
from .. import loggingfactory

brNodeHsLog = loggingfactory.getDefaultLogger()
brAgentLog = loggingfactory.getDefaultLogger()
brNodeCoreLog = loggingfactory.getDefaultLogger()

# Import protocols
import brCore.brSockets.brProtocols

import brCore.brSockets.brPacket
from brCore.brSockets.brNodeAgent import brSocketAgent
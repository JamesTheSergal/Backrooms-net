from core.brWebCore import brWebServer
from core.brWebCore import brWebPage
from core.notrustvars import enclave
from core.loggingfactory import timeProfiler
from node import BR_VERSION
import threading
import uuid


# I did not write this
# Code is from: https://stackoverflow.com/questions/12523586/python-format-size-application-converting-b-to-kb-mb-gb-tb
def humanbytes(B):
    """Return the given bytes as a human friendly KB, MB, GB, or TB string."""
    B = float(B)
    KB = float(1024)
    MB = float(KB ** 2) # 1,048,576
    GB = float(KB ** 3) # 1,073,741,824
    TB = float(KB ** 4) # 1,099,511,627,776

    if B < KB:
        return '{0} {1}'.format(B,'Bytes' if 0 == B > 1 else 'Byte')
    elif KB <= B < MB:
        return '{0:.2f} KB'.format(B / KB)
    elif MB <= B < GB:
        return '{0:.2f} MB'.format(B / MB)
    elif GB <= B < TB:
        return '{0:.2f} GB'.format(B / GB)
    elif TB <= B:
        return '{0:.2f} TB'.format(B / TB)

def genHeader():
        content = (
            "<head>\n"
            "<title>Backrooms-net Node</title>\n"
            '<meta name="twitter:title" content="Backrooms-net Node">\n'
            '<meta name="twitter:description" content="A secure node based communications network.">\n'
            "</head>\n"
            "<html>\n"
        )
        return content

def genNavBar(links:dict={}):
    navContent = (
        "<h1>Hello from the backrooms!&nbsp;</h1>\n" 
        "<p>\n"
    )

    for key in links.keys():
        navContent += f'<a href="{links[key]}">{key}</a>&nbsp;'
    navContent += "\n"
    navContent += "</p>\n"
    navContent += "<hr />\n"
    
    return navContent
     
def genBody(internalContent):
    content = (
        "<body>\n"
        + internalContent +
        "</body>\n"
    )
    return content

def genFooter():
    content = (
        "</html>\n"
        '<hr />\n'
        f'<pre><em>Running Backrooms-net node <span style="text-decoration: underline;">{BR_VERSION}</span></em></pre>\n'
    )
    return content

def genForm(postEndpoint, formName, dataName, formButtonText):
        content = (
            f'<form action={postEndpoint} method="post">\n'
            f'<label for="{dataName}">{formName}</label>\n'
            f'<input type="text" id="{dataName}" name="{dataName}"><br>\n'
            f'<input type="submit" value="{formButtonText}">\n'
            f'</form>\n'
        )
        return content
    
def genFileForm(postEndpoint, formName, dataName, formButtonText):
    content = (
        f'<form action="{postEndpoint}" method="post" enctype="multipart/form-data">\n'
        f'<label for="{dataName}">{formName}</label>\n'
        f'<input type="file" id="{dataName}" name="{dataName}">\n'
        f'<input type="submit" value="{formButtonText}">\n'
        f'</form>\n'
    )
    return content

class brWebUIModule(brWebPage):

    def __init__(self, secureEnclave: enclave) -> None:
        brWebPage.__init__(self)
        super().__init__()
        self.secureEnclave = secureEnclave # Threading locks are already implemented in the Enclave
        pass

    def brUIRoot(self, context: brWebServer.packetParser):
        self.addContent(
            genHeader() +
            genBody(
                genNavBar(
                      {
                        "Our Public Key": "/pubkey",
                        "Open Insecure Route": "/insecureannounce",
                        "Open Secure Route": "/announce",
                        "Stats": "/stats",
                      }
                ) +
                f'Welcome to the backrooms!\n'
            ) +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
        
    
    def brAnnouncePost(self, context: brWebServer.packetParser):
        self.addContent(context.bodyData)
        self.setOK()
        return self.buildResponse(context)

    def brAnnounce(self, context: brWebServer.packetParser):
        self.addContent(
            genHeader() +
            genNavBar() +
            genForm("/announce/publickey", "Your Public Key", "client-pub-key", "Submit") +
            genFileForm("/announce/publickey", "Or a public key file", "client-pub-key", "Submit") +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
    
    def clientGetUUID4(self, context: brWebServer.packetParser):
         self.addContent(
              str(uuid.uuid4())
         )
         self.setOK()
         return self.buildResponse(context)

    def ourPublicKey(self, context: brWebServer.packetParser):
        pubkey = self.secureEnclave.returnData("PublicKey")
        strkey = pubkey.save_pkcs1().decode('utf-8')
        self.addContent(
            f'<body><p>{strkey}</p></body>'
        )
        self.setOK()
        return self.buildResponse(context)
    
    def statsPage(self, context: brWebServer.packetParser):
        inBytes = self.secureEnclave.returnData("brWebCore_incomingBytes")
        outBytes = self.secureEnclave.returnData("brWebCore_outgoingBytes")
        requests = self.secureEnclave.returnData("brWebCore_requests")
        errors = self.secureEnclave.returnData("brWebCore_errors")
        connections = self.secureEnclave.returnData("brWebCore_connections")

        self.addContent(
            genHeader() +
            genNavBar() +
            genBody(
                 f'<p>We have handled {humanbytes(inBytes)} In</p>\n' +
                 f'<p>We have handled {humanbytes(outBytes)} Out</p>\n' +
                 f'<p>We have handled {requests} Requests</p>\n' +
                 f'<p>We have had {errors} Errors</p>\n' +
                 f'<p>We currently have {connections} Connections</p>\n'
            ) +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
    
    
    
    
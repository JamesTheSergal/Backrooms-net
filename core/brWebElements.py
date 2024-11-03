from core.brWebCore import brWebServer
from core.brWebCore import brWebPage
from node import BR_VERSION
import threading

def genHeader():
        content = (
            "<head>\n"
            "<title>Backrooms-net Node</title>\n"
            '<meta name="twitter:title" content="Backrooms-net Node">\n'
            '<meta name="twitter:description" content="A secure node based communications network.">\n'
            "</head>\n"
            "<html>\n"
            "<h1>Hello from the backrooms!&nbsp;</h1>\n"
            "<hr />\n"
        )
        return content
    
def genBody():
    content = (
        "<body>\n"
        "<p>The node is up and running! Good job!</p>"
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

    def __init__(self) -> None:
        brWebPage.__init__(self)
        super().__init__()
        pass

    def brUIRoot(self, context: brWebServer.packetParser):
        self.addContent(
            genHeader() +
            genBody() +
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
            genForm("/announce/publickey", "Your Public Key", "client-pub-key", "Submit") +
            genFileForm("/announce/publickey", "Or a public key file", "client-pub-key", "Submit") +
            genFooter()
        )
        self.setOK()
        return self.buildResponse(context)
    
    
    
    
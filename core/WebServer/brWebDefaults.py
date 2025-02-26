from core.brWebCore import brWebServer
from node import BR_VERSION

def defaultFourOhFour(context: brWebServer.packetParser):
    targetPath = context.requestPath
    head = (
        "<head>\n"
        "<title>Backrooms-net Node - 404!</title>\n"
        '<meta name="twitter:title" content="Backrooms-net Node">\n'
        '<meta name="twitter:description" content="A secure node based communications network.">\n'
        "</head>\n"
    )
    body = (
        "<body>\n"
        '<h1><span style="text-decoration: underline;"><span style="color: #ff0000; text-decoration: underline;">404! - Not found</span></span></h1>\n'
        '<hr />\n'
        f'<p>We could not find: "{targetPath}" on this server.</p>\n'
        "</body>\n"
    )
    footer = (
        '<hr />\n'
       f'<pre><em>Running Backrooms-net node <span style="text-decoration: underline;">{BR_VERSION}</span></em></pre>\n'
    )

    bodydata = head + body + footer
    bodydata = bytes(bodydata, encoding='utf-8')

    reply = brWebServer.requestResponse(
            data=bodydata,
            serverStatus=brWebServer.requestResponse.NOT_FOUND,
            connectionType=brWebServer.requestResponse.KEEP_ALIVE
    )

    return reply

def defaultServerError():
    head = (
        "<head>\n"
        "<title>Backrooms-net Node - 500!</title>\n"
        '<meta name="twitter:title" content="Backrooms-net Node">\n'
        '<meta name="twitter:description" content="A secure node based communications network.">\n'
        "</head>\n"
    )
    body = (
        "<body>\n"
        '<h1><span style="text-decoration: underline;"><span style="color: #ff0000; text-decoration: underline;">500! - Internal Error</span></span></h1>\n'
        '<hr />\n'
        f'<p>Sorry, we encountered an internal error while processing your request.</p>\n'
        "</body>\n"
    )
    footer = (
        '<hr />\n'
       f'<pre><em>Running Backrooms-net node <span style="text-decoration: underline;">{BR_VERSION}</span></em></pre>\n'
    )

    bodydata = head + body + footer
    bodydata = bytes(bodydata, encoding='utf-8')

    reply = brWebServer.requestResponse(
            data=bodydata,
            serverStatus=brWebServer.requestResponse.SERVER_ERROR,
            connectionType=brWebServer.requestResponse.KEEP_ALIVE
    )

    return reply

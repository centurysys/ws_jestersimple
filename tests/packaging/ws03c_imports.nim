# WS-03c: check the independent package/module namespace and both constructors.
import std/[asyncdispatch, asynchttpserver]
import jestersimple
import ws_jestersimple
import ws_jestersimple/jestersimple_extra

static:
  doAssert declared(WebSocket)
  doAssert DefaultMaxFrameBytes > 0
  doAssert DefaultMaxMessageBytes > 0

# Ensure both constructor overloads are available under their intended modules.
proc fromStdHttp(req: asynchttpserver.Request): Future[WebSocket] =
  ws_jestersimple.newWebSocket(req)

proc fromJesterSimple(req: jestersimple.Request): Future[WebSocket] =
  jestersimple_extra.newWebSocket(req)

when isMainModule:
  echo "WS-03c module imports OK"

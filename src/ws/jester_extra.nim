import asyncdispatch, asynchttpserver, jesterfork, jesterfork/private/utils,
    nativesockets, strutils
import ../ws

when useHttpBeast:
  import httpbeastfork, options, asyncnet

  proc newWebSocket*(req: httpbeastfork.Request): Future[WebSocket] {.async.} =
    ## Creates a new socket from an httpbeast request.
    try:
      let headers = req.headers.get

      if not headers.hasKey("Sec-WebSocket-Version"):
        req.send(Http404, "Not Found")
        raise newException(WebSocketHandshakeError, "Not a valid websocket handshake.")

      var ws = WebSocket()
      ws.masked = false

      # Here is the magic:
      req.forget() # Remove from HttpBeast event loop.
      asyncdispatch.register(req.client.AsyncFD) # Add to async event loop.

      ws.tcpSocket = newAsyncSocket(req.client.AsyncFD)
      await ws.handshake(headers)
      return ws

    except ValueError, KeyError:
      # Wrap all exceptions in a WebSocketCreationError so its easy to catch
      raise newException(
        WebSocketCreationError,
        "Failed to create WebSocket from request: " & getCurrentExceptionMsg()
      )

proc newWebSocket*(req: jesterfork.Request): Future[WebSocket] {.async.} =
  ## Creates a new socket from a jester request.
  return await newWebSocket(req.getNativeReq())

# WS-02a: loopback-only test server for wire-level Close behavior.
import std/[asyncdispatch, asynchttpserver, asyncnet, net, os, strutils]
import ws_jestersimple

# -----------------------------------------------------------------------------
# Test both directions of the Close handshake and the legacy close() wrapper.
# -----------------------------------------------------------------------------
proc handleRequest(req: Request) {.async.} =
  if req.url.path == "/health":
    await req.respond(Http200, "alive")
    return

  var socket: WebSocket
  try:
    socket = await newWebSocket(req)
    case req.url.path
    of "/peer-close":
      let (kind, _) = await socket.receivePacket()
      doAssert kind == Close
      doAssert socket.readyState == Closed
    of "/server-close", "/duplicate-close":
      await socket.closeAsync()
      if req.url.path == "/duplicate-close":
        await socket.closeAsync()
      doAssert socket.readyState == Closing
      let (kind, _) = await socket.receivePacket()
      doAssert kind == Close
      doAssert socket.readyState == Closed
    of "/no-reply":
      await socket.closeAsync()
      # The test application deliberately limits how long it waits for a peer.
      # ws-level read/idle timeouts are a separate step (WS-03a).
      await sleepAsync(150)
    of "/legacy-close":
      socket.close()
      # Keep this direct-socket callback alive for the legacy async close.
      await sleepAsync(100)
      doAssert socket.readyState == Closed
    else:
      discard
  except CatchableError as exc:
    stderr.writeLine("WS-02a server: " & exc.msg)
  finally:
    if not socket.isNil and cast[int](socket.tcpSocket.getFd()) != -1:
      try:
        socket.hangup()
      except CatchableError:
        discard

let port = Port(parseInt(getEnv("WS02A_PORT", "5542")))
var server = newAsyncHttpServer()
waitFor server.serve(port, handleRequest, address = "127.0.0.1")

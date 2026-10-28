# WS-02b: loopback server for split TCP reads and truncated frames.
import std/[asyncdispatch, asynchttpserver, asyncnet, net, os, strutils]
import ws

var eofCount = 0
var closedEofCount = 0
var unexpectedComplete = 0

# -----------------------------------------------------------------------------
# Serve regular HTTP and WebSocket reads on the same loopback listener.
# The transport belongs to this standalone test server, not to ws.
# -----------------------------------------------------------------------------
proc handleRequest(req: Request) {.async.} =
  if req.url.path == "/health":
    await req.respond(Http200, "alive")
    return
  if req.url.path == "/stats":
    await req.respond(Http200,
      $eofCount & "," & $closedEofCount & "," & $unexpectedComplete)
    return

  var socket: WebSocket
  try:
    socket = await newWebSocket(req)
    case req.url.path
    of "/echo":
      while socket.readyState == Open:
        let (kind, payload) = await socket.receivePacket()
        case kind
        of Text, Binary:
          await socket.send(payload, kind)
        of Close:
          break
        else:
          discard
    of "/eof":
      discard await socket.receivePacket()
      inc unexpectedComplete
      await socket.send("unexpected-complete-frame")
    else:
      discard
  except WebSocketClosedError:
    inc eofCount
    if not socket.isNil and socket.readyState == Closed:
      inc closedEofCount
  except CatchableError as exc:
    stderr.writeLine("WS-02b server: " & exc.msg)
  finally:
    if not socket.isNil and cast[int](socket.tcpSocket.getFd()) != -1:
      try:
        socket.hangup()
      except CatchableError:
        discard

let port = Port(parseInt(getEnv("WS02B_PORT", "5543")))
var server = newAsyncHttpServer()
waitFor server.serve(port, handleRequest, address = "127.0.0.1")

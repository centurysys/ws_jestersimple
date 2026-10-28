# WS-02d: RFC 6455 receive-side frame validation and fragment handling.
import std/[asyncdispatch, asynchttpserver, asyncnet, net, os, strutils]
import ws_jestersimple

var protocolRejects = 0
var unexpectedErrors = 0
var messages = 0

# -----------------------------------------------------------------------------
# Handle HTTP health/stats and echo valid WebSocket messages on loopback.
# -----------------------------------------------------------------------------
proc handleRequest(req: Request) {.async.} =
  if req.url.path == "/health":
    await req.respond(Http200, "alive")
    return
  if req.url.path == "/stats":
    await req.respond(Http200, $protocolRejects & "," & $unexpectedErrors &
      "," & $messages)
    return

  var socket: WebSocket
  try:
    socket = await newWebSocket(req)
    while socket.readyState == Open:
      let (kind, payload) = await socket.receivePacket()
      case kind
      of Text, Binary:
        inc messages
        await socket.send(payload, kind)
      of Ping:
        await socket.send(payload, Pong)
      of Pong:
        discard
      of Close:
        break
      of Cont:
        inc unexpectedErrors
        break
  except WebSocketFrameProtocolError:
    inc protocolRejects
  except WebSocketClosedError:
    discard
  except CatchableError as exc:
    inc unexpectedErrors
    stderr.writeLine("WS-02d unexpected error: " & exc.msg)
  finally:
    if not socket.isNil and cast[int](socket.tcpSocket.getFd()) != -1:
      try:
        socket.hangup()
      except CatchableError:
        discard

let port = Port(parseInt(getEnv("WS02D_PORT", "5545")))
var server = newAsyncHttpServer()
waitFor server.serve(port, handleRequest, address = "127.0.0.1")

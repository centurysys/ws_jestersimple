# WS-02c: verify full 64-bit lengths and bounded frame/message reception.
import std/[asyncdispatch, asynchttpserver, asyncnet, net, os, strutils]
import ws_jestersimple

var frameRejects = 0
var messageRejects = 0
var lengthRejects = 0
var unexpectedErrors = 0
var messages = 0

# -----------------------------------------------------------------------------
# Serve HTTP statistics and bounded WebSocket echo on a loopback listener.
# -----------------------------------------------------------------------------
proc handleRequest(req: Request) {.async.} =
  if req.url.path == "/health":
    await req.respond(Http200, "alive")
    return
  if req.url.path == "/stats":
    await req.respond(Http200, $frameRejects & "," & $messageRejects & "," &
      $lengthRejects & "," & $unexpectedErrors & "," & $messages)
    return

  var socket: WebSocket
  try:
    socket = await newWebSocket(req)
    if req.url.path == "/bounded":
      socket.setReceiveLimits(1024, 2048)

    while socket.readyState == Open:
      let (kind, payload) = await socket.receivePacket()
      case kind
      of Text, Binary:
        inc messages
        await socket.send(payload, kind)
      of Close:
        break
      else:
        discard
  except WebSocketFrameLengthError:
    inc lengthRejects
  except WebSocketFrameTooLargeError:
    inc frameRejects
  except WebSocketMessageTooLargeError:
    inc messageRejects
  except WebSocketClosedError:
    discard
  except CatchableError as exc:
    inc unexpectedErrors
    stderr.writeLine("WS-02c unexpected error: " & exc.msg)
  finally:
    if not socket.isNil and cast[int](socket.tcpSocket.getFd()) != -1:
      try:
        socket.hangup()
      except CatchableError:
        discard

let port = Port(parseInt(getEnv("WS02C_PORT", "5544")))
var server = newAsyncHttpServer()
waitFor server.serve(port, handleRequest, address = "127.0.0.1")

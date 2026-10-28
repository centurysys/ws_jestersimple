# WS-03a: control-frame receive helpers, periodic Ping lifetime and deadlines.
import std/[asyncdispatch, asynchttpserver, asyncnet, net, os, strutils]
import ws_jestersimple

var readTimeouts = 0
var heartbeatTimeouts = 0
var unexpected = 0

# -----------------------------------------------------------------------------
# Exercise receive helpers, explicit timeouts and periodic Ping task shutdown.
# -----------------------------------------------------------------------------
proc handleRequest(req: Request) {.async.} =
  if req.url.path == "/health":
    await req.respond(Http200, "alive")
    return
  if req.url.path == "/stats":
    await req.respond(Http200, $readTimeouts & "," & $heartbeatTimeouts &
      "," & $unexpected)
    return

  var ws: WebSocket
  try:
    ws = await newWebSocket(req)
    case req.url.path
    of "/text", "/default-idle":
      if req.url.path == "/default-idle":
        ws.setReadTimeout(0)
      let text = await ws.receiveStrPacket()
      await ws.send(text)
      discard await ws.receivePacket()
    of "/binary":
      let bytes = await ws.receiveBinaryPacket()
      var data = newString(bytes.len)
      for i, value in bytes:
        data[i] = char(value)
      await ws.send(data, Binary)
      discard await ws.receivePacket()
    of "/raw":
      let (opcode, payload) = await ws.receivePacket()
      if opcode != Ping or payload != "raw":
        raise newException(ValueError, "receivePacket must expose Ping")
      await ws.send("raw-ok")
      discard await ws.receivePacket()
    of "/read-idle", "/read-partial":
      ws.setReadTimeout(180)
      discard await ws.receiveStrPacket()
    of "/heart-ok", "/heart-timeout", "/heart-wrong-pong":
      ws.setHeartbeatTimeout(170)
      ws.setupPings(0.07)
      let text = await ws.receiveStrPacket()
      await ws.send(text)
      discard await ws.receivePacket()
    of "/stop":
      ws.setupPings(0.06)
      await sleepAsync(165)
      ws.stopPings()
      await ws.send("stopped")
      await sleepAsync(200)
      await ws.closeAsync()
      discard await ws.receivePacket()
    of "/replace":
      ws.setupPings(0.055)
      await sleepAsync(165)
      ws.setupPings(0.30)
      await ws.send("replaced")
      await sleepAsync(200)
      await ws.closeAsync()
      discard await ws.receivePacket()
    of "/config":
      var rejected = 0
      for value in [-1, -42]:
        try:
          ws.setReadTimeout(value)
        except ValueError:
          inc rejected
        try:
          ws.setHeartbeatTimeout(value)
        except ValueError:
          inc rejected
      for seconds in [0.0, -1.0]:
        try:
          ws.setupPings(seconds)
        except ValueError:
          inc rejected
      try:
        await ws.ping(newString(126))
      except ValueError:
        inc rejected
      await ws.send($rejected)
      discard await ws.receivePacket()
    else:
      raise newException(ValueError, "Unknown WS-03a route")
  except WebSocketReadTimeoutError:
    inc readTimeouts
  except WebSocketHeartbeatTimeoutError:
    inc heartbeatTimeouts
  except WebSocketClosedError:
    discard
  except CatchableError as exc:
    inc unexpected
    stderr.writeLine("WS-03a unexpected: " & exc.msg)
  finally:
    if not ws.isNil:
      ws.stopPings()
      if not ws.tcpSocket.isClosed:
        try:
          ws.hangup()
        except CatchableError:
          discard

let port = Port(parseInt(getEnv("WS03A_PORT", "5546")))
var server = newAsyncHttpServer()
waitFor server.serve(port, handleRequest, address = "127.0.0.1")

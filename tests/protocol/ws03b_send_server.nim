# WS-03b: concurrent writers, Close ordering, bounded send queue and deadlines.
import std/[asyncdispatch, asynchttpserver, asyncnet, net, os, strutils]
import ws

var writeTimeouts = 0
var queueRejections = 0
var unexpectedErrors = 0

# -----------------------------------------------------------------------------
# Serve separate paths without coupling to the Jester Simple adapter.
# -----------------------------------------------------------------------------
proc handleRequest(req: Request) {.async.} =
  if req.url.path == "/health":
    await req.respond(Http200, "ok")
    return
  if req.url.path == "/stats":
    await req.respond(Http200, $writeTimeouts & "," & $queueRejections &
      "," & $unexpectedErrors)
    return

  var ws: WebSocket
  try:
    ws = await newWebSocket(req)
    case req.url.path
    of "/concurrent":
      let a = ws.send(repeat("A", 1024 * 1024 + 101))
      let b = ws.send(repeat("B", 1024 * 1024 + 203))
      let c = ws.send("tail")
      await a
      await b
      await c
      if ws.pendingSendBytes() != 0:
        raise newException(ValueError, "Send reservations not released")
      await ws.closeAsync()
      discard await ws.receivePacket()

    of "/close-order":
      let large = ws.send(repeat("Q", 1024 * 1024 + 111))
      let closeFrame = ws.closeAsync()
      await large
      await closeFrame
      discard await ws.receivePacket()

    of "/ping-order":
      let large = ws.send(repeat("P", 1024 * 1024 + 131))
      let pingFuture = ws.ping("ordered")
      await large
      await pingFuture
      await ws.closeAsync()
      discard await ws.receivePacket()

    of "/queue-overlap":
      ws.setSendLimits(2 * 1024 * 1024 + 500)
      let first = ws.send(repeat("C", 1024 * 1024 + 101))
      let second = ws.send(repeat("D", 1024 * 1024 + 203))
      var rejected = false
      try:
        await ws.send(repeat("E", 1024 * 1024 + 333))
      except WebSocketSendQueueFullError:
        rejected = true
        inc queueRejections
      if not rejected:
        raise newException(ValueError, "Expected overlapping send rejection")
      await first
      await second
      await ws.closeAsync()
      discard await ws.receivePacket()

    of "/limit":
      ws.setSendLimits(128)
      var rejected = false
      try:
        await ws.send(repeat("X", 128))
      except WebSocketSendQueueFullError:
        rejected = true
        inc queueRejections
      if not rejected:
        raise newException(ValueError, "Expected send queue rejection")
      await ws.send("limit-ok")
      if ws.pendingSendBytes() != 0:
        raise newException(ValueError, "Send reservation leaked")
      discard await ws.receivePacket()

    of "/config":
      var rejected = 0
      for value in [-1, -100]:
        try:
          ws.setWriteTimeout(value)
        except ValueError:
          inc rejected
        try:
          ws.setSendLimits(value)
        except ValueError:
          inc rejected
      try:
        ws.setSendLimits(0)
      except ValueError:
        inc rejected
      await ws.send($rejected)
      discard await ws.receivePacket()

    of "/slow-reader":
      # Only this test is allowed a larger output budget.
      ws.setSendLimits(8 * 1024 * 1024)
      ws.setWriteTimeout(250)
      await ws.send(repeat("S", 6 * 1024 * 1024))
      raise newException(ValueError, "Slow reader did not hit write deadline")

    of "/echo":
      let text = await ws.receiveStrPacket()
      await ws.send(text)
      discard await ws.receivePacket()

    else:
      raise newException(ValueError, "Unknown WS-03b route")
  except WebSocketWriteTimeoutError:
    inc writeTimeouts
  except WebSocketClosedError:
    discard
  except CatchableError as exc:
    inc unexpectedErrors
    stderr.writeLine("WS-03b unexpected: " & exc.msg)
  finally:
    if not ws.isNil:
      ws.stopPings()
      if not ws.tcpSocket.isClosed:
        try:
          ws.hangup()
        except CatchableError:
          discard

let port = Port(parseInt(getEnv("WS03B_PORT", "5547")))
var server = newAsyncHttpServer()
waitFor server.serve(port, handleRequest, address = "127.0.0.1")

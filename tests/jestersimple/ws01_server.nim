# WS-01: loopback-only Jester Simple / treeform-ws integration server.
import std/[net, os, strutils]
import jestersimple
import ws
import ws/jestersimple_extra

settings:
  port = Port(parseInt(getEnv("WS01_PORT", "5541")))
  bindAddr = "127.0.0.1"
  maxConnections = 2
  keepAliveTimeoutMs = 1500

routes:
  get "/ping":
    resp "pong"

  get "/ws":
    try:
      let socket = await newWebSocket(request)
      enableRawMode
      # WS-01 tests only small, complete RFC 6455 frames. Existing ws.recvFrame
      # is not safe against arbitrary fragmented TCP input or huge lengths.
      while socket.readyState == Open:
        let (opcode, payload) = await socket.receivePacket()
        case opcode
        of Text, Binary:
          await socket.send(payload, opcode)
        of Close:
          break
        else:
          break
    except WebSocketHandshakeError:
      # This exception is raised strictly before beginUpgrade().
      resp Http400, "invalid-websocket-handshake"
    except WebSocketClosedError:
      enableRawMode
    except CatchableError:
      if request.upgradeStarted:
        # Once reserved, never send a second HTTP response.
        enableRawMode
      else:
        resp Http500, "websocket-failure"

  get "/ws-protocol":
    try:
      let socket = await newWebSocket(request, "chat")
      enableRawMode
      let (opcode, payload) = await socket.receivePacket()
      if opcode == Text:
        await socket.send(payload)
    except WebSocketHandshakeError:
      resp Http400, "invalid-websocket-handshake"
    except WebSocketClosedError:
      enableRawMode
    except CatchableError:
      if request.upgradeStarted:
        enableRawMode
      else:
        resp Http500, "websocket-failure"

  get "/ws-fault":
    try:
      discard await newWebSocket(request)
      enableRawMode
      raise newException(ValueError, "WS-01 deliberate post-101 failure")
    except WebSocketHandshakeError:
      resp Http400, "invalid-websocket-handshake"
    except CatchableError:
      # Transport must close the upgraded socket, not append HTTP 500.
      if request.upgradeStarted:
        enableRawMode
      else:
        resp Http500, "websocket-failure"

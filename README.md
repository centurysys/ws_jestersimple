# ws_jestersimple

This is the `ws_jestersimple` fork, derived from `treeform/ws` v0.6.0
(MIT; copyright notices retained in `LICENSE`). Its Nimble package and public
module names intentionally differ from upstream `ws` to prevent accidental
mixing or upgrades. Initial fork release: `0.1.0`.

- Nimble package: `ws_jestersimple` (requires Nim >= 2.2.12 and
  `jestersimple >= 1.0.0`).
- Main module: `import ws_jestersimple`.
- Jester Simple adapter: `import ws_jestersimple/jestersimple_extra`.
- Legacy Jester adapter (optional, requires `jester` separately):
  `import ws_jestersimple/jester_extra`.
- The WebSocket transport is owned by Jester Simple after Upgrade. Keep the
  route Future alive for the full WebSocket session; do not detach it with
  `asyncCheck` and return from the route.
- Debug/Release integration tests:
  `JS_ROOT=/path/to/jester_simple bash tests/packaging/run_ws03c.sh`.

For local development run `nimble develop` in the `jester_simple` repository,
then `nimble develop` in this repository. A checkout of upstream `ws` can
coexist with this fork; import only the desired module.

---

## Original upstream documentation (adapted imports)

<img src="docs/wsBanner.png">

# Simple WebSocket library for nim.

`nimble develop` (from this checkout)

![Github Actions](https://github.com/treeform/ws/workflows/Github%20Actions/badge.svg)

[API reference](https://treeform.github.io/ws)

Unlike upstream, this fork declares a Jester Simple dependency for its adapter.

## About

I love webSockets. They are easy to use and supported everywhere. I use them instead of HTTP REST APIs. I find it much easier to think in terms of client/server messages then verbs and resource paths. Inevitably you want the server to notify the client when some thing changes. Inevitably you will use webSockets. Then you will have two systems. Stop the pain and just use plain webSockets from the start. Say no to REST.

I recommend having only a webSocket server and host static html/js/css files some place like Amazon S3 or Google CloudStore. For HTTPS (or WSS in webSocket case) I usually wrap my webSocket server with Nginx with Let's Encrypt CertBot, and I also have just simply wrapped it with CloudFlare.

This was originally based on the work by niv https://github.com/niv/websocket.nim. Thank you!

This library is being actively developed and we'd be happy for you to use it.

`nimble develop` (from this checkout)

![Github Actions](https://github.com/treeform/ws/workflows/Github%20Actions/badge.svg)

Features:
* Client and Server Side WebSocket
* Async/Await Support
* WebSocket Protocols
* Timeouts and Disconnects
* SSL support
* Jester support
* Compliant with the [WebSocket protocol](https://tools.ietf.org/html/rfc6455).

### Documentation

API reference: https://treeform.github.io/ws/

## Example Echo Server:

Example echo server, will repeat what you send it:

```nim
import asyncdispatch, asynchttpserver, 

var connections = newSeq[WebSocket]()

proc cb(req: Request) {.async, gcsafe.} =
  if req.url.path == "/ws":
    try:
      var ws = await newWebSocket(req)
      connections.add ws
      await ws.send("Welcome to simple chat server")
      while ws.readyState == Open:
        let packet = await ws.receiveStrPacket()
        echo "Received packet: " & packet
        for other in connections:
          if other.readyState == Open:
            asyncCheck other.send(packet)
    except WebSocketClosedError:
      echo "Socket closed. "
    except WebSocketProtocolMismatchError:
      echo "Socket tried to use an unknown protocol: ", getCurrentExceptionMsg()
    except WebSocketError:
      echo "Unexpected socket error: ", getCurrentExceptionMsg()
  await req.respond(Http200, "Hello World")

var server = newAsyncHttpServer()
waitFor server.serve(Port(9001), cb)
```

And then in the browser type this JavaScript:

```js
ws = new WebSocket("ws://localhost:9001/ws")
ws.send("hi")
```

![alt text](tests/echo.png "Echo server example")


## Example Chat Server:

Example chat server, will send what you send to connected all clients.

```nim
import , asyncdispatch, asynchttpserver

var connections = newSeq[WebSocket]()

proc cb(req: Request) {.async, gcsafe.} =
  if req.url.path == "/ws":
    try:
      var ws = await newWebSocket(req)
      connections.add ws
      await ws.send("Welcome to simple chat server")
      while ws.readyState == Open:
        let packet = await ws.receiveStrPacket()
        for other in connections:
          if other.readyState == Open:
            asyncCheck other.send(packet)
    except WebSocketError:
      echo "socket closed:", getCurrentExceptionMsg()
  else:
    await req.respond(Http404, "Not found")

var server = newAsyncHttpServer()
waitFor server.serve(Port(9001), cb)
```

In one browser tab:
```js
// JavaScript code:
ws = new WebSocket("ws://localhost:9001/ws")
ws.send("How are you?")
```

Other browser tab:
```js
// JavaScript code:
ws = new WebSocket("ws://localhost:9001/ws")
ws.send("Good, you?")
```

## Example client socket:

Instead of being the server you are the client connecting to some other server:

```nim
import asyncdispatch, asynchttpserver, 

proc main() {.async.} =
  var ws = await newWebSocket("ws://127.0.0.1:9001/ws")
  echo await ws.receiveStrPacket()
  await ws.send("Hi, how are you?")
  echo await ws.receiveStrPacket()
  ws.close()

waitFor main()
```

SSL is also supported:
```nim
var ws = await newWebSocket("wss://echo.websocket.org")
```

You can also pass a protocol
```nim
var ws = await newWebsocket("wss://echo.websocket.org", protocol = "alpha")
```

## Using with Jester

The optional legacy `jester` adapter is retained separately, but requires `jester` to be installed:

```nim
import jester
import ws_jestersimple, ws_jestersimple/jester_extra

routes:
  get "/ws":
    var ws = await newWebSocket(request)
    await ws.send("Welcome to simple echo server")
    while ws.readyState == Open:
      let packet = await ws.receiveStrPacket()
      await ws.send(packet)
```

import asyncdispatch, ws_jestersimple

proc sendRemote(ws: WebSocket, data: string): Future[string] {.async.} =
  await ws.send(data)
  result = await ws.receiveStrPacket()

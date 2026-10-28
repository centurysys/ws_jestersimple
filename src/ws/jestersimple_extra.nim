# Jester Simple adapter for treeform/ws 0.6.0.
# The HTTP transport owns the AsyncSocket; a route must await the WS session.
import std/[asyncdispatch, base64, httpcore, strutils]
import jestersimple
import ws

# -----------------------------------------------------------------------------
# Read exactly one HTTP header field; do not ignore ambiguous duplicates.
# -----------------------------------------------------------------------------
proc oneHeader(headers: HttpHeaders, name: string): string =
  if not headers.hasKey(name):
    raise newException(WebSocketHandshakeError, "Missing " & name)
  let values = toSeq(headers[name])
  if values.len != 1:
    raise newException(WebSocketHandshakeError, "Repeated " & name)
  result = values[0]

# -----------------------------------------------------------------------------
# Match one complete case-insensitive token in a comma-separated HTTP field.
# -----------------------------------------------------------------------------
proc hasHttpToken(value, token: string): bool =
  for candidate in value.split(','):
    if cmpIgnoreCase(candidate.strip(chars = {' ', '\t'}), token) == 0:
      return true
  false

# -----------------------------------------------------------------------------
# Validate one RFC 7230 token (also used for WS subprotocol identifiers).
# -----------------------------------------------------------------------------
proc validToken(value: string): bool =
  if value.len == 0:
    return false
  for c in value:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9',
                '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^',
                '_', '`', '|', '~'}:
      return false
  true

# -----------------------------------------------------------------------------
# Validate the complete upgrade request without modifying its response state.
# -----------------------------------------------------------------------------
proc validateHandshake(req: jestersimple.Request,
                       protocol: string): tuple[key: string, protocol: string] =
  let native = req.getNativeReq()
  let headers = native.headers
  if req.reqMethod != HttpGet or native.protocol.major != 1 or
      native.protocol.minor != 1:
    raise newException(WebSocketHandshakeError, "WebSocket requires GET HTTP/1.1")

  if not hasHttpToken(oneHeader(headers, "Connection"), "Upgrade") or
      not hasHttpToken(oneHeader(headers, "Upgrade"), "websocket"):
    raise newException(WebSocketHandshakeError, "Missing WebSocket Upgrade tokens")

  if oneHeader(headers, "Sec-WebSocket-Version") != "13":
    raise newException(WebSocketHandshakeError, "Unsupported WebSocket version")

  let key = oneHeader(headers, "Sec-WebSocket-Key")
  if key.len != 24:
    raise newException(WebSocketHandshakeError, "Invalid WebSocket key length")
  try:
    let decoded = base64.decode(key)
    if decoded.len != 16 or base64.encode(decoded) != key:
      raise newException(WebSocketHandshakeError, "Invalid WebSocket key")
  except ValueError:
    raise newException(WebSocketHandshakeError, "Invalid WebSocket key")

  # A server is allowed to decline all offered subprotocols. The existing
  # ws.handshake() expects a single exact value; never give it the raw offer.
  if protocol.len > 0 and not validToken(protocol):
    raise newException(WebSocketHandshakeError, "Invalid selected subprotocol")
  if headers.hasKey("Sec-WebSocket-Protocol"):
    let offered = oneHeader(headers, "Sec-WebSocket-Protocol")
    var selected = false
    for candidate in offered.split(','):
      let name = candidate.strip(chars = {' ', '\t'})
      if not validToken(name):
        raise newException(WebSocketHandshakeError, "Invalid offered subprotocol")
      if name == protocol:
        selected = true
    if protocol.len > 0 and not selected:
      raise newException(WebSocketHandshakeError, "Subprotocol was not offered")
  elif protocol.len > 0:
    raise newException(WebSocketHandshakeError, "Subprotocol was not offered")

  result = (key: key, protocol: protocol)

# -----------------------------------------------------------------------------
# Upgrade the existing transport-owned socket only after validation succeeds.
# The caller sends HTTP errors for pre-upgrade failures and keeps its route
# Future alive until the WebSocket session ends.
# -----------------------------------------------------------------------------
proc newWebSocket*(req: jestersimple.Request,
                   protocol = ""): Future[WebSocket] {.async.} =
  let accepted = validateHandshake(req, protocol)

  # Build just the three fields consumed by ws.handshake(), so a valid list of
  # offered protocols cannot be confused with the selected single protocol.
  var handshakeHeaders = newHttpHeaders({
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": accepted.key
  })
  if accepted.protocol.len > 0:
    handshakeHeaders["Sec-WebSocket-Protocol"] = accepted.protocol

  # Jester Simple must be the sole owner of this FD. Do not re-register or
  # wrap the native socket, and do not attempt an HTTP error after this point.
  let socket = req.beginUpgrade()
  let webSocket = WebSocket(tcpSocket: socket, masked: false,
                            protocol: accepted.protocol)
  await webSocket.handshake(handshakeHeaders)
  return webSocket

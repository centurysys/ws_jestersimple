# Forked from treeform/ws 0.6.0 (MIT). See LICENSE and README.md.
import asyncdispatch, asynchttpserver, asyncnet, base64, httpclient, httpcore,
    nativesockets, net, random, std/sha1, std/monotimes, streams, strformat, strutils, uri

# Receive limits are per WebSocket. Defaults keep untrusted input bounded even
# when a WebSocket is constructed directly rather than via newWebSocket().
const
  DefaultMaxFrameBytes* = 1024 * 1024
  DefaultMaxMessageBytes* = 4 * 1024 * 1024
  DefaultMaxPendingSendBytes* = 4 * 1024 * 1024

type
  ReadyState* = enum
    Connecting = 0 # The connection is not yet open.
    Open = 1       # The connection is open and ready to communicate.
    Closing = 2    # The connection is in the process of closing.
    Closed = 3     # The connection is closed or couldn't be opened.

  WebSocket* = ref object
    tcpSocket*: AsyncSocket
    version*: int
    key*: string
    protocol*: string
    readyState*: ReadyState
    masked*: bool # send masked packets
    maxFrameBytes: int
    maxMessageBytes: int
    readTimeoutMs: int
    heartbeatTimeoutMs: int
    heartbeatPending: bool
    heartbeatPayload: string
    heartbeatSentTicks: int64
    heartbeatExpired: bool
    pingGeneration: uint64
    writeTimeoutMs: int
    maxPendingSendBytes: int
    queuedWriteBytes: int
    writeTail: Future[void]

  WebSocketError* = object of IOError
  WebSocketClosedError* = object of WebSocketError
  WebSocketCreationError* = object of WebSocketError
  WebSocketPacketTypeError* = object of WebSocketError
  WebSocketProtocolMismatchError* = object of WebSocketError
  WebSocketFailedUpgradeError* = object of WebSocketError
  WebSocketHandshakeError* = object of WebSocketError
  WebSocketFrameLengthError* = object of WebSocketError
  WebSocketFrameTooLargeError* = object of WebSocketError
  WebSocketMessageTooLargeError* = object of WebSocketError
  WebSocketFrameProtocolError* = object of WebSocketError
  WebSocketReadTimeoutError* = object of WebSocketClosedError
  WebSocketHeartbeatTimeoutError* = object of WebSocketClosedError
  WebSocketWriteTimeoutError* = object of WebSocketClosedError
  WebSocketSendQueueFullError* = object of WebSocketError

# -----------------------------------------------------------------------------
# Limit one complete frame read. A timeout terminates the connection because
# asyncdispatch.withTimeout does not cancel a pending AsyncSocket.recv().
# Zero disables the limit; timeouts are opt-in for compatibility.
# -----------------------------------------------------------------------------
proc setReadTimeout*(ws: WebSocket, milliseconds: int) =
  if milliseconds < 0:
    raise newException(ValueError, "WebSocket read timeout must be nonnegative")
  ws.readTimeoutMs = milliseconds

# -----------------------------------------------------------------------------
# Set the deadline for an unanswered periodic Ping. Only setupPings-generated
# Pings participate; zero disables Pong enforcement (legacy behavior).
# -----------------------------------------------------------------------------
proc setHeartbeatTimeout*(ws: WebSocket, milliseconds: int) =
  if milliseconds < 0:
    raise newException(ValueError, "WebSocket heartbeat timeout must be nonnegative")
  ws.heartbeatTimeoutMs = milliseconds
  ws.heartbeatPending = false
  ws.heartbeatPayload.setLen(0)

# -----------------------------------------------------------------------------
# Stop/revoke a periodic ping loop. The pending timer exits within 250 ms;
# there is no detached socket reader or per-Ping timer to leak.
# -----------------------------------------------------------------------------
proc stopPings*(ws: WebSocket) =
  inc ws.pingGeneration
  ws.heartbeatPending = false
  ws.heartbeatPayload.setLen(0)

# -----------------------------------------------------------------------------
# Terminate a timed-out socket so a pending recv() cannot consume future data.
# Jester Simple's HTTP transport checks isClosed before its final close.
# -----------------------------------------------------------------------------
proc terminateTimedOutSocket(ws: WebSocket) =
  ws.readyState = Closed
  ws.stopPings()
  if not ws.tcpSocket.isClosed:
    ws.tcpSocket.close()

# -----------------------------------------------------------------------------
# Bound total queued writes (including the active write) per connection.
# A finite cap prevents slow readers from consuming unbounded application RAM.
# -----------------------------------------------------------------------------
proc setSendLimits*(ws: WebSocket, pendingBytes: int) =
  if pendingBytes <= 0:
    raise newException(ValueError, "WebSocket send limit must be positive")
  ws.maxPendingSendBytes = pendingBytes

# -----------------------------------------------------------------------------
# Set a deadline for one complete frame write, starting when it acquires the
# write queue. Zero disables the deadline for backwards compatibility.
# -----------------------------------------------------------------------------
proc setWriteTimeout*(ws: WebSocket, milliseconds: int) =
  if milliseconds < 0:
    raise newException(ValueError, "WebSocket write timeout must be nonnegative")
  ws.writeTimeoutMs = milliseconds

# -----------------------------------------------------------------------------
# Expose the number of bytes currently reserved for queued/active frames.
# This is an accounting limit, not a copy of the pending payloads.
# -----------------------------------------------------------------------------
proc pendingSendBytes*(ws: WebSocket): int =
  ws.queuedWriteBytes

# -----------------------------------------------------------------------------
# Set independent receive limits; call before starting the receive loop.
# Zero-initialized WebSockets use conservative defaults automatically.
# -----------------------------------------------------------------------------
proc setReceiveLimits*(ws: WebSocket, frameBytes, messageBytes: int) =
  if frameBytes <= 0 or messageBytes <= 0:
    raise newException(ValueError, "WebSocket receive limits must be positive")
  ws.maxFrameBytes = frameBytes
  ws.maxMessageBytes = messageBytes

# -----------------------------------------------------------------------------
# Return receive limits for WebSockets created through any constructor.
# -----------------------------------------------------------------------------
proc frameLimit(ws: WebSocket): int =
  if ws.maxFrameBytes > 0: ws.maxFrameBytes
  else: DefaultMaxFrameBytes

proc messageLimit(ws: WebSocket): int =
  if ws.maxMessageBytes > 0: ws.maxMessageBytes
  else: DefaultMaxMessageBytes

func newWebSocketClosedError(): auto =
  newException(WebSocketClosedError, "Socket closed")

# -----------------------------------------------------------------------------
# Surface heartbeat timeout distinctly when its watchdog closed the socket.
# -----------------------------------------------------------------------------
proc raiseReadClosed(ws: WebSocket) =
  if ws.heartbeatExpired:
    raise newException(WebSocketHeartbeatTimeoutError,
      "WebSocket Pong deadline expired")
  raise newWebSocketClosedError()

template `[]`(value: uint8, index: int): bool =
  ## Get bits from uint8, uint8[2] gets 2nd bit.
  (value and (1 shl (7 - index))) != 0

proc nibbleFromChar(c: char): int =
  ## Converts hex chars like `0` to 0 and `F` to 15.
  case c:
    of '0'..'9': (ord(c) - ord('0'))
    of 'a'..'f': (ord(c) - ord('a') + 10)
    of 'A'..'F': (ord(c) - ord('A') + 10)
    else: 255

proc nibbleToChar(value: int): char =
  ## Converts number like 0 to `0` and 15 to `fg`.
  case value:
    of 0..9: char(value + ord('0'))
    else: char(value + ord('a') - 10)

proc decodeBase16*(str: string): string =
  ## Base16 decode a string.
  result = newString(str.len div 2)
  for i in 0 ..< result.len:
    result[i] = chr(
      (nibbleFromChar(str[2 * i]) shl 4) or
      nibbleFromChar(str[2 * i + 1]))

proc encodeBase16*(str: string): string =
  ## Base61 encode a string.
  result = newString(str.len * 2)
  for i, c in str:
    result[i * 2] = nibbleToChar(ord(c) shr 4)
    result[i * 2 + 1] = nibbleToChar(ord(c) and 0x0f)

proc genMaskKey(): array[4, char] =
  ## Generates a random key of 4 random chars.
  proc r(): char = char(rand(255))
  [r(), r(), r(), r()]

proc toSeq*(hv: HttpHeaderValues): seq[string] =
  ## Casts HttpHeaderValues to seq of strings.
  cast[seq[string]](hv)

proc handshake*(ws: WebSocket, headers: HttpHeaders) {.async.} =
  ## Handles the websocket handshake.
  ws.version = parseInt(headers["Sec-WebSocket-Version"])
  ws.key = headers["Sec-WebSocket-Key"].strip()
  if headers.hasKey("Sec-WebSocket-Protocol"):
    let wantProtocol = headers["Sec-WebSocket-Protocol"].strip()
    if ws.protocol != wantProtocol:
      raise newException(WebSocketProtocolMismatchError,
        &"Protocol mismatch (expected: {ws.protocol}, got: {wantProtocol})")

  let
    sh = secureHash(ws.key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    acceptKey = base64.encode(decodeBase16($sh))

  var response = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  response.add("Sec-WebSocket-Accept: " & acceptKey & "\c\L")
  response.add("Connection: Upgrade\c\L")
  response.add("Upgrade: webSocket\c\L")

  if ws.protocol != "":
    response.add("Sec-WebSocket-Protocol: " & ws.protocol & "\c\L")
  response.add "\c\L"

  await ws.tcpSocket.send(response)
  ws.readyState = Open

proc newWebSocket*(
  req: Request,
  protocol: string = ""
): Future[WebSocket] {.async.} =
  ## Creates a new socket from a request.
  try:
    if not req.headers.hasKey("Sec-WebSocket-Version"):
      raise newException(WebSocketHandshakeError, "Invalid WebSocket handshake")

    var ws = WebSocket()
    ws.masked = false
    ws.tcpSocket = req.client
    ws.protocol = protocol
    await ws.handshake(req.headers)
    return ws

  except ValueError, KeyError:
    # Wrap all exceptions in a WebSocketCreationError so its easy to catch.
    raise newException(
      WebSocketCreationError,
      "Failed to create WebSocket from request: " & getCurrentExceptionMsg()
    )

proc newWebSocket*(
  url: string,
  protocols: seq[string] = @[]
): Future[WebSocket] {.async.} =
  ## Creates a new WebSocket connection,
  ## protocol is optional, "" means no protocol.
  var ws = WebSocket()
  ws.masked = true
  ws.tcpSocket = newAsyncSocket()

  var uri = parseUri(url)
  var port = Port(9001)
  case uri.scheme
    of "wss":
      uri.scheme = "https"
      port = Port(443)
    of "ws":
      uri.scheme = "http"
      port = Port(80)
    else:
      raise newException(
        WebSocketError,
        &"Scheme {uri.scheme} not supported yet"
      )
  if uri.port.len > 0:
    port = Port(parseInt(uri.port))

  var client = newAsyncHttpClient()

  # Generate secure key.
  var secStr = newString(16)
  for i in 0 ..< secStr.len:
    secStr[i] = char rand(255)
  let secKey = base64.encode(secStr)

  client.headers = newHttpHeaders({
    "Connection": "Upgrade",
    "Upgrade": "websocket",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": secKey,
    # "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits"
  })
  if protocols.len > 0:
    client.headers["Sec-WebSocket-Protocol"] = protocols.join(", ")
  var res = await client.get($uri)
  let hasUpgrade = res.headers.getOrDefault("Upgrade")
  if hasUpgrade.toLowerAscii() != "websocket":
    raise newException(
      WebSocketFailedUpgradeError,
      &"Failed to Upgrade (Possibly Connected to non-WebSocket url)"
    )
  if protocols.len > 0:
    var resProtocol = res.headers.getOrDefault("Sec-WebSocket-Protocol")
    if resProtocol in protocols:
      ws.protocol = resProtocol
    else:
      raise newException(
        WebSocketProtocolMismatchError,
        &"Protocol mismatch (expected: {protocols}, got: {resProtocol})"
      )
  ws.tcpSocket = client.getSocket()

  ws.readyState = Open
  return ws

proc newWebSocket*(url: string, protocol: string):
    Future[WebSocket] {.async.} =
  return await newWebSocket(url, @[protocol])

type
  Opcode* = enum
    ## 4 bits. Defines the interpretation of the "Payload data".
    Cont = 0x0   ## Denotes a continuation frame.
    Text = 0x1   ## Denotes a text frame.
    Binary = 0x2 ## Denotes a binary frame.
    # 3-7 are reserved for further non-control frames.
    Close = 0x8  ## Denotes a connection close.
    Ping = 0x9   ## Denotes a ping.
    Pong = 0xa   ## Denotes a pong.
    # B-F are reserved for further control frames.

  #[
  +---------------------------------------------------------------+
  |0                   1                   2                   3  |
  |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1|
  +-+-+-+-+-------+-+-------------+-------------------------------+
  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
  | |1|2|3|       |K|             |                               |
  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
  |     Extended payload length continued, if payload len == 127  |
  + - - - - - - - - - - - - - - - +-------------------------------+
  |                               | Masking-key, if MASK set to 1 |
  +-------------------------------+-------------------------------+
  | Masking-key (continued)       |          Payload Data         |
  +-------------------------------- - - - - - - - - - - - - - - - +
  :                     Payload Data continued ...                :
  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
  |                     Payload Data continued ...                |
  +---------------------------------------------------------------+
  ]#
  Frame = tuple
    fin: bool ## Indicates that this is the final fragment in a message.
    rsv1: bool ## MUST be 0 unless negotiated that defines meanings
    rsv2: bool ## MUST be 0
    rsv3: bool ## MUST be 0
    opcode: Opcode ## Defines the interpretation of the "Payload data".
    mask: bool ## Defines whether the "Payload data" is masked.
    data: string ## Payload data

proc encodeFrame(f: Frame): string =
  ## Encodes a frame into a string buffer.
  ## See https://tools.ietf.org/html/rfc6455#section-5.2

  var ret = newStringStream()

  var b0 = (f.opcode.uint8 and 0x0f) # 0th byte: opcodes and flags.
  if f.fin:
    b0 = b0 or 128u8

  ret.write(b0)

  # Payload length can be 7 bits, 7+16 bits, or 7+64 bits.
  # 1st byte: payload len start and mask bit.
  var b1 = 0u8

  if f.data.len <= 125:
    b1 = f.data.len.uint8
  elif f.data.len > 125 and f.data.len <= 0xffff:
    b1 = 126u8
  else:
    b1 = 127u8

  if f.mask:
    b1 = b1 or (1 shl 7)

  ret.write(uint8 b1)

  # Only need more bytes if data len is 7+16 bits, or 7+64 bits.
  if f.data.len > 125 and f.data.len <= 0xffff:
    # Data len is 7+16 bits.
    ret.write(htons(f.data.len.uint16))
  elif f.data.len > 0xffff:
    # Data len is 7+64 bits.
    var len = f.data.len
    ret.write char((len shr 56) and 255)
    ret.write char((len shr 48) and 255)
    ret.write char((len shr 40) and 255)
    ret.write char((len shr 32) and 255)
    ret.write char((len shr 24) and 255)
    ret.write char((len shr 16) and 255)
    ret.write char((len shr 8) and 255)
    ret.write char(len and 255)

  var data = f.data

  if f.mask:
    # If we need to mask it generate random mask key and mask the data.
    let maskKey = genMaskKey()
    for i in 0..<data.len:
      data[i] = (data[i].uint8 xor maskKey[i mod 4].uint8).char
    # Write mask key next.
    ret.write(maskKey)

  # Write the data.
  ret.write(data)
  ret.setPosition(0)
  return ret.readAll()

# -----------------------------------------------------------------------------
# Write one encoded frame in bounded chunks. A whole frame is serialized;
# splitting it into TCP writes must not interleave another WebSocket frame.
# -----------------------------------------------------------------------------
proc writeEncodedFrame(ws: WebSocket, frame: string): Future[void] {.async.} =
  const writeChunk = 64 * 1024
  var offset = 0
  while offset < frame.len:
    let untilIndex = min(frame.len, offset + writeChunk)
    await ws.tcpSocket.send(frame[offset ..< untilIndex])
    offset = untilIndex

# -----------------------------------------------------------------------------
# Observe a socket write which was abandoned after its deadline. Closing the
# AsyncSocket is required: withTimeout() by itself does not cancel the send.
# -----------------------------------------------------------------------------
proc observeTimedOutWrite(writeFuture: Future[void]) =
  try:
    writeFuture.read()
  except CatchableError:
    discard

# -----------------------------------------------------------------------------
# Serialize all outbound frames, including Close, with a Future baton.
# Install the baton and reserve queue capacity before the first await.
# The baton completes in finally so a failed write cannot strand successors.
# -----------------------------------------------------------------------------
proc queueFrame(ws: WebSocket, opcode: Opcode, payload: string,
                closeFrame = false): Future[void] {.async.} =
  if payload.len > high(int) - 14:
    raise newException(WebSocketSendQueueFullError, "WebSocket send size overflow")

  let charge = payload.len + 14 # worst-case frame header and mask overhead
  let limit = if ws.maxPendingSendBytes > 0:
    ws.maxPendingSendBytes
  else:
    DefaultMaxPendingSendBytes

  if not closeFrame and (charge > limit or ws.queuedWriteBytes > limit - charge):
    raise newException(WebSocketSendQueueFullError,
      "WebSocket pending send limit exceeded")

  let previous = ws.writeTail
  let turn = newFuture[void]("ws.queueFrame")
  ws.writeTail = turn
  ws.queuedWriteBytes += charge

  try:
    if not previous.isNil:
      await previous
    if ws.readyState == Closed or ws.tcpSocket.isClosed:
      raise newWebSocketClosedError()

    let frame = encodeFrame((
      fin: true, rsv1: false, rsv2: false, rsv3: false,
      opcode: opcode, mask: ws.masked, data: payload
    ))
    let writeFuture = ws.writeEncodedFrame(frame)
    if ws.writeTimeoutMs > 0:
      if not (await withTimeout(writeFuture, ws.writeTimeoutMs)):
        writeFuture.addCallback(proc () = observeTimedOutWrite(writeFuture))
        raise newException(WebSocketWriteTimeoutError,
          "WebSocket frame write deadline expired")
    await writeFuture
  except CatchableError:
    ws.readyState = Closed
    ws.stopPings()
    # A partial frame makes the stream unusable. Closing also releases a
    # pending asyncnet.send() without leaving it writing on another session.
    if not ws.tcpSocket.isClosed:
      ws.tcpSocket.close()
    raise
  finally:
    ws.queuedWriteBytes -= charge
    if ws.writeTail == turn:
      ws.writeTail = nil
    if not turn.finished:
      turn.complete()

# -----------------------------------------------------------------------------
# Send one data/control frame in queue order. Calls after Close are ignored
# for compatibility; calls already queued before Close finish before it.
# -----------------------------------------------------------------------------
proc send*(ws: WebSocket, text: string,
           opcode = Opcode.Text): Future[void] {.async.} =
  if ws.readyState != Open:
    return
  await ws.queueFrame(opcode, text)

# -----------------------------------------------------------------------------
# Queue Close after any previously accepted data frames. The state changes
# before awaiting so subsequent application sends cannot overtake Close.
# The socket remains owned by the HTTP transport or caller.
# -----------------------------------------------------------------------------
proc sendCloseFrame(ws: WebSocket, payload: string): Future[void] {.async.} =
  if ws.readyState != Open:
    return
  if payload.len > 125:
    raise newException(WebSocketError, "Close payload exceeds 125 bytes")

  ws.readyState = Closing
  ws.stopPings()
  await ws.queueFrame(Opcode.Close, payload, closeFrame = true)

# -----------------------------------------------------------------------------
# Begin an orderly Close handshake. The caller must await the peer's Close
# response (normally via receivePacket) and release its own socket afterward.
# -----------------------------------------------------------------------------
proc closeAsync*(ws: WebSocket): Future[void] {.async.} =
  await ws.sendCloseFrame("")

# -----------------------------------------------------------------------------
# Read an exact number of TCP bytes, regardless of recv() boundaries.
# A zero-length read is successful without accessing the socket.
# -----------------------------------------------------------------------------
proc recvExact(ws: WebSocket, count: int): Future[string] {.async.} =
  if count < 0:
    raise newException(WebSocketError, "Negative WebSocket read length")
  if count == 0:
    return ""

  const readChunk = 16 * 1024
  result = newStringOfCap(min(count, readChunk))
  while result.len < count:
    let remaining = count - result.len
    var data: string
    try:
      data = await ws.tcpSocket.recv(min(remaining, readChunk))
    except IOError, OSError:
      ws.readyState = Closed
      ws.stopPings()
      ws.raiseReadClosed()
    if data.len == 0:
      ws.readyState = Closed
      ws.stopPings()
      ws.raiseReadClosed()
    result.add(data)

# -----------------------------------------------------------------------------
# Reject malformed framing before converting untrusted opcode values to enums.
# The caller/transport owns the socket and is responsible for closing it.
# -----------------------------------------------------------------------------
proc failProtocol(ws: WebSocket, message: string) =
  ws.readyState = Closed
  ws.stopPings()
  raise newException(WebSocketFrameProtocolError, message)

# -----------------------------------------------------------------------------
# Check RFC 3629 UTF-8 without accepting overlong encodings or surrogates.
# Validate complete messages, not individual fragmented UTF-8 frame payloads.
# -----------------------------------------------------------------------------
func validUtf8(data: string): bool =
  var i = 0
  while i < data.len:
    let first = data[i].uint8
    var follows = 0
    var secondMin = 0x80'u8
    var secondMax = 0xbf'u8

    case first
    of 0x00'u8..0x7f'u8:
      inc i
      continue
    of 0xc2'u8..0xdf'u8:
      follows = 1
    of 0xe0'u8:
      follows = 2
      secondMin = 0xa0'u8
    of 0xe1'u8..0xec'u8, 0xee'u8..0xef'u8:
      follows = 2
    of 0xed'u8:
      follows = 2
      secondMax = 0x9f'u8
    of 0xf0'u8:
      follows = 3
      secondMin = 0x90'u8
    of 0xf1'u8..0xf3'u8:
      follows = 3
    of 0xf4'u8:
      follows = 3
      secondMax = 0x8f'u8
    else:
      return false

    if data.len - i <= follows:
      return false
    let second = data[i + 1].uint8
    if second < secondMin or second > secondMax:
      return false
    for offset in 2..follows:
      let value = data[i + offset].uint8
      if value < 0x80'u8 or value > 0xbf'u8:
        return false
    i += follows + 1
  return true

# -----------------------------------------------------------------------------
# Close control frames contain zero bytes or a valid status code and UTF-8.
# Extensions and reserved status codes are not negotiated by this library.
# -----------------------------------------------------------------------------
func validClosePayload(payload: string): bool =
  if payload.len == 0:
    return true
  if payload.len == 1:
    return false
  let code = (int(payload[0].uint8) shl 8) or int(payload[1].uint8)
  if code < 1000 or code >= 5000 or code in [1004, 1005, 1006, 1015]:
    return false
  if code > 1014 and code < 3000:
    return false
  if payload.len == 2:
    return true
  return validUtf8(payload[2..^1])

proc recvFrame(ws: WebSocket, remainingMessageBytes: int):
    Future[Frame] {.async.} =
  ## Gets a frame from the WebSocket.
  ## See https://tools.ietf.org/html/rfc6455#section-5.2

  if ws.tcpSocket.isClosed:
    ws.readyState = Closed
    ws.stopPings()
    ws.raiseReadClosed()

  # TCP is a byte stream: each frame field can arrive in several reads.
  let header = await ws.recvExact(2)

  let b0 = header[0].uint8
  let b1 = header[1].uint8

  # Do not enum-cast reserved opcode values: they may trigger RangeDefect.
  result.fin = b0[0]
  result.rsv1 = b0[1]
  result.rsv2 = b0[2]
  result.rsv3 = b0[3]
  if result.rsv1 or result.rsv2 or result.rsv3:
    ws.failProtocol("Unexpected RSV bit (no extensions negotiated)")

  let rawOpcode = b0 and 0x0f'u8
  case rawOpcode
  of 0x0'u8, 0x1'u8, 0x2'u8, 0x8'u8, 0x9'u8, 0xa'u8:
    result.opcode = Opcode(rawOpcode)
  else:
    ws.failProtocol("Reserved WebSocket opcode")

  let isControl = rawOpcode >= 0x8'u8
  # An extended length is always illegal for a control frame. Reject it
  # before waiting for the extra bytes or allocating a payload buffer.
  if isControl and (not result.fin or (b1 and 0x7f'u8) > 125'u8):
    ws.failProtocol("Invalid control frame FIN or length")

  # Client frames must be masked; server frames must not be masked.
  result.mask = (b1 and 0x80'u8) != 0'u8
  if ws.masked == result.mask:
    ws.failProtocol("Unexpected WebSocket MASK bit")

  # Decode the full 64-bit network-order length without pointer casts.
  # Reject invalid and oversized lengths before reading a mask or payload.
  let headerLen = uint64(b1 and 0x7f)
  var payloadLen = headerLen
  if headerLen == 126'u64:
    let length = await ws.recvExact(2)
    payloadLen = (uint64(length[0].uint8) shl 8) or
                 uint64(length[1].uint8)
    if payloadLen < 126'u64:
      ws.readyState = Closed
      raise newException(WebSocketFrameLengthError,
        "Non-minimal 16-bit WebSocket payload length")
  elif headerLen == 127'u64:
    let length = await ws.recvExact(8)
    if (length[0].uint8 and 0x80'u8) != 0'u8:
      ws.readyState = Closed
      raise newException(WebSocketFrameLengthError,
        "WebSocket 64-bit payload length has its high bit set")
    payloadLen = 0'u64
    for value in length:
      payloadLen = (payloadLen shl 8) or uint64(value.uint8)
    if payloadLen < 65536'u64:
      ws.readyState = Closed
      raise newException(WebSocketFrameLengthError,
        "Non-minimal 64-bit WebSocket payload length")

  # int() would truncate on 32-bit devices. Never convert until validated.
  if payloadLen > uint64(high(int)) or
      payloadLen > uint64(ws.frameLimit()):
    ws.readyState = Closed
    raise newException(WebSocketFrameTooLargeError,
      "WebSocket frame exceeds receive limit")
  if not isControl and (remainingMessageBytes < 0 or
      payloadLen > uint64(remainingMessageBytes)):
    ws.readyState = Closed
    raise newException(WebSocketMessageTooLargeError,
      "WebSocket message exceeds receive limit")

  var maskKey = ""
  if result.mask:
    # Read the mask.
    maskKey = await ws.recvExact(4)

  # Read the data.
  result.data = await ws.recvExact(int(payloadLen))

  if result.mask:
    # Apply the masking key after all payload bytes have arrived.
    for i in 0 ..< result.data.len:
      result.data[i] = (result.data[i].uint8 xor maskKey[i mod 4].uint8).char

  if result.opcode == Close and not validClosePayload(result.data):
    ws.failProtocol("Invalid Close status code or UTF-8 reason")

# -----------------------------------------------------------------------------
# Observe a timed-out read after closing its socket. withTimeout() alone does
# not cancel the Future; this callback consumes its eventual result/exception.
# -----------------------------------------------------------------------------
proc observeTimedOutRead(readFuture: Future[Frame]) =
  try:
    discard readFuture.read()
  except CatchableError:
    discard

# -----------------------------------------------------------------------------
# Read the next frame under an optional per-frame deadline. On expiry, close
# the connection to prevent the abandoned Future from reading another frame.
# -----------------------------------------------------------------------------
proc readFrameWithDeadline(ws: WebSocket, remaining: int):
    Future[Frame] {.async.} =
  let readFuture = ws.recvFrame(remaining)
  if ws.readTimeoutMs > 0:
    if not (await withTimeout(readFuture, ws.readTimeoutMs)):
      readFuture.addCallback(proc () = observeTimedOutRead(readFuture))
      ws.terminateTimedOutSocket()
      raise newException(WebSocketReadTimeoutError,
        "WebSocket frame read deadline expired")
  return await readFuture

# -----------------------------------------------------------------------------
# Receive a complete data message, exposing non-fragmented control frames.
# -----------------------------------------------------------------------------
proc receivePacket*(ws: WebSocket): Future[(Opcode, string)] {.async.} =
  let limit = ws.messageLimit()
  var fragmented = false
  var messageOpcode = Text
  var message = ""

  while true:
    let remaining = if fragmented: limit - message.len else: limit
    let frame = await ws.readFrameWithDeadline(remaining)

    case frame.opcode
    of Close:
      if ws.readyState == Open:
        await ws.sendCloseFrame(frame.data)
      ws.readyState = Closed
      ws.stopPings()
      return (Close, frame.data)

    of Ping:
      if fragmented:
        await ws.send(frame.data, Pong)
        if ws.readyState != Open:
          raise newWebSocketClosedError()
        continue
      return (Ping, frame.data)

    of Pong:
      if ws.heartbeatPending and frame.data == ws.heartbeatPayload:
        ws.heartbeatPending = false
      if fragmented:
        continue
      return (Pong, frame.data)

    of Cont:
      if not fragmented:
        ws.failProtocol("Unexpected continuation frame")
      message.add(frame.data)
      if frame.fin:
        if messageOpcode == Text and not validUtf8(message):
          ws.failProtocol("Invalid UTF-8 text message")
        return (messageOpcode, message)

    of Text, Binary:
      if fragmented:
        ws.failProtocol("New data frame before fragmented message completed")
      if frame.fin:
        if frame.opcode == Text and not validUtf8(frame.data):
          ws.failProtocol("Invalid UTF-8 text message")
        return (frame.opcode, frame.data)
      fragmented = true
      messageOpcode = frame.opcode
      message = frame.data

# -----------------------------------------------------------------------------
# Ignore control frames while awaiting a Text packet; answer each Ping once.
# The public receivePacket API continues to expose Ping/Pong to its callers.
# -----------------------------------------------------------------------------
proc receiveStrPacket*(ws: WebSocket): Future[string] {.async.} =
  while true:
    let (opcode, data) = await ws.receivePacket()
    case opcode
    of Text:
      return data
    of Binary:
      raise newException(WebSocketPacketTypeError,
        "Expected string packet, received binary packet")
    of Ping:
      await ws.send(data, Pong)
      if ws.readyState != Open:
        ws.raiseReadClosed()
    of Pong:
      discard
    of Close:
      ws.raiseReadClosed()
    of Cont:
      ws.failProtocol("Unexpected continuation packet")

# -----------------------------------------------------------------------------
# Ignore control frames while awaiting a Binary packet; answer each Ping once.
# -----------------------------------------------------------------------------
proc receiveBinaryPacket*(ws: WebSocket): Future[seq[byte]] {.async.} =
  while true:
    let (opcode, data) = await ws.receivePacket()
    case opcode
    of Binary:
      return cast[seq[byte]](data)
    of Text:
      raise newException(WebSocketPacketTypeError,
        "Expected binary packet, received string packet")
    of Ping:
      await ws.send(data, Pong)
      if ws.readyState != Open:
        ws.raiseReadClosed()
    of Pong:
      discard
    of Close:
      ws.raiseReadClosed()
    of Cont:
      ws.failProtocol("Unexpected continuation packet")

# -----------------------------------------------------------------------------
# Send a valid Ping control frame with a bounded payload.
# -----------------------------------------------------------------------------
proc ping*(ws: WebSocket, data = "") {.async.} =
  if data.len > 125:
    raise newException(ValueError, "WebSocket Ping payload exceeds 125 bytes")
  await ws.send(data, Ping)

# -----------------------------------------------------------------------------
# Start periodic Pings. Repeated calls replace the old loop; stopPings() or
# closing the connection ends the task within 250 ms. Optional Pong deadlines
# require an active receive loop to process matching Pong frames.
# -----------------------------------------------------------------------------
proc setupPings*(ws: WebSocket, seconds: float) =
  if not (seconds > 0.0) or seconds > float(high(int) div 1000):
    raise newException(ValueError, "Invalid WebSocket Ping interval")
  if ws.readyState != Open:
    raise newException(ValueError, "WebSocket must be Open for periodic Pings")

  let intervalMs = max(1, int(seconds * 1000.0))
  ws.stopPings()
  ws.heartbeatExpired = false
  let generation = ws.pingGeneration
  const nanosPerMs = 1_000_000'i64

  proc pingLoop() {.async.} =
    var nextPingTicks = getMonoTime().ticks + int64(intervalMs) * nanosPerMs
    try:
      while ws.readyState == Open and ws.pingGeneration == generation:
        let now = getMonoTime().ticks
        if ws.heartbeatPending and ws.heartbeatTimeoutMs > 0 and
            now - ws.heartbeatSentTicks >=
              int64(ws.heartbeatTimeoutMs) * nanosPerMs:
          ws.heartbeatExpired = true
          ws.terminateTimedOutSocket()
          break

        if now >= nextPingTicks:
          nextPingTicks = now + int64(intervalMs) * nanosPerMs
          if not ws.heartbeatPending or ws.heartbeatTimeoutMs == 0:
            let payload = $now
            # Arm the Pong waiter before the first await: a fast peer can
            # reply while send() is suspended after writing the Ping.
            if ws.heartbeatTimeoutMs > 0:
              ws.heartbeatPayload = payload
              ws.heartbeatSentTicks = getMonoTime().ticks
              ws.heartbeatPending = true
            await ws.ping(payload)
            if ws.readyState != Open or ws.pingGeneration != generation:
              break

        let nowAfter = getMonoTime().ticks
        var delayMs = max(1'i64,
          (nextPingTicks - nowAfter + nanosPerMs - 1) div nanosPerMs)
        if ws.heartbeatPending and ws.heartbeatTimeoutMs > 0:
          let deadline = ws.heartbeatSentTicks +
            int64(ws.heartbeatTimeoutMs) * nanosPerMs
          let remaining = max(1'i64,
            (deadline - nowAfter + nanosPerMs - 1) div nanosPerMs)
          delayMs = min(delayMs, remaining)
        await sleepAsync(int(min(250'i64, delayMs)))
    except CatchableError:
      # Do not terminate a connection after this task was superseded/stopped.
      if ws.readyState == Open and ws.pingGeneration == generation:
        try:
          ws.terminateTimedOutSocket()
        except CatchableError:
          discard

  asyncCheck pingLoop()

proc hangup*(ws: WebSocket) =
  ## Closes the Socket without sending a close packet.
  ws.readyState = Closed
  ws.stopPings()
  try:
    if not ws.tcpSocket.isClosed:
      ws.tcpSocket.close()
  except:
    raise newException(
      WebSocketError,
      "Failed to hangup socket " & getCurrentExceptionMsg()
    )

# -----------------------------------------------------------------------------
# Legacy fire-and-forget Close. Existing direct-socket users keep this API,
# but transport-managed routes must use `await closeAsync()` instead.
# -----------------------------------------------------------------------------
proc close*(ws: WebSocket) =
  if ws.readyState != Open:
    return
  proc closeAndHangup() {.async.} =
    try:
      await ws.closeAsync()
    except CatchableError:
      discard
    # Legacy close() tears down the FD; closeAsync leaves it to its owner.
    try:
      ws.tcpSocket.close()
    except CatchableError:
      discard
    ws.readyState = Closed
  asyncCheck closeAndHangup()

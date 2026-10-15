using System;
using System.Buffers;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Fleck.Handlers
{
    internal class Hybi13Handler : IHandler
    {
        private const string WebSocketResponseGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        private static readonly Encoding UTF8 = new UTF8Encoding(false, true);
        private static readonly SHA1 SHA1 = SHA1.Create();
        private static readonly ThreadLocal<StringBuilder> StringBuilder = new ThreadLocal<StringBuilder>(() => new StringBuilder(1024));

        // buffers start small and grow on demand, so connections that never receive big messages don't hold big buffers
        private const int InitialBufferSize = 64 * 1024;

        // the read buffer holds a whole frame plus its header and the start of the next read
        private const int ReadBufferSlack = 64 * 1024;

        private readonly WebSocketHttpRequest _request;
        private readonly IWebSocketConnection _connection;
        private readonly int _maxMessageSize;
        private readonly int _maxDataSize;
        private byte[] _data;
        private int _dataLen;

        private FrameType? _frameType;
        private byte[] _message;
        private int _messageLen;
        private bool _closeReceived;

        public Hybi13Handler(WebSocketHttpRequest request, IWebSocketConnection connection, int maxMessageSize = WebSocketServer.DefaultMaxMessageSize)
        {
            _request = request;
            _connection = connection;
            if (maxMessageSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxMessageSize), "must be positive");

            _maxMessageSize = Math.Max(maxMessageSize, WebSocketServer.MinimumMaxMessageSize);
            _maxDataSize = (int)Math.Min((long)_maxMessageSize + ReadBufferSlack, int.MaxValue); // a limit near int.MaxValue mustn't overflow

            _data = ArrayPool<byte>.Shared.Rent(InitialBufferSize);
            _dataLen = 0;

            _frameType = null;
            _message = ArrayPool<byte>.Shared.Rent(InitialBufferSize);
            _messageLen = 0;
        }

        public void Dispose()
        {
            if (_data != null)
            {
                ArrayPool<byte>.Shared.Return(_data);
                _data = null;
            }

            if (_message != null)
            {
                ArrayPool<byte>.Shared.Return(_message);
                _message = null;
            }
        }

        // moves to a pooled buffer big enough for required, keeping the used bytes; only buffers past the pool's largest size allocate
        private static void Grow(ref byte[] buffer, int used, int required, int limit)
        {
            if (required > limit)
                throw new WebSocketException(WebSocketStatusCodes.MessageTooBig);

            var bigger = ArrayPool<byte>.Shared.Rent(Math.Min(Math.Max(required, buffer.Length * 2), limit));
            Buffer.BlockCopy(buffer, 0, bigger, 0, used);
            ArrayPool<byte>.Shared.Return(buffer);
            buffer = bigger;
        }

        public void Receive(Span<byte> newData)
        {
            // Ignore further data after either endpoint starts closing.
            if (_closeReceived || !_connection.IsAvailable)
                return;

            // checked against the limit itself, not just when growing, since the buffer can already be bigger than the limit
            // (it starts at InitialBufferSize and the pool rounds sizes up)
            var required = _dataLen + newData.Length;
            if (required > _maxDataSize)
                throw new WebSocketException(WebSocketStatusCodes.MessageTooBig);

            if (required > _data.Length)
                Grow(ref _data, _dataLen, required, _maxDataSize);

            var dest = new Span<byte>(_data, _dataLen, newData.Length);
            newData.CopyTo(dest);
            _dataLen += newData.Length;

            ReceiveData();
        }

        public MemoryBuffer CreateHandshake()
        {
            FleckLog.Debug("Building Hybi-14 Response");

            var builder = StringBuilder.Value;
            builder.Clear();

            builder.Append("HTTP/1.1 101 Switching Protocols\r\n");
            builder.Append("Upgrade: websocket\r\n");
            builder.Append("Connection: Upgrade\r\n");

            var responseKey = CreateResponseKey(_request["Sec-WebSocket-Key"]);
            builder.AppendFormat("Sec-WebSocket-Accept: {0}\r\n", responseKey);
            builder.Append("\r\n");

            var bytes = UTF8.GetBytes(builder.ToString());
            return new MemoryBuffer(bytes, bytes.Length, false);
        }

        public MemoryBuffer FrameText(string text)
        {
            var bytes = UTF8.GetBytes(text);
            var buffer = new MemoryBuffer(bytes, bytes.Length, false);
            return FrameText(buffer);
        }

        public MemoryBuffer FrameText(MemoryBuffer utf8StringBytes)
        {
            return FrameData(utf8StringBytes, FrameType.Text);
        }

        public MemoryBuffer FrameBinary(MemoryBuffer bytes)
        {
            return FrameData(bytes, FrameType.Binary);
        }

        public MemoryBuffer FrameBinary(ReadOnlySpan<byte> prefix, MemoryBuffer bytes)
        {
            return FrameData(bytes, FrameType.Binary, prefix);
        }

        public MemoryBuffer FramePing(MemoryBuffer bytes)
        {
            return FrameData(bytes, FrameType.Ping);
        }

        public MemoryBuffer FramePong(MemoryBuffer bytes)
        {
            return FrameData(bytes, FrameType.Pong);
        }

        public unsafe MemoryBuffer FrameClose(ushort code)
        {
            var codeSpan = new Span<byte>(&code, sizeof(ushort));
            codeSpan.Reverse();
            return FrameData(codeSpan, FrameType.Close);
        }

        private static MemoryBuffer FrameData(MemoryBuffer payload, FrameType frameType, ReadOnlySpan<byte> prefix = default)
        {
            var framed = FrameData((Span<byte>)payload, frameType, prefix);
            payload.Dispose();
            return framed;
        }

        // the prefix is written straight after the frame header, as the start of the frame's payload
        private static MemoryBuffer FrameData(Span<byte> payload, FrameType frameType, ReadOnlySpan<byte> prefix = default)
        {
            var length = prefix.Length + payload.Length;
            var data = ArrayPool<byte>.Shared.Rent(length + 16);
            var writer = new SpanWriter(data);

            byte op = (byte)((byte)frameType + 128);
            writer.Write(op);

            if (length > ushort.MaxValue)
            {
                writer.Write<byte>(127);
                writer.Write((ulong)length);
            }
            else if (length > 125)
            {
                writer.Write<byte>(126);
                writer.Write((ushort)length);
            }
            else
            {
                writer.Write((byte)length);
            }

            if (prefix.Length > 0)
                writer.Write(prefix);

            if (payload.Length > 0)
                writer.Write(payload);

            return new MemoryBuffer(data, writer.Length);
        }

        private void ReceiveData()
        {
            // Application callbacks can close locally while more frames remain in the same read.
            while (_dataLen >= 2 && !_closeReceived && _connection.IsAvailable)
            {
                FleckLog.Debug("Trying to read a packet");

                var isFinal = (_data[0] & 128) != 0;
                var reservedBits = (_data[0] & 112);
                var frameType = (FrameType)(_data[0] & 15);
                var isMasked = (_data[1] & 128) != 0;
                var length = (_data[1] & 127);


                var isControl = frameType >= FrameType.Close;

                if (!isMasked
                    || !frameType.IsDefined()
                    || reservedBits != 0 // Must be zero per spec 5.2
                    || (frameType == FrameType.Continuation && !_frameType.HasValue)
                    || (!isControl && frameType != FrameType.Continuation && _frameType.HasValue) // a new message mid-fragmented message
                    || (isControl && (!isFinal || length > 125))) // control frames can't be fragmented and are at most 125 bytes (5.5)
                    throw new WebSocketException(WebSocketStatusCodes.ProtocolError);

                var index = 2;
                int payloadLength;

                if (length == 127)
                {
                    if (_dataLen < index + 8)
                        return; //Not complete
                    payloadLength = new Span<byte>(_data, index, 8).ToLittleEndianInt();
                    index += 8;
                }
                else if (length == 126)
                {
                    if (_dataLen < index + 2)
                        return; //Not complete
                    payloadLength = new Span<byte>(_data, index, 2).ToLittleEndianInt();
                    index += 2;
                }
                else
                {
                    payloadLength = length;
                }

                FleckLog.Debug($"Expecting {payloadLength} byte payload");

                // reject from the header rather than buffering towards it. negative when a 64-bit length didn't fit in an int
                if (payloadLength < 0 || payloadLength > _maxMessageSize)
                    throw new WebSocketException(WebSocketStatusCodes.MessageTooBig);

                if (_dataLen < index + 4)
                    return; //Not complete

                var maskBytes = new Span<byte>(_data, index, 4);
                index += 4;

                if (_dataLen < index + payloadLength)
                    return; //Not complete

                var payloadData = new Span<byte>(_data, index, payloadLength);
                for (var i = 0; i < payloadLength; i++)
                {
                    payloadData[i] = (byte)(payloadData[i] ^ maskBytes[i % 4]);
                }

                if (isControl)
                {
                    // handled on its own, straight from the read buffer: control frames can arrive between the fragments of
                    // a message (5.4), which has to carry on unaffected
                    ProcessFrame(frameType, new ArraySegment<byte>(_data, index, payloadLength));

                    var controlBytesUsed = index + payloadLength;
                    Buffer.BlockCopy(_data, controlBytesUsed, _data, 0, _dataLen - controlBytesUsed);
                    _dataLen -= controlBytesUsed;
                    continue;
                }

                var messageLength = _messageLen + payloadLength;
                if (messageLength > _maxMessageSize)
                    throw new WebSocketException(WebSocketStatusCodes.MessageTooBig);

                if (messageLength > _message.Length)
                    Grow(ref _message, _messageLen, messageLength, _maxMessageSize);

                var messageDest = new Span<byte>(_message, _messageLen, payloadLength);
                payloadData.CopyTo(messageDest);
                _messageLen += payloadLength;

                var bytesUsed = index + payloadLength;
                Buffer.BlockCopy(_data, bytesUsed, _data, 0, _dataLen - bytesUsed);
                _dataLen -= index + payloadLength;

                if (frameType != FrameType.Continuation)
                    _frameType = frameType;

                if (isFinal && _frameType.HasValue)
                {
                    FleckLog.Debug($"Frame finished: {_frameType.Value}, {_messageLen} bytes");

                    ProcessFrame(_frameType.Value, new ArraySegment<byte>(_message, 0, _messageLen));
                    Clear();
                }
            }
        }

        private void ProcessFrame(FrameType frameType, ArraySegment<byte> buffer)
        {
            switch (frameType)
            {
                case FrameType.Close:
                    if (buffer.Count == 1 || buffer.Count > 125)
                        throw new WebSocketException(WebSocketStatusCodes.ProtocolError);

                    // echo the client's status code back, as RFC 6455 5.5.1 asks. an empty close has none, so reply normally
                    var closeCode = WebSocketStatusCodes.NormalClosure;
                    if (buffer.Count >= 2)
                    {
                        closeCode = (ushort)new Span<byte>(buffer.Array, buffer.Offset, 2).ToLittleEndianInt();
                        if (!WebSocketStatusCodes.ValidCloseCodes.Contains(closeCode) && (closeCode < 3000 || closeCode > 4999))
                            throw new WebSocketException(WebSocketStatusCodes.ProtocolError);
                    }

                    // answer the close and shut the socket, which raises OnClose once the connection is actually closed
                    _closeReceived = true;
                    _connection.Close(closeCode);
                    break;
                case FrameType.Binary:
                    _connection.OnBinary?.Invoke(buffer);
                    break;
                case FrameType.Ping:
                    _connection.OnPing?.Invoke(buffer);
                    break;
                case FrameType.Pong:
                    _connection.OnPong?.Invoke(buffer);
                    break;
                case FrameType.Text:
                    _connection.OnMessage?.Invoke(ReadUTF8PayloadData(buffer));
                    break;
                default:
                    FleckLog.Debug("Received unhandled " + frameType);
                    break;
            }
        }

        private void Clear()
        {
            _frameType = null;
            _messageLen = 0;
        }

        internal static string CreateResponseKey(string requestKey)
        {
            var combined = requestKey + WebSocketResponseGuid;

            var bytes = SHA1.ComputeHash(Encoding.ASCII.GetBytes(combined));

            return Convert.ToBase64String(bytes);
        }

        internal static string ReadUTF8PayloadData(ArraySegment<byte> bytes)
        {
            try
            {
                return UTF8.GetString(bytes.Array, bytes.Offset, bytes.Count);
            }
            catch (ArgumentException)
            {
                throw new WebSocketException(WebSocketStatusCodes.InvalidFramePayloadData);
            }
        }
    }
}

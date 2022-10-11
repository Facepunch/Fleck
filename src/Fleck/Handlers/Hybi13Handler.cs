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
        private static readonly ThreadLocal<SHA1> sha1Hash = new ThreadLocal<SHA1>(() => SHA1.Create());

        private readonly WebSocketHttpRequest _request;
        private readonly IWebSocketConnection _connection;
        private byte[] _data;
        private int _dataLen;

        private FrameType? _frameType;
        private byte[] _message;
        private int _messageLen;

        public Hybi13Handler(WebSocketHttpRequest request, IWebSocketConnection connection)
        {
            _request = request;
            _connection = connection;

            _data = ArrayPool<byte>.Shared.Rent(1 * 1024 * 1024); // 1 MB read buffer
            _dataLen = 0;

            _frameType = null;
            _message = ArrayPool<byte>.Shared.Rent(1 * 1024 * 1024); // 1 MB message length
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

        public void Receive(Span<byte> newData)
        {
            if (newData.Length + _dataLen >= _data.Length)
                throw new WebSocketException(WebSocketStatusCodes.MessageTooBig);

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

        private static MemoryBuffer FrameData(MemoryBuffer payload, FrameType frameType)
        {
            var framed = FrameData((Span<byte>)payload, frameType);
            payload.Dispose();
            return framed;
        }

        private static MemoryBuffer FrameData(Span<byte> payload, FrameType frameType)
        {
            var data = ArrayPool<byte>.Shared.Rent(payload.Length + 16);
            var writer = new SpanWriter(data);

            byte op = (byte)((byte)frameType + 128);
            writer.Write(op);

            if (payload.Length > ushort.MaxValue)
            {
                writer.Write<byte>(127);
                writer.Write((ulong)payload.Length);
            }
            else if (payload.Length > 125)
            {
                writer.Write<byte>(126);
                writer.Write((ushort)payload.Length);
            }
            else
            {
                writer.Write((byte)payload.Length);
            }

            if (payload.Length > 0)
                writer.Write(payload);

            return new MemoryBuffer(data, writer.Length);
        }

        private void ReceiveData()
        {
            while (_dataLen >= 2)
            {
                FleckLog.Debug("Trying to read a packet");

                var isFinal = (_data[0] & 128) != 0;
                var reservedBits = (_data[0] & 112);
                var frameType = (FrameType)(_data[0] & 15);
                var isMasked = (_data[1] & 128) != 0;
                var length = (_data[1] & 127);


                if (!isMasked
                    || !frameType.IsDefined()
                    || reservedBits != 0 // Must be zero per spec 5.2
                    || (frameType == FrameType.Continuation && !_frameType.HasValue))
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

                if (_messageLen + payloadLength > _message.Length)
                    throw new WebSocketException(WebSocketStatusCodes.MessageTooBig);

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

                    if (buffer.Count >= 2)
                    {
                        var closeCode = (ushort)new Span<byte>(buffer.Array, 0, 2).ToLittleEndianInt();
                        if (!WebSocketStatusCodes.ValidCloseCodes.Contains(closeCode) && (closeCode < 3000 || closeCode > 4999))
                            throw new WebSocketException(WebSocketStatusCodes.ProtocolError);
                    }

                    _connection.OnClose?.Invoke();
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

            var bytes = sha1Hash.Value.ComputeHash(Encoding.ASCII.GetBytes(combined));

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

using System;
using System.Buffers;
using System.IO;
using System.Threading;

namespace Fleck
{
    public class WebSocketConnection : IWebSocketConnection
    {
        private const int ReadSize = 8 * 1024;

        public ISocket Socket { get; set; }
        public IHandler Handler { get; set; }
        public Action OnOpen { get; set; }
        public Action OnClose { get; set; }
        public Action<string> OnMessage { get; set; }
        public BinaryDataHandler OnBinary { get; set; }
        public BinaryDataHandler OnPing { get; set; }
        public BinaryDataHandler OnPong { get; set; }
        public Action<Exception> OnError { get; set; }
        public IWebSocketConnectionInfo ConnectionInfo { get; private set; }
        public bool IsAvailable => !_closing && !_closed && Socket.Connected;

        private readonly Action<IWebSocketConnection> _initialize;
        private readonly Func<IWebSocketConnection, WebSocketHttpRequest, IHandler> _handlerFactory;
        private readonly Func<ArraySegment<byte>, WebSocketHttpRequest> _parseRequest;
        private int _pendingSendCount;
        private byte[] _receiveBuffer;
        private int _receiveOffset;
        private bool _closing;
        private bool _closed;

        public WebSocketConnection(
            ISocket socket,
            Action<IWebSocketConnection> initialize,
            Func<ArraySegment<byte>, WebSocketHttpRequest> parseRequest,
            Func<IWebSocketConnection, WebSocketHttpRequest, IHandler> handlerFactory)
        {
            Socket = socket;
            OnOpen = () => { };
            OnClose = () => { };
            OnMessage = x => { };
            OnBinary = x => { };
            OnPing = x => { };
            OnPong = x => { };
            OnError = x => { };
            _initialize = initialize;
            _handlerFactory = handlerFactory;
            _parseRequest = parseRequest;
        }

        public void Send(string message)
        {
            SendImpl(Handler.FrameText(message));
        }

        public void SendText(MemoryBuffer utf8StringBytes)
        {
            SendImpl(Handler.FrameText(utf8StringBytes));
        }

        public void Send(MemoryBuffer message)
        {
            SendImpl(Handler.FrameBinary(message));
        }

        public void SendPing(MemoryBuffer message)
        {
            SendImpl(Handler.FramePing(message));
        }

        public void SendPong(MemoryBuffer message)
        {
            SendImpl(Handler.FramePong(message));
        }

        private void SendImpl(MemoryBuffer buffer)
        {
            if (Handler == null)
                throw new InvalidOperationException("Cannot send before handshake");

            if (!IsAvailable)
            {
                FleckLog.Warn("Data sent while closing or after close. Ignoring.");
                return;
            }

            SendBytes(buffer);
        }

        public void Close()
        {
            Close(WebSocketStatusCodes.NormalClosure);
        }

        public void Close(ushort code)
        {
            if (_closing || _closed)
                return;

            _closing = true;

            if (Handler == null || !Socket.Connected)
            {
                CloseSocket();
                return;
            }

            var bytes = Handler.FrameClose(code);
            if (bytes.Length == 0)
                CloseSocket();
            else
                SendBytes(bytes, (i, s) => i.CloseSocket());
        }

        public bool CreateHandler(ArraySegment<byte> data)
        {
            var request = _parseRequest(data);
            if (request == null)
                return false;

            Handler = _handlerFactory(this, request);
            if (Handler == null)
                return false;

            ConnectionInfo = WebSocketConnectionInfo.Create(request, Socket.RemoteIpAddress, Socket.RemotePort);

            _initialize(this);

            var handshake = Handler.CreateHandshake();
            SendBytes(handshake, (instance, success) =>
            {
                if (success)
                    instance.OnOpen();
            });

            return true;
        }

        public void StartReceiving()
        {
            if (!IsAvailable)
                return;

            if (_receiveBuffer == null)
                _receiveBuffer = ArrayPool<byte>.Shared.Rent(ReadSize);

            Receive(_receiveBuffer, 0);
        }

        private void HandleReadSuccess(int bytesRead)
        {
            if (bytesRead <= 0)
            {
                FleckLog.Debug("0 bytes read. Closing.");
                CloseSocket();
                return;
            }

            FleckLog.Debug($"{bytesRead} bytes read");

            var readBytes = new Span<byte>(_receiveBuffer, 0, bytesRead);

            if (Handler != null)
            {
                Handler.Receive(readBytes);
                Receive(_receiveBuffer, 0);
            }
            else
            {
                _receiveOffset += bytesRead;
                var started = CreateHandler(new ArraySegment<byte>(_receiveBuffer, 0, _receiveOffset));
                Receive(_receiveBuffer, started ? 0 : _receiveOffset);
            }
        }

        private void HandleReadError(Exception e)
        {
            if (e is AggregateException)
            {
                var agg = e as AggregateException;
                HandleReadError(agg.InnerException);
                return;
            }

            if (e is ObjectDisposedException)
            {
                FleckLog.Warn("Swallowing ObjectDisposedException", e);
                return;
            }

            OnError(e);

            if (e is WebSocketException)
            {
                FleckLog.Debug("Error while reading", e);
                Close(((WebSocketException)e).StatusCode);
            }
            else if (e is IOException)
            {
                FleckLog.Debug("Error while reading", e);
                Close(WebSocketStatusCodes.AbnormalClosure);
            }
            else
            {
                FleckLog.Error("Application Error", e);
                Close(WebSocketStatusCodes.InternalServerError);
            }
        }

        private void Receive(byte[] buffer, int offset)
        {
            try
            {
                Socket.Stream.BeginRead(buffer, offset, buffer.Length - offset, result =>
                {
                    var instance = (WebSocketConnection)result.AsyncState;

                    try
                    {
                        var bytesRead = instance.Socket.Stream.EndRead(result);
                        instance.HandleReadSuccess(bytesRead);
                    }
                    catch (Exception e)
                    {
                        instance.HandleReadError(e);
                    }
                }, this);
            }
            catch (Exception e)
            {
                HandleReadError(e);
            }
        }

        private void HandleWriteError(Exception e)
        {
            if (e is IOException)
                FleckLog.Debug("Failed to send. Disconnecting.", e);
            else
                FleckLog.Info("Failed to send. Disconnecting.", e);

            OnError(e);
            CloseSocket();
        }

        private void SendBytes(MemoryBuffer bytes, Action<WebSocketConnection, bool> callback = null)
        {
            try
            {
                if (Interlocked.Increment(ref _pendingSendCount) > 2048)
                {
                    bytes.Dispose(); // we can safely dispose here since we're not sending it
                    throw new InvalidOperationException("Too many pending sends on WebSocket connection. Disconnecting.");
                }

                // TODO: this allocates for the delegate - could probably avoid that with QueuedStream
                Socket.Stream.BeginWrite(bytes.Data, 0, bytes.Length, result =>
                {
                    var instance = (WebSocketConnection)result.AsyncState;
                    var success = false;

                    try
                    {
                        DecrementPending();

                        instance.Socket.Stream.EndWrite(result);
                        FleckLog.Debug($"Sent {bytes.Length} bytes");

                        success = true;
                    }
                    catch (Exception e)
                    {
                        instance.HandleWriteError(e);
                    }
                    finally
                    {
                        bytes.Dispose();
                    }

                    try
                    {
                        callback?.Invoke(instance, success);
                    }
                    catch (Exception e)
                    {
                        instance.OnError(e);
                    }
                }, this);
            }
            catch (Exception e)
            {
                if (!(e is InvalidOperationException))
                {
                    DecrementPending(); // only BeginWrite could throw this exception type so we should undo the increment
                }

                HandleWriteError(e);
            }

            return;

            void DecrementPending()
            {
                if (Interlocked.Decrement(ref _pendingSendCount) < 0)
                {
                    FleckLog.Error("Pending send count on WebSocket connection has gone negative! Trying to fix it...");
                    _pendingSendCount = 0;
                }
            }
        }

        private void CloseSocket()
        {
            _closing = true;
            OnClose();
            _closed = true;
            Socket.Close();
            Socket.Dispose();
            _closing = false;
            _pendingSendCount = 0;

            Handler?.Dispose();
            Handler = null;

            if (_receiveBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(_receiveBuffer);
                _receiveBuffer = null;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fleck.Handlers;

namespace Fleck
{
    /// <summary>
    /// Opens client websocket connections (ws:// and wss://). The connection it produces is an <see cref="IWebSocketConnection"/>,
    /// the same as the server hands out, so it's used the same way.
    /// </summary>
    public class WebSocketClient
    {
        private const int MaxResponseSize = 16 * 1024;
        private static readonly Encoding Ascii = Encoding.ASCII;
        private static readonly RandomNumberGenerator KeyGenerator = RandomNumberGenerator.Create();

        private readonly Uri _uri;
        private int _maxMessageSize = WebSocketServer.DefaultMaxMessageSize;

        public WebSocketClient(string location)
        {
            _uri = new Uri(location);

            if (_uri.Scheme != "ws" && _uri.Scheme != "wss")
                throw new ArgumentException("Location must be a ws:// or wss:// address", nameof(location));
        }

        public string Location => _uri.ToString();

        public SslProtocols EnabledSslProtocols { get; set; } = SslProtocols.None;

        // how long connecting, TLS and the handshake can take altogether. zero or less turns it off
        public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(10);

        // sent as the Origin header when set
        public string Origin { get; set; }

        // sub protocols to offer. the server's choice, if any, is in ConnectionInfo.SubProtocol
        public IList<string> SubProtocols { get; } = new List<string>();

        // extra headers for the handshake request
        public IDictionary<string, string> Headers { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // largest message the connection can receive; positive values below WebSocketServer.MinimumMaxMessageSize are clamped to it
        public int MaxMessageSize
        {
            get => _maxMessageSize;
            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException(nameof(value), "MaxMessageSize must be positive");

                _maxMessageSize = Math.Max(value, WebSocketServer.MinimumMaxMessageSize);
            }
        }

        /// <summary>
        /// Connects and completes the websocket handshake. config runs before the connection opens, so it's where to set
        /// OnOpen, OnMessage and the rest. The task completes once the connection is open.
        /// </summary>
        public async Task<IWebSocketConnection> Connect(Action<IWebSocketConnection> config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            var key = CreateKey();
            var request = CreateRequest(key);

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            var timedOut = 0;
            Timer timer = null;
            SocketWrapper wrapper = null;

            if (HandshakeTimeout > TimeSpan.Zero && HandshakeTimeout < TimeSpan.FromMilliseconds(uint.MaxValue - 1))
            {
                timer = new Timer(_ =>
                {
                    Interlocked.Exchange(ref timedOut, 1);
                    try { socket.Dispose(); } catch (Exception) { }
                }, null, HandshakeTimeout, Timeout.InfiniteTimeSpan);
            }

            try
            {
                await Task.Factory.FromAsync(socket.BeginConnect(_uri.DnsSafeHost, _uri.Port, null, null), socket.EndConnect).ConfigureAwait(false);

                wrapper = new SocketWrapper(socket);

                if (_uri.Scheme == "wss")
                    await wrapper.AuthenticateAsClient(_uri.DnsSafeHost, EnabledSslProtocols).ConfigureAwait(false);

                var stream = wrapper.Stream;
                await stream.WriteAsync(request, 0, request.Length).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);

                var response = await ReadResponse(stream).ConfigureAwait(false);
                var subProtocol = ValidateResponse(response.Request, key);
                var leftover = response.Leftover;

                wrapper.EnableQueuedWrites();

                var connection = new WebSocketConnection(wrapper, null, null, null, null);
                config(connection);

                var info = WebSocketConnectionInfo.Create(CreateInfoRequest(subProtocol), wrapper.RemoteIpAddress, wrapper.RemotePort);
                var handler = new Hybi13Handler(null, connection, _maxMessageSize, isClient: true);

                // the connection owns the socket from here on, including cleanup
                timer?.Dispose();
                timer = null;
                connection.StartClient(handler, info, leftover);

                return connection;
            }
            catch (Exception e)
            {
                try { wrapper?.Dispose(); } catch (Exception) { }
                try { socket.Dispose(); } catch (Exception) { }

                if (Volatile.Read(ref timedOut) != 0)
                    throw new TimeoutException("The websocket handshake didn't complete in time", e);

                throw;
            }
            finally
            {
                timer?.Dispose();
            }
        }

        private static string CreateKey()
        {
            var bytes = new byte[16];
            KeyGenerator.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private byte[] CreateRequest(string key)
        {
            var builder = new StringBuilder();
            builder.Append("GET ").Append(_uri.PathAndQuery).Append(" HTTP/1.1\r\n");
            builder.Append("Host: ").Append(_uri.Authority).Append("\r\n");
            builder.Append("Upgrade: websocket\r\n");
            builder.Append("Connection: Upgrade\r\n");
            builder.Append("Sec-WebSocket-Key: ").Append(key).Append("\r\n");
            builder.Append("Sec-WebSocket-Version: 13\r\n");

            if (!string.IsNullOrEmpty(Origin))
                builder.Append("Origin: ").Append(CheckHeaderValue(Origin)).Append("\r\n");

            if (SubProtocols.Count > 0)
                builder.Append("Sec-WebSocket-Protocol: ").Append(string.Join(", ", SubProtocols.Select(CheckHeaderValue))).Append("\r\n");

            foreach (var header in Headers)
                builder.Append(CheckHeaderValue(header.Key)).Append(": ").Append(CheckHeaderValue(header.Value)).Append("\r\n");

            builder.Append("\r\n");
            return Ascii.GetBytes(builder.ToString());
        }

        // stops a value from adding headers or ending the request early
        private static string CheckHeaderValue(string value)
        {
            if (value.IndexOfAny(new[] { '\r', '\n' }) >= 0)
                throw new ArgumentException("Header names and values can't contain line breaks");

            return value;
        }

        private WebSocketHttpRequest CreateInfoRequest(string subProtocol)
        {
            var request = new WebSocketHttpRequest
            {
                Method = "GET",
                Path = _uri.PathAndQuery,
                Scheme = _uri.Scheme,
            };

            request.Headers["Host"] = _uri.Authority;

            if (!string.IsNullOrEmpty(Origin))
                request.Headers["Origin"] = Origin;

            if (subProtocol != null)
                request.Headers["Sec-WebSocket-Protocol"] = subProtocol;

            return request;
        }

        private struct Response
        {
            public WebSocketHttpRequest Request; // holds the response's status line and headers
            public ArraySegment<byte> Leftover;
        }

        private static async Task<Response> ReadResponse(Stream stream)
        {
            var buffer = new byte[2048];
            var length = 0;
            int end;

            while ((end = IndexOfHeaderEnd(buffer, length)) < 0)
            {
                if (length == buffer.Length)
                {
                    if (buffer.Length >= MaxResponseSize)
                        throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "Handshake response is too large");

                    Array.Resize(ref buffer, buffer.Length * 2);
                }

                var read = await stream.ReadAsync(buffer, length, buffer.Length - length).ConfigureAwait(false);
                if (read <= 0)
                    throw new IOException("The connection closed during the websocket handshake");

                length += read;
            }

            var lines = Ascii.GetString(buffer, 0, end).Split(new[] { "\r\n" }, StringSplitOptions.None);
            var statusParts = lines[0].Split(new[] { ' ' }, 3);
            if (statusParts.Length < 2 || !statusParts[0].StartsWith("HTTP/1.1", StringComparison.Ordinal))
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "Invalid handshake response");

            var response = new WebSocketHttpRequest { Method = statusParts[1] }; // the status code
            foreach (var line in lines.Skip(1))
            {
                var colon = line.IndexOf(':');
                if (colon <= 0)
                    throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "Invalid handshake response header");

                response.Headers[line.Substring(0, colon).Trim()] = line.Substring(colon + 1).Trim();
            }

            var bodyStart = end + 4;
            return new Response
            {
                Request = response,
                Leftover = new ArraySegment<byte>(buffer, bodyStart, length - bodyStart),
            };
        }

        private static int IndexOfHeaderEnd(byte[] buffer, int length)
        {
            for (var i = 0; i + 3 < length; i++)
            {
                if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                    return i;
            }

            return -1;
        }

        // returns the sub protocol the server chose, if any
        private string ValidateResponse(WebSocketHttpRequest response, string key)
        {
            if (response.Method != "101")
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "The server didn't switch protocols, status " + response.Method);

            if (!string.Equals(response["Upgrade"], "websocket", StringComparison.OrdinalIgnoreCase))
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "Handshake response has no websocket upgrade");

            var connectionHeader = response["Connection"] ?? "";
            if (!connectionHeader.Split(',').Any(t => string.Equals(t.Trim(), "Upgrade", StringComparison.OrdinalIgnoreCase)))
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "Handshake response has no connection upgrade");

            if (response["Sec-WebSocket-Accept"] != Hybi13Handler.CreateResponseKey(key))
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "Handshake response has the wrong Sec-WebSocket-Accept");

            if (response["Sec-WebSocket-Extensions"] != null)
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "The server chose an extension that wasn't offered");

            var subProtocol = response["Sec-WebSocket-Protocol"];
            if (subProtocol != null && !SubProtocols.Contains(subProtocol))
                throw new WebSocketException(WebSocketStatusCodes.ProtocolError, "The server chose a sub protocol that wasn't offered");

            return subProtocol;
        }
    }
}

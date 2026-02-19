using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using Fleck.Helpers;

namespace Fleck
{
    public class WebSocketServer : IWebSocketServer
    {
        private readonly string _scheme;
        private readonly IPAddress _locationIP;
        private Action<IWebSocketConnection> _config;

        public static readonly ConnectionLimiter Limiter = new ConnectionLimiter();

        public WebSocketServer(string location, bool supportDualStack = true, int backlog = 100, int maxConnections = 500, int maxConnectionsPerIP = 5)
        {
            var uri = new Uri(location);

            Port = uri.Port;
            Location = location;
            SupportDualStack = supportDualStack;
            Backlog = backlog;

            _locationIP = ParseIPAddress(uri);
            _scheme = uri.Scheme;
            var socket = new Socket(_locationIP.AddressFamily, SocketType.Stream, ProtocolType.IP);

            if (SupportDualStack)
            {
                if (!FleckRuntime.IsRunningOnMono() && FleckRuntime.IsRunningOnWindows())
                {
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
                }
            }

            ListenerSocket = new SocketWrapper(socket);
            Limiter.Clear();
            Limiter.SetConnectionLimits(maxConnections, maxConnectionsPerIP);
        }

        public ISocket ListenerSocket { get; set; }
        public string Location { get; }
        public bool SupportDualStack { get; }
        public int Port { get; private set; }
        public X509Certificate2 Certificate { get; set; }
        public SslProtocols EnabledSslProtocols { get; set; }
        public bool RestartAfterListenError { get; set; }
        public int Backlog { get; set; }

        public bool IsSecure => _scheme == "wss" && Certificate != null;

        public void Dispose()
        {
            ListenerSocket.Dispose();
        }

        private IPAddress ParseIPAddress(Uri uri)
        {
            var ipStr = uri.Host;

            if (ipStr == "0.0.0.0")
                return IPAddress.Any;

            if (ipStr == "[0000:0000:0000:0000:0000:0000:0000:0000]")
                return IPAddress.IPv6Any;

            try
            {
                return IPAddress.Parse(ipStr);
            }
            catch (Exception ex)
            {
                throw new FormatException("Failed to parse the IP address part of the location. Please make sure you specify a valid IP address. Use 0.0.0.0 or [::] to listen on all interfaces.", ex);
            }
        }

        public void Start(Action<IWebSocketConnection> config)
        {
            var ipLocal = new IPEndPoint(_locationIP, Port);
            ListenerSocket.Bind(ipLocal);
            ListenerSocket.Listen(Backlog);
            Port = ((IPEndPoint)ListenerSocket.LocalEndPoint).Port;
            FleckLog.Info($"Server started at {Location} (actual port {Port})");
            if (_scheme == "wss")
            {
                if (Certificate == null)
                {
                    FleckLog.Error("Scheme cannot be 'wss' without a Certificate");
                    return;
                }
            }
            ListenForClients();
            _config = config;
        }

        private void ListenForClients()
        {
            ListenerSocket.Accept(OnClientConnect, e =>
            {
                FleckLog.Error("Listener socket is closed", e);
                if (RestartAfterListenError)
                {
                    FleckLog.Info("Listener socket restarting");
                    try
                    {
                        ListenerSocket.Dispose();
                        var socket = new Socket(_locationIP.AddressFamily, SocketType.Stream, ProtocolType.IP);
                        ListenerSocket = new SocketWrapper(socket);
                        Start(_config);
                        FleckLog.Info("Listener socket restarted");
                    }
                    catch (Exception ex)
                    {
                        FleckLog.Error("Listener could not be restarted", ex);
                    }
                }
            });
        }

        private void OnClientConnect(ISocket clientSocket)
        {
            if (clientSocket == null) return; // socket closed

            FleckLog.Debug($"Client connected from {clientSocket.RemoteIpAddress}:{clientSocket.RemotePort.ToString()}");

            bool allowed = Limiter.TryAdd(clientSocket.RemoteIpAddress);

            ListenForClients();

            if (!allowed) // rate limit, don't initiate handshake, close socket immediately
            {
                clientSocket.Close();
                return;
            }

            WebSocketConnection connection = null;

            connection = new WebSocketConnection(
                clientSocket,
                _config,
                bytes => RequestParser.Parse(bytes, _scheme),
                (c, r) => HandlerFactory.BuildHandler(r, c));

            if (IsSecure)
            {
                FleckLog.Debug("Authenticating Secure Connection");
                clientSocket
                    .Authenticate(Certificate,
                                  EnabledSslProtocols,
                                  connection.StartReceiving,
                                  e => FleckLog.Warn("Failed to Authenticate", e));
            }
            else
            {
                connection.StartReceiving();
            }
        }
    }
}

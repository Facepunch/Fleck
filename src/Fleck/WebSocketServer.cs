using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Threading.Tasks;
using Fleck.Helpers;

namespace Fleck
{
    public class WebSocketServer : IWebSocketServer
    {
        private readonly string _scheme;
        private readonly IPAddress _locationIP;
        private Action<IWebSocketConnection> _config;

        public readonly ConnectionLimiter Limiter;

        public WebSocketServer(string location, bool supportDualStack = true, int backlog = 100, int maxConnections = 500, int maxConnectionsPerIP = 5)
        {
            var uri = new Uri(location);

            Port = uri.Port;
            Location = location;
            SupportDualStack = supportDualStack;
            Backlog = backlog;

            _locationIP = ParseIPAddress(uri);
            _scheme = uri.Scheme;

            ListenerSocket = new SocketWrapper(CreateListenerSocket());
            Limiter = new ConnectionLimiter();
            Limiter.SetConnectionLimits(maxConnections, maxConnectionsPerIP);
        }

        public ISocket ListenerSocket { get; set; }
        public string Location { get; }
        public bool SupportDualStack { get; }
        public int Port { get; private set; }
        public X509Certificate2 Certificate { get; set; }
        public SslProtocols EnabledSslProtocols { get; set; }
        public bool RestartAfterListenError { get; set; } = true;
        public int Backlog { get; set; }

        public bool IsSecure => _scheme == "wss" && Certificate != null;

        private const int MaxRestartDelaySeconds = 30;

        private readonly object _listenerSync = new object();
        private bool _disposed;

        public void Dispose()
        {
            lock (_listenerSync)
            {
                _disposed = true;
                ListenerSocket.Dispose();
            }
        }

        private Socket CreateListenerSocket()
        {
            var socket = new Socket(_locationIP.AddressFamily, SocketType.Stream, ProtocolType.IP);

            if (SupportDualStack)
            {
                if (!FleckRuntime.IsRunningOnMono() && FleckRuntime.IsRunningOnWindows())
                {
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
                }
            }

            return socket;
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
            _config = config;
            ListenForClients();
        }

        private void ListenForClients()
        {
            ListenerSocket.Accept(OnClientConnect, e =>
            {
                FleckLog.Error("Listener socket is closed", e);
                if (RestartAfterListenError)
                {
                    RestartListener();
                }
            });
        }

        private async void RestartListener()
        {
            bool noDelay;
            try
            {
                noDelay = ListenerSocket.NoDelay;
            }
            catch (Exception)
            {
                noDelay = false;
            }

            for (var attempt = 1; ; attempt++)
            {
                // Persistent errors (e.g. out of file descriptors) would otherwise restart in a tight loop
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(attempt, MaxRestartDelaySeconds)));

                lock (_listenerSync)
                {
                    if (_disposed)
                        return;

                    FleckLog.Info("Listener socket restarting");
                    try
                    {
                        ListenerSocket.Dispose();
                        ListenerSocket = new SocketWrapper(CreateListenerSocket());
                        ListenerSocket.NoDelay = noDelay;
                        Start(_config);
                        FleckLog.Info("Listener socket restarted");
                        return;
                    }
                    catch (Exception ex)
                    {
                        FleckLog.Error("Listener could not be restarted", ex);
                    }
                }
            }
        }

        private void OnClientConnect(ISocket clientSocket)
        {
            if (clientSocket == null) return; // socket closed

            ListenForClients();

            // Exceptions escaping this method reach the listener's error handler and stop the accept loop
            WebSocketConnection connection = null;
            bool allowed = false;

            try
            {
                FleckLog.Debug($"Client connected from {clientSocket.RemoteIpAddress}:{clientSocket.RemotePort.ToString()}");

                allowed = Limiter.TryAdd(clientSocket.RemoteIpAddress);

                if (!allowed) // rate limit, don't initiate handshake, close socket immediately
                {
                    clientSocket.Close();
                    return;
                }

                connection = new WebSocketConnection(
                    clientSocket,
                    _config,
                    bytes => RequestParser.Parse(bytes, _scheme),
                    (c, r) => HandlerFactory.BuildHandler(r, c),
                    Limiter);

                if (IsSecure)
                {
                    FleckLog.Debug("Authenticating Secure Connection");
                    var secureConnection = connection;
                    clientSocket
                        .Authenticate(
                            Certificate,
                            EnabledSslProtocols,
                            secureConnection.StartReceiving,
                            e =>
                            {
                                FleckLog.Warn("Failed to Authenticate", e);

                                // the handshake never started, so nothing else will release the slot or the socket
                                secureConnection.ReleaseLimiterSlot();
                                clientSocket.Close();
                            });
                }
                else
                {
                    connection.StartReceiving();
                }
            }
            catch (Exception e)
            {
                if (allowed)
                {
                    if (connection != null)
                    {
                        connection.ReleaseLimiterSlot();
                    }
                    else
                    {
                        Limiter.Remove(clientSocket.RemoteIpAddress);
                    }
                }

                clientSocket.Close();

                FleckLog.Warn("Exception during socket start", e);
            }
        }
    }
}

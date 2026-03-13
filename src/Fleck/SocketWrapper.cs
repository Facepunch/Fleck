using Fleck.Helpers;
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Fleck
{
    public class SocketWrapper : ISocket
    {
        public const uint KeepAliveInterval = 60000;
        public const uint RetryInterval = 10000;
        public const int RetryProbes = 3;

        private const int SOL_TCP = 6;

        private const int TCP_KEEPIDLE = 4;
        private const int TCP_KEEPINTVL = 5;
        private const int TCP_KEEPCNT = 6;

        private static readonly byte[] keepAliveValues;
    
        private readonly Socket _socket;
        private CancellationTokenSource _tokenSource;
        private TaskFactory _taskFactory;

        public IPAddress RemoteIpAddress
        {
            get
            {
                var endpoint = _socket.RemoteEndPoint as IPEndPoint;
                return endpoint?.Address;
            }
        }

        public int RemotePort => _socket.RemoteEndPoint is IPEndPoint endpoint ? endpoint.Port : -1;

        static SocketWrapper()
        {
            const int size = sizeof(uint);
            uint on = 1;

            byte[] inArray = new byte[size * 3];
            Array.Copy(BitConverter.GetBytes(on), 0, inArray, 0, size);
            Array.Copy(BitConverter.GetBytes(KeepAliveInterval), 0, inArray, size, size);
            Array.Copy(BitConverter.GetBytes(RetryInterval), 0, inArray, size * 2, size);

            keepAliveValues = inArray;
        }

        public SocketWrapper(Socket socket)
        {
            _tokenSource = new CancellationTokenSource();
            _taskFactory = new TaskFactory(_tokenSource.Token);
            _socket = socket;
            if (_socket.Connected)
                Stream = new NetworkStream(_socket);

            // The tcp keepalive default values on most systems
            // are huge (~7200s). Set them to something more reasonable.
            if (FleckRuntime.IsRunningOnWindows())
            {
                socket.IOControl(IOControlCode.KeepAliveValues, keepAliveValues, null);
            }
            else if (FleckRuntime.IsRunningOnLinux())
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                int fd = (int)socket.Handle;

                // linux uses seconds, unlike milliseconds in windows - https://man7.org/linux/man-pages/man7/tcp.7.html
                int keepAlive = (int)KeepAliveInterval / 1000;
                int retryInterval = (int)RetryInterval / 1000;
                int probeCount = RetryProbes;

                setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, ref keepAlive, sizeof(int));
                setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, ref retryInterval, sizeof(int));
                setsockopt(fd, SOL_TCP, TCP_KEEPCNT, ref probeCount, sizeof(int));
            }
        }

        public Task Authenticate(X509Certificate2 certificate, SslProtocols enabledSslProtocols, Action callback, Action<Exception> error)
        {
            var ssl = new SslStream(Stream, false);
            Stream = new QueuedStream(ssl);
            Func<AsyncCallback, object, IAsyncResult> begin =
                (cb, s) => ssl.BeginAuthenticateAsServer(certificate, false, enabledSslProtocols, false, cb, s);

            Task task = Task.Factory.FromAsync(begin, ssl.EndAuthenticateAsServer, null);
            task.ContinueWith(t => callback(), TaskContinuationOptions.NotOnFaulted)
                .ContinueWith(t => error(t.Exception), TaskContinuationOptions.OnlyOnFaulted);
            task.ContinueWith(t => error(t.Exception), TaskContinuationOptions.OnlyOnFaulted);

            return task;
        }

        public void Listen(int backlog)
        {
            _socket.Listen(backlog);
        }

        public void Bind(EndPoint endPoint)
        {
            _socket.Bind(endPoint);
        }

        public bool Connected => _socket.Connected;

        public Stream Stream { get; private set; }

        public bool NoDelay
        {
            get => _socket.NoDelay;
            set => _socket.NoDelay = value;
        }

        public EndPoint LocalEndPoint => _socket.LocalEndPoint;

        public Task<ISocket> Accept(Action<ISocket> callback, Action<Exception> error)
        {
            Func<IAsyncResult, ISocket> end = r => _tokenSource.Token.IsCancellationRequested ? null : new SocketWrapper(_socket.EndAccept(r));
            var task = _taskFactory.FromAsync(_socket.BeginAccept, end, null);
            task.ContinueWith(t => callback(t.Result), TaskContinuationOptions.OnlyOnRanToCompletion)
                .ContinueWith(t => error(t.Exception), TaskContinuationOptions.OnlyOnFaulted);
            task.ContinueWith(t => error(t.Exception), TaskContinuationOptions.OnlyOnFaulted);
            return task;
        }

        public void Dispose()
        {
            _tokenSource.Cancel();
            if (Stream != null) Stream.Dispose();
            if (_socket != null) _socket.Dispose();
        }

        public void Close()
        {
            _tokenSource.Cancel();
            if (Stream != null) Stream.Close();
            if (_socket != null) _socket.Close();
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);
    }
}

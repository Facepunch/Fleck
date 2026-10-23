using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class WebSocketClientTests
    {
        private WebSocketServer _server;
        private readonly ConcurrentQueue<string> _serverMessages = new ConcurrentQueue<string>();

        private static MemoryBuffer Copy(ReadOnlySpan<byte> data)
        {
            var buffer = new MemoryBuffer(data.Length);
            data.CopyTo(new Span<byte>(buffer.Data, 0, data.Length));
            return buffer.Slice(data.Length);
        }

        [SetUp]
        public void Setup()
        {
            _server = new WebSocketServer("ws://127.0.0.1:0", supportDualStack: false, maxConnectionsPerIP: -1);
            _server.Start(socket =>
            {
                socket.OnOpen = () => socket.Send("welcome");
                socket.OnMessage = message =>
                {
                    _serverMessages.Enqueue(message);
                    socket.Send("echo " + message);
                };
                socket.OnBinary = data => socket.Send(Copy(data));
            });
        }

        [TearDown]
        public void TearDown()
        {
            _server.Dispose();
        }

        private string Url => $"ws://127.0.0.1:{_server.Port}/path?x=1";

        private static async Task<T> Wait<T>(TaskCompletionSource<T> source)
        {
            var finished = await Task.WhenAny(source.Task, Task.Delay(TimeSpan.FromSeconds(10)));
            Assert.AreSame(source.Task, finished, "timed out");
            return await source.Task;
        }

        [Test]
        public async Task TextRoundTripsWithServer([Values] bool useAsync)
        {
            var welcome = new TaskCompletionSource<string>();
            var echo = new TaskCompletionSource<string>();
            var client = new WebSocketClient(Url);

            var connection = await client.Connect(socket =>
            {
                socket.OnMessage = message =>
                {
                    if (message == "welcome") welcome.TrySetResult(message);
                    else echo.TrySetResult(message);
                };
            }, useAsync);

            Assert.AreEqual("welcome", await Wait(welcome));
            connection.Send("hello");
            Assert.AreEqual("echo hello", await Wait(echo));
            Assert.AreEqual("/path?x=1", connection.ConnectionInfo.Path);
            connection.Close();
        }

        [Test]
        public async Task LargeBinaryRoundTripsWithServer([Values] bool useAsync)
        {
            var payload = new byte[200 * 1024];
            new Random(1).NextBytes(payload);
            var received = new TaskCompletionSource<byte[]>();

            var connection = await new WebSocketClient(Url).Connect(socket =>
            {
                socket.OnBinary = data => received.TrySetResult(data.ToArray());
            }, useAsync);

            connection.Send(Copy(payload));
            CollectionAssert.AreEqual(payload, await Wait(received));
            connection.Close();
        }

        [Test]
        public async Task OnCloseRaisedWhenClosed([Values] bool useAsync)
        {
            var closed = new TaskCompletionSource<bool>();
            var connection = await new WebSocketClient(Url).Connect(socket => socket.OnClose = () => closed.TrySetResult(true), useAsync);

            connection.Close();
            Assert.IsTrue(await Wait(closed));
        }

        [Test]
        public async Task ReopensAfterClose([Values] bool useAsync)
        {
            var closed = new TaskCompletionSource<bool>();
            var client = new WebSocketClient(Url);
            var connection = await client.Connect(socket => socket.OnClose = () => closed.TrySetResult(true), useAsync);
            connection.Close();
            Assert.IsTrue(await Wait(closed));

            var welcome = new TaskCompletionSource<bool>();
            connection = await client.Connect(socket => socket.OnOpen = () => welcome.TrySetResult(true), useAsync);
            Assert.IsTrue(await Wait(welcome));
        }

        [Test]
        public void FailsWhenServerDoesNotUpgrade([Values] bool useAsync)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                var accepting = Task.Run(async () =>
                {
                    using var tcp = await listener.AcceptTcpClientAsync();
                    var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    await tcp.GetStream().WriteAsync(response, 0, response.Length);
                    await Task.Delay(500);
                });

                var client = new WebSocketClient($"ws://127.0.0.1:{port}/");
                Assert.ThrowsAsync<WebSocketException>(async () => await client.Connect(socket => { }, useAsync));
                accepting.Wait();
            }
            finally
            {
                listener.Stop();
            }
        }

        [Test]
        public void RejectsNonWebSocketScheme()
        {
            Assert.Throws<ArgumentException>(() => new WebSocketClient("http://localhost/"));
        }

        [Test]
        public void RejectsLineBreaksInHeaders()
        {
            var client = new WebSocketClient(Url);
            client.Headers["X-Test"] = "a\r\nInjected: yes";
            Assert.ThrowsAsync<ArgumentException>(async () => await client.Connect(socket => { }));
        }
    }
}

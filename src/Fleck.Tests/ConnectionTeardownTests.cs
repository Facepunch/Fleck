using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class ConnectionTeardownTests
    {
        private LogLevel _originalLevel;
        private Action<LogLevel, string, Exception> _originalAction;
        private ConcurrentQueue<string> _errors;
        private WebSocketServer _server;

        [SetUp]
        public void SetUp()
        {
            _originalLevel = FleckLog.Level;
            _originalAction = FleckLog.LogAction;
            _errors = new ConcurrentQueue<string>();
            FleckLog.Level = LogLevel.Error;
            FleckLog.LogAction = (level, message, ex) => _errors.Enqueue(message + " " + ex);
        }

        [TearDown]
        public void TearDown()
        {
            // FleckLog is global and connections close on IO threads, so finish this test's connections (quietly) before
            // the next test installs its own LogAction, or their late errors would land in its _errors
            FleckLog.LogAction = (level, message, ex) => { };

            foreach (var connection in _connections)
                connection.Close();

            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (Volatile.Read(ref _openConnections) > 0 && DateTime.UtcNow < deadline)
                Thread.Sleep(10);

            _server?.Dispose();
            _server = null;
            _connections = new ConcurrentBag<IWebSocketConnection>();
            Volatile.Write(ref _openConnections, 0);

            FleckLog.Level = _originalLevel;
            FleckLog.LogAction = _originalAction;
        }

        private ConcurrentBag<IWebSocketConnection> _connections = new ConcurrentBag<IWebSocketConnection>();
        private int _openConnections;

        // these tests make lots of connections from 127.0.0.1, so turn off the per-IP limits. connections are tracked so
        // TearDown can wait for them to finish closing
        private void StartServer(Action<IWebSocketConnection> config, TimeSpan? handshakeTimeout = null)
        {
            _server = new WebSocketServer("ws://127.0.0.1:0", supportDualStack: false, maxConnectionsPerIP: -1);
            _server.Limiter.SetAttemptLimits(-1, TimeSpan.Zero);
            if (handshakeTimeout.HasValue)
                _server.HandshakeTimeout = handshakeTimeout.Value;
            _server.Start(socket =>
            {
                _connections.Add(socket);
                Interlocked.Increment(ref _openConnections);

                config(socket);

                var onClose = socket.OnClose;
                socket.OnClose = () =>
                {
                    try
                    {
                        onClose?.Invoke();
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _openConnections);
                    }
                };
            });
        }

        private Uri ServerUri => new Uri($"ws://127.0.0.1:{_server.Port}/");

        [Test]
        public async Task ClientsThatDontFinishTheirHandshakeAreDisconnected()
        {
            StartServer(socket => { }, handshakeTimeout: TimeSpan.FromMilliseconds(500));

            // connects but never sends its handshake request
            using var silent = new TcpClient();
            await silent.ConnectAsync("127.0.0.1", _server.Port);

            // a normal client, which should stay connected past the timeout
            using var normal = new ClientWebSocket();
            await normal.ConnectAsync(ServerUri, CancellationToken.None);

            // the server closes it without having read anything, which shows up as either an orderly close or a reset
            var buffer = new byte[16];
            var read = silent.GetStream().ReadAsync(buffer, 0, buffer.Length);
            Assert.IsTrue(await Task.WhenAny(read, Task.Delay(5000)) == read, "the silent client was never disconnected");
            try
            {
                Assert.AreEqual(0, await read, "the silent client should be sent nothing, just disconnected");
            }
            catch (System.IO.IOException)
            {
                // reset by the server
            }

            Assert.AreEqual(WebSocketState.Open, normal.State, "the client that completed its handshake was disconnected");
        }

        [Test]
        public async Task AServerWithAnUnschedulableHandshakeTimeoutStillAcceptsClients()
        {
            // TimeSpan.MaxValue is a natural way to say "no timeout", and used to make every connection fail to start
            StartServer(socket => { }, handshakeTimeout: TimeSpan.MaxValue);

            using var client = new ClientWebSocket();
            await client.ConnectAsync(ServerUri, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.AreEqual(WebSocketState.Open, client.State);
        }

        [Test]
        public async Task DroppingClientsWithSendsInFlightDoesNotCorruptThePendingCount()
        {
            const int clientCount = 3;
            var connections = new ConcurrentQueue<IWebSocketConnection>();
            var closedCount = 0;
            StartServer(socket =>
            {
                socket.OnOpen = () => connections.Enqueue(socket);
                socket.OnClose = () => Interlocked.Increment(ref closedCount);
            });

            // clients that never read, so sends back up until the pending limit drops them with lots still in flight.
            // whether the count used to go negative depended on in-flight sends finishing after the close, which several
            // connections being dropped at once makes very likely
            var clients = new List<ClientWebSocket>();
            try
            {
                for (var i = 0; i < clientCount; i++)
                {
                    var client = new ClientWebSocket();
                    clients.Add(client);
                    await client.ConnectAsync(ServerUri, CancellationToken.None);
                }

                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (connections.Count < clientCount && DateTime.UtcNow < deadline)
                    await Task.Delay(10);

                var message = new string('x', 64 * 1024);
                for (var i = 0; i < 3000; i++)
                {
                    foreach (var connection in connections)
                        connection.Send(message); // must not throw once the connection has been dropped
                }

                deadline = DateTime.UtcNow.AddSeconds(5);
                while (Volatile.Read(ref closedCount) < clientCount && DateTime.UtcNow < deadline)
                    await Task.Delay(10);

                Assert.AreEqual(clientCount, Volatile.Read(ref closedCount), "the clients were never dropped");
                await Task.Delay(1000); // let the in-flight sends complete

                Assert.IsEmpty(_errors.Where(e => e.Contains("negative")), "pending send count went negative");
            }
            finally
            {
                foreach (var client in clients)
                    client.Dispose();
            }
        }

        [Test]
        public async Task DataArrivingWhileTheServerClosesDoesNotFault()
        {
            var faults = new ConcurrentQueue<Exception>();
            StartServer(socket =>
            {
                // close as soon as the connection opens, racing the data the client sends straight after connecting
                socket.OnOpen = socket.Close;
                socket.OnError = e => { if (!(e is System.IO.IOException)) faults.Enqueue(e); };
            });

            var payload = Encoding.UTF8.GetBytes("hello");
            for (var i = 0; i < 50; i++)
            {
                using var client = new ClientWebSocket();

                try
                {
                    await client.ConnectAsync(ServerUri, CancellationToken.None);
                    for (var j = 0; j < 10; j++)
                        await client.SendAsync(payload, WebSocketMessageType.Text, true, CancellationToken.None);
                }
                catch (System.Net.WebSockets.WebSocketException)
                {
                    // the server closed first
                }
            }

            await Task.Delay(500);

            Assert.IsEmpty(faults.Select(e => e.GetType().Name + ": " + e.Message), "OnError reported faults");
            Assert.IsEmpty(_errors.Where(e => e.Contains("Application Error")), "Fleck logged application errors");
        }

        [Test]
        public async Task SendsFromManyThreadsArriveIntactAndInOrder()
        {
            const int threadCount = 8;
            const int messagesPerThread = 200;

            var opened = new TaskCompletionSource<IWebSocketConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
            StartServer(socket => socket.OnOpen = () => opened.TrySetResult(socket));

            using var client = new ClientWebSocket();
            await client.ConnectAsync(ServerUri, CancellationToken.None);
            var connection = await opened.Task.WaitAsync(TimeSpan.FromSeconds(5));

            // a mix of sizes, including ones large enough that a single write may be split
            var padding = new[] { 0, 100, 5000, 70000, 300000 };
            var senders = Enumerable.Range(0, threadCount).Select(t => Task.Run(() =>
            {
                for (var i = 0; i < messagesPerThread; i++)
                    connection.Send($"{t}:{i}:" + new string((char)('a' + t), padding[(t + i) % padding.Length]));
            })).ToArray();

            var lastSeen = Enumerable.Repeat(-1, threadCount).ToArray();
            var buffer = new byte[1024 * 1024];
            var received = 0;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            while (received < threadCount * messagesPerThread)
            {
                var length = 0;
                WebSocketReceiveResult result;
                do
                {
                    result = await client.ReceiveAsync(new ArraySegment<byte>(buffer, length, buffer.Length - length), cts.Token);
                    length += result.Count;
                } while (!result.EndOfMessage);

                Assert.AreEqual(WebSocketMessageType.Text, result.MessageType);

                var parts = Encoding.UTF8.GetString(buffer, 0, length).Split(':');
                var thread = int.Parse(parts[0]);
                var index = int.Parse(parts[1]);

                Assert.AreEqual(lastSeen[thread] + 1, index, $"messages from thread {thread} arrived out of order");
                Assert.AreEqual(padding[(thread + index) % padding.Length], parts[2].Length, "message was corrupted");
                Assert.IsTrue(parts[2].All(c => c == (char)('a' + thread)), "message was corrupted");

                lastSeen[thread] = index;
                received++;
            }

            await Task.WhenAll(senders);
        }

        [Test]
        public async Task ALogActionThatThrowsWhileHandlingAReadErrorDoesNotCrashAndStillCloses()
        {
            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            StartServer(socket =>
            {
                socket.OnError = e => throw new InvalidOperationException("application handler failed");
                socket.OnClose = () => closed.TrySetResult(true);
            });

            using var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", _server.Port);
            var stream = tcp.GetStream();

            var handshake = Encoding.ASCII.GetBytes(
                "GET / HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                "Sec-WebSocket-Version: 13\r\n\r\n");
            await stream.WriteAsync(handshake, 0, handshake.Length);

            var response = new StringBuilder();
            var one = new byte[1];
            while (!response.ToString().EndsWith("\r\n\r\n"))
            {
                Assert.AreEqual(1, await stream.ReadAsync(one, 0, 1), "connection closed during the handshake");
                response.Append((char)one[0]);
            }

            // from here on every log call throws, including the ones made while handling the bad frame on an IO thread,
            // which used to escape and take the process down
            FleckLog.Level = LogLevel.Debug;
            FleckLog.LogAction = (level, message, ex) => throw new InvalidOperationException("LogAction failed");

            var unmasked = new byte[] { 0x81, 0x02, (byte)'h', (byte)'i' };
            await stream.WriteAsync(unmasked, 0, unmasked.Length);

            Assert.IsTrue(await Task.WhenAny(closed.Task, Task.Delay(5000)) == closed.Task, "the connection was never closed");
        }

        [Test]
        public async Task ThrowingOnErrorStillClosesTheConnection()
        {
            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            StartServer(socket =>
            {
                socket.OnError = e => throw new InvalidOperationException("application handler failed");
                socket.OnClose = () => closed.TrySetResult(true);
            });

            using var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", _server.Port);
            var stream = tcp.GetStream();

            var handshake = Encoding.ASCII.GetBytes(
                "GET / HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                "Sec-WebSocket-Version: 13\r\n\r\n");
            await stream.WriteAsync(handshake, 0, handshake.Length);

            var response = new StringBuilder();
            var one = new byte[1];
            while (!response.ToString().EndsWith("\r\n\r\n"))
            {
                Assert.AreEqual(1, await stream.ReadAsync(one, 0, 1), "connection closed during the handshake");
                response.Append((char)one[0]);
            }

            StringAssert.StartsWith("HTTP/1.1 101", response.ToString());

            // clients must mask their frames, so this is a protocol error, which raises OnError
            var unmasked = new byte[] { 0x81, 0x02, (byte)'h', (byte)'i' };
            await stream.WriteAsync(unmasked, 0, unmasked.Length);

            Assert.IsTrue(await Task.WhenAny(closed.Task, Task.Delay(5000)) == closed.Task, "the connection was never closed");
            Assert.IsNotEmpty(_errors.Where(e => e.Contains("OnError handler threw")), "the handler's exception should be logged");
        }
    }
}

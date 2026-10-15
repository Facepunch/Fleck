using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class SendQueueTests
    {
        // records every write; completes them inline (synchronously) or later on the thread pool, and tracks how many
        // writes were ever outstanding at once
        private class FakeWriteStream : Stream
        {
            private readonly bool _async;
            private int _outstanding;
            private int _writeIndex;

            public int MaxOutstanding;
            public readonly ConcurrentQueue<byte[]> Writes = new ConcurrentQueue<byte[]>();
            public readonly ConcurrentQueue<int> WriterThreads = new ConcurrentQueue<int>();
            public Func<int, Exception> FailWrite = i => null;

            // when set, the next write's completion waits for Release, then runs on a dedicated thread
            public volatile bool HoldNextWrite;
            public readonly ManualResetEventSlim Release = new ManualResetEventSlim(false);
            public readonly TaskCompletionSource<bool> HeldWriteCompleted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            public int ReleasingThreadId;

            public FakeWriteStream(bool async)
            {
                _async = async;
            }

            public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            {
                var outstanding = Interlocked.Increment(ref _outstanding);
                int max;
                while (outstanding > (max = Volatile.Read(ref MaxOutstanding)) && Interlocked.CompareExchange(ref MaxOutstanding, outstanding, max) != max)
                {
                }

                WriterThreads.Enqueue(Environment.CurrentManagedThreadId);

                var copy = new byte[count];
                Array.Copy(buffer, offset, copy, 0, count);
                var error = FailWrite(Interlocked.Increment(ref _writeIndex) - 1);

                if (HoldNextWrite)
                {
                    HoldNextWrite = false;
                    var held = new FakeResult(state, false, error);
                    var releaser = new Thread(() =>
                    {
                        Release.Wait();
                        Writes.Enqueue(copy);
                        Interlocked.Decrement(ref _outstanding);
                        try
                        {
                            callback?.Invoke(held);
                        }
                        finally
                        {
                            HeldWriteCompleted.TrySetResult(true);
                        }
                    });
                    ReleasingThreadId = releaser.ManagedThreadId;
                    releaser.Start();
                    return held;
                }

                var result = new FakeResult(state, !_async, error);

                void Complete()
                {
                    if (error == null)
                        Writes.Enqueue(copy);

                    Interlocked.Decrement(ref _outstanding);
                    callback?.Invoke(result);
                }

                if (_async)
                {
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        Thread.SpinWait(5000); // leave time for anything else to (wrongly) start another write
                        Complete();
                    });
                }
                else
                {
                    Complete();
                }

                return result;
            }

            // what the client sends: each BeginRead takes the next chunk (waiting for one if needed), on the thread pool
            public readonly BlockingCollection<byte[]> Incoming = new BlockingCollection<byte[]>();

            // when set, a read with data already waiting completes inline, like NetworkStream does
            public volatile bool SynchronousReads;

            public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            {
                if (SynchronousReads && Incoming.TryTake(out var ready))
                {
                    var completed = new FakeResult(state, true, null) { BytesRead = Math.Min(count, ready.Length) };
                    Array.Copy(ready, 0, buffer, offset, completed.BytesRead);
                    callback?.Invoke(completed);
                    return completed;
                }

                var result = new FakeResult(state, false, null);
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    byte[] chunk;
                    try
                    {
                        chunk = Incoming.Take();
                    }
                    catch (InvalidOperationException)
                    {
                        chunk = new byte[0]; // no more: the client went away
                    }

                    result.BytesRead = Math.Min(count, chunk.Length);
                    Array.Copy(chunk, 0, buffer, offset, result.BytesRead);
                    callback?.Invoke(result);
                });
                return result;
            }

            public override int EndRead(IAsyncResult asyncResult)
            {
                return ((FakeResult)asyncResult).BytesRead;
            }

            public override void EndWrite(IAsyncResult asyncResult)
            {
                var error = ((FakeResult)asyncResult).Error;
                if (error != null)
                    throw error;
            }

            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private class FakeResult : IAsyncResult
        {
            public FakeResult(object state, bool completedSynchronously, Exception error)
            {
                AsyncState = state;
                CompletedSynchronously = completedSynchronously;
                Error = error;
            }

            public Exception Error { get; }
            public int BytesRead;
            public object AsyncState { get; }
            public WaitHandle AsyncWaitHandle => throw new NotSupportedException();
            public bool CompletedSynchronously { get; }
            public bool IsCompleted => true;
        }

        private class TestConnection
        {
            public WebSocketConnection Connection;
            public FakeWriteStream Stream;
            public Mock<ISocket> Socket;
            public ConnectionLimiter Limiter;
            public readonly TaskCompletionSource<bool> Opened = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly TaskCompletionSource<bool> Closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            // frames the server wrote after the handshake, as (opcode, payload)
            public (int Opcode, byte[] Payload)[] Frames()
            {
                return Stream.Writes.Skip(1).Select(ParseFrame).ToArray();
            }
        }

        private static (int Opcode, byte[] Payload) ParseFrame(byte[] frame)
        {
            var opcode = frame[0] & 0x0F;
            var length = frame[1] & 0x7F;
            var offset = 2;
            if (length == 126)
            {
                length = (frame[2] << 8) | frame[3];
                offset = 4;
            }
            else if (length == 127)
            {
                length = (int)((long)frame[6] << 24 | (long)frame[7] << 16 | (long)frame[8] << 8 | frame[9]);
                offset = 10;
            }

            Assert.AreEqual(offset + length, frame.Length, "each write should be exactly one frame");
            return (opcode, frame.Skip(offset).Take(length).ToArray());
        }

        private static TestConnection Connect(bool asyncWrites, Action<IWebSocketConnection> configure = null)
        {
            var test = Create(asyncWrites, configure);
            Assert.IsTrue(test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));
            return test;
        }

        private static readonly byte[] HandshakeRequest = Encoding.ASCII.GetBytes(
            "GET / HTTP/1.1\r\n" +
            "Host: 127.0.0.1\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
            "Sec-WebSocket-Version: 13\r\n\r\n");

        // a connection that hasn't received its handshake request yet
        private static TestConnection Create(bool asyncWrites, Action<IWebSocketConnection> configure = null, TimeSpan? handshakeTimeout = null)
        {
            var test = new TestConnection { Stream = new FakeWriteStream(asyncWrites) };

            var connected = true;
            var socket = test.Socket = new Mock<ISocket>();
            socket.SetupGet(s => s.Connected).Returns(() => connected);
            socket.SetupGet(s => s.Stream).Returns(test.Stream);
            socket.SetupGet(s => s.RemoteIpAddress).Returns(IPAddress.Loopback);
            socket.Setup(s => s.Close()).Callback(() => connected = false);

            var limiter = test.Limiter = new ConnectionLimiter();
            limiter.TryAdd(IPAddress.Loopback);

            test.Connection = new WebSocketConnection(
                socket.Object,
                c =>
                {
                    c.OnOpen = () => test.Opened.TrySetResult(true);
                    c.OnClose = () => test.Closed.TrySetResult(true);
                    configure?.Invoke(c);
                },
                bytes => RequestParser.Parse(bytes),
                (c, r) => HandlerFactory.BuildHandler(r, c),
                limiter,
                handshakeTimeout);

            return test;
        }

        private static async Task WaitFor(Func<bool> condition, string message)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!condition())
            {
                if (DateTime.UtcNow > deadline)
                    Assert.Fail(message);

                await Task.Delay(5);
            }
        }

        [Test]
        public async Task WritesNeverOverlap()
        {
            const int threadCount = 8;
            const int messagesPerThread = 200;

            var test = Connect(asyncWrites: true);
            await test.Opened.Task.WaitAsync(TimeSpan.FromSeconds(5));

            await Task.WhenAll(Enumerable.Range(0, threadCount).Select(t => Task.Run(() =>
            {
                for (var i = 0; i < messagesPerThread; i++)
                    test.Connection.Send($"{t}:{i}");
            })));

            await WaitFor(() => test.Stream.Writes.Count == 1 + threadCount * messagesPerThread, "not every message was written");

            Assert.AreEqual(1, test.Stream.MaxOutstanding, "a write was started while another was still in flight");

            // and each thread's messages went out in the order it sent them
            var lastSeen = Enumerable.Repeat(-1, threadCount).ToArray();
            foreach (var (opcode, payload) in test.Frames())
            {
                Assert.AreEqual(1, opcode);
                var parts = Encoding.UTF8.GetString(payload).Split(':');
                var thread = int.Parse(parts[0]);
                var index = int.Parse(parts[1]);
                Assert.AreEqual(lastSeen[thread] + 1, index);
                lastSeen[thread] = index;
            }
        }

        [Test]
        public void SynchronousCompletionsAreWrittenInOrderWithoutRecursing()
        {
            var test = Connect(asyncWrites: false);
            Assert.IsTrue(test.Opened.Task.IsCompleted);

            for (var i = 0; i < 20000; i++)
                test.Connection.Send(i.ToString());

            var frames = test.Frames();
            Assert.AreEqual(20000, frames.Length);
            for (var i = 0; i < frames.Length; i++)
                Assert.AreEqual(i.ToString(), Encoding.UTF8.GetString(frames[i].Payload));
        }

        [Test]
        public void SendsFromOnOpenAreNotHeldBackUntilItReturns()
        {
            // more than the pending send limit: if these queued up until OnOpen returned, the connection would be dropped
            const int messageCount = 3000;

            var test = Connect(asyncWrites: false, c =>
            {
                c.OnOpen = () =>
                {
                    for (var i = 0; i < messageCount; i++)
                        c.Send(i.ToString());
                };
            });

            Assert.IsTrue(test.Connection.IsAvailable, "the connection was dropped");
            Assert.AreEqual(messageCount, test.Frames().Length);
        }

        [Test]
        public async Task AThrowingLogActionDoesNotStallTheConnection()
        {
            var originalLevel = FleckLog.Level;
            var originalAction = FleckLog.LogAction;

            try
            {
                // the first message fails, so handling it logs (and throws) on the thread pool
                var test = Connect(asyncWrites: true);
                test.Stream.FailWrite = i => i == 1 ? new IOException("connection reset") : null;
                await test.Opened.Task.WaitAsync(TimeSpan.FromSeconds(5));

                FleckLog.Level = LogLevel.Debug;
                FleckLog.LogAction = (level, message, ex) => throw new InvalidOperationException("LogAction failed");

                test.Connection.Send("fails");

                Assert.IsTrue(await Task.WhenAny(test.Closed.Task, Task.Delay(5000)) == test.Closed.Task, "the failed connection was never closed");
            }
            finally
            {
                FleckLog.Level = originalLevel;
                FleckLog.LogAction = originalAction;
            }
        }

        [Test]
        public async Task OneThreadDoesNotWriteEverythingOthersQueue()
        {
            var test = Connect(asyncWrites: false);

            // hold a write in flight so everything else queues up behind it
            test.Stream.HoldNextWrite = true;
            test.Connection.Send("held");
            for (var i = 0; i < 1000; i++)
                test.Connection.Send(i.ToString());

            // finishing the held write carries on writing on that thread, but only for a bounded number of sends
            test.Stream.Release.Set();
            await WaitFor(() => test.Stream.Writes.Count == 1 + 1 + 1000, "not every message was written");

            var byReleasingThread = test.Stream.WriterThreads.Count(t => t == test.Stream.ReleasingThreadId);
            Assert.LessOrEqual(byReleasingThread, 64, "the thread that finished the held write kept writing the whole queue");

            var frames = test.Frames();
            Assert.AreEqual("held", Encoding.UTF8.GetString(frames[0].Payload));
            for (var i = 0; i < 1000; i++)
                Assert.AreEqual(i.ToString(), Encoding.UTF8.GetString(frames[i + 1].Payload), "messages went out of order");
        }

        [Test]
        public void SendDoesNotThrowWhenHandlingAFailedWriteThrows()
        {
            var originalLevel = FleckLog.Level;
            var originalAction = FleckLog.LogAction;

            try
            {
                var test = Connect(asyncWrites: false);
                test.Stream.FailWrite = i => i == 1 ? new IOException("connection reset") : null;

                FleckLog.Level = LogLevel.Debug;
                FleckLog.LogAction = (level, message, ex) => throw new InvalidOperationException("LogAction failed");

                // the write fails synchronously, so it's handled (and the logging throws) inside this Send
                Assert.DoesNotThrow(() => test.Connection.Send("fails"));
                Assert.IsTrue(test.Closed.Task.IsCompleted, "the failed connection was never closed");
            }
            finally
            {
                FleckLog.Level = originalLevel;
                FleckLog.LogAction = originalAction;
            }
        }

        [Test]
        public async Task OnOpenAlwaysComesBeforeOnMessage()
        {
            var events = new ConcurrentQueue<string>();
            var test = Create(asyncWrites: false, c =>
            {
                c.OnOpen = () => events.Enqueue("open");
                c.OnMessage = m => events.Enqueue("message " + m);
            });

            try
            {
                // the handshake response stays in flight, while the client has already sent a message
                test.Stream.HoldNextWrite = true;
                test.Stream.Incoming.Add(HandshakeRequest);
                var mask = new byte[] { 1, 2, 3, 4 };
                test.Stream.Incoming.Add(new byte[] { 0x81, 0x82, mask[0], mask[1], mask[2], mask[3], (byte)('h' ^ 1), (byte)('i' ^ 2) });

                test.Connection.StartReceiving();
                await Task.Delay(300);
                CollectionAssert.IsEmpty(events, "the message was delivered before the connection was opened");

                test.Stream.Release.Set();
                await WaitFor(() => events.Count == 2, "the connection didn't open and receive the message");
                CollectionAssert.AreEqual(new[] { "open", "message hi" }, events.ToArray());
            }
            finally
            {
                // ends the pending read, which would otherwise keep a thread pool thread waiting for the rest of the run
                test.Stream.Release.Set();
                test.Stream.Incoming.CompleteAdding();
            }
        }

        [TestCase(FrameType.Text)]
        [TestCase(FrameType.Binary)]
        [TestCase(FrameType.Ping)]
        [TestCase(FrameType.Pong)]
        public void ClosingFromADataHandlerStopsDispatchingBufferedFrames(FrameType firstFrameType)
        {
            var events = new ConcurrentQueue<string>();
            var test = Create(asyncWrites: false, c =>
            {
                void CloseFromHandler(string name)
                {
                    events.Enqueue(name);
                    c.Close();
                }

                c.OnMessage = m => CloseFromHandler("Text");
                c.OnBinary = data => CloseFromHandler("Binary");
                c.OnPing = data => CloseFromHandler("Ping");
                c.OnPong = data => CloseFromHandler("Pong");
                c.OnClose = () => events.Enqueue("Close");
            });

            byte[] Frame(FrameType type) => new Hybi14DataFrame
            {
                IsFinal = true,
                IsMasked = true,
                MaskKey = 0x12345678,
                FrameType = type,
                Payload = new byte[] { (byte)'x' }
            }.ToBytes();

            try
            {
                test.Stream.SynchronousReads = true;
                test.Stream.Incoming.Add(HandshakeRequest);
                test.Stream.Incoming.Add(Frame(firstFrameType)
                    .Concat(Frame(FrameType.Text))
                    .Concat(Frame(FrameType.Binary))
                    .Concat(Frame(FrameType.Ping))
                    .Concat(Frame(FrameType.Pong)).ToArray());

                test.Connection.StartReceiving();

                CollectionAssert.AreEqual(new[] { firstFrameType.ToString(), "Close" }, events.ToArray(),
                    "buffered frames were dispatched after the first handler closed the connection");
                test.Socket.Verify(s => s.Close(), Times.Once);
            }
            finally
            {
                test.Stream.Incoming.CompleteAdding();
                test.Connection.Close();
            }
        }

        [Test]
        public async Task ReadsThatCompleteSynchronouslyDoNotRecurse()
        {
            // far more back-to-back reads than the stack could hold if each one recursed into the next
            const int frameCount = 200000;

            var received = 0;
            var test = Create(asyncWrites: false, c => c.OnMessage = m => Interlocked.Increment(ref received));

            try
            {
                test.Stream.SynchronousReads = true;
                test.Stream.Incoming.Add(HandshakeRequest);

                var mask = new byte[] { 1, 2, 3, 4 };
                var frame = new byte[] { 0x81, 0x81, mask[0], mask[1], mask[2], mask[3], (byte)('x' ^ 1) };
                for (var i = 0; i < frameCount; i++)
                    test.Stream.Incoming.Add(frame);

                test.Connection.StartReceiving();

                await WaitFor(() => Volatile.Read(ref received) == frameCount, $"only {Volatile.Read(ref received)} of {frameCount} messages arrived");
                Assert.IsTrue(test.Connection.IsAvailable);
            }
            finally
            {
                test.Stream.Incoming.CompleteAdding();
            }
        }

        [Test]
        public void SendingFromTheConfigCallbackThrowsInsteadOfWritingBeforeTheHandshake()
        {
            Exception thrown = null;
            var test = Connect(asyncWrites: false, c =>
            {
                try
                {
                    c.Send("too early");
                }
                catch (Exception e)
                {
                    thrown = e;
                }
            });

            Assert.IsInstanceOf<InvalidOperationException>(thrown);
            var first = Encoding.ASCII.GetString(test.Stream.Writes.First());
            StringAssert.StartsWith("HTTP/1.1 101", first, "something was written ahead of the handshake response");
            CollectionAssert.IsEmpty(test.Frames());

            // and once open, sending works
            test.Connection.Send("fine");
            Assert.AreEqual("fine", Encoding.UTF8.GetString(test.Frames().Single().Payload));
        }

        [Test]
        public async Task AConnectionThatNeverCompletesItsHandshakeIsClosed()
        {
            var test = Create(asyncWrites: false, handshakeTimeout: TimeSpan.FromMilliseconds(200));

            // OnClose isn't hooked up yet (that happens when the handshake request arrives), so watch the socket itself
            await WaitFor(() => !test.Socket.Object.Connected, "the connection was never closed");
            test.Socket.Verify(s => s.Close(), Times.Once);
            CollectionAssert.IsEmpty(test.Stream.Writes, "nothing should be written to a client that never sent its handshake");
        }

        [Test]
        public async Task AHandshakeThatCompletesAfterItsTimeoutDoesNotOpen()
        {
            var test = Create(asyncWrites: false, handshakeTimeout: TimeSpan.FromMilliseconds(200));
            test.Stream.HoldNextWrite = true;

            try
            {
                Assert.IsTrue(test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));
                await WaitFor(() => !test.Socket.Object.Connected, "the handshake timeout did not close the socket");

                // A successful transport write can report its completion after the timeout has closed the connection.
                test.Stream.Release.Set();
                await test.Stream.HeldWriteCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));

                Assert.IsFalse(test.Opened.Task.IsCompleted, "OnOpen ran after OnClose");
                test.Socket.Verify(s => s.Close(), Times.Once);
            }
            finally
            {
                test.Stream.Release.Set();
                test.Connection.Close();
            }
        }

#if DEBUG
        [Test]
        public async Task AHandshakeCannotOpenAfterItsTimeoutHasStartedClosing()
        {
            var originalLevel = FleckLog.Level;
            var originalAction = FleckLog.LogAction;
            var timeoutStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var finishTimeout = new ManualResetEventSlim(false);
            var test = Create(asyncWrites: false, handshakeTimeout: TimeSpan.FromMilliseconds(200));
            test.Stream.HoldNextWrite = true;

            try
            {
                FleckLog.Level = LogLevel.Debug;
                FleckLog.LogAction = (level, message, ex) =>
                {
                    if (message == "Handshake not completed in time. Closing.")
                    {
                        timeoutStarted.TrySetResult(true);
                        finishTimeout.Wait(TimeSpan.FromSeconds(5));
                    }
                };

                Assert.IsTrue(test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));
                await timeoutStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

                // Complete the write after the timeout has committed to closing, but before it closes the socket.
                test.Stream.Release.Set();
                await test.Stream.HeldWriteCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));

                Assert.IsFalse(test.Opened.Task.IsCompleted, "the handshake overtook a timeout already closing it");
            }
            finally
            {
                finishTimeout.Set();
                test.Stream.Release.Set();
                try
                {
                    await WaitFor(() => !test.Socket.Object.Connected, "the timeout did not finish closing the socket");
                }
                finally
                {
                    test.Connection.Close();
                    FleckLog.Level = originalLevel;
                    FleckLog.LogAction = originalAction;
                }
            }
        }
#endif

        [Test]
        public async Task AThrowingLogActionDoesNotPreventTheHandshakeTimeout()
        {
            var originalLevel = FleckLog.Level;
            var originalAction = FleckLog.LogAction;
            var test = Create(asyncWrites: false, handshakeTimeout: TimeSpan.FromMilliseconds(200));
            test.Limiter.SetConnectionLimits(1, 1);

            try
            {
                FleckLog.Level = LogLevel.Debug;
                FleckLog.LogAction = (level, message, ex) => throw new InvalidOperationException("LogAction failed");

                await WaitFor(() => !test.Socket.Object.Connected, "a throwing logger prevented the handshake timeout from closing");

                test.Socket.Verify(s => s.Close(), Times.Once);
                test.Socket.Verify(s => s.Dispose(), Times.Once);
                Assert.IsTrue(test.Limiter.TryAdd(IPAddress.Loopback), "the timeout did not release the limiter slot");
            }
            finally
            {
                FleckLog.Level = originalLevel;
                FleckLog.LogAction = originalAction;
                test.Connection.Close();
            }
        }

        [Test]
        public void ClosingWhileSettingUpStopsWithoutSendingTheHandshake()
        {
            // stands in for the handshake timeout firing on another thread while the request is being handled
            var test = Create(asyncWrites: false, c => c.Close());

            bool started = true;
            Assert.DoesNotThrow(() => started = test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));

            Assert.IsFalse(started);
            CollectionAssert.IsEmpty(test.Stream.Writes, "nothing should be sent on a connection closed while it was being set up");
            test.Socket.Verify(s => s.Close(), Times.Once);
        }

        [Test]
        public void AHandshakeTimeoutTooLongForATimerMeansNoTimeout()
        {
            TestConnection test = null;
            Assert.DoesNotThrow(() => test = Create(asyncWrites: false, handshakeTimeout: TimeSpan.MaxValue));

            Assert.IsTrue(test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));
            Assert.IsTrue(test.Connection.IsAvailable);
        }

        [Test]
        public async Task TheHandshakeTimeoutStopsOnceTheHandshakeIsDone()
        {
            var test = Create(asyncWrites: false, handshakeTimeout: TimeSpan.FromMilliseconds(200));
            Assert.IsTrue(test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));

            await Task.Delay(500);

            Assert.IsTrue(test.Connection.IsAvailable, "a connection that completed its handshake was closed by the timeout");
        }

        [Test]
        public void ClosingBeforeTheHandshakeIsSentDoesNotSendACloseFrame()
        {
            // the application's config callback throws while the connection is being set up, so the handshake response is
            // never sent, and the read loop's error handling then closes the connection
            var test = Create(asyncWrites: false, c => throw new InvalidOperationException("config failed"));
            Assert.Throws<InvalidOperationException>(() => test.Connection.CreateHandler(new ArraySegment<byte>(HandshakeRequest)));

            test.Connection.Close(WebSocketStatusCodes.InternalServerError);

            CollectionAssert.IsEmpty(test.Stream.Writes, "nothing should be written to a client that never got the handshake response");
            test.Socket.Verify(s => s.Close(), Times.Once);
        }

        [Test]
        public void SendingToAClosedConnectionDoesNotThrowEvenIfTheLogActionDoes()
        {
            var originalLevel = FleckLog.Level;
            var originalAction = FleckLog.LogAction;

            try
            {
                var test = Connect(asyncWrites: false);
                test.Connection.Close();

                FleckLog.Level = LogLevel.Warn;
                FleckLog.LogAction = (level, message, ex) => throw new InvalidOperationException("LogAction failed");

                // the ignored send logs a warning, which mustn't come out of Send
                Assert.DoesNotThrow(() => test.Connection.Send("too late"));
                Assert.DoesNotThrow(() => test.Connection.Send(new MemoryBuffer(4).Slice(4)));
            }
            finally
            {
                FleckLog.Level = originalLevel;
                FleckLog.LogAction = originalAction;
            }
        }

        [Test]
        public void TheSocketIsClosedEvenIfOnCloseAndTheLogActionThrow()
        {
            var originalLevel = FleckLog.Level;
            var originalAction = FleckLog.LogAction;

            try
            {
                var test = Connect(asyncWrites: false, c => c.OnClose = () => throw new InvalidOperationException("OnClose failed"));

                FleckLog.Level = LogLevel.Debug;
                FleckLog.LogAction = (level, message, ex) => throw new InvalidOperationException("LogAction failed");

                Assert.DoesNotThrow(() => test.Connection.Close());

                test.Socket.Verify(s => s.Close(), Times.Once, "the socket was left open");
                test.Socket.Verify(s => s.Dispose(), Times.Once);
            }
            finally
            {
                FleckLog.Level = originalLevel;
                FleckLog.LogAction = originalAction;
            }
        }

        [Test]
        public async Task ConcurrentClosesSendOneCloseFrame()
        {
            for (var i = 0; i < 300; i++)
            {
                var test = Connect(asyncWrites: true);
                await test.Opened.Task.WaitAsync(TimeSpan.FromSeconds(5));

                using var start = new Barrier(2);
                await Task.WhenAll(
                    Task.Run(() => { start.SignalAndWait(); test.Connection.Close(WebSocketStatusCodes.NormalClosure); }),
                    Task.Run(() => { start.SignalAndWait(); test.Connection.Close(WebSocketStatusCodes.GoingAway); }));

                await test.Closed.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.AreEqual(1, test.Frames().Count(f => f.Opcode == 8), "more than one close frame was sent");
            }
        }
    }
}

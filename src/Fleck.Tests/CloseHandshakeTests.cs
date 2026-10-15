using System;
using System.Linq;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using Fleck.Handlers;
using Moq;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class CloseHandshakeTests
    {
        private static byte[] MaskedCloseFrame(params byte[] payload)
        {
            var mask = new byte[] { 0x12, 0x34, 0x56, 0x78 };
            var frame = new byte[6 + payload.Length];
            frame[0] = 0x88;
            frame[1] = (byte)(0x80 | payload.Length);
            Array.Copy(mask, 0, frame, 2, 4);
            for (var i = 0; i < payload.Length; i++)
                frame[6 + i] = (byte)(payload[i] ^ mask[i % 4]);
            return frame;
        }

        [TestCase((ushort)1000)]
        [TestCase((ushort)1001)]
        [TestCase((ushort)4001)]
        public void CloseFrameFromClientIsAnsweredWithTheSameCode(ushort code)
        {
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            var onCloseCalled = false;
            connection.SetupProperty(c => c.OnClose, () => onCloseCalled = true);

            var handler = new Hybi13Handler(new WebSocketHttpRequest(), connection.Object);
            handler.Receive(MaskedCloseFrame((byte)(code >> 8), (byte)code));

            // the connection answers the close and shuts the socket, which is what raises OnClose
            connection.Verify(c => c.Close(code), Times.Once);
            Assert.IsFalse(onCloseCalled, "OnClose should only be raised once the socket is actually closed");

            handler.Dispose();
        }

        [Test]
        public void CloseFrameWithoutACodeIsAnsweredNormally()
        {
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            var handler = new Hybi13Handler(new WebSocketHttpRequest(), connection.Object);

            handler.Receive(MaskedCloseFrame());

            connection.Verify(c => c.Close(WebSocketStatusCodes.NormalClosure), Times.Once);
            handler.Dispose();
        }

        [Test]
        public void FramesAfterACloseFrameAreIgnored()
        {
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            var messages = 0;
            connection.SetupProperty(c => c.OnMessage, m => messages++);

            var handler = new Hybi13Handler(new WebSocketHttpRequest(), connection.Object);

            // a close frame and a text frame arriving together, then another text frame in a later read
            var mask = new byte[] { 0x12, 0x34, 0x56, 0x78 };
            var text = new byte[] { 0x81, 0x82, mask[0], mask[1], mask[2], mask[3], (byte)('h' ^ 0x12), (byte)('i' ^ 0x34) };
            handler.Receive(MaskedCloseFrame(0x03, 0xE8).Concat(text).ToArray());
            handler.Receive(text);

            connection.Verify(c => c.Close(WebSocketStatusCodes.NormalClosure), Times.Once);
            Assert.AreEqual(0, messages, "nothing after the close frame should be delivered");

            handler.Dispose();
        }

        [TestCase(WebSocketCloseStatus.NormalClosure)]
        [TestCase(WebSocketCloseStatus.EndpointUnavailable)]
        public async Task ClientInitiatedCloseCompletes(WebSocketCloseStatus status)
        {
            var server = new WebSocketServer("ws://127.0.0.1:0", supportDualStack: false);
            var closed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            server.Start(socket => socket.OnClose = () => closed.TrySetResult(true));

            try
            {
                using var client = new ClientWebSocket();
                await client.ConnectAsync(new Uri($"ws://127.0.0.1:{server.Port}/"), CancellationToken.None);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await client.CloseAsync(status, "", cts.Token);

                Assert.AreEqual(WebSocketState.Closed, client.State);
                Assert.AreEqual(status, client.CloseStatus, "the server should echo the client's close code");
                Assert.IsTrue(await Task.WhenAny(closed.Task, Task.Delay(5000)) == closed.Task, "server never raised OnClose");
            }
            finally
            {
                server.Dispose();
            }
        }
    }
}

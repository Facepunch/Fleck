using System;
using Fleck.Handlers;
using Moq;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class MaxMessageSizeTests
    {
        private static readonly byte[] Mask = { 0x12, 0x34, 0x56, 0x78 };

        // a masked client frame; opcode 1 is text, 0 is a continuation
        private static byte[] Frame(int opcode, bool final, int payloadLength, ulong? declaredLength = null)
        {
            var length = declaredLength ?? (ulong)payloadLength;
            var header = length <= 125 ? 2 : length <= ushort.MaxValue ? 4 : 10;
            var frame = new byte[header + 4 + payloadLength];

            frame[0] = (byte)((final ? 0x80 : 0) | opcode);
            if (header == 2)
            {
                frame[1] = (byte)(0x80 | (int)length);
            }
            else if (header == 4)
            {
                frame[1] = 0x80 | 126;
                frame[2] = (byte)(length >> 8);
                frame[3] = (byte)length;
            }
            else
            {
                frame[1] = 0x80 | 127;
                for (var i = 0; i < 8; i++)
                    frame[2 + i] = (byte)(length >> (56 - 8 * i));
            }

            Array.Copy(Mask, 0, frame, header, 4);
            for (var i = 0; i < payloadLength; i++)
                frame[header + 4 + i] = (byte)('x' ^ Mask[i % 4]);

            return frame;
        }

        private static (Hybi13Handler Handler, Func<int> Received) CreateHandler(int maxMessageSize)
        {
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            var received = 0;
            connection.SetupProperty(c => c.OnMessage, m => received = m.Length);
            return (new Hybi13Handler(new WebSocketHttpRequest(), connection.Object, maxMessageSize), () => received);
        }

        private static void AssertTooBig(Action action)
        {
            var e = Assert.Throws<WebSocketException>(() => action());
            Assert.AreEqual(WebSocketStatusCodes.MessageTooBig, e.StatusCode);
        }

        [TestCase(1, 1024)]
        [TestCase(125, 1024)]
        [TestCase(1023, 1024)]
        [TestCase(1024, 1024)]
        [TestCase(2048, 2048)]
        public void SmallLimitsAreClampedAndTheEffectiveLimitIsEnforced(int requested, int effective)
        {
            using (var server = new WebSocketServer("ws://127.0.0.1:0"))
            {
                server.MaxMessageSize = requested;
                Assert.AreEqual(effective, server.MaxMessageSize);
            }

            var (handler, received) = CreateHandler(requested);
            try
            {
                handler.Receive(Frame(1, true, effective));
                Assert.AreEqual(effective, received());
                AssertTooBig(() => handler.Receive(Frame(1, true, effective + 1)));
            }
            finally
            {
                handler.Dispose();
            }
        }

        [TestCase(FrameType.Close)]
        [TestCase(FrameType.Ping)]
        [TestCase(FrameType.Pong)]
        public void SmallLimitsAllowMaximumSizedControlFrames(FrameType type)
        {
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            byte[] received = null;
            connection.SetupProperty(c => c.OnPing, data => received = data.ToArray());
            connection.SetupProperty(c => c.OnPong, data => received = data.ToArray());
            var handler = new Hybi13Handler(new WebSocketHttpRequest(), connection.Object, 1);

            try
            {
                var frame = Frame((int)type, true, 125);
                if (type == FrameType.Close)
                {
                    frame[6] = (byte)(0x03 ^ Mask[0]);
                    frame[7] = (byte)(0xE8 ^ Mask[1]);
                }

                Assert.DoesNotThrow(() => handler.Receive(frame));
                if (type == FrameType.Close)
                    connection.Verify(c => c.Close(WebSocketStatusCodes.NormalClosure), Times.Once);
                else
                    Assert.AreEqual(new string('x', 125), System.Text.Encoding.ASCII.GetString(received));
            }
            finally
            {
                handler.Dispose();
            }
        }

        [Test]
        public void MessagesUpToTheLimitAreAccepted()
        {
            var (handler, received) = CreateHandler(4096);
            handler.Receive(Frame(1, true, 4096));
            Assert.AreEqual(4096, received());
            handler.Dispose();
        }

        [Test]
        public void ALimitSmallerThanTheInitialBufferIsEnforced()
        {
            // the buffers start at 64KB, which used to let anything up to that through
            var (handler, _) = CreateHandler(4096);
            AssertTooBig(() => handler.Receive(Frame(1, true, 4097)));
            handler.Dispose();
        }

        [Test]
        public void ALimitThatIsNotAPowerOfTwoIsEnforced()
        {
            // the pool rounds buffers up to a power of two (2MB here), which used to let anything up to that through
            const int limit = 1_500_000;
            var (handler, received) = CreateHandler(limit);

            handler.Receive(Frame(1, true, limit));
            Assert.AreEqual(limit, received());

            AssertTooBig(() => handler.Receive(Frame(1, true, limit + 1)));
            handler.Dispose();
        }

        [Test]
        public void FragmentedMessagesAreLimitedByTheirTotalSize()
        {
            var (handler, _) = CreateHandler(4096);
            handler.Receive(Frame(1, false, 3000));
            AssertTooBig(() => handler.Receive(Frame(0, true, 3000)));
            handler.Dispose();
        }

        [Test]
        public void AnOversizedFrameIsRejectedFromItsHeader()
        {
            // only the header arrives, declaring more than the limit
            var (handler, _) = CreateHandler(4096);
            AssertTooBig(() => handler.Receive(Frame(1, true, 0, declaredLength: 100_000)));
            handler.Dispose();
        }

        [Test]
        public void ALengthThatDoesNotFitAnIntIsRejected()
        {
            // used to come out negative and fail with an ArgumentOutOfRangeException instead
            var (handler, _) = CreateHandler(4096);
            AssertTooBig(() => handler.Receive(Frame(1, true, 0, declaredLength: 0x80000000UL)));
            handler.Dispose();
        }

        [Test]
        public void AVeryLargeLimitDoesNotOverflow()
        {
            // int.MaxValue + the read buffer slack used to wrap negative and refuse anything past the initial buffer
            var (handler, received) = CreateHandler(int.MaxValue);
            handler.Receive(Frame(1, true, 200_000));
            Assert.AreEqual(200_000, received());
            handler.Dispose();
        }

        [TestCase(0)]
        [TestCase(-1)]
        public void TheLimitMustBePositive(int limit)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new Hybi13Handler(new WebSocketHttpRequest(), null, limit));

            var server = new WebSocketServer("ws://127.0.0.1:0");
            Assert.Throws<ArgumentOutOfRangeException>(() => server.MaxMessageSize = limit);
            server.Dispose();
        }
    }
}

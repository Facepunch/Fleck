using System;
using Fleck.Handlers;
using Moq;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class Hybi13HandlerTests
    {
        // payload sizes where adding the 5 byte prefix moves the frame into the next length encoding
        [TestCase(0)]
        [TestCase(120)]
        [TestCase(121)]
        [TestCase(65530)]
        [TestCase(65531)]
        public void PrefixedBinaryFrameMatchesFramingTheJoinedBytes(int payloadLength)
        {
            var handler = new Hybi13Handler(new WebSocketHttpRequest(), null);
            var prefix = new byte[] { 1, 2, 3, 4, 5 };

            var payload = new MemoryBuffer(payloadLength).Slice(payloadLength);
            for (var i = 0; i < payloadLength; i++)
                payload.Data[i] = (byte)i;

            var joined = new MemoryBuffer(prefix.Length + payloadLength).Slice(prefix.Length + payloadLength);
            prefix.CopyTo(joined.Data, 0);
            Array.Copy(payload.Data, 0, joined.Data, prefix.Length, payloadLength);

            var expected = handler.FrameBinary(joined);
            var actual = handler.FrameBinary(prefix, payload);

            Assert.IsTrue(((Span<byte>)actual).SequenceEqual((Span<byte>)expected));

            expected.Dispose();
            actual.Dispose();
            handler.Dispose();
        }

        [Test]
        public void ReceivesMessagesLargerThanTheInitialBuffers()
        {
            byte[] received = null;
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            connection.SetupGet(c => c.OnBinary).Returns(data => received = data.ToArray());

            var handler = new Hybi13Handler(new WebSocketHttpRequest(), connection.Object, 256 * 1024);
            var payload = CreatePayload(200 * 1024);
            ReceiveFrame(handler, payload);

            Assert.AreEqual(payload, received);
            handler.Dispose();
        }

        [Test]
        public void RejectsMessagesLargerThanTheMaxSize()
        {
            var connection = new Mock<IWebSocketConnection>();
            connection.SetupGet(c => c.IsAvailable).Returns(true);
            var handler = new Hybi13Handler(new WebSocketHttpRequest(), connection.Object, 256 * 1024);

            var exception = Assert.Throws<WebSocketException>(() => ReceiveFrame(handler, CreatePayload(256 * 1024 + 1)));
            Assert.AreEqual(WebSocketStatusCodes.MessageTooBig, exception.StatusCode);
            handler.Dispose();
        }

        private static byte[] CreatePayload(int length)
        {
            var payload = new byte[length];
            for (var i = 0; i < length; i++)
                payload[i] = (byte)i;
            return payload;
        }

        // a masked binary frame the way a client sends it, handed over in reads the size WebSocketConnection uses
        private static void ReceiveFrame(Hybi13Handler handler, byte[] payload)
        {
            var frame = new Hybi14DataFrame
            {
                IsFinal = true,
                IsMasked = true,
                MaskKey = 0x12345678,
                FrameType = FrameType.Binary,
                Payload = payload
            }.ToBytes();

            const int readSize = 8 * 1024;
            for (var offset = 0; offset < frame.Length; offset += readSize)
                handler.Receive(new Span<byte>(frame, offset, Math.Min(readSize, frame.Length - offset)));
        }
    }
}

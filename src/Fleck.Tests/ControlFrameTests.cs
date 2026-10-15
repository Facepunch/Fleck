using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Fleck.Handlers;
using Moq;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class ControlFrameTests
    {
        private static readonly byte[] Mask = { 0x12, 0x34, 0x56, 0x78 };

        private static byte[] Frame(FrameType type, bool final, byte[] payload)
        {
            var header = payload.Length <= 125 ? 2 : 4;
            var frame = new byte[header + 4 + payload.Length];

            frame[0] = (byte)((final ? 0x80 : 0) | (byte)type);
            if (header == 2)
            {
                frame[1] = (byte)(0x80 | payload.Length);
            }
            else
            {
                frame[1] = 0x80 | 126;
                frame[2] = (byte)(payload.Length >> 8);
                frame[3] = (byte)payload.Length;
            }

            Array.Copy(Mask, 0, frame, header, 4);
            for (var i = 0; i < payload.Length; i++)
                frame[header + 4 + i] = (byte)(payload[i] ^ Mask[i % 4]);

            return frame;
        }

        private static byte[] Text(string s) => Encoding.UTF8.GetBytes(s);

        private class Recorder
        {
            public readonly Mock<IWebSocketConnection> Connection = new Mock<IWebSocketConnection>();
            public readonly List<string> Messages = new List<string>();
            public readonly List<string> Pings = new List<string>();
            public Hybi13Handler Handler;

            public Recorder()
            {
                Connection.SetupGet(c => c.IsAvailable).Returns(true);
                Connection.SetupProperty(c => c.OnMessage, m => Messages.Add(m));
                Connection.SetupProperty(c => c.OnPing, data => Pings.Add(Encoding.UTF8.GetString(data)));
                Handler = new Hybi13Handler(new WebSocketHttpRequest(), Connection.Object);
            }
        }

        private static void AssertProtocolError(Action action)
        {
            var e = Assert.Throws<WebSocketException>(() => action());
            Assert.AreEqual(WebSocketStatusCodes.ProtocolError, e.StatusCode);
        }

        [Test]
        public void APingBetweenFragmentsDoesNotDisturbTheMessage()
        {
            var r = new Recorder();

            r.Handler.Receive(Frame(FrameType.Text, false, Text("hel")));
            r.Handler.Receive(Frame(FrameType.Ping, true, Text("are you there")));
            r.Handler.Receive(Frame(FrameType.Continuation, true, Text("lo")));

            CollectionAssert.AreEqual(new[] { "are you there" }, r.Pings);
            CollectionAssert.AreEqual(new[] { "hello" }, r.Messages);
            r.Handler.Dispose();
        }

        [Test]
        public void ControlFramesArrivingTogetherWithFragmentsAreAllHandled()
        {
            var r = new Recorder();

            // everything in one read
            r.Handler.Receive(Frame(FrameType.Text, false, Text("a"))
                .Concat(Frame(FrameType.Ping, true, Text("1")))
                .Concat(Frame(FrameType.Pong, true, Text("2")))
                .Concat(Frame(FrameType.Continuation, false, Text("b")))
                .Concat(Frame(FrameType.Ping, true, Text("3")))
                .Concat(Frame(FrameType.Continuation, true, Text("c")))
                .ToArray());

            CollectionAssert.AreEqual(new[] { "1", "3" }, r.Pings);
            CollectionAssert.AreEqual(new[] { "abc" }, r.Messages);
            r.Handler.Dispose();
        }

        [Test]
        public void ACloseBetweenFragmentsClosesWithoutDeliveringThePartialMessage()
        {
            var r = new Recorder();

            r.Handler.Receive(Frame(FrameType.Text, false, Text("partial")));
            r.Handler.Receive(Frame(FrameType.Close, true, new byte[] { 0x03, 0xE8 }));

            r.Connection.Verify(c => c.Close(WebSocketStatusCodes.NormalClosure), Times.Once);
            CollectionAssert.IsEmpty(r.Messages);
            r.Handler.Dispose();
        }

        [Test]
        public void ControlFramesOver125BytesAreRejected()
        {
            var r = new Recorder();
            AssertProtocolError(() => r.Handler.Receive(Frame(FrameType.Ping, true, new byte[126])));
            r.Handler.Dispose();
        }

        [Test]
        public void FragmentedControlFramesAreRejected()
        {
            var r = new Recorder();
            AssertProtocolError(() => r.Handler.Receive(Frame(FrameType.Ping, false, Text("x"))));
            r.Handler.Dispose();
        }

        [Test]
        public void ANewMessageInTheMiddleOfAFragmentedOneIsRejected()
        {
            var r = new Recorder();
            r.Handler.Receive(Frame(FrameType.Text, false, Text("first")));
            AssertProtocolError(() => r.Handler.Receive(Frame(FrameType.Text, true, Text("second"))));
            r.Handler.Dispose();
        }
    }
}

using System;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class SpanWriterTests
    {
        [Test]
        public void WritesThatExactlyFillTheSpanSucceed()
        {
            var data = new byte[8];
            var writer = new SpanWriter(data);

            writer.Write<byte>(1);
            writer.Write((ushort)0x0203);
            writer.Write(new ReadOnlySpan<byte>(new byte[] { 4, 5 }));
            writer.Write(new Span<byte>(new byte[] { 6, 7, 8 }));

            Assert.AreEqual(8, writer.Length);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, data);
        }

        [Test]
        public void WritingNothingToAFullSpanDoesNothing()
        {
            var writer = new SpanWriter(new byte[2]);
            writer.Write(new ReadOnlySpan<byte>(new byte[] { 1, 2 }));

            writer.Write<byte>(Span<byte>.Empty); // the Span<T> overload
            writer.Write(ReadOnlySpan<byte>.Empty);

            Assert.AreEqual(2, writer.Length);
        }

        [Test]
        public void WritingPastTheEndThrows()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                var writer = new SpanWriter(new byte[2]);
                writer.Write(new ReadOnlySpan<byte>(new byte[] { 1, 2, 3 }));
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var writer = new SpanWriter(new byte[2]);
                writer.Write<byte>(1);
                writer.Write((ushort)2);
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var writer = new SpanWriter(new byte[2]);
                writer.Write(new Span<byte>(new byte[] { 1, 2, 3 }));
            });
        }
    }
}

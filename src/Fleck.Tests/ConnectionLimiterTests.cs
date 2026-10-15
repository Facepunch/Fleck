using System;
using System.Net;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class ConnectionLimiterTests
    {
        private static IPAddress Address(int i) => new IPAddress(new byte[] { 10, 0, (byte)(i >> 8), (byte)i });

        [Test]
        public void IPsThatLeaveAreForgottenOnceTheirWindowPasses()
        {
            var limiter = new ConnectionLimiter();
            limiter.SetAttemptLimits(5, TimeSpan.FromSeconds(5));

            // e.g. scanners that connect once and never come back
            for (var i = 0; i < 100; i++)
            {
                Assert.IsTrue(limiter.TryAdd(Address(i)));
                limiter.Remove(Address(i));
            }

            // still within their attempt windows, so they're remembered for rate limiting
            Assert.AreEqual(100, limiter.TrackedClientCount);

            limiter.Prune(DateTime.UtcNow.AddSeconds(10));

            Assert.AreEqual(0, limiter.TrackedClientCount);
        }

        [Test]
        public void IPsWithActiveConnectionsAreKept()
        {
            var limiter = new ConnectionLimiter();
            limiter.SetAttemptLimits(5, TimeSpan.FromSeconds(5));

            Assert.IsTrue(limiter.TryAdd(Address(1)));

            limiter.Prune(DateTime.UtcNow.AddSeconds(10));

            Assert.AreEqual(1, limiter.TrackedClientCount);
        }

        [Test]
        public void LeavingAfterTheWindowForgetsImmediately()
        {
            var limiter = new ConnectionLimiter();
            limiter.SetAttemptLimits(5, TimeSpan.FromMilliseconds(1));

            Assert.IsTrue(limiter.TryAdd(Address(1)));
            System.Threading.Thread.Sleep(20);
            limiter.Remove(Address(1));

            Assert.AreEqual(0, limiter.TrackedClientCount);
        }

        [Test]
        public void ANewIPGetsTheFullAttemptLimit()
        {
            var limiter = new ConnectionLimiter();
            limiter.SetAttemptLimits(3, TimeSpan.FromMinutes(1));

            for (var i = 0; i < 3; i++)
            {
                Assert.IsTrue(limiter.TryAdd(Address(1)), $"attempt {i + 1} of 3 should be allowed");
                limiter.Remove(Address(1));
            }

            Assert.IsFalse(limiter.TryAdd(Address(1)), "the fourth attempt within the window should be refused");
        }

        [Test]
        public void AnIPWhoseWindowPassedGetsTheSameLimitAsANewOne()
        {
            var limiter = new ConnectionLimiter();
            limiter.SetAttemptLimits(3, TimeSpan.FromMilliseconds(50));

            // keep a connection open so the entry is kept past its window
            Assert.IsTrue(limiter.TryAdd(Address(1)));
            System.Threading.Thread.Sleep(100);

            var allowed = 0;
            while (limiter.TryAdd(Address(1)))
                allowed++;

            Assert.AreEqual(3, allowed);
        }

        [Test]
        public void ConnectingAndDisconnectingInALoopIsStillLimited()
        {
            var limiter = new ConnectionLimiter();
            limiter.SetAttemptLimits(5, TimeSpan.FromMinutes(1));

            var allowed = 0;
            for (var i = 0; i < 20; i++)
            {
                if (!limiter.TryAdd(Address(1)))
                    continue;

                allowed++;
                limiter.Remove(Address(1));
            }

            Assert.AreEqual(5, allowed);
        }
    }
}

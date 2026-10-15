using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace Fleck.Tests
{
    [TestFixture]
    public class FleckLogTests
    {
        private LogLevel _originalLevel;
        private Action<LogLevel, string, Exception> _originalAction;
        private List<LogLevel> _logged;

        [SetUp]
        public void SetUp()
        {
            _originalLevel = FleckLog.Level;
            _originalAction = FleckLog.LogAction;
            _logged = new List<LogLevel>();
            FleckLog.LogAction = (level, message, ex) => _logged.Add(level);
        }

        [TearDown]
        public void TearDown()
        {
            FleckLog.Level = _originalLevel;
            FleckLog.LogAction = _originalAction;
        }

        [Test]
        public void LevelIsTheMinimumLogged()
        {
            FleckLog.Level = LogLevel.Warn;

            FleckLog.Warn("warn");
            FleckLog.Error("error");

            CollectionAssert.AreEqual(new[] { LogLevel.Warn, LogLevel.Error }, _logged);
        }

        [Test]
        public void ErrorLevelOnlyLogsErrors()
        {
            FleckLog.Level = LogLevel.Error;

            FleckLog.Warn("warn");
            FleckLog.Error("error");

            CollectionAssert.AreEqual(new[] { LogLevel.Error }, _logged);
        }

        [Test]
        public void IsEnabled()
        {
            FleckLog.Level = LogLevel.Info;

            Assert.IsFalse(FleckLog.IsEnabled(LogLevel.Debug));
            Assert.IsTrue(FleckLog.IsEnabled(LogLevel.Info));
            Assert.IsTrue(FleckLog.IsEnabled(LogLevel.Warn));
            Assert.IsTrue(FleckLog.IsEnabled(LogLevel.Error));
        }
    }
}

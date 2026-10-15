using System;
using System.Diagnostics;

namespace Fleck
{
    public enum LogLevel
    {
        Debug,
        Info,
        Warn,
        Error
    }

    public class FleckLog
    {
        /// <summary>
        /// The minimum level that gets passed to <see cref="LogAction"/>.
        /// </summary>
        public static LogLevel Level = LogLevel.Info;
        
        public static Action<LogLevel, string, Exception> LogAction = (level, message, ex) =>
        {
#if DEBUG
            Console.WriteLine("{0} [{1}] {2} {3}", DateTime.Now, level, message, ex);
#endif
        };
        
        public static void Warn(string message, Exception ex = null)
        {
            if (IsEnabled(LogLevel.Warn))
                LogAction?.Invoke(LogLevel.Warn, message, ex);
        }
        
        public static void Error(string message, Exception ex = null)
        {
            if (IsEnabled(LogLevel.Error))
                LogAction?.Invoke(LogLevel.Error, message, ex);
        }

        [Conditional("DEBUG")]
        public static void Debug(string message, Exception ex = null)
        {
            if (IsEnabled(LogLevel.Debug))
                LogAction?.Invoke(LogLevel.Debug, message, ex);
        }
        
        [Conditional("DEBUG")]
        public static void Info(string message, Exception ex = null)
        {
            if (IsEnabled(LogLevel.Info))
                LogAction?.Invoke(LogLevel.Info, message, ex);
        }

        public static bool IsEnabled(LogLevel level)
        {
            return level >= Level;
        }
    }
}

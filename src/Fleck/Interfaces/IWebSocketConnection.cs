using System;

namespace Fleck
{
    public delegate void BinaryDataHandler(Span<byte> data);

    public interface IWebSocketConnection
    {
        Action OnOpen { get; set; }
        Action OnClose { get; set; }
        Action<string> OnMessage { get; set; }
        BinaryDataHandler OnBinary { get; set; }
        BinaryDataHandler OnPing { get; set; }
        BinaryDataHandler OnPong { get; set; }
        Action<Exception> OnError { get; set; }
        void Send(string message);
        void Send(MemoryBuffer message);
        void Send(ReadOnlySpan<byte> prefix, MemoryBuffer message);
        void SendPing(MemoryBuffer message);
        void SendPong(MemoryBuffer message);
        void Close();
        void Close(ushort code);
        IWebSocketConnectionInfo ConnectionInfo { get; }
        bool IsAvailable { get; }
        int MaxPendingSends { get; set; }
    }
}

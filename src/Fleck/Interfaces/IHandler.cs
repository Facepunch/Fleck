using System;

namespace Fleck
{
    public interface IHandler : IDisposable
    {
        void Receive(Span<byte> newData);
        MemoryBuffer CreateHandshake();
        MemoryBuffer FrameText(string text);
        MemoryBuffer FrameText(MemoryBuffer utf8StringBytes);
        MemoryBuffer FrameBinary(MemoryBuffer bytes);
        MemoryBuffer FrameBinary(ReadOnlySpan<byte> prefix, MemoryBuffer bytes);
        MemoryBuffer FramePing(MemoryBuffer bytes);
        MemoryBuffer FramePong(MemoryBuffer bytes);
        MemoryBuffer FrameClose(ushort code);
    }
}

